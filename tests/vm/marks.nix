/*
  fwmark VM test: `sroutes` set `meta mark` on inbound packets
  so an out-of-nftables `ip rule` can steer them to an
  alternate routing table. Three NixOS VMs (client, router,
  server) on a lan/wan topology. The mark target is selected
  by source IP via a `node` (a child zone of `lan` with a
  specific /32 address), so the same lan iface carries both
  marked and unmarked traffic with no zone-overlap rejection.

  Topology:
                  lan vlan 1                   wan vlan 2
              192.168.1.0/24                  203.0.113.0/24
   [client] ── eth1 (.10 + .5/32)  ─── eth1 [router] eth2 ── (.10) eth1 [server]
                                          (.1)            (.1)

  The client carries two source addresses on eth1 — a primary
  192.168.1.10/24 (creates the connected route) and a /32
  alias 192.168.1.5 (no connected route, just a usable source
  IP). The test uses `ping -I <src>` to choose which lan IP
  the kernel puts on the wire.

  Router's nftzones config:
    - `lan`  zone: cidr 192.168.1.0/24, iface eth1.
    - `wan`  zone: cidr 203.0.113.0/24, iface eth2.
    - `marked-host` node: child of `lan`, address.ipv4 = 192.168.1.5.
    - filter: lan → wan accept (covers both parent and child).
    - snat: lan → wan masquerade (covers both).
    - sroute on `marked-host` sets `meta mark 100`.

  Outside nftzones (via `systemd.network` on the router):
    - routing-policy rule: `from all fwmark 100 lookup 100`.
    - table 100 has a single `unreachable default` route.

  End-to-end flow:
    - Packet from src=192.168.1.10 → matches `lan` only, no
      sroute, no mark, main table → reaches server.
    - Packet from src=192.168.1.5 → matches `marked-host`,
      sroute fires (`meta mark set 100`), routing decision
      consults fwmark, table 100 returns `unreachable`,
      kernel emits ICMP destination-unreachable back. Ping
      fails with an unreachable-class error.

  Caveat: the marked-path filter coverage relies on the lan→
  wan filter applying to children too — nftzones' zone parent
  dispatch sends child traffic through the parent's chain
  unless the child has its own rule. Tested in
  `tests/integration/scenarios/parent-basic.nix`.

  Companion files: `forward.nix`, `vlan.nix`, `rpfilter.nix`.
*/
{
  pkgs,
  nftypes,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl) accept mangle;
  inherit (nftypes.dsl.fields) meta;

  lanNet = "192.168.1";
  wanNet = "203.0.113";

  routerLanIp = "${lanNet}.1";
  routerWanIp = "${wanNet}.1";

  clientNormalIp = "${lanNet}.10";
  clientMarkedIp = "${lanNet}.5";
  serverWanIp = "${wanNet}.10";
in
pkgs.testers.nixosTest {
  name = "nftzones-marks";

  nodes = {
    client =
      { lib, ... }:
      {
        virtualisation.vlans = [ 1 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        # Anchor `network-online.target` — NixOS enables
        # `systemd-networkd-wait-online.service` but nothing
        # in the default stack pulls in the target itself.
        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        # Primary /24 plus a /32 alias. The /32 doesn't create
        # an additional connected route — it's just a usable
        # source IP that `ping -I` can pick.
        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [
            "${clientNormalIp}/24"
            "${clientMarkedIp}/32"
          ];
          networkConfig.Gateway = routerLanIp;
        };
      };

    router =
      { lib, pkgs, ... }:
      {
        imports = [ nftzonesModule ];

        virtualisation.vlans = [
          1
          2
        ];

        boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
          interfaces.eth2.ipv4.addresses = lib.mkForce [ ];

          nftables.enable = true;

          nftzones = {
            enable = true;
            tables.fw = {
              zones = {
                lan = {
                  interfaces = [ "eth1" ];
                  cidrs = [ "${lanNet}.0/24" ];
                };
                wan = {
                  interfaces = [ "eth2" ];
                  cidrs = [ "${wanNet}.0/24" ];
                };
              };

              # Child zone of `lan` keyed on the /32 — lets
              # the sroute below scope by source IP without
              # claiming a duplicate iface for a second zone
              # (which the interfaceOverlap validator rejects).
              nodes.marked-host = {
                zone = "lan";
                address.ipv4 = clientMarkedIp;
              };

              # Permit lan → wan forwarding. Covers both the
              # parent and the marked-host child via nftzones'
              # zone-parent dispatch (child traffic falls
              # through to parent's chain unless overridden).
              filters.lan-out = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ accept ];
              };

              # Masquerade lan → wan so the normal-path return
              # traffic finds its way back. (Marked path never
              # reaches POSTROUTING — table 100's unreachable
              # default drops first.)
              snats.lan-snat = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule.masquerade = { };
              };

              # The point of the test — sroute sets meta mark
              # at PREROUTING priority `mangle` (-150), before
              # the routing decision (-100). The mark is
              # therefore visible to the kernel's RPDB lookup
              # that follows.
              sroutes.marked-host-via-table-100 = {
                from = [ "marked-host" ];
                rule = [ (mangle meta.mark 100) ];
              };
            };
          };
        };

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network = {
          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            address = [ "${routerLanIp}/24" ];
          };
          networks."10-eth2" = {
            matchConfig.Name = "eth2";
            address = [ "${routerWanIp}/24" ];

            # Routing policy: any packet with `fwmark 100`
            # looks up table 100 first. systemd-networkd
            # installs this rule when eth2 comes up.
            routingPolicyRules = [
              {
                routingPolicyRuleConfig = {
                  FirewallMark = 100;
                  Table = 100;
                };
              }
            ];

            # Table 100 contains exactly one route: an
            # unreachable default. Marked traffic hits this
            # and the kernel emits ICMP destination-
            # unreachable back to the source.
            routes = [
              {
                routeConfig = {
                  Type = "unreachable";
                  Destination = "0.0.0.0/0";
                  Table = 100;
                };
              }
            ];
          };
        };

        # `conntrack` lets the test inspect what hit the
        # router — useful when a subtest fails since the
        # marked-path entry shows up in conntrack even though
        # routing then discards it.
        environment.systemPackages = [ pkgs.conntrack-tools ];
      };

    server =
      { lib, ... }:
      {
        virtualisation.vlans = [ 2 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [ "${serverWanIp}/24" ];
          networkConfig.Gateway = routerWanIp;
        };
      };
  };

  testScript = ''
    start_all()

    client.wait_for_unit("network-online.target")
    router.wait_for_unit("network-online.target")
    server.wait_for_unit("network-online.target")

    def conntrack(args):
        return router.succeed(f"conntrack -L {args} 2>/dev/null")

    # See `forward.nix` for the rationale on this wrapper —
    # on failure dumps router state including `ip rule` and
    # the alternate routing table.
    class diag_subtest:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            self._cm = subtest(self.name)
            return self._cm.__enter__()

        def __exit__(self, exc_type, exc, tb):
            if exc_type is not None:
                try:
                    ruleset = router.succeed("nft list ruleset")
                    ct = router.succeed("conntrack -L 2>/dev/null || true")
                    routes = router.succeed(
                        "ip -4 route; echo --- table 100 ---;"
                        " ip -4 route show table 100;"
                        " echo --- ip rule ---;"
                        " ip -4 rule"
                    )
                except Exception:
                    ruleset = ct = routes = "(failed to capture)"
                print(
                    f"\n=== router state at failure of {self.name!r} ===\n"
                    f"--- nft list ruleset ---\n{ruleset}\n"
                    f"--- conntrack -L ---\n{ct}\n"
                    f"--- ip route / rule ---\n{routes}\n"
                    f"=== end router state ===\n",
                    flush=True,
                )
            return self._cm.__exit__(exc_type, exc, tb)

    with diag_subtest("normal src reaches server (no mark, main table)"):
        # Source 192.168.1.10 doesn't match the marked-host
        # node (which is keyed on 192.168.1.5/32). No sroute,
        # no mark, main table; default route via eth2 takes
        # the packet to server. Return traffic returns via the
        # stateful prelude.
        router.succeed("conntrack -F")
        out = client.succeed(
            "ping -I ${clientNormalIp} -c 1 -W 2 ${serverWanIp}"
        )
        ct = conntrack("-p icmp -s ${clientNormalIp}")

        assert "0% packet loss" in out, (
            f"expected normal src ping to succeed, got: {out!r}"
        )
        assert "[UNREPLIED]" not in ct, (
            f"expected reply observed (no [UNREPLIED]) for normal flow:\n{ct}"
        )

    with diag_subtest("marked-host src is rerouted to unreachable table 100"):
        # Same destination, same egress iface, only source
        # differs. sroute matches `from = [ "marked-host" ]`,
        # sets mark=100, RPDB sends it to table 100, kernel
        # finds only the unreachable default, returns ICMP
        # destination-unreachable. ping reports it both in
        # output text and exit code.
        router.succeed("conntrack -F")
        result = client.execute(
            "ping -I ${clientMarkedIp} -c 1 -W 2 ${serverWanIp}"
        )

        assert result[0] != 0, (
            "expected marked-host src ping to fail (table 100 has "
            f"unreachable default), but it succeeded: {result[1]!r}"
        )
        # `unreachable` route emits ICMP host-/net-unreachable
        # on miss; ping surfaces one of "Destination Net
        # Unreachable", "Destination Host Unreachable", or
        # "Network is unreachable". Accept any unreachable
        # variant — `100% packet loss` alone would mean the
        # packet got out but no reply came (sroute didn't
        # actually mark).
        assert "nreachable" in result[1], (
            f"expected ICMP unreachable in ping output, got: {result[1]!r}"
        )
  '';
}
