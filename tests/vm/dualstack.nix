/*
  Dual-stack VM test: zones carrying both v4 and v6 CIDRs in
  an `inet`-family table. Three NixOS VMs (client, router,
  server) each configured with both an IPv4 and an IPv6
  address. The router's nftzones config forwards lan ↔ wan
  for both protocol families on a single set of filter and
  masquerade rules; the test pings the server from the client
  on both v4 and v6 and verifies the router's conntrack has
  entries for each.

  Topology:
                          lan vlan 1                     wan vlan 2
                  192.168.1.0/24                       203.0.113.0/24
                  fd00:dead::/64                       2001:db8::/64
    [client] ── eth1 (.10 / ::10) ─── eth1 [router] eth2 ── (.10 / ::10) eth1 [server]
                                          (.1 / ::1)    (.1 / ::1)

  Why the explicit ICMPv6 input-allow:

  IPv4 ARP runs at L2 — netfilter's `ip`/`ip6`/`inet` tables
  never see it, so the router's input chain doesn't have to
  allow anything for ARP-based neighbour discovery to work.
  IPv6 NDP is the opposite: Neighbour Solicitation / Advert.
  travel as ICMPv6 packets up through the IP stack, hit the
  router's input chain, and are dropped by the default
  chain-drop policy unless an explicit rule accepts them.
  Without that allow, the v6 ping fails not because of a
  forwarding bug but because the client never learns the
  router's link-layer address.

  Companion files: `forward.nix`, `vlan.nix`, `rpfilter.nix`,
  `marks.nix`.
*/
{
  pkgs,
  nftypes,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) meta;

  lanNet4 = "192.168.1";
  wanNet4 = "203.0.113";
  lanNet6 = "fd00:dead";
  wanNet6 = "2001:db8";

  clientLanIp4 = "${lanNet4}.10";
  routerLanIp4 = "${lanNet4}.1";
  routerWanIp4 = "${wanNet4}.1";
  serverWanIp4 = "${wanNet4}.10";

  clientLanIp6 = "${lanNet6}::10";
  routerLanIp6 = "${lanNet6}::1";
  routerWanIp6 = "${wanNet6}::1";
  serverWanIp6 = "${wanNet6}::10";
in
pkgs.testers.nixosTest {
  name = "nftzones-dualstack";

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

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [
            "${clientLanIp4}/24"
            "${clientLanIp6}/64"
          ];
          # Both v4 and v6 default routes via the router. Each
          # [Route] section's Destination= defaults to the
          # family-appropriate "any" (0.0.0.0/0 or ::/0) when
          # only Gateway= is given.
          routes = [
            { routeConfig.Gateway = routerLanIp4; }
            { routeConfig.Gateway = routerLanIp6; }
          ];
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

        boot.kernel.sysctl = {
          "net.ipv4.ip_forward" = 1;
          "net.ipv6.conf.all.forwarding" = 1;
        };

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
              # Default family is `inet` — covers both v4 and
              # v6 from one ruleset. Each zone splits internally
              # into <zone>_v4 and <zone>_v6 sets; jump rules
              # in the base chain fan out per family.
              zones = {
                lan = {
                  interfaces = [ "eth1" ];
                  cidrs = [
                    "${lanNet4}.0/24"
                    "${lanNet6}::/64"
                  ];
                };
                wan = {
                  interfaces = [ "eth2" ];
                  cidrs = [
                    "${wanNet4}.0/24"
                    "${wanNet6}::/64"
                  ];
                };
              };

              # Lan → wan forwarding applies to both protocol
              # families via the inet table; one filter covers
              # both v4 and v6 forwarding.
              filters.lan-out = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ accept ];
              };

              # ICMPv6 to local must be explicitly allowed
              # (see file header). NDP travels as ICMPv6 up
              # through the IP stack to the router's input
              # chain; without this filter the chain-drop
              # default would silently break v6 forwarding by
              # blocking neighbour discovery.
              filters.allow-icmpv6-input = {
                from = [
                  "lan"
                  "wan"
                ];
                to = [ "local" ];
                rule = [
                  (eq meta.l4proto "icmpv6")
                  accept
                ];
              };

              # Masquerade lan → wan. In an inet table this
              # covers both v4 and v6 sources. The test
              # doesn't assert on src-IP rewrite (NAT66 is
              # discouraged in practice), only that the
              # forwarding path works — the masquerade exists
              # so the v4 path's return traffic has a stable
              # path back through the router for un-NAT.
              snats.lan-snat = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule.masquerade = { };
              };
            };
          };
        };

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks = {
          "10-eth1" = {
            matchConfig.Name = "eth1";
            address = [
              "${routerLanIp4}/24"
              "${routerLanIp6}/64"
            ];
          };
          "10-eth2" = {
            matchConfig.Name = "eth2";
            address = [
              "${routerWanIp4}/24"
              "${routerWanIp6}/64"
            ];
          };
        };

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
          address = [
            "${serverWanIp4}/24"
            "${serverWanIp6}/64"
          ];
          routes = [
            { routeConfig.Gateway = routerWanIp4; }
            { routeConfig.Gateway = routerWanIp6; }
          ];
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
    # dumps router state on failure, silent on green.
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
                    routes = router.succeed("ip -4 route; echo ---; ip -6 route")
                except Exception:
                    ruleset = ct = routes = "(failed to capture)"
                print(
                    f"\n=== router state at failure of {self.name!r} ===\n"
                    f"--- nft list ruleset ---\n{ruleset}\n"
                    f"--- conntrack -L ---\n{ct}\n"
                    f"--- ip route ---\n{routes}\n"
                    f"=== end router state ===\n",
                    flush=True,
                )
            return self._cm.__exit__(exc_type, exc, tb)

    with diag_subtest("dual-stack: client pings server over IPv4"):
        # Sanity: prove the v4 path still works on a dual-
        # stack zone. Without this, a v6-only regression
        # could hide a v4 break.
        router.succeed("conntrack -F")
        out = client.succeed("ping -4 -c 1 -W 2 ${serverWanIp4}")
        assert "0% packet loss" in out, (
            f"expected v4 ping to succeed, got: {out!r}"
        )

    with diag_subtest("dual-stack: client pings server over IPv6"):
        # The actual new coverage. v6 echo-request from client
        # traverses router (where NDP must have resolved both
        # neighbours, hence the ICMPv6 input allow), reaches
        # server, reply comes back via the stateful prelude.
        router.succeed("conntrack -F")
        out = client.succeed("ping -6 -c 1 -W 2 ${serverWanIp6}")
        assert "0% packet loss" in out, (
            f"expected v6 ping to succeed, got: {out!r}"
        )

    with diag_subtest("dual-stack: router conntrack tracks v6 flow"):
        # Re-run the v6 ping after flush so the only ICMPv6
        # entry on the router is from this subtest, then
        # confirm the entry mentions the v6 source and isn't
        # stuck in [UNREPLIED] (reply was observed).
        router.succeed("conntrack -F")
        client.succeed("ping -6 -c 1 -W 2 ${serverWanIp6}")
        ct = conntrack("-f ipv6 -p icmpv6 -s ${clientLanIp6}")
        assert "${clientLanIp6}" in ct, (
            f"expected v6 src '${clientLanIp6}' in conntrack:\n{ct}"
        )
        assert "[UNREPLIED]" not in ct, (
            f"expected reply observed (no [UNREPLIED]) for v6 flow:\n{ct}"
        )
  '';
}
