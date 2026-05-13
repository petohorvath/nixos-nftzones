/*
  rpfilter VM test: `settings.rpfilter = true` synthesizes a
  prerouting-at-raw chain that drops packets whose source IP
  doesn't reverse-route through the ingress interface. Three
  NixOS VMs (client, router, spoofer) on a lan/wan topology.

  Topology:
                lan vlan 1                       wan vlan 2
            192.168.1.0/24                    203.0.113.0/24
   [client] ── eth1 (.10)  ── eth1 [router] eth2 ── (.99 + .lan.99/32 alias) [spoofer]
                                  (.1)            (.1)

  Spoofer's eth1 carries two addresses:
    - 203.0.113.99/24 — its legitimate wan-range identity
    - 192.168.1.99/32 — a lan-range alias, intentionally on the
      *wan* interface so that the kernel happily forms a packet
      with this source but routes it via the wan-side default
      gateway. The /32 (not /24) keeps it from creating a
      bogus connected route to 192.168.1.0/24 on eth1.

  Router's filter chain is intentionally permissive (lan↔wan
  accept, no default-deny policy) so that the only mechanism
  that can drop the spoofed packet is rpfilter itself. Without
  rpfilter, the spoofed ping would reach client. With rpfilter,
  the packet is dropped at PREROUTING priority -300 — *before*
  conntrack (priority -200) creates an entry, so the assertion
  can lean on conntrack on the router being empty for the
  spoofed flow.

  Subtests:
    - Legit src (203.0.113.99): rpfilter accepts (FIB lookup
      for 203.0.113.99 points at eth2, matches iif). Ping
      reaches client and returns.
    - Spoofed src (192.168.1.99): rpfilter drops (FIB lookup
      for 192.168.1.99 points at eth1, doesn't match iif eth2).
      Ping fails; no conntrack entry on router.

  Companion files: `forward.nix` (lan/wan NAT + policy),
  `vlan.nix` (router-on-a-stick inter-VLAN).
*/
{
  pkgs,
  nftypes,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl) accept;

  lanNet = "192.168.1";
  wanNet = "203.0.113";

  clientLanIp = "${lanNet}.10";
  routerLanIp = "${lanNet}.1";
  routerWanIp = "${wanNet}.1";
  spooferWanIp = "${wanNet}.99";
  spooferSpoofedIp = "${lanNet}.99";
in
pkgs.testers.nixosTest {
  name = "nftzones-rpfilter";

  nodes = {
    client =
      { lib, ... }:
      {
        virtualisation.vlans = [ 1 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          # Nullify the per-vlan auto-IP `virtualisation.vlans`
          # injects on eth1 so the explicit unit below is the
          # only one that lands an Address= for the iface.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        # Anchor `network-online.target` to `multi-user.target`.
        # NixOS enables `systemd-networkd-wait-online.service`
        # (wanted-by network-online), but nothing in the default
        # stack pulls in network-online itself.
        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [ "${clientLanIp}/24" ];
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
              # The point of the test — turning this on synthesizes
              # a prerouting-at-raw chain that drops packets whose
              # saddr doesn't reverse-route via the ingress iface.
              settings.rpfilter = true;

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

              # Permissive both directions so rpfilter is the
              # *only* mechanism that can drop the spoofed probe.
              # If a wan→lan filter were missing or default-deny,
              # the spoofed ping would fail for the wrong reason
              # and the test would be uninformative.
              filters.lan-to-wan-allow = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ accept ];
              };
              filters.wan-to-lan-allow = {
                from = [ "wan" ];
                to = [ "lan" ];
                rule = [ accept ];
              };
            };
          };
        };

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks = {
          "10-eth1" = {
            matchConfig.Name = "eth1";
            address = [ "${routerLanIp}/24" ];
          };
          "10-eth2" = {
            matchConfig.Name = "eth2";
            address = [ "${routerWanIp}/24" ];
          };
        };

        # `conntrack` lets the spoofed subtest verify that
        # rpfilter dropped the packet *before* conntrack got a
        # chance to create an entry (rpfilter runs at prerouting
        # priority -300, conntrack at -200).
        environment.systemPackages = [ pkgs.conntrack-tools ];
      };

    spoofer =
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

        # Two Address= entries on eth1: a normal wan-range IP
        # plus a /32 alias from the lan range. The /32 alone
        # gives the kernel a usable source IP without creating a
        # connected route to 192.168.1.0/24 on the wan iface —
        # any packet whose dst is in 192.168.1.0/24 hits the
        # default gateway (the router) rather than ARP'ing for
        # the dst on eth1's local L2.
        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [
            "${spooferWanIp}/24"
            "${spooferSpoofedIp}/32"
          ];
          networkConfig.Gateway = routerWanIp;
        };
      };
  };

  testScript = ''
    start_all()

    client.wait_for_unit("network-online.target")
    router.wait_for_unit("network-online.target")
    spoofer.wait_for_unit("network-online.target")

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

    with diag_subtest("rpfilter accepts legit src (203.0.113.99 → client)"):
        # Spoofer pings client using its real wan-range source.
        # rpfilter's FIB lookup for 203.0.113.99 points at eth2
        # (the wan iface where the packet arrived), so the check
        # passes and the ping reaches client through the
        # permissive forward filter. Evidence the reply came
        # back: conntrack's entry for the flow loses the
        # [UNREPLIED] flag (set when only the original direction
        # has been seen). ICMP doesn't reach [ASSURED] after a
        # single echo+reply on every kernel, so [UNREPLIED]
        # absence is the portable indicator.
        router.succeed("conntrack -F")
        out = spoofer.succeed(
            "ping -I ${spooferWanIp} -c 1 -W 2 ${clientLanIp}"
        )
        ct = conntrack("-p icmp -s ${spooferWanIp}")

        assert "0% packet loss" in out, (
            f"expected legit src ping to succeed, got: {out!r}"
        )
        assert "[UNREPLIED]" not in ct, (
            f"expected reply observed (no [UNREPLIED]) for legit flow:\n{ct}"
        )

    with diag_subtest("rpfilter drops spoofed src (192.168.1.99 → client)"):
        # Same destination, same egress iface, only src differs.
        # rpfilter looks up the FIB for 192.168.1.99 — points at
        # eth1 (the lan iface where the router knows 192.168.1.0/24
        # lives). The ingress iface (eth2) doesn't match, so
        # the synthesized prerouting-at-raw chain drops the
        # packet. Because rpfilter runs at priority -300, before
        # conntrack at -200, no conntrack entry forms — assertion
        # leans on that.
        router.succeed("conntrack -F")
        result = spoofer.execute(
            "ping -I ${spooferSpoofedIp} -c 1 -W 2 ${clientLanIp}"
        )
        ct = conntrack("-p icmp -s ${spooferSpoofedIp}")

        assert result[0] != 0, (
            "expected spoofed src ping to be dropped by rpfilter, "
            f"but it succeeded: {result[1]!r}"
        )
        # Filter already scoped to `-s spooferSpoofedIp`; if
        # rpfilter dropped before conntrack, the table contains
        # nothing matching this src. A non-empty result means
        # conntrack saw the packet, which means rpfilter didn't
        # fire.
        assert ct.strip() == "", (
            f"rpfilter let spoofed src create a conntrack entry:\n{ct}"
        )
  '';
}
