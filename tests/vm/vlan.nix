/*
  Inter-VLAN routing VM test: router-on-a-stick. Three NixOS
  VMs (router, vlan-iot, vlan-admin) sharing a single trunk
  vlan; each end-host tags its frames with a distinct 802.1Q
  ID, the router demuxes via sub-interfaces and applies its
  per-zone forward filter. Asserts:

    - Inter-VLAN allow (admin VLAN reaches iot VLAN through
      the router)
    - Inter-VLAN default-deny (iot cannot initiate to admin;
      chain-level policy drops without a matching filter)

  Topology:
                          trunk vlan 3 (untagged carrier)
                            router eth1 (no IP)
                          ├── eth1.10 (vlan tag 10) 192.168.10.1/24  ── iot
                          └── eth1.20 (vlan tag 20) 192.168.20.1/24  ── admin

    [vlan-iot]   eth1 (no IP), eth1.10 (vlan 10, 192.168.10.10/24)  ─┐
                                                                     │ vlan 3
    [vlan-admin] eth1 (no IP), eth1.20 (vlan 20, 192.168.20.10/24)  ─┘

  Companion: `forward.nix` covers L3 forwarding + NAT + policy
  on a more conventional lan/wan topology.
*/
{
  pkgs,
  nftypes,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl) accept;

  iotNet = "192.168.10";
  adminNet = "192.168.20";

  routerIotIp = "${iotNet}.1";
  routerAdminIp = "${adminNet}.1";
  vlanIotIp = "${iotNet}.10";
  vlanAdminIp = "${adminNet}.10";

  iotVlanId = 10;
  adminVlanId = 20;
in
pkgs.testers.nixosTest {
  name = "nftzones-vlan";

  nodes = {
    router =
      { lib, pkgs, ... }:
      {
        imports = [ nftzonesModule ];

        virtualisation.vlans = [ 3 ];

        boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          # Trunk parent — no IP. Nullify the per-vlan auto-IP
          # `virtualisation.vlans` would otherwise drop on eth1
          # so all addressing lives on the tagged sub-interfaces
          # below.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];

          nftables.enable = true;

          nftzones = {
            enable = true;
            tables.fw = {
              zones = {
                # Both zones key off the trunk's 802.1Q sub-
                # interfaces; the router uses those sub-iface
                # names directly (no parent eth1 in any zone).
                iot = {
                  interfaces = [ "eth1.${toString iotVlanId}" ];
                  cidrs = [ "${iotNet}.0/24" ];
                };
                admin = {
                  interfaces = [ "eth1.${toString adminVlanId}" ];
                  cidrs = [ "${adminNet}.0/24" ];
                };
              };

              # Inter-VLAN allow: admin manages iot devices. No
              # reverse filter — iot → admin is dropped at the
              # forward chain's `policy drop`. Return traffic for
              # admin-initiated flows is accepted by the stateful
              # prelude, so this single rule gives admin a working
              # bidirectional channel without granting iot the
              # ability to initiate.
              filters.admin-to-iot = {
                from = [ "admin" ];
                to = [ "iot" ];
                rule = [ accept ];
              };
            };
          };
        };

        # Anchor for `network-online.target` — see vlan-iot config
        # for rationale.
        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        # Trunk parent eth1 (no IP), plus the two 802.1Q sub-
        # interfaces declared as `vlan`-kind netdevs and attached
        # to the parent via the trunk's `VLAN=` directive.
        systemd.network = {
          netdevs."10-eth1.${toString iotVlanId}" = {
            netdevConfig = {
              Name = "eth1.${toString iotVlanId}";
              Kind = "vlan";
            };
            vlanConfig.Id = iotVlanId;
          };
          netdevs."10-eth1.${toString adminVlanId}" = {
            netdevConfig = {
              Name = "eth1.${toString adminVlanId}";
              Kind = "vlan";
            };
            vlanConfig.Id = adminVlanId;
          };
          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            vlan = [
              "eth1.${toString iotVlanId}"
              "eth1.${toString adminVlanId}"
            ];
          };
          networks."10-eth1.${toString iotVlanId}" = {
            matchConfig.Name = "eth1.${toString iotVlanId}";
            address = [ "${routerIotIp}/24" ];
          };
          networks."10-eth1.${toString adminVlanId}" = {
            matchConfig.Name = "eth1.${toString adminVlanId}";
            address = [ "${routerAdminIp}/24" ];
          };
        };

        # `conntrack` lets the deny subtest verify the firewall
        # (not VLAN demux or routing) is the layer dropping
        # iot→admin traffic — the ICMP entry stays [UNREPLIED]
        # and never reaches [ASSURED].
        environment.systemPackages = [ pkgs.conntrack-tools ];
      };

    # Two VLAN-tagged hosts share the trunk vlan (3). Each tags
    # its frames with a distinct 802.1Q ID, so frames traversing
    # the shared L2 broadcast domain are demuxed by the receiving
    # sub-interface — the textbook router-on-a-stick pattern,
    # mirrored at the host side.
    vlan-iot =
      { lib, ... }:
      {
        virtualisation.vlans = [ 3 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          # Trunk parent — no IP. Nullify the per-vlan auto-IP
          # `virtualisation.vlans` would otherwise drop on eth1.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        # Anchor `network-online.target` to `multi-user.target`.
        # NixOS enables `systemd-networkd-wait-online.service`
        # (wanted-by network-online), but nothing in the default
        # stack pulls in network-online itself, so without this
        # the target sits inactive and the test driver's
        # `wait_for_unit("network-online.target")` finds it with
        # no pending jobs.
        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network = {
          netdevs."10-eth1.${toString iotVlanId}" = {
            netdevConfig = {
              Name = "eth1.${toString iotVlanId}";
              Kind = "vlan";
            };
            vlanConfig.Id = iotVlanId;
          };
          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            vlan = [ "eth1.${toString iotVlanId}" ];
          };
          networks."10-eth1.${toString iotVlanId}" = {
            matchConfig.Name = "eth1.${toString iotVlanId}";
            address = [ "${vlanIotIp}/24" ];
            networkConfig.Gateway = routerIotIp;
          };
        };
      };

    vlan-admin =
      { lib, ... }:
      {
        virtualisation.vlans = [ 3 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          # See vlan-iot for rationale on the eth1 nullification.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        # Anchor for `network-online.target` — see vlan-iot config
        # for rationale.
        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network = {
          netdevs."10-eth1.${toString adminVlanId}" = {
            netdevConfig = {
              Name = "eth1.${toString adminVlanId}";
              Kind = "vlan";
            };
            vlanConfig.Id = adminVlanId;
          };
          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            vlan = [ "eth1.${toString adminVlanId}" ];
          };
          networks."10-eth1.${toString adminVlanId}" = {
            matchConfig.Name = "eth1.${toString adminVlanId}";
            address = [ "${vlanAdminIp}/24" ];
            networkConfig.Gateway = routerAdminIp;
          };
        };
      };
  };

  testScript = ''
    start_all()

    # With `networking.useNetworkd = true`, systemd-networkd-wait-
    # online is pulled in and `network-online.target` becomes a
    # precise signal: it fires once every configured interface has
    # an address.
    router.wait_for_unit("network-online.target")
    vlan_iot.wait_for_unit("network-online.target")
    vlan_admin.wait_for_unit("network-online.target")

    def conntrack(args):
        return router.succeed(f"conntrack -L {args} 2>/dev/null")

    # `subtest` wrapper that dumps the router's nftables ruleset,
    # conntrack table, and routing table on failure. Silent on
    # green; captures the firewall's state at the moment of
    # failure on red.
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

    with diag_subtest("inter-VLAN: admin-VLAN reaches iot-VLAN through router"):
        # admin (vlan tag 20, 192.168.20.10) → router eth1.20
        # → forward chain matches admin-to-iot filter → router
        # eth1.10 → iot (vlan tag 10, 192.168.10.10). Stateful
        # prelude carries the echo reply back. Confirms that
        # zone membership keyed off VLAN sub-interface names
        # drives correct dispatch on a single physical trunk port.
        #
        # The first probe across this path traverses three ARP
        # boundaries (admin → router admin sub-iface → router iot
        # sub-iface → iot); a cold cache can lose the first packet
        # within the 2 s budget. Warm with one tolerated probe
        # before the asserting one — if the warm-up succeeds the
        # asserting probe also succeeds, and if the warm-up loses
        # to ARP the assert still has a populated cache to work
        # with.
        vlan_admin.execute("ping -c1 -W2 ${vlanIotIp}")
        out = vlan_admin.succeed("ping -c1 -W2 ${vlanIotIp}")
        assert "0% packet loss" in out, (
            f"expected admin → iot ping to succeed, got: {out!r}"
        )

    with diag_subtest("inter-VLAN: iot-VLAN cannot initiate to admin-VLAN"):
        # No iot-to-admin filter exists; the forward chain's
        # `policy drop` catches the unmatched flow. Reverse of
        # the previous test — proves the inter-VLAN allow is
        # one-directional (admin→iot only) and does not leak.
        #
        # Conntrack on the router: a successful echo + reply
        # transitions the ICMP entry to `[ASSURED]` (bidirectional
        # traffic seen). If the firewall drops the echo-request,
        # `[ASSURED]` never appears and `[UNREPLIED]` stays set.
        router.succeed("conntrack -F")  # isolate from earlier subtest
        result = vlan_iot.execute("ping -c1 -W2 ${vlanAdminIp}")
        ct = conntrack("-p icmp -d ${vlanAdminIp}")

        assert result[0] != 0, (
            "expected iot → admin ping to be dropped by default "
            f"forward policy, but it succeeded: {result[1]!r}"
        )
        assert "[ASSURED]" not in ct, (
            f"firewall let iot → admin ICMP complete a bidirectional flow:\n{ct}"
        )
  '';
}
