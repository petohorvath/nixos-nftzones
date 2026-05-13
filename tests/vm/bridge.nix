/*
  Bridge-family VM test: `family = "bridge"` table that
  filters frames at the L2 layer as they traverse a Linux
  bridge. Three NixOS VMs (vmA, bridge, vmB), with the bridge
  VM running an L2 bridge (`br0`) spanning two virtual links
  and an nftzones-managed bridge filter on `br0`.

  Topology:
                       vlan 1                          vlan 2
   [vmA] ── eth1 ── eth1 [bridge] eth2 ── eth1 [vmB]
            .10        (br0 .1/24)              .20

  The bridge VM's eth1 and eth2 are bridge ports of `br0`.
  Frames between vmA and vmB transit the bridge at L2 — they
  never hit the bridge VM's L3 routing — and pass through
  `family = "bridge"` filter chains in the process.

  Compile tier (`bridge-filter.nix`) pins that nftzones emits
  a bridge-family table with the right chain naming
  (`forward-at-filter`, canonical priority `filter` not raw
  `-200`); this VM test pins that the live kernel actually
  installs the table, that bridged frames traverse it, and
  that an inline `counter` statement increments per matched
  frame.

  Router config (nftzones):
    - `family = "bridge"` — L2 filtering.
    - `settings.stateful = false` — bridges typically don't
      conntrack, and the inet-style stateful prelude doesn't
      cleanly apply to bridge chains.
    - `settings.chainPolicy = "accept"` — default-permissive
      so the counter rule sees traffic without a competing
      drop. The point of the test isn't blocking; it's
      proving the bridge chain actually runs against
      forwarded frames.
    - One filter `from = [ "bridged" ]; to = [ "bridged" ]`
      with `[ (counter {}) accept ]` — counter increments
      per matched frame, accept lets the frame through.

  End-to-end flow:
    - vmA ARPs for vmB → bridge floods → vmB replies → MAC
      learned. nftables bridge-family hooks run on each frame
      (including ARP, depending on kernel hooks).
    - vmA pings vmB → forward chain on bridge increments
      counter, accepts, frame egresses on the other port.

  Companion files: `forward.nix`, `vlan.nix`, `rpfilter.nix`,
  `marks.nix`, `droutes.nix`, `dualstack.nix`.
*/
{
  pkgs,
  nftypes,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl) accept counter;

  net = "10.0.0";
  bridgeIp = "${net}.1";
  vmAIp = "${net}.10";
  vmBIp = "${net}.20";
in
pkgs.testers.nixosTest {
  name = "nftzones-bridge";

  nodes = {
    vmA =
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
          address = [ "${vmAIp}/24" ];
        };
      };

    bridge =
      { lib, pkgs, ... }:
      {
        imports = [ nftzonesModule ];

        virtualisation.vlans = [
          1
          2
        ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          # eth1 + eth2 are bridge slaves; no IP of their own.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
          interfaces.eth2.ipv4.addresses = lib.mkForce [ ];

          nftables.enable = true;

          nftzones = {
            enable = true;
            tables.fw = {
              family = "bridge";

              settings = {
                # Bridge family doesn't have a sensible
                # conntrack hookup in the kernel's standard
                # bridge chains; turn off the inet-style
                # stateful prelude rather than emit rules
                # that target a hook the kernel won't fill.
                stateful = false;
                # Default-accept on all chains so the
                # counter rule is the only nftzones-emitted
                # rule that fires against forwarded frames.
                # The test asserts the counter ticked up;
                # any default-drop would compete and confuse
                # the signal.
                chainPolicy = "accept";
              };

              zones.bridged.interfaces = [ "br0" ];

              # Counter+accept on every frame forwarded
              # within the bridged zone. The counter's
              # `packets` field is what the test reads.
              filters.bridged-counter = {
                from = [ "bridged" ];
                to = [ "bridged" ];
                rule = [
                  (counter { })
                  accept
                ];
              };
            };
          };
        };

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network = {
          # `br0` is a Linux bridge with vmA's vlan and vmB's
          # vlan as members. The IP on `br0` keeps wait-online
          # happy (it has something to mark "configured") and
          # gives the bridge a sane L3 identity in case any
          # control-plane traffic targets it; frame forwarding
          # between vmA and vmB doesn't use this address.
          netdevs."10-br0".netdevConfig = {
            Name = "br0";
            Kind = "bridge";
          };

          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            networkConfig.Bridge = "br0";
          };
          networks."10-eth2" = {
            matchConfig.Name = "eth2";
            networkConfig.Bridge = "br0";
          };
          networks."10-br0" = {
            matchConfig.Name = "br0";
            address = [ "${bridgeIp}/24" ];
          };
        };
      };

    vmB =
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
          address = [ "${vmBIp}/24" ];
        };
      };
  };

  testScript = ''
    import re

    start_all()

    vmA.wait_for_unit("network-online.target")
    bridge.wait_for_unit("network-online.target")
    vmB.wait_for_unit("network-online.target")

    # See `forward.nix` for the rationale on this wrapper —
    # dumps bridge state on failure (the live nftables
    # ruleset is the most useful thing to see when a bridge
    # filter test misfires).
    class diag_subtest:
        def __init__(self, name):
            self.name = name

        def __enter__(self):
            self._cm = subtest(self.name)
            return self._cm.__enter__()

        def __exit__(self, exc_type, exc, tb):
            if exc_type is not None:
                try:
                    ruleset = bridge.succeed("nft list ruleset")
                    fdb = bridge.succeed("bridge fdb show; echo ---; ip link show br0")
                except Exception:
                    ruleset = fdb = "(failed to capture)"
                print(
                    f"\n=== bridge state at failure of {self.name!r} ===\n"
                    f"--- nft list ruleset ---\n{ruleset}\n"
                    f"--- bridge fdb + link ---\n{fdb}\n"
                    f"=== end bridge state ===\n",
                    flush=True,
                )
            return self._cm.__exit__(exc_type, exc, tb)

    with diag_subtest("L2 bridge forwards vmA → vmB through nftzones filter"):
        # ARP between vmA and vmB transits the bridge first,
        # so a successful ping proves both L2 forwarding and
        # ARP propagation work. The pre-ping ARP exchange
        # also ticks the counter — by the time the assertion
        # runs there are at least a handful of matched
        # frames.
        out = vmA.succeed("ping -c 1 -W 2 ${vmBIp}")
        assert "0% packet loss" in out, (
            f"expected L2-bridged ping to succeed, got: {out!r}"
        )

        # `nft list ruleset` on the bridge surfaces all
        # anonymous counters inline as `counter packets N
        # bytes M`. Find at least one with `packets >= 1` —
        # proves a frame actually matched the bridged-to-
        # bridged filter chain rather than the kernel
        # silently bypassing it.
        ruleset = bridge.succeed("nft list ruleset")
        matches = [
            int(p) for p in re.findall(r"counter packets (\d+)", ruleset)
        ]
        assert matches, (
            f"no anonymous counter found in bridge ruleset:\n{ruleset}"
        )
        assert max(matches) >= 1, (
            f"bridge filter chain saw zero packets — counters: {matches}"
        )
  '';
}
