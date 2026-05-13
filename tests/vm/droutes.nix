/*
  droutes VM test: `droutes` set `meta mark` on packets the
  router itself generates (OUTPUT@mangle), so that a downstream
  `ip rule` can steer locally-originated traffic onto an
  alternate routing table.

  Symmetric counterpart to `marks.nix`, which tests `sroutes`
  (PREROUTING@mangle, forwarded traffic). Same building blocks
  — meta mark + ip rule + alternate table containing
  `unreachable default` — different chain hook.

  Topology:
                       wan vlan 2 (203.0.113.0/24)
    [router] ── eth1 (.1) ─── eth1 (.10) [target]

  Router config:
    - Single `target` zone matching `target`'s /32.
    - `droutes.target-via-unreachable` sets `meta mark 200`
      on any OUTPUT-hook packet destined for the target zone.
    - `settings.chainPolicy = "accept"` keeps the OUTPUT
      filter chain permissive — the test mechanism is the
      droute mark + ip rule path, not a filter drop.

  Outside nftzones (via `systemd.network`):
    - `from all fwmark 200 lookup 200`.
    - Table 200: `unreachable default`.

  End-to-end flow:
    - Router pings `127.0.0.1` → droute doesn't match (dst
      not in `target` zone). No mark. Main table. Reaches
      loopback.
    - Router pings `target` → droute matches, mark=200,
      routing decision consults fwmark, table 200 returns
      `unreachable`, kernel emits ICMP destination-
      unreachable locally. Ping fails with an unreachable-
      class error.

  Caveat: the target VM exists *only* so the router has a
  real reachable destination that the droute can then divert.
  Without a real target VM, ping would fail with "no route
  to host" regardless of the droute — the test couldn't
  distinguish "droute fired" from "destination unreachable
  at L3".

  Companion files: `forward.nix`, `vlan.nix`, `rpfilter.nix`,
  `marks.nix` (sroutes counterpart), `dualstack.nix`.
*/
{
  pkgs,
  nftypes,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;

  wanNet = "203.0.113";
  routerWanIp = "${wanNet}.1";
  targetIp = "${wanNet}.10";
in
pkgs.testers.nixosTest {
  name = "nftzones-droutes";

  nodes = {
    router =
      { lib, pkgs, ... }:
      {
        imports = [ nftzonesModule ];

        virtualisation.vlans = [ 2 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];

          nftables.enable = true;

          nftzones = {
            enable = true;
            tables.fw = {
              # OUTPUT/INPUT/FORWARD chains default-accept so
              # the droute mark + ip rule combination is the
              # only path that can drop the test ping. A
              # default-drop policy would confuse "droute fired"
              # with "filter chain dropped it".
              settings.chainPolicy = "accept";

              zones.target = {
                cidrs = [ "${targetIp}/32" ];
              };

              # Mark router-originated traffic destined for
              # the target zone. Lands in
              # `output-at-mangle__target` with `type route`
              # (output-hook routing-decision tap).
              droutes.target-via-unreachable = {
                to = [ "target" ];
                rule = [ (mangle meta.mark 200) ];
              };
            };
          };
        };

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [ "${routerWanIp}/24" ];

          # `fwmark 200` packets look up table 200, which has
          # only the unreachable default — the kernel returns
          # ICMP destination-unreachable locally.
          routingPolicyRules = [
            {
              routingPolicyRuleConfig = {
                FirewallMark = 200;
                Table = 200;
              };
            }
          ];
          routes = [
            {
              routeConfig = {
                Type = "unreachable";
                Destination = "0.0.0.0/0";
                Table = 200;
              };
            }
          ];
        };

        environment.systemPackages = [ pkgs.conntrack-tools ];
      };

    target =
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
          address = [ "${targetIp}/24" ];
        };
      };
  };

  testScript = ''
    start_all()

    router.wait_for_unit("network-online.target")
    target.wait_for_unit("network-online.target")

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
                    routes = router.succeed(
                        "ip -4 route; echo --- table 200 ---;"
                        " ip -4 route show table 200;"
                        " echo --- ip rule ---;"
                        " ip -4 rule"
                    )
                except Exception:
                    ruleset = routes = "(failed to capture)"
                print(
                    f"\n=== router state at failure of {self.name!r} ===\n"
                    f"--- nft list ruleset ---\n{ruleset}\n"
                    f"--- ip route / rule ---\n{routes}\n"
                    f"=== end router state ===\n",
                    flush=True,
                )
            return self._cm.__exit__(exc_type, exc, tb)

    with diag_subtest("control: router pings localhost (no droute match)"):
        # 127.0.0.1 doesn't match the `target` zone CIDR, so
        # the droute rule's `to = [ "target" ]` skips it. No
        # mark, main table, route via lo, reply via lo. Pins
        # that the droute isn't blanketing all OUTPUT traffic
        # by accident.
        out = router.succeed("ping -c 1 -W 2 127.0.0.1")
        assert "0% packet loss" in out, (
            f"expected loopback ping to succeed, got: {out!r}"
        )

    with diag_subtest("droute marks router→target, table 200 unreachable"):
        # Same OUTPUT chain, different destination — this one
        # matches `target` zone. droute fires (`meta mark set
        # 200`), routing decision consults fwmark, table 200
        # has only the unreachable default. Kernel emits ICMP
        # destination-unreachable locally; ping reports it.
        result = router.execute("ping -c 1 -W 2 ${targetIp}")
        assert result[0] != 0, (
            "expected router ping to target to fail (droute marks "
            "→ table 200 unreachable), but it succeeded: "
            f"{result[1]!r}"
        )
        # `unreachable` route surfaces as "Network is
        # unreachable", "Destination Net Unreachable", or
        # "Destination Host Unreachable" depending on the
        # ping/iputils version. Accept any unreachable
        # variant — `100% packet loss` alone would mean the
        # packet got out but no reply came (droute didn't
        # actually mark).
        assert "nreachable" in result[1], (
            f"expected ICMP unreachable in ping output, got: {result[1]!r}"
        )
  '';
}
