/*
  Activation VM test: drives a real `switch-to-configuration test`
  pathway end-to-end, instead of calling `nft -f` directly the way
  `atomic-reload.nix` does. Pins that nixpkgs' nftables activation
  script (`delete table; nft -f <new>` per the `tables.<name>.content`
  option) correctly transitions between two nftzones-managed configs
  without breaking established connections — and that nftzones'
  emitted text loads cleanly through the production reload path,
  not just through a hand-rolled `nft -f` transaction.

  Why this is separate from `atomic-reload.nix`: that test stages
  a pre-rendered v2 ruleset and applies it with a single `nft -f`
  transaction. The real activation path is two separate steps in
  the nftables service's reload script (delete the old table,
  then load the new content). The window between them is the
  audit's M5 concern; we don't observe a hole here (nixpkgs runs
  both within one transaction file via stdin), but emitting a
  ruleset the production reload script can't apply would surface
  as a failed `switch-to-configuration` — which this test
  catches.

  Three NixOS VMs (client, router, server). The router boots with
  a v1 ruleset (`allow-ssh` filter from lan→wan) and carries a
  `specialisation.v2` that overrides the table body to drop
  lan→wan SSH. Running `/run/current-system/specialisation/v2/bin/
  switch-to-configuration test` from the test driver replaces v1
  with v2 through the real activation path. The test asserts
  ruleset state before and after, plus session survival via
  the shared reload verifier (also used by `atomic-reload.nix`).

  Companion file: `atomic-reload.nix` (same scenario via direct
  `nft -f` rather than the activation script).
*/
{
  pkgs,
  nftypes,
  nftzones,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl) accept eq;
  inherit (nftypes.dsl.fields) tcp;

  lanNet = "192.168.1";
  wanNet = "203.0.113";

  clientLanIp = "${lanNet}.10";
  routerLanIp = "${lanNet}.1";
  routerWanIp = "${wanNet}.1";
  serverWanIp = "${wanNet}.10";

  baseZones = {
    lan = {
      interfaces = [ "eth1" ];
      cidrs = [ "${lanNet}.0/24" ];
    };
    wan = {
      interfaces = [ "eth2" ];
      cidrs = [ "${wanNet}.0/24" ];
    };
  };

  baseSnats = {
    lan-out.from = [ "lan" ];
    lan-out.to = [ "wan" ];
    lan-out.rule.masquerade = { };
  };

  basePolicies = {
    lan-to-wan.from = [ "lan" ];
    lan-to-wan.to = [ "wan" ];
    lan-to-wan.verdict = "drop";
  };

  v1Body = {
    zones = baseZones;
    snats = baseSnats;
    policies = basePolicies;
    filters.allow-ssh = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
    };
  };

  v2Body = {
    zones = baseZones;
    snats = baseSnats;
    policies = basePolicies;
    # No allow-ssh — lan→wan TCP/22 falls to policies.lan-to-wan drop.
  };
in
pkgs.testers.nixosTest {
  name = "nftzones-activation";

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
            tables.fw = v1Body;
          };
        };

        # Alternative system reachable at
        # `/run/current-system/specialisation/v2/bin/switch-to-configuration`.
        # The specialisation rebuilds the whole NixOS toplevel with the
        # base config plus this override; activating it runs the same
        # `switch-to-configuration` logic `nixos-rebuild switch` uses.
        # `lib.mkForce` is needed because the base already sets
        # `tables.fw` and submodule values can't merge into different
        # bodies — we want a wholesale replacement.
        specialisation.v2.configuration = {
          networking.nftzones.tables.fw = lib.mkForce v2Body;
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

        environment.systemPackages = [ pkgs.conntrack-tools ];
      };

    server =
      { lib, pkgs, ... }:
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

        services.openssh = {
          enable = true;
          settings = {
            PermitRootLogin = "yes";
            PasswordAuthentication = false;
          };
        };
      };
  };

  testScript = builtins.readFile ./reload-verification.py + ''
    start_all()

    with verify_reload(
        client=client, router=router, server=server,
        server_ip="${serverWanIp}", subtest=subtest,
    ):
        v1_ruleset = router.succeed("nft list table inet fw")
        assert "tcp dport 22 accept" in v1_ruleset, (
            f"v1 didn't render the allow-ssh rule:\n{v1_ruleset}"
        )

        # Exercise the same activation script nixos-rebuild invokes. A
        # rendering bug rejected by the nftables reload must fail here.
        router.succeed(
            "/run/current-system/specialisation/v2/bin/"
            "switch-to-configuration test"
        )

        v2_ruleset = router.succeed("nft list table inet fw")
        assert "tcp dport 22 accept" not in v2_ruleset, (
            f"v2 still carries the v1 allow rule after switch:\n{v2_ruleset}"
        )
        assert "drop" in v2_ruleset, (
            f"v2 ruleset missing the lan→wan drop policy:\n{v2_ruleset}"
        )
  '';
}
