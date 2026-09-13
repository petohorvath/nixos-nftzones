/*
  Atomic-reload VM test: changing a nftzones-managed ruleset
  mid-flight via `nft -f` should preserve in-flight TCP
  connections while applying the new rules immediately to
  every new flow. Pins the user-facing scenario "edit
  nftzones config, `nixos-rebuild switch`, SSH session
  survives."

  Three NixOS VMs (client, router, server). The router boots
  with a v1 ruleset that allows SSH lan→wan. A pre-rendered
  v2 ruleset is staged under `/etc/nftzones-v2.nft`; v2 omits
  the SSH allow so new lan→wan TCP/22 connections fall to the
  chain-policy default (drop).

  Mechanism: `v2RulesetText` is rendered at Nix-build time
  via the same `nftzones.mkTable` + `nftypes.toText` path the
  NixOS module uses to populate `networking.nftables.tables.
  <name>.content`. Prepending `delete table inet fw` makes
  the file a single atomic `nft -f` transaction — the kernel
  removes the old table and installs the new one in one
  shot, with no time window where the firewall is empty.

  Test order:
    1. Client opens a persistent SSH to server via
       ControlMaster (a background session that the test
       driver can reuse).
    2. `hello-1` echo through the persistent session — pins
       that v1 actually allows SSH.
    3. Router atomically reloads to v2 via `nft -f`.
    4. `hello-2` echo through the *same* persistent session
       — pins atomicity: conntrack's ESTABLISHED entry
       survives the swap, v2's stateful prelude accepts the
       in-flight flow.
    5. Fresh SSH attempt — `ConnectTimeout=5` so the test
       doesn't hang. v2's lan→wan path has no SSH allow, so
       the SYN dies at the chain-policy drop. Assertion: the
       attempt fails.

  Companion files: `forward.nix`, `vlan.nix`, `rpfilter.nix`,
  `marks.nix`, `droutes.nix`, `dualstack.nix`, `bridge.nix`.
*/
{
  pkgs,
  nftypes,
  nftzones,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl)
    eq
    accept
    ;
  inherit (nftypes.dsl.fields) tcp;

  lanNet = "192.168.1";
  wanNet = "203.0.113";

  clientLanIp = "${lanNet}.10";
  routerLanIp = "${lanNet}.1";
  routerWanIp = "${wanNet}.1";
  serverWanIp = "${wanNet}.10";

  # Shared zone definitions used by both v1 and v2.
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
    # Masquerade so return traffic finds its way back. Same
    # in v1 and v2 — the swap is purely about the filter
    # chain, not NAT.
    lan-out.from = [ "lan" ];
    lan-out.to = [ "wan" ];
    lan-out.rule.masquerade = { };
  };

  basePolicies = {
    # Explicit default-deny on lan→wan. v1 layers an allow
    # filter on top; v2 omits it so new connections fall
    # through to drop. This makes "did the filter actually
    # change?" easy to assert.
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
    # No allow-ssh filter — new lan→wan flows hit the
    # policies.lan-to-wan drop above. Established flows
    # still ride the stateful prelude.
  };

  # Render v2 as a single atomic `nft -f` transaction. The
  # leading `delete table inet fw` removes the old table
  # before `add table inet fw` re-creates it; both commands
  # land in one kernel transaction so there's no firewall-
  # less window between them.
  v2RulesetText = ''
    delete table inet fw
    ${nftypes.toText (nftypes.dsl.ruleset [ (nftzones.mkTable "fw" v2Body) ])}
  '';
in
pkgs.testers.nixosTest {
  name = "nftzones-atomic-reload";

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

        # v2 rendered at build time, staged in /etc for `nft
        # -f` during the test. Same render path the NixOS
        # module uses to feed `networking.nftables.tables.
        # <name>.content`, just rendered into the full
        # command-form a `nft -f` invocation expects.
        environment.etc."nftzones-v2.nft".text = v2RulesetText;

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
        # One nft transaction swaps the table while leaving conntrack intact.
        router.succeed("nft -f /etc/nftzones-v2.nft")
  '';
}
