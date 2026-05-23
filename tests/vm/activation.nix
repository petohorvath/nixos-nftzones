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
  ControlMaster (mirrors `atomic-reload.nix`).

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

  testScript = ''
    start_all()

    client.wait_for_unit("network-online.target")
    router.wait_for_unit("network-online.target")
    server.wait_for_unit("network-online.target")

    server.wait_for_unit("sshd.service")
    server.wait_for_open_port(22)

    # SSH-key bootstrap — same shape as atomic-reload.nix.
    client.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
    client.succeed('ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519')
    pubkey = client.succeed("cat /root/.ssh/id_ed25519.pub").strip()
    server.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
    server.succeed(f"echo '{pubkey}' > /root/.ssh/authorized_keys")
    server.succeed("chmod 600 /root/.ssh/authorized_keys")

    ssh_base_opts = (
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=5"
    )
    ssh_opts = (
        f"{ssh_base_opts} -o ServerAliveInterval=3 -o ServerAliveCountMax=2"
    )
    cm_opts = "-o ControlMaster=auto -o ControlPath=/tmp/ssh-cm-%r@%h:%p"

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
                    services = router.succeed(
                        "systemctl status nftables.service --no-pager 2>&1 || true"
                    )
                except Exception:
                    ruleset = ct = services = "(failed to capture)"
                print(
                    f"\n=== state at failure of {self.name!r} ===\n"
                    f"--- nft list ruleset (router) ---\n{ruleset}\n"
                    f"--- conntrack -L (router) ---\n{ct}\n"
                    f"--- nftables.service (router) ---\n{services}\n"
                    f"=== end state ===\n",
                    flush=True,
                )
            return self._cm.__exit__(exc_type, exc, tb)

    with diag_subtest("v1: SSH allow rule is live before the switch"):
        # Sanity: the v1 rendered ruleset must mention `tcp dport 22 accept`
        # in the lan-to-wan sub-chain. If it doesn't, the test below would
        # spuriously pass (v1 already blocks).
        v1_ruleset = router.succeed("nft list table inet fw")
        assert "tcp dport 22 accept" in v1_ruleset, (
            f"v1 didn't render the allow-ssh rule:\n{v1_ruleset}"
        )

        client.succeed(
            "systemd-run --quiet --collect --unit nft-ssh-master "
            f"-- ssh {ssh_base_opts} {cm_opts} -NM root@${serverWanIp}"
        )
        client.wait_until_succeeds(
            f"ssh {cm_opts} -O check root@${serverWanIp}",
            timeout=15,
        )
        out = client.succeed(
            f"timeout 30 ssh {cm_opts} root@${serverWanIp} 'echo hello-1'"
        )
        assert "hello-1" in out, f"v1 SSH didn't echo hello-1: {out!r}"

    with diag_subtest("switch-to-configuration: real activation path applies v2"):
        # The specialisation's `switch-to-configuration test` is the
        # same script `nixos-rebuild switch` invokes in production. It
        # runs every activation hook, reloads changed services, and
        # tears down units removed by the new generation. The nftables
        # service's reload action runs nixpkgs'
        # `reload-with-flush-fallback` script under the hood (delete
        # old table, load new content); a downstream rendering bug
        # that emits text the kernel rejects would surface as a
        # non-zero exit here.
        router.succeed(
            "/run/current-system/specialisation/v2/bin/switch-to-configuration test"
        )

        v2_ruleset = router.succeed("nft list table inet fw")
        assert "tcp dport 22 accept" not in v2_ruleset, (
            f"v2 still carries the v1 allow rule after switch:\n{v2_ruleset}"
        )
        # Tail policy survives.
        assert "drop" in v2_ruleset, (
            f"v2 ruleset missing the lan→wan drop policy:\n{v2_ruleset}"
        )

    with diag_subtest("established session survives the activation"):
        # ControlMaster's persistent connection rides conntrack's
        # ESTABLISHED entry. v2's stateful prelude (`ct state
        # established,related accept`) must let the in-flight flow
        # through. If activation cleared conntrack or stalled long
        # enough to drop the entry, this echo would fail.
        out = client.succeed(
            f"timeout 30 ssh {cm_opts} root@${serverWanIp} 'echo hello-2'"
        )
        assert "hello-2" in out, (
            f"v2 activation broke the in-flight SSH: {out!r}"
        )

    with diag_subtest("v2: fresh SSH attempts are blocked by the new policy"):
        # Identical assertion shape to atomic-reload.nix — proves the
        # activation didn't just *look* like it applied v2 but actually
        # rejected new SYNs at the chain policy.
        result = client.execute(
            f"timeout 8 ssh {ssh_opts} -o BatchMode=yes "
            f"root@${serverWanIp} 'echo should-not-arrive'"
        )
        assert result[0] != 0, (
            "expected new SSH attempt to fail after v2 activation, "
            f"but it succeeded: {result[1]!r}"
        )
        assert "should-not-arrive" not in result[1], (
            f"new SSH leaked an echo through despite v2 drop: {result[1]!r}"
        )
  '';
}
