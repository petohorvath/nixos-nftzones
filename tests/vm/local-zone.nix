/*
  Local zone VM test (#54, ADR-0013): a `local` direction matches
  only the router's own traffic at every hook it compiles to.

    - An snat from `local` rewrites packets the router generates
      (`meta iif 0` at postrouting) but not forwarded lan traffic.
    - A filter from `local` to `local` matches `meta iif "lo"` at
      input, so it no longer opens the port to the lan. The router
      turns `settings.loopback` off, so that cell really runs.
    - The same filter with a `chain` override at output matches
      `fib daddr type local` and governs the router's traffic to
      itself there.

  Topology:
                      lan vlan 1                wan vlan 2
                  192.168.1.0/24             203.0.113.0/24
    [client]  ─── eth1 (.10)   ─── eth1 [router] eth2 ─── (.10) eth1 [server]
                                  (.1)            (.1, .2)

  The router owns 203.0.113.2 as a second wan address, the snat
  target, so the server can answer it and peer-echo can report it.
*/
{ inputs, pkgs }:
let
  nftypes = inputs.nix-nftypes.lib;

  inherit (nftypes.dsl) accept eq;
  inherit (nftypes.dsl.fields) tcp;

  lanNet = "192.168.1";
  wanNet = "203.0.113";

  clientLanIp = "${lanNet}.10";
  routerLanIp = "${lanNet}.1";
  routerWanIp = "${wanNet}.1";
  routerSnatIp = "${wanNet}.2";
  serverWanIp = "${wanNet}.10";

  # Answer every connection on `port` with the peer's address.
  peerEcho = port: ''
    ${pkgs.python3}/bin/python3 -c '
    import socket
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", ${toString port}))
    s.listen()
    while True:
        conn, addr = s.accept()
        try:
            conn.sendall(addr[0].encode())
        finally:
            conn.close()
    '
  '';
in
pkgs.testers.runNixOSTest {
  name = "nftzones-local-zone";

  nodes = {
    client =
      { lib, pkgs, ... }:
      {
        virtualisation.vlans = [ 1 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          # See `forward.nix` for the mkForce nullification.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [ "${clientLanIp}/24" ];
          networkConfig.Gateway = routerLanIp;
        };

        environment.systemPackages = [ pkgs.netcat-openbsd ];
      };

    router =
      { lib, pkgs, ... }:
      {
        imports = [ inputs.self.nixosModules.default ];

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

          # Every filter base chain drops by default (the
          # `chainPolicy` default), so each allowed path below
          # is one an entry opens.
          nftzones = {
            enable = true;
            tables.fw = {
              # Without the loopback rule, the router's traffic to
              # itself reaches the `self-in` cell at input.
              settings.loopback = false;

              zones = {
                lan.interfaces = [ "eth1" ];
                wan.interfaces = [ "eth2" ];
              };

              policies = {
                lan-out = {
                  from = [ "lan" ];
                  to = [ "wan" ];
                  verdict = "accept";
                };
                router-out = {
                  from = [ "local" ];
                  to = [ "wan" ];
                  verdict = "accept";
                };
              };

              filters = {
                # Before #54 this compiled to an unconditional jump
                # at input, so the lan reached port 8080 too.
                self-in = {
                  from = [ "local" ];
                  to = [ "local" ];
                  rule = [
                    (eq tcp.dport 8080)
                    accept
                  ];
                };

                # The router's traffic to itself passes output first,
                # where the drop policy applies too.
                self-out = {
                  from = [ "local" ];
                  to = [ "local" ];
                  chain = {
                    hook = "output";
                    priority = "filter";
                  };
                  rule = [
                    (eq tcp.dport 8080)
                    accept
                  ];
                };

                # Gives the input hook a base chain, and with it the
                # drop policy. It names `wan`, not `lan`: a `lan`
                # jump sorts before `local` and would hide the old
                # unconditional `local` jump from the lan test.
                wan-ssh = {
                  from = [ "wan" ];
                  to = [ "local" ];
                  rule = [
                    (eq tcp.dport 22)
                    accept
                  ];
                };
              };

              # Before #54 this jumped on every packet out of eth2,
              # so forwarded lan traffic was rewritten too.
              snats.router-out = {
                from = [ "local" ];
                to = [ "wan" ];
                # `family` disambiguates snat in an `inet` table.
                rule.action.snat = {
                  addr = routerSnatIp;
                  family = "ip";
                };
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
            address = [
              "${routerWanIp}/24"
              "${routerSnatIp}/24"
            ];
          };
        };

        # Port 8080 is what `self-in` and `self-out` open; 8081 is the control
        # it does not.
        systemd.services.self-echo = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          script = peerEcho 8080;
        };
        systemd.services.self-echo-control = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          script = peerEcho 8081;
        };

        environment.systemPackages = [ pkgs.netcat-openbsd ];
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

        # The gateway routes replies to the lan back through the
        # router, so un-NATed lan traffic still completes.
        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [ "${serverWanIp}/24" ];
          networkConfig.Gateway = routerWanIp;
        };

        systemd.services.peer-echo = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          script = peerEcho 9999;
        };
      };
  };

  testScript = ''
    start_all()

    client.wait_for_unit("network-online.target")
    router.wait_for_unit("network-online.target")
    server.wait_for_unit("network-online.target")

    server.wait_for_open_port(9999)
    router.wait_for_open_port(8080)
    router.wait_for_open_port(8081)

    # See `forward.nix`: dump the router's ruleset when a subtest
    # fails.
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
                except Exception:
                    ruleset = "(failed to capture)"
                print(
                    f"\n=== router ruleset at failure of {self.name!r} ===\n"
                    f"{ruleset}\n=== end router ruleset ===\n",
                    flush=True,
                )
            return self._cm.__exit__(exc_type, exc, tb)

    with diag_subtest("snat from local rewrites the router's own traffic"):
        peer = router.succeed("nc -w 3 ${serverWanIp} 9999").strip()
        assert peer == "${routerSnatIp}", (
            f"expected the server to see ${routerSnatIp}, got {peer!r}"
        )

    with diag_subtest("snat from local leaves forwarded lan traffic alone"):
        peer = client.succeed("nc -w 3 ${serverWanIp} 9999").strip()
        assert peer == "${clientLanIp}", (
            f"expected the server to see ${clientLanIp}, got {peer!r}"
        )

    with diag_subtest("local to local admits the router's own traffic"):
        peer = router.succeed("nc -w 3 ${routerLanIp} 8080").strip()
        assert peer == "${routerLanIp}", (
            f"expected 8080 to answer the router itself, got {peer!r}"
        )

    with diag_subtest("local to local opens only its own port"):
        # Both chains drop by default, and only `self-out` and
        # `self-in` accept the router's traffic to itself, on 8080.
        status, out = router.execute("nc -w 3 ${routerLanIp} 8081 </dev/null")
        assert status != 0 and out.strip() == "", (
            f"expected 8081 to stay closed to the router, got {out!r}"
        )

    with diag_subtest("local to local does not open the port to the lan"):
        status, out = client.execute("nc -w 3 ${routerLanIp} 8080 </dev/null")
        assert status != 0 and out.strip() == "", (
            f"expected 8080 to stay closed to the lan, got {out!r}"
        )
  '';
}
