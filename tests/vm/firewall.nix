/*
  End-to-end VM test — three NixOS VMs (client, router, server) on
  two virtual LANs. The router runs `nftzones`-managed nftables
  with a realistic mix of features; the test asserts traffic
  behaviour from a live kernel:

    - L3 forwarding lan → wan
    - ICMP forwarding (echo)
    - SSH allowed lan → wan (TCP forward + stateful return)
    - SNAT masquerade (server observes router-wan-IP, not client-IP)
    - DNAT port forward (external traffic to router:8080 lands on
      server:80)
    - DNS redirect (client query for an unreachable resolver bends
      to the router's local dnsmasq, which serves a fixed answer)
    - Default-deny wan → lan (uninitiated server-side ssh fails)

  Topology:
                      lan vlan 1                wan vlan 2
                  192.168.1.0/24             203.0.113.0/24
    [client]  ─── eth1 (.10)   ─── eth1 [router] eth2 ─── (.10) eth1 [server]
                                  (.1)            (.1)

  Closes the README "no real-kernel VM tests yet" gap. This is the
  slow tier of the suite — booting three VMs takes 30-60s per
  build.
*/
{
  pkgs,
  nftypes,
  nftzonesModule,
  ...
}:
let
  inherit (nftypes.dsl)
    eq
    accept
    ;
  inherit (nftypes.dsl.fields) tcp udp;

  lanNet = "192.168.1";
  wanNet = "203.0.113";

  clientLanIp = "${lanNet}.10";
  routerLanIp = "${lanNet}.1";
  routerWanIp = "${wanNet}.1";
  serverWanIp = "${wanNet}.10";
in
pkgs.testers.nixosTest {
  name = "nftzones-firewall";

  nodes = {
    client =
      { ... }:
      {
        virtualisation.vlans = [ 1 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = [
              {
                address = clientLanIp;
                prefixLength = 24;
              }
            ];
          };
          defaultGateway = routerLanIp;
        };

        environment.systemPackages = with pkgs; [
          curl
          dnsutils
          netcat-openbsd
        ];
      };

    router =
      { lib, ... }:
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

          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = [
              {
                address = routerLanIp;
                prefixLength = 24;
              }
            ];
          };
          interfaces.eth2 = {
            useDHCP = false;
            ipv4.addresses = [
              {
                address = routerWanIp;
                prefixLength = 24;
              }
            ];
          };

          nftables.enable = true;

          nftzones = {
            enable = true;
            # Pretty-print rendering — works around a quirk in
            # nftypes' compact `toTextBlock` where chain bodies
            # are emitted without a trailing `;` before `}`.
            pretty = true;
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

              # Permit any lan-initiated traffic to wan; stateful
              # prelude handles return traffic.
              filters.lan-out-allow = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ accept ];
              };

              # Allow inbound traffic that has been DNAT'd to land
              # on the wan side (the dnat below rewrites destination
              # to a wan-resident IP, so the post-NAT direction is
              # wan→wan in the forward chain).
              filters.dnat-http = {
                from = [ "wan" ];
                to = [ "wan" ];
                rule = [
                  (eq tcp.dport 80)
                  accept
                ];
              };

              # SNAT lan→wan so the server sees router-wan-IP.
              snats.lan-out = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule.masquerade = { };
              };

              # External 8080 → server:80.
              dnats.public-http = {
                from = [ "wan" ];
                rule = {
                  match = [ (eq tcp.dport 8080) ];
                  action.dnat = {
                    family = "ip";
                    addr = serverWanIp;
                    port = 80;
                  };
                };
              };

              # Redirect lan-side DNS to the local dnsmasq.
              dnats.dns-redirect = {
                from = [ "lan" ];
                rule = {
                  match = [ (eq udp.dport 53) ];
                  action.redirect = { port = 53; };
                };
              };

              # Default-deny uninitiated wan→lan; established/related
              # are accepted by the stateful prelude.
              policies.wan-to-lan = {
                from = [ "wan" ];
                to = [ "lan" ];
                verdict = "drop";
              };
            };
          };
        };

        # Local DNS resolver — answers `test.example.` with a fixed
        # address so the redirect test can verify it hit dnsmasq
        # rather than reaching upstream (which is unreachable in the
        # sandbox anyway).
        services.dnsmasq = {
          enable = true;
          settings = {
            port = 53;
            listen-address = [
              "127.0.0.1"
              routerLanIp
            ];
            no-resolv = true;
            address = [ "/test.example/198.51.100.99" ];
          };
        };
      };

    server =
      { pkgs, ... }:
      {
        virtualisation.vlans = [ 2 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = [
              {
                address = serverWanIp;
                prefixLength = 24;
              }
            ];
          };
          defaultGateway = routerWanIp;
        };

        services.openssh = {
          enable = true;
          settings = {
            PermitRootLogin = "yes";
            PasswordAuthentication = false;
          };
        };

        # Tiny TCP server that responds with the connecting peer's
        # IP — used to verify SNAT masquerade replaces the lan-side
        # client IP with the router-wan IP.
        systemd.services.peer-echo = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          script = ''
            ${pkgs.python3}/bin/python3 -c '
            import socket
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", 9999))
            s.listen()
            while True:
                conn, addr = s.accept()
                try:
                    conn.sendall(addr[0].encode())
                finally:
                    conn.close()
            '
          '';
        };

        # Plain HTTP server on :80 — DNAT port-forward target.
        systemd.services.testweb = {
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          script = ''
            cd /tmp
            echo "hello-from-server" > index.html
            ${pkgs.python3}/bin/python3 -m http.server 80
          '';
        };

        environment.systemPackages = [ pkgs.netcat-openbsd ];
      };
  };

  testScript = ''
    start_all()

    client.wait_for_unit("network-online.target")
    router.wait_for_unit("network-online.target")
    server.wait_for_unit("network-online.target")

    server.wait_for_unit("sshd.service")
    server.wait_for_open_port(22)
    server.wait_for_unit("peer-echo.service")
    server.wait_for_open_port(9999)
    server.wait_for_unit("testweb.service")
    server.wait_for_open_port(80)

    router.wait_for_unit("dnsmasq.service")
    router.wait_for_open_port(53)

    # Bootstrap an SSH key for client → server tests.
    client.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
    client.succeed('ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519')
    pubkey = client.succeed("cat /root/.ssh/id_ed25519.pub").strip()
    server.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
    server.succeed(f"echo '{pubkey}' > /root/.ssh/authorized_keys")
    server.succeed("chmod 600 /root/.ssh/authorized_keys")

    ssh_opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"

    with subtest("L3 forwarding: client can ping server through router"):
        client.succeed("ping -c1 -W2 ${serverWanIp}")

    with subtest("ICMP forwarding lan → wan"):
        out = client.succeed("ping -c3 -W2 ${serverWanIp}")
        assert "0% packet loss" in out, f"expected no loss, got: {out!r}"

    with subtest("SSH allowed lan → wan"):
        out = client.succeed(f"ssh {ssh_opts} root@${serverWanIp} 'echo hello-from-ssh'")
        assert "hello-from-ssh" in out, f"unexpected ssh output: {out!r}"

    with subtest("SNAT masquerade: server sees router-wan-IP, not client-IP"):
        peer = client.succeed("nc -w 3 ${serverWanIp} 9999").strip()
        assert peer == "${routerWanIp}", (
            "masquerade missing — server saw "
            + repr(peer)
            + ", expected '${routerWanIp}'"
        )

    with subtest("DNAT port forward: external 8080 lands on server:80"):
        # Connect from server-side back to router-wan:8080 (acting as
        # an "external" caller relative to the lan); DNAT bends to
        # serverWanIp:80, which the testweb service answers.
        out = server.succeed(
            "curl -s --max-time 5 http://${routerWanIp}:8080/index.html"
        )
        assert "hello-from-server" in out, f"unexpected dnat response: {out!r}"

    with subtest("DNS redirect: lan-side DNS query bends to router dnsmasq"):
        # Client queries an unreachable resolver (8.8.8.8 isn't routable
        # in the sandbox); redirect forwards it to the router's local
        # dnsmasq which serves a fixed answer for test.example.
        out = client.succeed(
            "dig +time=2 +tries=1 @8.8.8.8 test.example. +short"
        ).strip()
        assert out == "198.51.100.99", (
            f"expected redirect to local resolver answering 198.51.100.99, got {out!r}"
        )

    with subtest("default policy drops uninitiated wan → lan"):
        # Add a route on server so it knows how to reach lan; the
        # policy must still drop the connection at the router.
        server.succeed("ip route add ${lanNet}.0/24 via ${routerWanIp}")
        result = server.execute(
            f"ssh {ssh_opts} -o BatchMode=yes root@${clientLanIp} 'true'"
        )
        assert result[0] != 0, (
            "expected uninitiated wan → lan ssh to be dropped by policy, "
            f"but it succeeded: {result[1]!r}"
        )
  '';
}
