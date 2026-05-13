/*
  End-to-end VM test — six NixOS VMs (client, router, server,
  external, vlan-iot, vlan-admin) across three virtual links.
  The router runs `nftzones`-managed nftables with a realistic
  mix of features; the test asserts traffic behaviour from a live
  kernel:

    - L3 forwarding lan → wan
    - ICMP forwarding (echo)
    - SSH allowed lan → wan (TCP forward + stateful return)
    - SNAT masquerade (server observes router-wan-IP, not client-IP)
    - DNAT port forward (external traffic to router:8080 lands on
      server:80)
    - DNS redirect (client query for an unreachable resolver bends
      to the router's local dnsmasq, which serves a fixed answer)
    - Default-deny wan → lan (uninitiated server-side ssh fails)
    - Inter-VLAN routing allow (admin VLAN reaches iot VLAN through
      a single trunk port via 802.1Q-tagged sub-interfaces)
    - Inter-VLAN default-deny (iot cannot initiate to admin —
      chain-level policy drops without a matching filter)

  Topology:
                      lan vlan 1                wan vlan 2
                  192.168.1.0/24             203.0.113.0/24
    [client]  ─── eth1 (.10)   ─── eth1 [router] eth2 ─── (.10) eth1 [server]
                                  (.1)            (.1)
                                                ╲─── (.20) eth1 [external]

                                trunk vlan 3 (untagged carrier)
                                  router eth3 (no IP)
                                ├── eth3.10 (vlan tag 10) 192.168.10.1/24  ── iot
                                └── eth3.20 (vlan tag 20) 192.168.20.1/24  ── admin

    [vlan-iot]   eth1 (no IP), eth1.10 (vlan 10, 192.168.10.10/24)  ─┐
                                                                     │ vlan 3
    [vlan-admin] eth1 (no IP), eth1.20 (vlan 20, 192.168.20.10/24)  ─┘

  `external` is on the wan vlan but not the server itself, so
  the DNAT port-forward test isn't hairpin (which Linux drops
  without explicit hairpin SNAT). The two VLAN hosts share a
  single nixosTest vlan (3) acting as the trunk; their VLAN
  sub-interfaces tag and demux frames so each VM only sees its
  own broadcast domain. The router exposes both VLANs as
  sub-interfaces on a single physical NIC — the textbook
  router-on-a-stick pattern.

  Booting six VMs takes ~60-90s per build. This is the slow tier
  of the suite.
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
  iotNet = "192.168.10";
  adminNet = "192.168.20";

  clientLanIp = "${lanNet}.10";
  routerLanIp = "${lanNet}.1";
  routerWanIp = "${wanNet}.1";
  serverWanIp = "${wanNet}.10";
  externalWanIp = "${wanNet}.20";

  routerIotIp = "${iotNet}.1";
  routerAdminIp = "${adminNet}.1";
  vlanIotIp = "${iotNet}.10";
  vlanAdminIp = "${adminNet}.10";

  iotVlanId = 10;
  adminVlanId = 20;
in
pkgs.testers.nixosTest {
  name = "nftzones-firewall";

  nodes = {
    client =
      { lib, ... }:
      {
        virtualisation.vlans = [ 1 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          # `lib.mkForce` overrides the default per-vlan IP that
          # `nixosTest`'s `virtualisation.vlans` machinery assigns;
          # without it, the auto-IP and our explicit one both land
          # on the interface and the test topology becomes
          # ambiguous.
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [
              {
                address = clientLanIp;
                prefixLength = 24;
              }
            ];
          };
          defaultGateway = lib.mkForce routerLanIp;
        };

        environment.systemPackages = with pkgs; [
          curl
          dnsutils
          netcat-openbsd
          tcpdump
        ];
      };

    router =
      { lib, ... }:
      {
        imports = [ nftzonesModule ];

        virtualisation.vlans = [
          1
          2
          3
        ];

        boot.kernel.sysctl."net.ipv4.ip_forward" = 1;

        networking = {
          useDHCP = false;
          firewall.enable = false;

          # `lib.mkForce` overrides the per-vlan auto-IP that
          # `virtualisation.vlans` injects (see client config for
          # rationale).
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [
              {
                address = routerLanIp;
                prefixLength = 24;
              }
            ];
          };
          interfaces.eth2 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [
              {
                address = routerWanIp;
                prefixLength = 24;
              }
            ];
          };
          # eth3 is the trunk port — no IP of its own. The
          # auto-assigned per-vlan IP would land on the parent
          # otherwise; force it empty so all addressing lives on
          # the VLAN sub-interfaces below.
          interfaces.eth3 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [ ];
          };

          # 802.1Q sub-interfaces on the trunk. Each tag
          # corresponds to one zone-as-VLAN.
          vlans = {
            "eth3.${toString iotVlanId}" = {
              id = iotVlanId;
              interface = "eth3";
            };
            "eth3.${toString adminVlanId}" = {
              id = adminVlanId;
              interface = "eth3";
            };
          };
          interfaces."eth3.${toString iotVlanId}".ipv4.addresses = [
            {
              address = routerIotIp;
              prefixLength = 24;
            }
          ];
          interfaces."eth3.${toString adminVlanId}".ipv4.addresses = [
            {
              address = routerAdminIp;
              prefixLength = 24;
            }
          ];

          nftables.enable = true;

          nftzones = {
            enable = true;
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
                # 802.1Q-tagged sub-interfaces on the trunk;
                # zone membership keyed off the sub-interface name
                # (and CIDR) means inter-VLAN matching is
                # transparent to the rest of the rule set.
                iot = {
                  interfaces = [ "eth3.${toString iotVlanId}" ];
                  cidrs = [ "${iotNet}.0/24" ];
                };
                admin = {
                  interfaces = [ "eth3.${toString adminVlanId}" ];
                  cidrs = [ "${adminNet}.0/24" ];
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

              # SNAT wan→wan masquerade — covers the DNAT
              # port-forward return path. The test topology puts
              # `external` and `server` on the same /24, so a
              # bare DNAT would let the server reply directly to
              # external (bypassing the router's un-DNAT). This
              # masquerade rewrites the source to router-wan so
              # the reply must come back through us. Mirrors the
              # standard "hairpin SNAT" deployment pattern.
              snats.wan-hairpin = {
                from = [ "wan" ];
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
                  action.redirect = {
                    port = 53;
                  };
                };
              };

              # Default-deny uninitiated wan→lan; established/related
              # are accepted by the stateful prelude.
              policies.wan-to-lan = {
                from = [ "wan" ];
                to = [ "lan" ];
                verdict = "drop";
              };

              # Inter-VLAN allow: admin manages iot devices.
              # No reverse filter — iot → admin is dropped at the
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
      { lib, pkgs, ... }:
      {
        virtualisation.vlans = [ 2 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          # `lib.mkForce` overrides the per-vlan auto-IP (see
          # client config for rationale).
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [
              {
                address = serverWanIp;
                prefixLength = 24;
              }
            ];
          };
          defaultGateway = lib.mkForce routerWanIp;
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

        environment.systemPackages = with pkgs; [
          netcat-openbsd
          tcpdump
        ];
      };

    external =
      { lib, pkgs, ... }:
      {
        virtualisation.vlans = [ 2 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [
              {
                address = externalWanIp;
                prefixLength = 24;
              }
            ];
          };
          defaultGateway = lib.mkForce routerWanIp;
        };

        environment.systemPackages = [ pkgs.curl ];
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
          # Trunk parent — no IP of its own; tagged sub-interface
          # below carries all traffic. Force-empty to override the
          # per-vlan auto-IP virtualisation.vlans drops on eth1.
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [ ];
          };

          vlans."eth1.${toString iotVlanId}" = {
            id = iotVlanId;
            interface = "eth1";
          };
          interfaces."eth1.${toString iotVlanId}".ipv4.addresses = [
            {
              address = vlanIotIp;
              prefixLength = 24;
            }
          ];

          defaultGateway = lib.mkForce routerIotIp;
        };
      };

    vlan-admin =
      { lib, pkgs, ... }:
      {
        virtualisation.vlans = [ 3 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          interfaces.eth1 = {
            useDHCP = false;
            ipv4.addresses = lib.mkForce [ ];
          };

          vlans."eth1.${toString adminVlanId}" = {
            id = adminVlanId;
            interface = "eth1";
          };
          interfaces."eth1.${toString adminVlanId}".ipv4.addresses = [
            {
              address = vlanAdminIp;
              prefixLength = 24;
            }
          ];

          defaultGateway = lib.mkForce routerAdminIp;
        };

        environment.systemPackages = [ pkgs.tcpdump ];
      };
  };

  testScript = ''
    start_all()

    # `network-online.target` is only pulled in when systemd-networkd
    # is active; the script-based networking nixosTest defaults to
    # leaves it inactive. Wait for the broader `multi-user.target`
    # instead — by then static-IP units have configured each
    # interface (see network-addresses-eth*-start.service).
    client.wait_for_unit("multi-user.target")
    router.wait_for_unit("multi-user.target")
    server.wait_for_unit("multi-user.target")
    external.wait_for_unit("multi-user.target")
    vlan_iot.wait_for_unit("multi-user.target")
    vlan_admin.wait_for_unit("multi-user.target")

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

    # ServerAliveInterval/CountMax bound *post-handshake* stalls
    # (ConnectTimeout only bounds the handshake): if the transport
    # silently wedges, ssh dies in ~6s instead of waiting out the
    # test's 60-min global timeout. Seen in CI when the driver's
    # console-expect loop missed the exit-code marker after an
    # otherwise-successful ssh.
    ssh_opts = (
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=5 -o ServerAliveInterval=3 -o ServerAliveCountMax=2"
    )

    # tcpdump-based wire assertions. Four flags carry meaning:
    #   -p   non-promiscuous; capture only what the host's NIC
    #        actually accepts. Critical on shared VLANs (e.g. the
    #        wan vlan with external+router+server): in promisc,
    #        server's eth1 sees external↔router frames addressed
    #        to *other* MACs and the wire assertions fire on
    #        traffic that never entered the host.
    #   -nn  no DNS / port-name resolution; keeps output stable.
    #   -l   line-buffered stdout so kill-time flush keeps the
    #        last few captured packets.
    # `nohup` + redirected stdin/stdout/stderr keeps the bg
    # process off the test driver's shell-session pipe. The 0.3 s
    # start sleep lets the BPF filter attach before the trigger;
    # the 0.2 s stop sleep lets tcpdump flush after SIGTERM.
    # Output lives at /tmp/cap.out — overwritten per call, so
    # subtests must read it before starting a new capture.
    def start_pcap(machine, iface, expr):
        machine.succeed("rm -f /tmp/cap.out /tmp/cap.pid")
        machine.succeed(
            f"nohup tcpdump -p -i {iface} -nn -l '{expr}' "
            f"  > /tmp/cap.out 2>/dev/null </dev/null & "
            f"echo $! > /tmp/cap.pid; "
            f"sleep 0.3"
        )
        # Confirm tcpdump survived its startup window — a typo'd
        # BPF filter or a missing interface makes it exit within
        # ms, which would otherwise silently pass any negative-
        # path assertion that checks for an empty pcap.
        machine.succeed("kill -0 $(cat /tmp/cap.pid)")

    def stop_pcap(machine):
        machine.execute(
            "if [ -f /tmp/cap.pid ]; then "
            "  kill $(cat /tmp/cap.pid) 2>/dev/null || true; "
            "  rm -f /tmp/cap.pid; "
            "  sleep 0.2; "
            "fi"
        )
        return machine.succeed("cat /tmp/cap.out 2>/dev/null || true")

    with subtest("L3 forwarding: client can ping server through router"):
        client.succeed("ping -c1 -W2 ${serverWanIp}")

    with subtest("ICMP forwarding lan → wan"):
        out = client.succeed("ping -c3 -W2 ${serverWanIp}")
        assert "0% packet loss" in out, f"expected no loss, got: {out!r}"

    with subtest("SSH allowed lan → wan"):
        # `timeout 30` is the outermost wall-clock guard — if both
        # ConnectTimeout and ServerAlive miss the stall, this still
        # caps the command at 30s (exit 124) so the subtest fails
        # fast instead of pinning the whole VM run on the global
        # timeout.
        out = client.succeed(f"timeout 30 ssh {ssh_opts} root@${serverWanIp} 'echo hello-from-ssh'")
        assert "hello-from-ssh" in out, f"unexpected ssh output: {out!r}"

    with subtest("SNAT masquerade: server sees router-wan-IP, not client-IP"):
        # Userspace assertion (peer-echo's recv) plus a wire-level
        # check: capture on server's eth1, look for the post-SNAT
        # source in the actual IP headers. Without the wire check,
        # a conntrack-cached path could let userspace report the
        # right address even if nftables stopped applying SNAT.
        start_pcap(server, "eth1", "tcp port 9999")
        peer = client.succeed("nc -w 3 ${serverWanIp} 9999").strip()
        pcap = stop_pcap(server)

        assert peer == "${routerWanIp}", (
            "masquerade missing — server saw "
            + repr(peer)
            + ", expected '${routerWanIp}'"
        )
        # Trailing dot anchors the IP to tcpdump's `<ip>.<port>`
        # delimiter — without it `203.0.113.1` would substring-
        # match inside `203.0.113.10` (the server IP).
        assert "${routerWanIp}." in pcap, (
            f"expected SNAT src '${routerWanIp}' in pcap, got:\n{pcap}"
        )
        assert "${clientLanIp}." not in pcap, (
            f"un-SNAT'd client IP '${clientLanIp}' leaked onto wan:\n{pcap}"
        )

    with subtest("DNAT port forward: external 8080 lands on server:80"):
        # The `external` VM is on the wan vlan but not the server
        # itself, so the connection isn't hairpin: external → router
        # (rewrites destination to serverWanIp:80) → server, reply
        # via router (un-DNATs back) → external. testweb on server
        # answers with a known body.
        #
        # Wire check pinned alongside the body check: server sees
        # dst port 80 (post-DNAT) and src host = routerWanIp (post-
        # wan-hairpin masquerade), never the raw 8080 nor the
        # external-VM IP. Catches regressions that move the DNAT
        # to the wrong stage or drop the hairpin SNAT.
        start_pcap(server, "eth1", "tcp")
        out = external.succeed(
            "curl -s --max-time 5 http://${routerWanIp}:8080/index.html"
        )
        pcap = stop_pcap(server)

        assert "hello-from-server" in out, f"unexpected dnat response: {out!r}"
        # Port-80 match needs the trailing `:` (dst) or ` ` (src)
        # to exclude the `.8080` substring. IP-match needs the
        # trailing `.` to exclude longer IPs that share the prefix
        # (203.0.113.1 vs 203.0.113.10/20).
        assert ".80:" in pcap or ".80 " in pcap, (
            f"expected DNAT'd dst port 80 in pcap, got:\n{pcap}"
        )
        assert ".8080" not in pcap, (
            f"un-DNAT'd port 8080 reached server:\n{pcap}"
        )
        assert "${routerWanIp}." in pcap, (
            f"expected hairpin-SNAT src '${routerWanIp}' in pcap:\n{pcap}"
        )
        assert "${externalWanIp}." not in pcap, (
            f"un-SNAT'd external IP '${externalWanIp}' leaked to server:\n{pcap}"
        )

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
        # Without the wire check, this subtest passes if ssh fails
        # for *any* reason (missing route, network unreachable, MTU
        # quirks); capturing on the lan side proves the firewall
        # is the one dropping it.
        server.succeed("ip route add ${lanNet}.0/24 via ${routerWanIp}")
        start_pcap(client, "eth1", "tcp and src host ${serverWanIp}")
        result = server.execute(
            f"ssh {ssh_opts} -o BatchMode=yes root@${clientLanIp} 'true'"
        )
        pcap = stop_pcap(client)

        assert result[0] != 0, (
            "expected uninitiated wan → lan ssh to be dropped by policy, "
            f"but it succeeded: {result[1]!r}"
        )
        assert pcap.strip() == "", (
            f"firewall let wan → lan SYNs through to client:\n{pcap}"
        )

    with subtest("non-DNAT'd wan port is not forwarded"):
        # Only `tcp.dport 8080` has a DNAT match. A request to any
        # other wan port must not reach the router (no wan→local
        # filter; chain-policy drop) nor anything behind it (the
        # wan→wan filter accepts only post-DNAT dport 80). Catches
        # regressions that widen `dnats.public-http.rule.match`,
        # widen `filters.dnat-http`, or open up wan→local.
        #
        # Wire-level: server's eth1 sees zero TCP traffic on port
        # 8081 during the curl window. Proves the firewall — not
        # routing or any other layer — is what stops it.
        start_pcap(server, "eth1", "tcp port 8081")
        result = external.execute(
            "curl -sS --max-time 3 -o /dev/null "
            "http://${routerWanIp}:8081/"
        )
        pcap = stop_pcap(server)

        assert result[0] != 0, (
            "expected curl to fail on non-DNAT'd wan port 8081 — "
            f"firewall over-permits, got: {result[1]!r}"
        )
        assert pcap.strip() == "", (
            f"firewall let non-DNAT'd port 8081 through to server:\n{pcap}"
        )

    with subtest("inter-VLAN: admin-VLAN reaches iot-VLAN through router"):
        # admin (vlan tag 20, 192.168.20.10) → router eth3.20
        # → forward chain matches admin-to-iot filter → router
        # eth3.10 → iot (vlan tag 10, 192.168.10.10). Stateful
        # prelude carries the echo reply back. Confirms that
        # zone membership keyed off VLAN sub-interface names
        # (eth3.10, eth3.20) drives correct dispatch on a single
        # physical trunk port.
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

    with subtest("inter-VLAN: iot-VLAN cannot initiate to admin-VLAN"):
        # No iot-to-admin filter exists; the forward chain's
        # `policy drop` catches the unmatched flow. Reverse of
        # the previous test — proves the inter-VLAN allow is
        # one-directional (admin→iot only) and does not leak.
        #
        # Wire-level: vlan-admin's tagged sub-interface sees zero
        # ICMP echo-requests from the iot host during the ping.
        # Pins the drop at the firewall rather than at routing,
        # VLAN demux, or any other layer.
        start_pcap(vlan_admin, "eth1.${toString adminVlanId}",
                   "icmp and src host ${vlanIotIp}")
        result = vlan_iot.execute("ping -c1 -W2 ${vlanAdminIp}")
        pcap = stop_pcap(vlan_admin)

        assert result[0] != 0, (
            "expected iot → admin ping to be dropped by default "
            f"forward policy, but it succeeded: {result[1]!r}"
        )
        assert pcap.strip() == "", (
            f"firewall let iot → admin ICMP through to vlan-admin:\n{pcap}"
        )
  '';
}
