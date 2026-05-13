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
          useNetworkd = true;
          # Nullify the per-vlan auto-IP `virtualisation.vlans`
          # injects on eth1 (otherwise it would generate a
          # `40-eth1.network` competing with the explicit unit
          # below).
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

        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [ "${clientLanIp}/24" ];
          networkConfig.Gateway = routerLanIp;
        };

        environment.systemPackages = with pkgs; [
          curl
          dnsutils
          netcat-openbsd
        ];
      };

    router =
      { lib, pkgs, ... }:
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
          useNetworkd = true;

          # Nullify per-vlan auto-IPs `virtualisation.vlans`
          # injects on the parent ifaces — we own all addressing
          # via the explicit `systemd.network` block below. eth3
          # is the trunk and never carries an IP itself; all eth3
          # addressing lives on the .10 / .20 sub-interfaces.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
          interfaces.eth2.ipv4.addresses = lib.mkForce [ ];
          interfaces.eth3.ipv4.addresses = lib.mkForce [ ];

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

        # Anchor for `network-online.target` — see client config
        # for rationale.
        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        # Explicit `.netdev` + `.network` units for the router's
        # five addressable interfaces. Two .netdev files declare
        # the 802.1Q sub-interfaces on the trunk (eth3.10, eth3.20);
        # the matching .network for eth3 attaches them via the
        # `VLAN=` directive. The three IP-bearing units cover lan
        # (eth1), wan (eth2), and the two VLAN-tagged sub-ifaces.
        # No `Gateway=` anywhere — the router *is* the gateway.
        systemd.network = {
          netdevs."10-eth3.${toString iotVlanId}" = {
            netdevConfig = {
              Name = "eth3.${toString iotVlanId}";
              Kind = "vlan";
            };
            vlanConfig.Id = iotVlanId;
          };
          netdevs."10-eth3.${toString adminVlanId}" = {
            netdevConfig = {
              Name = "eth3.${toString adminVlanId}";
              Kind = "vlan";
            };
            vlanConfig.Id = adminVlanId;
          };
          networks."10-eth1" = {
            matchConfig.Name = "eth1";
            address = [ "${routerLanIp}/24" ];
          };
          networks."10-eth2" = {
            matchConfig.Name = "eth2";
            address = [ "${routerWanIp}/24" ];
          };
          networks."10-eth3" = {
            matchConfig.Name = "eth3";
            vlan = [
              "eth3.${toString iotVlanId}"
              "eth3.${toString adminVlanId}"
            ];
          };
          networks."10-eth3.${toString iotVlanId}" = {
            matchConfig.Name = "eth3.${toString iotVlanId}";
            address = [ "${routerIotIp}/24" ];
          };
          networks."10-eth3.${toString adminVlanId}" = {
            matchConfig.Name = "eth3.${toString adminVlanId}";
            address = [ "${routerAdminIp}/24" ];
          };
        };

        # `systemd-resolved` is enabled by default alongside
        # `useNetworkd` and binds port 53 on the loopback, which
        # collides with the dnsmasq listen-address below. The
        # router doesn't need a stub resolver — it serves DNS via
        # dnsmasq for the DNS-redirect test — so disable resolved
        # here to free the port.
        services.resolved.enable = false;

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

        # `conntrack` lets the test query the router's connection-
        # tracking table to verify NAT translation and that deny-
        # path flows never reached ESTABLISHED. Single source of
        # truth on the firewall itself, replaces wire-level pcaps.
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
          # See client for rationale on the mkForce nullification.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        # Anchor for `network-online.target` — see client config
        # for rationale.
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

    external =
      { lib, pkgs, ... }:
      {
        virtualisation.vlans = [ 2 ];

        networking = {
          useDHCP = false;
          firewall.enable = false;
          useNetworkd = true;
          # See client for rationale on the mkForce nullification.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        # Anchor for `network-online.target` — see client config
        # for rationale.
        systemd.targets.network-online.wantedBy = [ "multi-user.target" ];

        systemd.network.networks."10-eth1" = {
          matchConfig.Name = "eth1";
          address = [ "${externalWanIp}/24" ];
          networkConfig.Gateway = routerWanIp;
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
          useNetworkd = true;
          # Trunk parent — no IP of its own; the tagged sub-iface
          # below carries all traffic. Nullify the per-vlan auto-
          # IP `virtualisation.vlans` would otherwise drop on eth1.
          interfaces.eth1.ipv4.addresses = lib.mkForce [ ];
        };

        # Anchor for `network-online.target` — see client config
        # for rationale.
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

        # Anchor for `network-online.target` — see client config
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
    # an address. Per-service readiness (sshd, peer-echo, testweb,
    # dnsmasq) still has explicit waits below.
    client.wait_for_unit("network-online.target")
    router.wait_for_unit("network-online.target")
    server.wait_for_unit("network-online.target")
    external.wait_for_unit("network-online.target")
    vlan_iot.wait_for_unit("network-online.target")
    vlan_admin.wait_for_unit("network-online.target")

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

    # Wire-level assertions go through the router's conntrack
    # table, not packet captures on destinations. Conntrack
    # records each connection's original tuple (pre-NAT, as
    # seen at the firewall's input) and reply tuple (post-NAT,
    # the form the firewall expects return traffic in). Reading
    # both at the router gives a direct view of what NAT did
    # without depending on libpcap/promisc/shared-L2 behaviour
    # of the destination's NIC.
    def conntrack(args):
        return router.succeed(f"conntrack -L {args} 2>/dev/null")

    # `subtest` wrapper that dumps the router's nftables ruleset,
    # conntrack table, and routing table to the test log when the
    # body raises. Silent on the green path; on red it cuts
    # diagnosis time by capturing the firewall's state *at the
    # moment of failure* instead of leaving you to reconstruct it
    # from kernel logs. A plain class avoids depending on
    # contextlib being in the driver script's import set.
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

    with diag_subtest("L3 forwarding: client can ping server through router"):
        client.succeed("ping -c1 -W2 ${serverWanIp}")

    with diag_subtest("ICMP forwarding lan → wan"):
        out = client.succeed("ping -c3 -W2 ${serverWanIp}")
        assert "0% packet loss" in out, f"expected no loss, got: {out!r}"

    with diag_subtest("SSH allowed lan → wan"):
        # `timeout 30` is the outermost wall-clock guard — if both
        # ConnectTimeout and ServerAlive miss the stall, this still
        # caps the command at 30s (exit 124) so the subtest fails
        # fast instead of pinning the whole VM run on the global
        # timeout.
        out = client.succeed(f"timeout 30 ssh {ssh_opts} root@${serverWanIp} 'echo hello-from-ssh'")
        assert "hello-from-ssh" in out, f"unexpected ssh output: {out!r}"

    with diag_subtest("SNAT masquerade: server sees router-wan-IP, not client-IP"):
        # Userspace assertion (peer-echo's recv) plus a conntrack
        # check on the router. With SNAT applied, the entry's
        # reply tuple has dst=routerWanIp (return traffic is
        # routed back through the firewall for un-NAT). Without
        # SNAT, reply.dst would be the raw clientLanIp.
        router.succeed("conntrack -F")  # isolate from earlier subtests
        peer = client.succeed("nc -w 3 ${serverWanIp} 9999").strip()
        ct = conntrack("-p tcp --dport 9999")

        assert peer == "${routerWanIp}", (
            "masquerade missing — server saw "
            + repr(peer)
            + ", expected '${routerWanIp}'"
        )
        assert "dst=${routerWanIp}" in ct, (
            f"expected SNAT reply-tuple dst=${routerWanIp} on router:\n{ct}"
        )
        assert "dst=${clientLanIp}" not in ct, (
            f"un-SNAT'd reply-tuple dst=${clientLanIp} on router:\n{ct}"
        )

    with diag_subtest("DNAT port forward: external 8080 lands on server:80"):
        # The `external` VM is on the wan vlan but not the server
        # itself, so the connection isn't hairpin: external → router
        # (rewrites destination to serverWanIp:80) → server, reply
        # via router (un-DNATs back) → external. testweb on server
        # answers with a known body.
        #
        # Conntrack check pinned alongside the body check: the
        # router's entry has dport=8080 in the original tuple
        # (the curl target) and sport=80 + src=serverWanIp in the
        # reply tuple (DNAT applied). Catches regressions that
        # leave 8080 raw or DNAT to the wrong destination.
        router.succeed("conntrack -F")  # isolate from earlier subtests
        out = external.succeed(
            "curl -s --max-time 5 http://${routerWanIp}:8080/index.html"
        )
        ct = conntrack("-p tcp --dport 8080")

        assert "hello-from-server" in out, f"unexpected dnat response: {out!r}"
        assert "dport=8080" in ct, (
            f"expected curl-target dport=8080 in router conntrack:\n{ct}"
        )
        assert "sport=80" in ct, (
            f"expected DNAT'd reply-tuple sport=80 in router conntrack:\n{ct}"
        )
        assert "src=${serverWanIp}" in ct, (
            f"expected DNAT'd reply-tuple src=${serverWanIp} in router conntrack:\n{ct}"
        )

    with diag_subtest("DNS redirect: lan-side DNS query bends to router dnsmasq"):
        # Client queries an unreachable resolver (8.8.8.8 isn't routable
        # in the sandbox); redirect forwards it to the router's local
        # dnsmasq which serves a fixed answer for test.example.
        out = client.succeed(
            "dig +time=2 +tries=1 @8.8.8.8 test.example. +short"
        ).strip()
        assert out == "198.51.100.99", (
            f"expected redirect to local resolver answering 198.51.100.99, got {out!r}"
        )

    with diag_subtest("default policy drops uninitiated wan → lan"):
        # Add a route on server so it knows how to reach lan; the
        # policy must still drop the connection at the router.
        # Without a wire-level check, this subtest passes if ssh
        # fails for *any* reason (missing route, MTU quirks, etc.);
        # asking conntrack on the router whether the flow ever
        # reached ESTABLISHED pins the firewall as the cause.
        server.succeed("ip route add ${lanNet}.0/24 via ${routerWanIp}")
        router.succeed("conntrack -F")  # isolate from earlier subtests
        result = server.execute(
            f"ssh {ssh_opts} -o BatchMode=yes root@${clientLanIp} 'true'"
        )
        ct = conntrack("-p tcp -d ${clientLanIp} --dport 22")

        assert result[0] != 0, (
            "expected uninitiated wan → lan ssh to be dropped by policy, "
            f"but it succeeded: {result[1]!r}"
        )
        assert "ESTABLISHED" not in ct, (
            f"firewall let wan → lan ssh reach ESTABLISHED on router:\n{ct}"
        )

    with diag_subtest("non-DNAT'd wan port is not forwarded"):
        # Only `tcp.dport 8080` has a DNAT match. A request to any
        # other wan port must not reach the router (no wan→local
        # filter; chain-policy drop) nor anything behind it (the
        # wan→wan filter accepts only post-DNAT dport 80). Catches
        # regressions that widen `dnats.public-http.rule.match`,
        # widen `filters.dnat-http`, or open up wan→local.
        #
        # Conntrack on the router: with the firewall dropping at
        # FORWARD before any reply, the entry never transitions
        # past SYN_SENT and never reaches ESTABLISHED. Anchors the
        # drop at the firewall, not at routing.
        router.succeed("conntrack -F")  # isolate from earlier subtests
        result = external.execute(
            "curl -sS --max-time 3 -o /dev/null "
            "http://${routerWanIp}:8081/"
        )
        ct = conntrack("-p tcp --dport 8081")

        assert result[0] != 0, (
            "expected curl to fail on non-DNAT'd wan port 8081 — "
            f"firewall over-permits, got: {result[1]!r}"
        )
        assert "ESTABLISHED" not in ct, (
            f"firewall let non-DNAT'd 8081 reach ESTABLISHED on router:\n{ct}"
        )

    with diag_subtest("inter-VLAN: admin-VLAN reaches iot-VLAN through router"):
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
        # Anchors the drop at the firewall rather than routing,
        # VLAN demux, or any other layer.
        router.succeed("conntrack -F")  # isolate from earlier subtests
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
