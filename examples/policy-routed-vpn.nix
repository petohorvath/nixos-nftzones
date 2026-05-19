/*
  Example: policy-routed VPN egress.

  A router with a primary WAN uplink and a secondary VPN
  tunnel. Most traffic egresses through the WAN; selected
  zones — and selected destination networks on the router
  itself — get marked into an alternate routing table so an
  `ip rule fwmark <n> lookup <table>` outside nftables steers
  them onto the tunnel.

    [trusted] ── lan0    ┐
    [guest  ] ── guest0  ┼── [router] ── wan0 ── [internet]
                         │       │
                         │       └─── wg0 ── [vpn endpoint]
                         │
                         └─── [10.50.0.0/16 = remote office]

  Behaviour:
    - Trusted LAN egresses straight out the WAN, SNAT'd
      behind the router's WAN address.
    - Guest egresses get policy-routed via the VPN — `sroute`
      marks them at prerouting; an `ip rule` outside nftables
      diverts to a tunnel-bound routing table.
    - Locally-originated traffic to the remote office network
      (10.50.0.0/16) is also tunnelled — `droute` marks at
      the output hook for the same `ip rule` to pick up.
    - Inbound from WAN is denied except SSH from LAN, one
      HTTPS port-forward, and ICMP echo.
    - Default-deny posture is explicit (mirrors the implicit
      chain-policy default but reads better at the config
      site).

  Wire it into a NixOS host:

    # configuration.nix
    { inputs, pkgs, ... }:
    {
      networking.nftables.enable = true;
      networking.nftzones = {
        enable = true;
        tables.fw = import ./examples/policy-routed-vpn.nix {
          nftypes  = inputs.nftypes.lib;
          nftzones = inputs.nftzones.lib.${pkgs.system};
        };
      };
    }
*/
{
  nftypes,
  nftzones,
  ...
}:
let
  inherit (nftypes.dsl) eq accept mangle;
  inherit (nftypes.dsl.fields) tcp meta;
  snip = nftzones.snippets;
in
{
  zones = {
    lan = {
      interfaces = [ "lan0" ];
      cidrs = [ "192.168.10.0/24" ];
    };
    guest = {
      interfaces = [ "guest0" ];
      cidrs = [ "192.168.20.0/24" ];
    };
    # Address-only zone (no interface) — used purely as a
    # destination match for the droute below.
    remote-office.cidrs = [ "10.50.0.0/16" ];
    wan.interfaces = [ "wan0" ];
    vpn.interfaces = [ "wg0" ];
  };

  filters = {
    # Trusted LAN reaches anything on the WAN or the VPN.
    # Return traffic rides the stateful prelude — no explicit
    # reply rule needed.
    lan-out = {
      from = [ "lan" ];
      to = [
        "wan"
        "vpn"
      ];
      rule = [ accept ];
    };

    # Guest hosts may only reach the internet (the sroute
    # below diverts the actual routing onto the tunnel — the
    # forward-chain decision is still `to = wan` because
    # zone membership is interface-driven and policy-routing
    # is invisible to the firewall classifier).
    guest-out = {
      from = [ "guest" ];
      to = [ "wan" ];
      rule = [ accept ];
    };

    # Router accepts SSH from the LAN only.
    lan-admin-ssh = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = snip.accept.tcp 22;
    };

    # WAN may ping the router (cheap external uptime probe).
    wan-ping = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = snip.accept.icmp.v4 8;
    };

    # Post-DNAT half of the WAN→internal port-forward below.
    # Without this rule the wan-to-lan policy would drop the
    # rewritten packet.
    inbound-https = {
      from = [ "wan" ];
      to = [ "lan" ];
      rule = [
        (eq tcp.dport 443)
        accept
      ];
    };
  };

  # Policy-routing: mark guest traffic at prerouting so an
  # external `ip rule fwmark 100 lookup vpn` steers it onto
  # the tunnel-bound routing table. Outside nftables:
  #   ip route add default dev wg0 table vpn
  #   ip rule  add fwmark 100      lookup vpn
  sroutes.guest-via-vpn = {
    from = [ "guest" ];
    rule = [ (mangle meta.mark 100) ];
    comment = "guest egress → VPN tunnel";
  };

  # Same idea for router-originated traffic bound for the
  # remote office network. Output-hook mark; ip-rule diverts
  # locally-generated packets.
  droutes.work-remote-via-vpn = {
    to = [ "remote-office" ];
    rule = [ (mangle meta.mark 100) ];
    comment = "local→remote-office → VPN tunnel";
  };

  # WAN port-forward to the internal HTTPS host.
  dnats.public-https = {
    from = [ "wan" ];
    rule = {
      match = [ (eq tcp.dport 443) ];
      action.dnat = {
        family = "ip";
        addr = "192.168.10.10";
        port = 443;
      };
    };
  };

  # Source-NAT LAN+guest egress behind the router's WAN
  # address. VPN-bound traffic stays unNAT'd inside the
  # tunnel — only WAN-destined cells are masqueraded.
  snats.uplink = {
    from = [
      "lan"
      "guest"
    ];
    to = [ "wan" ];
    rule.masquerade = { };
  };

  # Default-deny inbound. The chain-policy default is `drop`
  # already, but stating these makes the security posture
  # explicit and reads better at the config site.
  policies = {
    wan-to-lan = {
      from = [ "wan" ];
      to = [ "lan" ];
      verdict = "drop";
    };
    wan-to-local = {
      from = [ "wan" ];
      to = [ "local" ];
      verdict = "drop";
    };
    guest-to-lan = {
      from = [ "guest" ];
      to = [ "lan" ];
      verdict = "drop";
    };
    guest-to-local = {
      from = [ "guest" ];
      to = [ "local" ];
      verdict = "drop";
    };
  };
}
