/*
  Example: home / SOHO router.

  The 80% case — one trusted LAN behind a single WAN uplink,
  with NAT, a default-deny inbound posture, and one inbound
  port-forward.

    [LAN hosts] ── lan0 ── [router] ── wan0 ── [internet]
                 192.168.1.0/24

  Behaviour:
    - LAN hosts reach anything on the WAN; the stateful prelude
      carries return traffic. Source-NAT'd behind the router's
      WAN address.
    - The router itself accepts SSH only from the LAN.
    - Inbound from the WAN is dropped by default, except a
      single port-forward: WAN :443 → an internal web server.
    - WAN may ICMP-ping the router (handy for uptime checks);
      everything else WAN→router is dropped.

  Wire it into a NixOS host:

    # configuration.nix
    { inputs, pkgs, ... }:
    {
      networking.nftables.enable = true;
      networking.nftzones = {
        enable = true;
        tables.fw = import ./examples/home-router.nix {
          nftypes = inputs.nftypes.lib;
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
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
  snip = nftzones.snippets;
in
{
  zones = {
    # The trusted side. `cidrs` lets rules match on source /
    # destination address in addition to the interface.
    lan = {
      interfaces = [ "lan0" ];
      cidrs = [ "192.168.1.0/24" ];
    };
    # The uplink. No `cidrs` — a WAN address is whatever the ISP
    # hands out, so zone membership is interface-only.
    wan = {
      interfaces = [ "wan0" ];
    };
  };

  filters = {
    # All LAN-initiated traffic is allowed out. Return traffic
    # rides the stateful prelude — no explicit wan→lan rule
    # needed for replies.
    lan-out = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ accept ];
    };

    # The router itself accepts SSH from the LAN only. `to =
    # [ "local" ]` targets the router's own input chain. The
    # `snippets.accept.tcp` shorthand expands to the same
    # match + verdict a hand-written body would.
    lan-admin-ssh = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = snip.accept.tcp 22;
    };

    # WAN may ping the router (ICMP echo-request, type 8) — a
    # cheap external uptime probe. Nothing else WAN→router is
    # allowed; `policies.wan-to-local` below drops the rest.
    wan-ping = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = snip.accept.icmp.v4 8;
    };

    # The post-DNAT half of the port-forward below. `dnats`
    # rewrites the destination at prerouting; by the time the
    # packet reaches the forward chain its destination is the
    # internal host, so the direction is wan→lan. Without this
    # filter the `wan-to-lan` drop policy would discard it.
    inbound-https = {
      from = [ "wan" ];
      to = [ "lan" ];
      rule = [
        (eq tcp.dport 443)
        accept
      ];
    };
  };

  # Port-forward: inbound WAN :443 → the internal web server.
  # DNAT runs at prerouting, before the routing decision, so
  # the rewritten packet is routed straight to the LAN host.
  dnats.public-https = {
    from = [ "wan" ];
    rule = {
      match = [ (eq tcp.dport 443) ];
      # `family = "ip"` is required in an inet-family table —
      # nft can't otherwise disambiguate an ip-vs-ip6 target.
      action.dnat = {
        family = "ip";
        addr = "192.168.1.10";
        port = 443;
      };
    };
  };

  # Masquerade LAN traffic behind the router's WAN address.
  snats.uplink = {
    from = [ "lan" ];
    to = [ "wan" ];
    rule.masquerade = { };
  };

  # Default-deny inbound. The chain-policy default is already
  # `drop`, but stating these makes the security posture
  # explicit and self-documenting.
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
  };
}
