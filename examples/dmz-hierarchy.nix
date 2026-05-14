/*
  Example: DMZ with per-host rules via zone hierarchy.

  A DMZ subnet whose individual hosts are modelled as `nodes` —
  per-host child zones of the `dmz` parent. Each node lowers to
  a /32 and gets its own dispatch sub-chain, so rules can be
  written against a *specific host* while the parent zone
  carries the shared fallback.

    [LAN] ── lan0 ──┐
                    ├── [router] ── wan0 ── [internet]
    [DMZ] ── dmz0 ──┘
       ├── web-server  192.168.2.10
       └── mail-server 192.168.2.20

  Dispatch model (see docs/specs/zone-parent.md):
    - Traffic to a node's /32 enters that node's sub-chain.
      `lan → web-server:443` hits the `web-inbound` rule.
    - If the node sub-chain doesn't match, evaluation falls
      back to the parent `dmz` chain. `web-server → wan` has no
      node rule, so it falls through to the parent's `dmz-out`
      filter — child nodes inherit the parent's outbound
      allowance without restating it.
    - A brand-new DMZ host with no node entry gets only the
      parent rules until it's promoted to a node of its own.

  Everything unstated is dropped by the chain-policy default:
  `dmz → lan` (a compromised DMZ host can't pivot inward),
  `lan → web-server` on non-service ports, `wan → anything`.

  Wire it into a NixOS host:

    networking.nftzones.tables.fw = import ./examples/dmz-hierarchy.nix {
      nftypes = inputs.nftypes.lib;
      nftzones = inputs.nftzones.lib.${pkgs.system};
    };
*/
{
  nftypes,
  nftzones,
  ...
}:
let
  inherit (nftypes.dsl) accept;
  snip = nftzones.snippets;
in
{
  zones = {
    lan = {
      interfaces = [ "lan0" ];
      cidrs = [ "192.168.1.0/24" ];
    };
    wan = {
      interfaces = [ "wan0" ];
    };
    # The DMZ parent zone. Its `cidrs` covers the whole DMZ
    # subnet; the nodes below carve out individual hosts.
    dmz = {
      interfaces = [ "dmz0" ];
      cidrs = [ "192.168.2.0/24" ];
    };
  };

  # Per-host child zones. A node's `zone` field names its
  # parent; its `address` lowers to a /32 the dispatcher keys
  # on. Referenced by name in `from` / `to` like any zone.
  nodes = {
    web-server = {
      zone = "dmz";
      address.ipv4 = "192.168.2.10";
    };
    mail-server = {
      zone = "dmz";
      address.ipv4 = "192.168.2.20";
    };
  };

  filters = {
    # Per-host inbound: the LAN reaches web-server on HTTP /
    # HTTPS only. Lands in web-server's child sub-chain.
    web-inbound = {
      from = [ "lan" ];
      to = [ "web-server" ];
      rule = snip.accept.tcp [
        80
        443
      ];
    };

    # Per-host inbound: the LAN reaches mail-server on the mail
    # service ports only. Lands in mail-server's child sub-chain.
    mail-inbound = {
      from = [ "lan" ];
      to = [ "mail-server" ];
      rule = snip.accept.tcp [
        25
        143
        993
      ];
    };

    # Parent-level rule. `from = [ "dmz" ]` attaches this to the
    # dmz dispatcher, so it runs as the fallback for *every*
    # DMZ host — including web-server and mail-server, whose
    # node sub-chains don't otherwise match their own outbound
    # traffic. One rule, inherited by all children.
    dmz-out = {
      from = [ "dmz" ];
      to = [ "wan" ];
      rule = [ accept ];
    };

    # The LAN reaches the internet directly.
    lan-out = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ accept ];
    };
  };

  # Masquerade both internal zones behind the WAN address.
  # `from` lists the parent `dmz` — children are covered by the
  # parent's NAT entry just as they are by its filter.
  snats.uplink = {
    from = [
      "lan"
      "dmz"
    ];
    to = [ "wan" ];
    rule.masquerade = { };
  };
}
