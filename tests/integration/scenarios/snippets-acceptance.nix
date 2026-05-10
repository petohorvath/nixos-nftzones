/*
  Snippets acceptance scenario — one filter per `(verdict, proto)`
  combination, twelve total. Compiled end-to-end through
  `mkRuleset` and `nft -j --check`; succeeds iff every emitted
  shape is kernel-accepted.

  Split across three tables to avoid family-mismatch issues with
  ICMP under `inet`: TCP+UDP land in an `inet` table (both
  families, both L4 protocols), v4 ICMP lands in an `ip` table,
  v6 ICMP lands in an `ip6` table. All twelve filters share one
  zone shape (single source zone → `local`) — the only thing
  varying is the rule body produced by the snippet.

  No structural assertions; the unit tests in `tests/unit/snippets.nix`
  pin every emitted shape, so this scenario only needs to prove
  the kernel accepts them.
*/
{ nftypes, nftzones, ... }:
let
  inherit (nftzones.snippets)
    accept
    drop
    reject
    ;

  mkZones = ifname: {
    src = {
      interfaces = [ ifname ];
    };
  };

  toLocal = rule: {
    from = [ "src" ];
    to = [ "local" ];
    inherit rule;
  };
in
{
  body = [
    {
      name = "snippets-l4";
      body = {
        family = "inet";
        zones = mkZones "eth0";
        filters = {
          accept-tcp = toLocal (accept.tcp 22);
          accept-udp = toLocal (accept.udp 53);
          drop-tcp = toLocal (drop.tcp 23);
          drop-udp = toLocal (drop.udp 137);
          reject-tcp = toLocal (reject.tcp 3389);
          reject-udp = toLocal (reject.udp 161);
        };
      };
    }

    {
      name = "snippets-icmp4";
      body = {
        family = "ip";
        zones = mkZones "eth1";
        filters = {
          accept-icmp = toLocal (accept.icmp.v4 8);
          drop-icmp = toLocal (drop.icmp.v4 9);
          reject-icmp = toLocal (reject.icmp.v4 8);
        };
      };
    }

    {
      name = "snippets-icmp6";
      body = {
        family = "ip6";
        zones = mkZones "eth2";
        filters = {
          accept-icmp = toLocal (accept.icmp.v6 128);
          drop-icmp = toLocal (drop.icmp.v6 134);
          reject-icmp = toLocal (reject.icmp.v6 128);
        };
      };
    }
  ];
}
