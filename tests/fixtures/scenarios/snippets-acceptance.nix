/*
  Snippets acceptance scenario — one filter per `(verdict, proto)`
  combination, twelve total, plus a single port range, which the
  snippets match with `eq`. Compiled end-to-end through
  `mkRuleset` and `nft -j --check`; succeeds iff every emitted
  shape is kernel-accepted.

  Split across three tables to avoid family-mismatch issues with
  ICMP under `inet`: TCP+UDP land in an `inet` table (both
  families, both L4 protocols), `icmp` lands in an `ip` table,
  `icmpv6` lands in an `ip6` table. All twelve filters share one
  zone shape (single source zone → `local`) — the only thing
  varying is the rule body produced by the snippet.

  No structural assertions; the unit tests in `tests/unit/snippets.nix`
  pin every emitted shape, so this scenario only needs to prove
  the kernel accepts them.
*/
{ nftzones, ... }:
let
  inherit (nftzones.snippets)
    accept
    drop
    reject
    ;

  mkZones = interfaceName: {
    src = {
      interfaces = [ interfaceName ];
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
          accept-tcp-range = toLocal (accept.tcp "8000-8100");
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
          accept-icmp = toLocal (accept.icmp 8);
          drop-icmp = toLocal (drop.icmp 9);
          reject-icmp = toLocal (reject.icmp 8);
        };
      };
    }

    {
      name = "snippets-icmp6";
      body = {
        family = "ip6";
        zones = mkZones "eth2";
        filters = {
          accept-icmp = toLocal (accept.icmpv6 128);
          drop-icmp = toLocal (drop.icmpv6 134);
          reject-icmp = toLocal (reject.icmpv6 128);
        };
      };
    }
  ];
}
