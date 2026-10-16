/*
  Dual-stack scenario — a zone with both v4 and v6 CIDRs becomes
  two zone sets (`_v4` and `_v6`); jump rules in the base chain
  fan out one variant per family. Pin that the dual-family
  output renders into a valid `inet`-family table.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) accept;
in
{
  body = {
    zones = {
      lan = {
        interfaces = [ "lan0" ];
        cidrs = [
          "10.0.0.0/24"
          "fd00::/64"
        ];
      };
      wan = {
        interfaces = [ "wan0" ];
        cidrs = [
          "203.0.113.0/24"
          "2001:db8::/32"
        ];
      };
    };

    filters.allow-out = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ accept ];
    };
  };

  assertions = compiled: [
    {
      description = "default family is inet";
      expr = compiled.tables.dual-stack.family;
      expected = "inet";
    }
    {
      description = "each dual-stack zone splits into v4 + v6 sets";
      expr = {
        lanV4 = compiled.tables.dual-stack.sets ? lan_v4;
        lanV6 = compiled.tables.dual-stack.sets ? lan_v6;
        wanV4 = compiled.tables.dual-stack.sets ? wan_v4;
        wanV6 = compiled.tables.dual-stack.sets ? wan_v6;
      };
      expected = {
        lanV4 = true;
        lanV6 = true;
        wanV4 = true;
        wanV6 = true;
      };
    }
  ];
}
