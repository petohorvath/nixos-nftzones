/*
  Dual-stack scenario — a zone with both v4 and v6 CIDRs becomes
  two zone sets (`_v4` and `_v6`); jump rules in the base chain
  fan out one variant per family. Pin that the dual-family
  output renders into a valid `inet`-family table.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
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
}
