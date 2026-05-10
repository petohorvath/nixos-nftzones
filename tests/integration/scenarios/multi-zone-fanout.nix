/*
  Cartesian-product scenario — `from = [ lan guest ] × to = [ wan vpn ]`
  produces four sub-chains, all sharing the same rule body.
  Exercises the cartesian expansion over both directions.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) accept;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      guest.interfaces = [ "guest0" ];
      wan.interfaces = [ "wan0" ];
      vpn.interfaces = [ "wg0" ];
    };

    filters.allow-out = {
      from = [
        "lan"
        "guest"
      ];
      to = [
        "wan"
        "vpn"
      ];
      rule = [ accept ];
    };
  };

  assertions = compiled: [
    {
      description = "2 from-zones × 2 to-zones = 4 sub-chains plus the base chain";
      expr = builtins.attrNames compiled.tables.multi-zone-fanout.chains;
      expected = [
        "forward-at-filter"
        "forward-at-filter__guest-to-vpn"
        "forward-at-filter__guest-to-wan"
        "forward-at-filter__lan-to-vpn"
        "forward-at-filter__lan-to-wan"
      ];
    }
  ];
}
