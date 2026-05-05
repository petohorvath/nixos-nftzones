/*
  Cartesian-product scenario — `from = [ lan guest ] × to = [ wan vpn ]`
  produces four sub-chains, all sharing the same rule body.
  Exercises the cartesian expansion over both directions.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
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
}
