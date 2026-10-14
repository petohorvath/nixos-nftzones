/*
  Rejection scenario for `checkSubChainNameCollisions` — the zone
  pairs `a-to → b` and `a → to-b` both build the sub-chain name
  `forward-at-filter__a-to-to-b`. Without rejection, their cells
  merge into one sub-chain behind a single base-chain jump gated on
  whichever pair came first: `y` fires on `a-to → b` traffic, and
  `a → to-b` traffic never reaches its rule.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  description = "checkSubChainNameCollisions: zone pairs a-to → b and a → to-b share one sub-chain name";

  body = {
    zones = {
      a.interfaces = [ "eth-a" ];
      a-to.interfaces = [ "eth-ato" ];
      b.interfaces = [ "eth-b" ];
      to-b.interfaces = [ "eth-tob" ];
    };

    filters = {
      x = {
        from = [ "a-to" ];
        to = [ "b" ];
        rule = [ accept ];
        comment = "x";
      };
      y = {
        from = [ "a" ];
        to = [ "to-b" ];
        rule = [ accept ];
        comment = "y";
      };
    };
  };
}
