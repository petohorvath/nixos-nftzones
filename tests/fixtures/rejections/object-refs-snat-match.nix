/*
  Rejection scenario for `objectRefUnknown` — an snat's `match`
  references a set that hasn't been declared in `objects.sets`.
  An snat's match is checked like a filter's rule or a dnat's
  match, so the reference fails at compile time instead of at
  `nft load` time.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) expr inSet;
  inherit (nftypes.dsl.fields) ip;
in
{
  description = "objectRefUnknown: snat match references undeclared set";

  errors = [
    {
      tag = "objectRefUnknown";
      path = [
        "snats"
        "outbound"
        "rule"
      ];
    }
  ];

  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    snats.outbound = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = {
        match = [ (inSet ip.daddr (expr.setRef "missing-set")) ];
        action.masquerade = { };
      };
    };
  };
}
