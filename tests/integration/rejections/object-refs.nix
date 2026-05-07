/*
  Rejection scenario for `checkObjectRefs` — a filter rule
  references a counter that hasn't been declared in
  `objects.counters`. Without rejection, the rendered ruleset
  would reference a non-existent counter and fail at `nft load`
  time instead of compile time.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) counter accept;
in
{
  description = "checkObjectRefs: rule references undeclared counter";

  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    filters.f = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [
        (counter.ref "missing-counter")
        accept
      ];
    };
  };
}
