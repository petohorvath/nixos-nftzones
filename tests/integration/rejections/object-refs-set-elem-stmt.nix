/*
  Rejection scenario for `checkObjectRefs` — an
  `objects.sets.<name>.elem` entry uses `dsl.expr.elem { val;
  stmt; }` whose stateful statement references an undeclared
  counter. Set / map elements may carry per-element statements
  (counters, limits, …); the validator must walk them just
  like rule bodies. The complementary case (rule body refs)
  is covered by object-refs.nix.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) counter;
  inherit (nftypes.dsl.expr) elem;
in
{
  description = "checkObjectRefs: set element-attached stmt references unknown counter";

  body = {
    zones.lan.interfaces = [ "lan0" ];

    objects.sets.tracker = {
      type = "ipv4_addr";
      elem = [
        (elem {
          val = "1.2.3.4";
          stmt = [ (counter.ref "ghost-counter") ];
        })
      ];
    };
  };
}
