/*
  Rejection scenario for `objectRefUnknown` — an
  `objects.sets.<name>.stmt` entry references an undeclared
  counter. Sets and maps may carry stateful statements (counters,
  limits, …) for their elements; Phase 1 must walk them just like
  rule bodies. The complementary case (rule body refs) is covered
  by object-refs.nix.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) counter;
in
{
  description = "objectRefUnknown: set stmt references unknown counter";

  errors = [
    {
      tag = "objectRefUnknown";
      path = [
        "objects"
        "sets"
        "tracker"
      ];
    }
  ];

  body = {
    zones.lan.interfaces = [ "lan0" ];

    objects.sets.tracker = {
      type = "ipv4_addr";
      elem = [ "1.2.3.4" ];
      stmt = [ (counter.ref "ghost-counter") ];
    };
  };
}
