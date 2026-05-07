/*
  Priority-slots scenario — one entry per slot (preDispatch /
  subChain / postDispatch) in a single chain. Validates that the
  base-chain rule order (stateful → preDispatch → jumps →
  postDispatch) renders into a syntactically valid chain.

  Under the current model, all three priority slots land in the
  sub-chain's `preChildCells` / `postChildCells` (priority < 100
  → preChild, ≥ 100 → postChild). Base chain only carries
  stateful preludes plus the dispatch jump.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    filters = {
      early = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ accept ];
        priority = "first";
      };
      regular = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ accept ];
      };
      late = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ accept ];
        priority = "last";
      };
    };
  };

  assertions = compiled: [
    {
      description = "base chain has stateful preludes (2) + dispatch jump (1)";
      expr = builtins.length compiled.tables.priority-slots.chains."forward-at-filter".rules;
      expected = 3;
    }
    {
      description = "all three priority-slotted entries land in the sub-chain";
      expr = builtins.length compiled.tables.priority-slots.chains."forward-at-filter__lan-to-wan".rules;
      expected = 3;
    }
  ];
}
