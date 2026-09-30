/*
  internal/expand — Phase 2 of the compile pipeline, exposed under
  `nftzones.internal.expand`.

  Fans each entry into a flat list of cells via cartesian product
  over the entry's directions (`from`, `to`). Phase 3 (dispatch +
  sort) consumes the cell lists.

  Pipeline pattern: each phase takes `{ table; ctx }` and returns
  the same shape, mirroring `internal.normalize`. Phase 2 reads
  the artifacts Phase 1 produced (`ctx.expandedGroups`,
  `ctx.resolvedPriorities`) plus the original entries on `table`,
  and writes `ctx.cells`.

  Phase pipeline (Phase 2 portion):

      { table; ctx (post-Phase 1) }
        ↓ expandTable    ctx.cells
      { table; ctx }
*/
{ inputs, internal }:
let
  inherit (inputs) lib;
  inherit (internal.entry) toCells;

  expandTable =
    { table, ctx }:
    let
      /*
        Build the cell list for one rule group. `withPriority`
        toggles whether `ctx.resolvedPriorities` is overlaid —
        policies don't carry a `priority` field and are excluded.
      */
      cellsForGroup =
        groupName: withPriority:
        lib.concatMap (
          entryName:
          let
            entry = table.${groupName}.${entryName};
            expanded = ctx.expandedGroups.${groupName}.${entryName};
            base =
              entry
              // expanded
              // {
                name = entryName;
              }
              // (lib.optionalAttrs withPriority {
                priority = ctx.resolvedPriorities.${groupName}.${entryName};
              });
          in
          toCells base
        ) (builtins.attrNames table.${groupName});

      cells = {
        filters = cellsForGroup "filters" true;
        policies = cellsForGroup "policies" false;
        snats = cellsForGroup "snats" true;
        dnats = cellsForGroup "dnats" true;
        sroutes = cellsForGroup "sroutes" true;
        droutes = cellsForGroup "droutes" true;
      };
    in
    {
      inherit table;
      ctx = ctx // {
        inherit cells;
      };
    };
in
{
  inherit expandTable;
}
