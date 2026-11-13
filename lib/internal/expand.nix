/*
  internal/expand — Phase 2 of the compile pipeline, exposed under
  `nftzones.internal.expand`.

  Fans each entry into a flat list of cells via cartesian product
  over the entry's directions (`from`, `to`), then drops each cell
  whose local-zone direction cannot match at the cell's hook
  (ADR-0013). Phase 3 (dispatch + sort) consumes the cell lists.

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
  inherit (internal.placement) chainAttrsForCell;
  inherit (internal.zone) localCellMatchable;

  expandTable =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (table.settings) localZone;

      # A cell whose local-zone direction cannot match at its hook
      # would compile to no jump at best; drop it (ADR-0013). Phase 1
      # has already rejected such cells built from explicit names, so
      # only cells a wildcard produced reach this filter.
      matchable =
        groupName: cell:
        localCellMatchable family localZone (chainAttrsForCell groupName localZone cell).hook cell;

      /*
        Build the cell list for one rule group. Each cell records
        its `group`, which Phase 4 reads to pick the rule body's
        shape. `withPriority` toggles whether
        `ctx.resolvedPriorities` is overlaid — policies don't carry
        a `priority` field and are excluded.
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
                group = groupName;
                name = entryName;
              }
              // (lib.optionalAttrs withPriority {
                priority = ctx.resolvedPriorities.${groupName}.${entryName};
              });
          in
          builtins.filter (matchable groupName) (toCells base)
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
