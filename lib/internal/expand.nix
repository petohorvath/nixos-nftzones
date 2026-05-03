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

  ===== expandTable =====

  Reads:  ctx.expandedGroups, ctx.resolvedPriorities,
          table.{filters, policies, snats, dnats, sroutes, droutes}
  Writes: ctx.cells

  For each entry in each rule group, overlays the entry's body
  with its wildcard-expanded directions (replacing the user's
  raw `from` / `to` lists) and the resolved int priority (where
  applicable), then cartesian-products via
  `internal.entry.toCells`. The result is a flat list of cells per
  group.

  Each cell preserves the entry's body fields (`rule`, `comment`,
  `chain`, …) plus a `name` field carrying the original entry's
  attrset key — Phase 3 sorts by `(priority, name)` and the name
  acts as a stable tiebreaker.

  Output shape (`chain` is always-present, may be null):
    cells = {
      filters  = [ { from; to;   name; rule; priority; comment; chain; } … ];
      policies = [ { from; to;   name; verdict; comment } … ];   # no priority
      snats    = [ { from; to;   name; rule; priority; comment; chain; } … ];
      dnats    = [ { from;       name; rule; priority; comment; chain; } … ];
      sroutes  = [ { from;       name; rule; priority; comment } … ];
      droutes  = [ {       to;   name; rule; priority; comment } … ];
    };
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
