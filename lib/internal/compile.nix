/*
  internal/compile — pipeline orchestrator for the nftzones compile
  pipeline. Exposed under `nftzones.internal.compile`.

  Pipes Phase 1 → 2 → 3 → 4 in order:

      table (evaluated `nftzones.types.table` value)
        ↓ normalizeTable      Phase 1 — validates + lowers nodes
        ↓ expandTable         Phase 2 — cells per group
        ↓ dispatchAndSort     Phase 3 — chain buckets
        ↓ emitTable           Phase 4 — assembles `ctx.output`
      { table; ctx (full pipeline state) }

  Phase 1's `normalizeTable` throws on validation errors; the
  throw propagates up. Phases 2-4 trust upstream — no further
  validation, no error aggregation. If a downstream phase blows
  up, that's a bug, not a user error.
*/
{ inputs, internal }:
let
  inherit (inputs) lib nftypes;
  inherit (internal.normalize) normalizeTable;
  inherit (internal.expand) expandTable;
  inherit (internal.dispatch) dispatchAndSort;
  inherit (internal.emit) emitTable;

  compile =
    table:
    lib.pipe table [
      normalizeTable
      expandTable
      dispatchAndSort
      emitTable
    ];

  mkTable = table: (compile table).ctx.output;

  mkRuleset = table: nftypes.dsl.ruleset [ (mkTable table) ];
in
{
  inherit
    compile
    mkRuleset
    mkTable
    ;
}
