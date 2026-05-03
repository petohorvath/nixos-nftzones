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

  ===== compile =====

  Input:  an evaluated `nftzones.types.table` value
  Output: `{ table; ctx }` — full pipeline state (every artifact
          each phase wrote — `mergedZones`, `expandedGroups`,
          `chainBuckets`, `zoneSets`, `baseChains`, `subChains`,
          `userObjects`, `output`, …). Tests / debugging tools
          consume the full state; the public API surface
          (`mkTable`, `mkRuleset`) extracts just `ctx.output`.

  ===== mkTable =====

  Input:  an evaluated `nftzones.types.table` value
  Output: an `nftypes.dsl.table` marker value, ready to embed in
          a ruleset or render to JSON.

  Convenience over `compile`: extracts `ctx.output`.

  ===== mkRuleset =====

  Input:  an evaluated `nftzones.types.table` value
  Output: an `nftypes.dsl.ruleset` value containing the single
          compiled table — the canonical `{ nftables = [ ... ]; }`
          envelope ready for `nft -f -j`.

  Multi-table consumers should compose externally:
    `nftypes.dsl.ruleset [ (mkTable x) (mkTable y) ]`.
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
    mkTable
    mkRuleset
    ;
}
