/*
  internal/dispatch — Phase 3 of the compile pipeline, exposed
  under `nftzones.internal.dispatch`.

  Buckets each cell from Phase 2 by `(chain, sub-chain, sub-slot)`
  ready for Phase 4 to emit. Every cell lives in exactly one
  sub-chain; within the sub-chain, cells split into pre-child and
  post-child slots around the eventual child-dispatch jump
  position. Policies (no priority) trail as tail rules.

  Pipeline pattern: each phase takes `{ table; ctx }` and returns
  the same shape, mirroring `internal.normalize` / `internal.expand`.

  Phase pipeline (Phase 3 portion):

      { table; ctx (post-Phase 2) }
        ↓ groupCellsByChain    ctx.groupedByChain
        ↓ buildChainBuckets    ctx.chainBuckets
      { table; ctx }
*/
{ inputs, internal }:
let
  inherit (inputs) lib;
  inherit (internal.priority) entryPriorities;
  inherit (internal.placement)
    baseChainNameOf
    chainAttrsForCell
    subChainKeyOf
    ;

  # Sub-chain pre/post-child-dispatch cutoff. Cells with resolved
  # priority below this fall in the `preChildCells` slot (fire
  # before child-dispatch jumps); cells at or above fall in
  # `postChildCells` (fire after children return — parent
  # fallback). Default (500) lands in `postChildCells` naturally.
  preChildCutoff = entryPriorities.postDispatch;

  # Sort by `(priority asc, name asc)`. Caller filters out
  # policies first if needed (policies have no `priority`).
  sortByPriorityName = lib.sort (
    a: b: if a.priority != b.priority then a.priority < b.priority else a.name < b.name
  );

  sortByName = lib.sort (a: b: a.name < b.name);

  /*
    Build one sub-chain attrset from a list of cells sharing a
    sub-chain key. Cells partition into pre-child / post-child
    slots by priority cutoff at 100; policies (no priority) tail
    `postChildCells`. Only the directions actually present on the
    cells get `from` / `to` fields (no nulls).

    Invariant (set by Phase 2): every non-policy cell carries a
    resolved int `priority`; only policies are field-less.
  */
  subChainOf =
    cells:
    let
      firstCell = builtins.head cells;

      preParts = lib.partition (c: (c ? priority) && c.priority < preChildCutoff) cells;
      preChildCells = sortByPriorityName preParts.right;

      # `postChildCells`: the remainder — non-policy cells with
      # priority >= cutoff, plus policies (which lack a `priority`
      # field). Sort the priority-bearing portion, then append
      # policies sorted by name as tail rules.
      postRest = preParts.wrong;
      postPriorityParts = lib.partition (c: c ? priority) postRest;
      postChildCells = sortByPriorityName postPriorityParts.right ++ sortByName postPriorityParts.wrong;
    in
    lib.optionalAttrs (firstCell ? from) { inherit (firstCell) from; }
    // lib.optionalAttrs (firstCell ? to) { inherit (firstCell) to; }
    // {
      inherit postChildCells preChildCells;
    };

  /*
    Build one chain bucket from chain attrs + a list of cells
    sharing the chain. Partitions cells per `(from, to)` sub-chain
    key, then `subChainOf` does the slot split + sort within each.
    The base chain itself no longer holds pre/post slots — every
    cell lives in its sub-chain.
  */
  bucketOf =
    chainAttrs: cells:
    chainAttrs
    // {
      subChains = lib.mapAttrs (_: subChainOf) (lib.groupBy subChainKeyOf cells);
    };

  groupCellsByChain =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (table) family;

      /*
        Data flow:
          ctx.cells              : { <group> = [ <cell> … ]; … }
          → pairWithChain        : { <group> = [ { attrs; cell } … ]; … }
          → concatAttrValues     : [ { attrs; cell } … ]
          → groupBy baseChainName : { <chain> = [ { attrs; cell } … ]; … }
          → coalesce             : { <chain> = { attrs; cells }; … }
        `attrs` ({ hook; priority; }) is computed once per cell and
        carried through so `buildChainBuckets` doesn't recompute it.
      */
      pairWithChain = lib.mapAttrs (
        group:
        map (cell: {
          attrs = chainAttrsForCell group localZone cell;
          inherit cell;
        })
      );

      coalesce = lib.mapAttrs (
        _: items: {
          attrs = (builtins.head items).attrs;
          cells = map (item: item.cell) items;
        }
      );

      groupedByChain = lib.pipe ctx.cells [
        pairWithChain
        lib.concatAttrValues
        (lib.groupBy (item: baseChainNameOf family item.attrs))
        coalesce
      ];
    in
    {
      inherit table;
      ctx = ctx // {
        inherit groupedByChain;
      };
    };

  buildChainBuckets =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        chainBuckets = lib.mapAttrs (
          _: chainGroup: bucketOf chainGroup.attrs chainGroup.cells
        ) ctx.groupedByChain;
      };
    };

  dispatchAndSort =
    state:
    lib.pipe state [
      groupCellsByChain
      buildChainBuckets
    ];
in
{
  inherit
    buildChainBuckets
    dispatchAndSort
    groupCellsByChain
    ;
}
