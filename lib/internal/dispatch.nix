/*
  internal/dispatch — Phase 3 of the compile pipeline, exposed
  under `nftzones.internal.dispatch`.

  Buckets each cell from Phase 2 by `(chain, slot)` ready for
  Phase 4 to emit. Each cell ends up in exactly one bucket; buckets
  are sorted by `(priority, name)` with policies (no priority)
  trailing as tail rules.

  Pipeline pattern: each phase takes `{ table; ctx }` and returns
  the same shape, mirroring `internal.normalize` / `internal.expand`.

  Phase pipeline (Phase 3 portion):

      { table; ctx (post-Phase 2) }
        ↓ groupCellsByChain    ctx.groupedByChain
        ↓ buildChainBuckets    ctx.chainBuckets
      { table; ctx }

  ===== groupCellsByChain =====

  Reads:  ctx.cells, table.settings.localZone
  Writes: ctx.groupedByChain

  Determines each cell's destination chain (`{ hook; priority; }`)
  and groups cells by chain name. The chain attrs are preserved
  per group so `buildChainBuckets` doesn't recompute them.

  Each cell's chain is determined by:
    - The cell's `chain` override if set (`{ hook; priority; }`).
    - Otherwise per-group default:
        filters / policies → input / forward / output (filter
                              priority), dispatched by host
                              position (`to == localZone` → input,
                              `from == localZone` → output, else
                              forward).
        snats              → postrouting (srcnat priority).
        dnats              → prerouting  (dstnat priority).
        sroutes            → prerouting  (mangle priority).
        droutes            → output      (mangle priority).

  Output shape:
    groupedByChain = {
      "<hook>-at-<priority>" = {
        attrs = { hook; priority; };
        cells = [ <cell> … ];
      };
      …
    };

  ===== buildChainBuckets =====

  Reads:  ctx.groupedByChain
  Writes: ctx.chainBuckets

  Builds the final bucket per chain group: splits cells by slot,
  partitions the `subChains` slot per `(from, to)` pair, sorts
  each slot.

  Each cell's slot within the chain is determined by priority:
    - Cells with priority resolved to `1` (`first`) or `50`
      (`preDispatch`) → `preDispatch` slot (base chain, before the
      sub-chain dispatch jumps).
    - Cells with priority resolved to `100` (`postDispatch`) or
      `999` (`last`) → `postDispatch` slot (base chain, after the
      sub-chain dispatch jumps).
    - All other cells (default priority `500`, or any unmarked
      int) → `subChains` slot, partitioned per `(from, to)` pair.
    - Policies have no priority; they always go in `subChains` and
      sort to the end of their per-pair list as tail rules.

  Output shape:
    chainBuckets = {
      "<hook>-at-<priority>" = {
        hook         = <string>;
        priority     = <symbol or int>;
        preDispatch  = [ <sorted cells> ];
        subChains = {
          "<from>-to-<to>" = {
            from  = <zone-name>;
            to    = <zone-name>;
            cells = [ <sorted cells, policies last> ];
          };
          # Single-direction chains carry only the present direction:
          "<from>" = { from = <zone-name>; cells = […]; };
          "<to>"   = { to   = <zone-name>; cells = […]; };
        };
        postDispatch = [ <sorted cells> ];
      };
      …
    };

  Chain bucket keys (`"input-at-filter"`, `"prerouting-at-raw"`,
  etc.) are decorative — every bucket carries `hook` and `priority`
  as fields so Phase 4 reads structured data, not parsed strings.
  Sub-chain keys are likewise decorative; `from` / `to` live on the
  sub-chain itself.

  Override + default-chain collision (e.g., user override hits
  `(input, filter)` which is also the default input filter chain)
  is fine — both produce the same key, cells merge naturally into
  one bucket.

  ===== dispatchAndSort =====

  Orchestrator: pipes `groupCellsByChain` then
  `buildChainBuckets`. Returns `{ table; ctx }` with
  `ctx.chainBuckets` set.
*/
{ inputs, internal }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes.compatibility) priorityIntsDefault;
  inherit (internal.priority) entryPriorities;

  # Name-keyed views of nftypes' canonical enums — `hooks.input` /
  # `chainPriorities.filter` read as the string but trip a
  # missing-attr error if nftypes ever drops a name we reference
  # below. Replaces both the hardcoded literals and the lazy
  # `_validateCanonical` assert that never fired.
  hooks = lib.genAttrs nftypes.enums.hook lib.id;
  chainPriorities = lib.genAttrs (builtins.attrNames priorityIntsDefault) lib.id;

  # Resolved-priority values that opt cells out into the base chain
  # pre/post-dispatch slots. `default` (500) and any other unmarked
  # int land in the `subChains` slot.
  preDispatchSet = [
    entryPriorities.first
    entryPriorities.preDispatch
  ];
  postDispatchSet = [
    entryPriorities.postDispatch
    entryPriorities.last
  ];

  # Default chain attrs per group (excluding filters / policies,
  # which dispatch by host position).
  defaultGroupChainAttrs = {
    snats = {
      hook = hooks.postrouting;
      priority = chainPriorities.srcnat;
    };
    dnats = {
      hook = hooks.prerouting;
      priority = chainPriorities.dstnat;
    };
    sroutes = {
      hook = hooks.prerouting;
      priority = chainPriorities.mangle;
    };
    droutes = {
      hook = hooks.output;
      priority = chainPriorities.mangle;
    };
  };

  filterChainHook =
    localZone: cell:
    if cell ? to && cell.to == localZone then
      hooks.input
    else if cell ? from && cell.from == localZone then
      hooks.output
    else
      hooks.forward;

  /*
    Compute a cell's chain attrs `{ hook; priority; }` — the
    structured chain identity that travels with the cell through
    bucketing into Phase 4. Source of truth, in order:
      1. Cell's `chain` override if set.
      2. Filter / policy → input / forward / output by host
         position (filter priority).
      3. Otherwise per-group default (`defaultGroupChainAttrs`).
  */
  chainAttrsOf =
    group: localZone: cell:
    if (cell.chain or null) != null then
      { inherit (cell.chain) hook priority; }
    else if group == "filters" || group == "policies" then
      {
        hook = filterChainHook localZone cell;
        priority = chainPriorities.filter;
      }
    else
      defaultGroupChainAttrs.${group};

  # Bucket key for a chain — `"<hook>-at-<priority>"` (e.g.
  # `"input-at-filter"`). Decorative; bucket carries the structured
  # `{ hook; priority; }` separately for Phase 4.
  chainNameOf = chainAttrs: "${chainAttrs.hook}-at-${toString chainAttrs.priority}";

  # Classify a cell into one of the three slots within its chain
  # (see "Slot" in the design doc terminology). Field-less policies
  # fall through to `subChains` as tail rules.
  slotFor =
    cell:
    if !(cell ? priority) then
      "subChains"
    else if builtins.elem cell.priority preDispatchSet then
      "preDispatch"
    else if builtins.elem cell.priority postDispatchSet then
      "postDispatch"
    else
      "subChains";

  # Sub-chain key for a cell within its chain bucket — `"<from>-to-<to>"`
  # for bidirectional cells, bare `"<from>"` or `"<to>"` for
  # single-direction. Decorative; sub-chain carries `from` / `to`
  # as fields.
  subChainNameOf =
    cell:
    if cell ? from && cell ? to then
      "${cell.from}-to-${cell.to}"
    else if cell ? from then
      cell.from
    else
      cell.to;

  /*
    Sort cells: non-policy by (priority asc, name asc); policies
    by name and appended at the end (tail rules).

    Invariant (set by Phase 2): every cell carries a resolved int
    `priority` *except* policy cells, which intentionally omit the
    field so they can be identified here without a separate "kind"
    tag. Filter / snat / dnat / sroute / droute entries default to
    the resolved `"default"` priority (500) when the user doesn't
    set one — only policies are field-less.
  */
  sortMixed =
    cells:
    let
      parts = lib.partition (c: c ? priority) cells;

      byPriorityAndName = lib.sort (
        a: b: if a.priority != b.priority then a.priority < b.priority else a.name < b.name
      ) parts.right;

      byName = lib.sort (a: b: a.name < b.name) parts.wrong;
    in
    byPriorityAndName ++ byName;

  /*
    Build one sub-chain attrset from a list of cells sharing a
    sub-chain key. Carries only the directions actually present
    on the cells (no null fields).
  */
  subChainOf =
    cells:
    let
      firstCell = builtins.head cells;
    in
    lib.optionalAttrs (firstCell ? from) { inherit (firstCell) from; }
    // lib.optionalAttrs (firstCell ? to) { inherit (firstCell) to; }
    // {
      cells = sortMixed cells;
    };

  /*
    Build one chain bucket from chain attrs + a list of cells
    sharing the chain. Splits cells by slot, partitions
    `subChains` slot by sub-chain key, sorts everything.
  */
  bucketOf =
    chainAttrs: cells:
    let
      bySlot = lib.groupBy slotFor cells;
    in
    chainAttrs
    // {
      preDispatch = sortMixed (bySlot.preDispatch or [ ]);
      subChains = lib.mapAttrs (_: subChainOf) (lib.groupBy subChainNameOf (bySlot.subChains or [ ]));
      postDispatch = sortMixed (bySlot.postDispatch or [ ]);
    };

  groupCellsByChain =
    { table, ctx }:
    let
      inherit (table.settings) localZone;

      /*
        Data flow:
          ctx.cells              : { <group> = [ <cell> … ]; … }
          → pairWithChain        : { <group> = [ { attrs; cell } … ]; … }
          → concatAttrValues     : [ { attrs; cell } … ]
          → groupBy chainName    : { <chain> = [ { attrs; cell } … ]; … }
          → coalesce             : { <chain> = { attrs; cells }; … }
        `attrs` ({ hook; priority; }) is computed once per cell and
        carried through so `buildChainBuckets` doesn't recompute it.
      */
      pairWithChain = lib.mapAttrs (
        group:
        map (cell: {
          attrs = chainAttrsOf group localZone cell;
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
        (lib.groupBy (item: chainNameOf item.attrs))
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
    groupCellsByChain
    buildChainBuckets
    dispatchAndSort
    ;
}
