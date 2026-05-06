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

  Builds the final bucket per chain group: partitions cells per
  `(from, to)` sub-chain, then within each sub-chain splits cells
  into pre-child-dispatch and post-child-dispatch by priority
  cutoff at 100. Each slot pre-sorted by `(priority asc, name asc)`;
  policies (no priority) appended last to `postChildCells`.

  Slot semantics within a sub-chain:
    - Cells with priority < 100 (`first` = 1, `preDispatch` = 50,
      or any int < 100) → `preChildCells`. Phase 4 emits these
      before the sub-chain's child-dispatch jumps fire.
    - Cells with priority >= 100 (`postDispatch` = 100,
      `default` = 500, `last` = 999, or any int >= 100), and
      policies (no priority) → `postChildCells`. Phase 4 emits
      these after child-dispatch jumps return without verdict —
      i.e., as parent-fallback rules.
    - The base chain itself no longer carries pre/post slots;
      every cell lives in its sub-chain. Rules that conceptually
      need to fire "before any zone dispatch" land in each root
      sub-chain's pre-child slot — equivalent for any traffic
      that matched a root.

  Output shape:
    chainBuckets = {
      "<hook>-at-<priority>" = {
        hook      = <string>;
        priority  = <symbol or int>;
        subChains = {
          "<from>-to-<to>" = {
            from           = <zone-name>;
            to             = <zone-name>;
            preChildCells  = [ <sorted cells, priority < 100> ];
            postChildCells = [ <sorted cells, priority >= 100,
                                policies appended last> ];
          };
          # Single-direction chains carry only the present
          # direction:
          "<from>" = { from = <zone-name>;  preChildCells = […];
                       postChildCells = […]; };
          "<to>"   = { to   = <zone-name>;  preChildCells = […];
                       postChildCells = […]; };
        };
      };
      …
    };

  Bucket keys are *base chain names* (`"input-at-filter"`,
  `"prerouting-at-raw"`, etc.) computed by `baseChainNameOf` from
  `(hook, priority)`; Phase 4 emits them as the actual nftables
  base chain names. The `<hook>-at-<priority>` form is a naming
  convention — every bucket also carries `hook` and `priority` as
  fields so Phase 4 reads structured data, not parsed strings.
  Sub-chain keys (`"lan-to-wan"`, `"wan"`, etc.) are likewise
  decorative within Phase 3; Phase 4 uses them to build the full
  sub-chain name as `<baseChainName>__<subChainKey>`.

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
  inherit (nftypes) priorityNameOf;
  inherit (nftypes.compatibility) priorityIntsDefault;
  inherit (internal.priority) entryPriorities;

  # Name-keyed views of nftypes' canonical enums — `hooks.input` /
  # `chainPriorities.filter` read as the string but trip a
  # missing-attr error if nftypes ever drops a name we reference
  # below. Replaces both the hardcoded literals and the lazy
  # `_validateCanonical` assert that never fired.
  hooks = lib.genAttrs nftypes.enums.hook lib.id;
  chainPriorities = lib.genAttrs (builtins.attrNames priorityIntsDefault) lib.id;

  # Sub-chain pre/post-child-dispatch cutoff. Cells with resolved
  # priority below this fall in the `preChildCells` slot (fire
  # before child-dispatch jumps); cells at or above fall in
  # `postChildCells` (fire after children return — parent
  # fallback). Default (500) lands in `postChildCells` naturally.
  preChildCutoff = entryPriorities.postDispatch;

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

  # Base chain name — `"<hook>-at-<priority>"` (e.g.
  # `"input-at-filter"`). Used as the bucket key in `chainBuckets`
  # *and* as the chain name Phase 4 emits in the nftables output.
  # The format is a naming convention; bucket carries the
  # structured `{ hook; priority; }` separately so Phase 4 reads
  # fields, not parsed strings.
  #
  # Priority is canonicalized via `nftypes.compatibility.priorityNameOf`
  # so int and symbol forms of the same value share one bucket
  # (`chain.priority = 0` and the default `"filter"` collapse into
  # `"input-at-filter"`). The lookup is family-aware — bridge's
  # `filter = -200` canonicalizes correctly, unlike the prior
  # inet-only inline implementation.
  baseChainNameOf =
    family: chainAttrs:
    "${chainAttrs.hook}-at-${toString (priorityNameOf family chainAttrs.priority)}";

  # Sub-chain key for a cell within its chain bucket —
  # `"<from>-to-<to>"` for bidirectional cells, bare `"<from>"` or
  # `"<to>"` for single-direction. Decorative; sub-chain carries
  # `from` / `to` as fields.
  subChainKeyOf =
    cell:
    if cell ? from && cell ? to then
      "${cell.from}-to-${cell.to}"
    else if cell ? from then
      cell.from
    else
      cell.to;

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
      inherit preChildCells postChildCells;
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
    groupCellsByChain
    buildChainBuckets
    dispatchAndSort
    ;
}
