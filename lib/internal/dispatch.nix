/*
  internal/dispatch — Phase 3 of the compile pipeline, exposed
  under `nftzones.internal.dispatch`.

  Builds one dispatch tree per base chain from the Phase 2 cells,
  ready for Phase 4 to render:

      ctx.dispatchTrees.<baseChainName> = {
        hook; priority;
        roots = [ <sub-chain name> … ];
        subChains.<sub-chain name> = {
          from?; to?;
          preChildCells; postChildCells;
          children = [ <sub-chain name> … ];
        };
      }

  Every cell lives in exactly one sub-chain; within it, cells split
  into pre-child and post-child slots around the child-dispatch
  jumps (ADR-0008). Policies (no priority) trail as tail rules.
  From-side dispatch is hierarchical (ADR-0006): `roots` are the
  sub-chains the base chain jumps to, `children` the sub-chains a
  parent jumps to, and parents without cells of their own appear
  as transparent dispatchers with empty slots.

  Pipeline pattern: each phase takes `{ table; ctx }` and returns
  the same shape, mirroring `internal.normalize` / `internal.expand`.

  Phase pipeline (Phase 3 portion):

      { table; ctx (post-Phase 2) }
        ↓ groupCellsByChain    ctx.groupedByChain
        ↓ buildDispatchTrees   ctx.dispatchTrees
      { table; ctx }
*/
{ inputs, internal }:
let
  inherit (inputs) lib;
  inherit (internal.priority) entryPriorities;
  inherit (internal.placement)
    baseChainNameOf
    chainAttrsForCell
    subChainNameOf
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
    sub-chain name. Cells partition into pre-child / post-child
    slots by priority cutoff at 100; policies (no priority) tail
    `postChildCells`. Only the directions actually present on the
    cells get `from` / `to` fields (no nulls).

    Invariant (set by Phase 2): every non-policy cell carries a
    resolved int `priority`; only policies are field-less.

    Reading `from` / `to` off the first cell assumes the cells share
    their zones. `placement.subChainNameOf` keeps zone pairs apart
    from each other and from single zones (ADR-0011), but a from-only
    and a to-only sub-chain for the same zone still share a name
    (#20).
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
    Build one base chain's dispatch tree from its chain attrs and
    the cells placed in it. Partitions cells per `(from, to)`
    sub-chain, keyed by the sub-chain name Phase 4 emits, then
    `subChainOf` does the slot split + sort within each.
  */
  dispatchTreeOf =
    zoneMembership: baseChainName: chainAttrs: cells:
    let
      cellSubChains = lib.mapAttrs (_: subChainOf) (lib.groupBy (subChainNameOf baseChainName) cells);

      /*
        Only root zones jump from the base chain, so every ancestor
        of a cell-bearing sub-chain needs a sub-chain to dispatch
        through, even without cells of its own. Cell-bearing
        sub-chains win over these transparent dispatchers.
      */
      transparentDispatcherOf =
        ancestor: toZone:
        lib.optionalAttrs (toZone != null) { to = toZone; }
        // {
          from = ancestor;
          preChildCells = [ ];
          postChildCells = [ ];
        };

      transparentDispatchersFor =
        subChain:
        let
          toZone = subChain.to or null;
        in
        lib.listToAttrs (
          map (
            ancestor:
            lib.nameValuePair (subChainNameOf baseChainName {
              from = ancestor;
              to = toZone;
            }) (transparentDispatcherOf ancestor toZone)
          ) (zoneMembership.ancestorsOf (subChain.from or null))
        );

      transparentDispatchers = lib.foldlAttrs (
        acc: _: subChain:
        acc // transparentDispatchersFor subChain
      ) { } cellSubChains;

      slottedSubChains = transparentDispatchers // cellSubChains;

      # A child-dispatch jump keeps the parent's to-zone, so it
      # targets a child only where that child's subtree has a
      # sub-chain for the same to-zone.
      childrenFor =
        subChain:
        lib.pipe (zoneMembership.childrenOf.${subChain.from} or [ ]) [
          (map (
            child:
            subChainNameOf baseChainName {
              from = child;
              to = subChain.to or null;
            }
          ))
          (builtins.filter (name: slottedSubChains ? ${name}))
        ];

      subChains = lib.mapAttrs (
        _: subChain: subChain // { children = lib.optionals (subChain ? from) (childrenFor subChain); }
      ) slottedSubChains;

      # Hierarchy is from-side only (ADR-0006): sub-chains without
      # a `from` dispatch straight from the base chain.
      isRoot = subChain: !(subChain ? from) || builtins.elem subChain.from zoneMembership.rootZoneNames;
    in
    chainAttrs
    // {
      inherit subChains;
      roots = builtins.filter (name: isRoot subChains.${name}) (builtins.attrNames subChains);
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
        carried through so `buildDispatchTrees` doesn't recompute it.
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

  buildDispatchTrees =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        dispatchTrees = lib.mapAttrs (
          baseChainName: chainGroup:
          dispatchTreeOf ctx.zoneMembership baseChainName chainGroup.attrs chainGroup.cells
        ) ctx.groupedByChain;
      };
    };

  dispatchAndSort =
    state:
    lib.pipe state [
      groupCellsByChain
      buildDispatchTrees
    ];
in
{
  inherit
    buildDispatchTrees
    dispatchAndSort
    groupCellsByChain
    ;
}
