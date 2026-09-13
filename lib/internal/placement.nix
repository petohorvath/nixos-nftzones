/*
  internal/placement — exposes chain-placement helpers under
  `nftzones.internal.placement`.

  Owns override precedence, per-group defaults, local-zone hook
  selection, and canonical chain naming. Phase 1 validates entry
  placements here; Phase 3 places each expanded cell here.

  Exported:
    - `chainAttrsForEntry`      — `group → localZone → entry →
                                  [{ hook; priority; }]`. Validation
                                  candidates from wildcard-expanded,
                                  deduplicated direction lists;
                                  never builds the cell cartesian.
    - `chainAttrsForCell`       — `group → localZone → cell →
                                  { hook; priority; }`. One concrete
                                  cell's placement. Both functions
                                  prefer `chain` overrides, then
                                  local-zone hooks for filters /
                                  policies, then group defaults.
    - `baseChainNameOf`         — `family → { hook; priority; } →
                                  "<hook>-at-<priority>"`. The
                                  bucket-key / base-chain-name
                                  format. Priority is canonicalized
                                  via `nftypes.priorityNameOf` so
                                  int and symbol forms of the same
                                  value collapse to one key.
    - `subChainKeyOf`           — `{ from?; to?; ... } →
                                  "<from>-to-<to>"` / `"<from>"` /
                                  `"<to>"`. The local sub-chain
                                  key inside a bucket; accepts
                                  cell-shaped attrsets (extra
                                  fields ignored).

  Wired into the surface from `lib/internal/default.nix` as a
  layer-0 leaf with no inter-module dependencies.
*/
{ inputs }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes) priorityNameOf;
  inherit (nftypes.compatibility) priorityIntsDefault;

  hookNames = lib.genAttrs nftypes.enums.hook lib.id;
  priorityNames = lib.genAttrs (builtins.attrNames priorityIntsDefault) lib.id;

  defaultGroupChainAttrs = {
    snats = {
      hook = hookNames.postrouting;
      priority = priorityNames.srcnat;
    };
    dnats = {
      hook = hookNames.prerouting;
      priority = priorityNames.dstnat;
    };
    sroutes = {
      hook = hookNames.prerouting;
      priority = priorityNames.mangle;
    };
    droutes = {
      hook = hookNames.output;
      priority = priorityNames.mangle;
    };
  };

  filterChainPriority = priorityNames.filter;

  filterChainHook =
    localZone: cell:
    if cell ? to && cell.to == localZone then
      hookNames.input
    else if cell ? from && cell.from == localZone then
      hookNames.output
    else
      hookNames.forward;

  # Both entry analysis and cell dispatch use this precedence.
  # Keep filter hooks lazy: overrides and fixed group defaults
  # do not need to inspect the entry's directions.
  selectChainAttrs =
    group: entry: filterHooks:
    if (entry.chain or null) != null then
      [ { inherit (entry.chain) hook priority; } ]
    else if group == "filters" || group == "policies" then
      map (hook: {
        inherit hook;
        priority = filterChainPriority;
      }) filterHooks
    else
      [ defaultGroupChainAttrs.${group} ];

  chainAttrsForCell =
    group: localZone: cell:
    builtins.head (selectChainAttrs group cell [ (filterChainHook localZone cell) ]);

  /*
    Entry-level validation candidates, without building cells.
    Directions must already be wildcard-expanded and deduplicated.
    Preserve the conservative validation contract: a local-zone
    reference contributes its hook even when the opposite list
    is empty; overrides and fixed defaults are always checked.
    A local-to-local entry therefore checks input and output,
    while its concrete cell dispatches to input.
  */
  chainAttrsForEntry =
    group: localZone: entry:
    let
      fromHasLocal = builtins.elem localZone entry.from;
      toHasLocal = builtins.elem localZone entry.to;
      nonLocalFrom = builtins.length entry.from > (if fromHasLocal then 1 else 0);
      nonLocalTo = builtins.length entry.to > (if toHasLocal then 1 else 0);

      filterHooks =
        lib.optional toHasLocal hookNames.input
        ++ lib.optional fromHasLocal hookNames.output
        ++ lib.optional (nonLocalFrom && nonLocalTo) hookNames.forward;
    in
    selectChainAttrs group entry filterHooks;

  # Base chain name — `"<hook>-at-<priority>"` (e.g.
  # `"input-at-filter"`). Used as the bucket key in
  # `dispatch.chainBuckets` and as the chain name Phase 4 emits in
  # the nftables output. The format is a naming convention; bucket
  # carries the structured `{ hook; priority; }` separately so
  # Phase 4 reads fields, not parsed strings.
  #
  # Priority is canonicalized via `nftypes.priorityNameOf` so int
  # and symbol forms of the same value share one bucket
  # (`chain.priority = 0` and the default `"filter"` collapse into
  # `"input-at-filter"`). The lookup is family-aware — bridge's
  # `filter = -200` canonicalizes correctly, unlike the prior
  # inet-only inline implementation.
  #
  # Single source of truth for the bucket-key format; consumers
  # that synthesize a chain placement (e.g. Phase 4's rpfilter
  # collision check) must build the same key by calling this.
  baseChainNameOf =
    family: chainAttrs: "${chainAttrs.hook}-at-${toString (priorityNameOf family chainAttrs.priority)}";

  /*
    Sub-chain key for a cell within its chain bucket —
    `"<from>-to-<to>"` for bidirectional cells, bare `"<from>"`
    or `"<to>"` for single-direction. Accepts any attrset with
    optional `from` / `to` keys (other fields ignored), so it
    works on cells, sub-chains, or hand-built attrsets alike.

    Throws if neither key is present, since the resulting key
    would be empty — a sub-chain must be reachable by at least
    one of from/to.
  */
  subChainKeyOf =
    {
      from ? null,
      to ? null,
      ...
    }:
    if from != null && to != null then
      "${from}-to-${to}"
    else if from != null then
      from
    else if to != null then
      to
    else
      throw "internal.placement.subChainKeyOf: at least one of `from` / `to` must be non-null";

in
{
  inherit
    chainAttrsForCell
    chainAttrsForEntry
    baseChainNameOf
    subChainKeyOf
    ;
}
