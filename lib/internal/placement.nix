/*
  internal/placement — exposes chain-placement helpers under
  `nftzones.internal.placement`.

  Single source of truth for the per-group default chain attrs
  and the local-zone-driven filter/policy hook. Phase 1's
  `internal.normalize.checkChainPlacement` and Phase 3's
  `internal.dispatch.chainAttrsOf` both consume these — keeping
  them here prevents the two from drifting apart as new groups
  or hooks land.

  Exported:
    - `defaultGroupChainAttrs`  — `{ <group> = { hook; priority; }; … }`
                                  for non-filter groups (snats /
                                  dnats / sroutes / droutes).
                                  Filters and policies dispatch
                                  by host position via
                                  `filterChainHook`, so they have
                                  no entry here.
    - `filterChainHook`         — given a `localZone` and a
                                  cell-shaped attrset (with
                                  `from?` / `to?` fields), returns
                                  the hook the cell's filter or
                                  policy rule dispatches to:
                                    `to == localZone`   → `input`
                                    `from == localZone` → `output`
                                    else                → `forward`
    - `filterChainPriority`     — canonical symbol (`"filter"`)
                                  used for filter/policy chains.
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
    - `walkParents`             — `mergedZones → zoneName →
                                  [ancestor]`. Walks the parent
                                  chain (strict ancestors), cycle-
                                  safe. Single helper for both
                                  validators (overlap, hierarchy)
                                  and emit's intermediate-chain
                                  synthesis.
    - `hooksWithIifname`        — hooks where the `iifname` /
                                  `iif` match field is available.
                                  Mirror of `nftypes.compatibility.
                                  hooksWithOifname` for the input-
                                  side. Local because upstream
                                  doesn't expose it (yet).

  Wired into the surface from `lib/internal/default.nix` as a
  layer-0 leaf with no inter-module dependencies.
*/
{ inputs }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes) priorityNameOf;
  inherit (nftypes.compatibility) priorityIntsDefault;

  /*
    Hooks where the input interface (`iifname` / `iif`) match
    field carries a real value. Mirror of `nftypes.compatibility.
    hooksWithOifname`. `output` is excluded — locally-generated
    packets have no input device. `ingress` is excluded too —
    nftzones' zone-firewall model doesn't currently use device-
    bound ingress chains, and including it would invite false
    positives from validators that ask the question without
    having a `device` binding to qualify the answer.
  */
  hooksWithIifname = [
    "prerouting"
    "input"
    "forward"
    "postrouting"
  ];

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

  /*
    Walk the strict ancestor chain of `name` in `mergedZones` —
    parent, grandparent, … excluding `name` itself. Returns a
    list ordered root-ward (immediate parent first, root last).

    Stops at:
      - `null` parent (root reached, return list as built),
      - an unresolved parent name (not in `mergedZones`),
      - a name already visited (cycle — defensive against
        fixtures that bypass `checkParentCycles`).

    Used by:
      - `internal.normalize.relatedByHierarchy` (overlap
        validators skip pairs in an ancestor relation),
      - `internal.emit.buildEffectiveSubChains` (synthesize
        empty intermediate sub-chains for the dispatch chain).

    Both consumers want "list of ancestors" and don't care about
    cycle detection; `checkParentCycles` is the dedicated cycle
    validator.
  */
  walkParents =
    mergedZones: name:
    let
      step =
        visited: cur:
        if cur == null then
          [ ]
        else
          let
            zone = mergedZones.${cur} or null;
            parent = if zone == null then null else zone.parent or null;
          in
          if parent == null || builtins.elem parent visited || !(mergedZones ? ${parent}) then
            [ ]
          else
            [ parent ] ++ step (visited ++ [ parent ]) parent;
    in
    step [ name ] name;
in
{
  inherit
    defaultGroupChainAttrs
    filterChainHook
    filterChainPriority
    baseChainNameOf
    subChainKeyOf
    walkParents
    hooksWithIifname
    ;
}
