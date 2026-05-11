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
in
{
  inherit
    defaultGroupChainAttrs
    filterChainHook
    filterChainPriority
    baseChainNameOf
    ;
}
