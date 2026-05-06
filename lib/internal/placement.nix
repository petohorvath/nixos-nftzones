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

  Wired into the surface from `lib/internal/default.nix` as a
  layer-0 leaf with no inter-module dependencies.
*/
{ inputs }:
let
  inherit (inputs) lib nftypes;
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
in
{
  inherit defaultGroupChainAttrs filterChainHook filterChainPriority;
}
