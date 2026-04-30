/*
  internal/wildcard — exposes wildcard-zone helpers under
  `nftzones.internal.wildcard`.

  Exported functions:
    - `expandWildcard` — substitutes the wildcard zone name in a
                          `from` / `to` list with the full list of
                          in-scope zones, deduplicating result.

  Used by the compile pipeline's normalize phase to turn entries
  like `[ "all" "lan" ]` into concrete zone lists like
  `[ "lan" "wan" "local" "dmz" ]` before per-rule expansion.

  ===== expandWildcard =====

  Signature is curried-positional rather than the project's usual
  attrset-arg style: most consumers (`lib.concatMap`, `lib.imap0`,
  per-direction loops in `internal.normalize.expandWildcardZones`)
  partially apply the leading `wildcard` and `allZones` arguments
  and pass the resulting unary function over many `zones` lists.

  Inputs:
    wildcard  — name treated as the "all zones" placeholder
                (`table.settings.wildcardZone`, default `"all"`).
    allZones  — concrete zone names the wildcard expands to.
                Typically all declared zones plus
                `table.settings.localZone`.
    zones     — user-supplied `from` / `to` list, possibly
                containing the wildcard.

  Output:
    The `zones` list with each wildcard entry replaced by
    `allZones`, then deduplicated (preserving first-occurrence
    order). Non-wildcard entries pass through unchanged.

  Example:
    expandWildcard "all" [ "lan" "wan" "local" ] [ "lan" "all" ]
    => [ "lan" "wan" "local" ]
    # The "all" expands to the scope, then `lan` (already present)
    # is deduplicated; result keeps first-occurrence order.

  Edge cases:
    - Empty `zones` → empty result.
    - `zones` without the wildcard → identical (after dedup).
    - `zones` with only the wildcard → the full scope.
    - Wildcard repeated in `zones` → expanded once (dedup).
*/
{ inputs }:
let
  inherit (inputs) lib;

  expandWildcard =
    wildcard: allZones: zones:
    lib.unique (lib.concatMap (z: if z == wildcard then allZones else [ z ]) zones);
in
{
  inherit expandWildcard;
}
