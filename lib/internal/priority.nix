/*
  internal/priority — exposes priority-resolution helpers under
  `nftzones.internal.priority`.

  Exported:
    - `resolvePriority` — resolve an entry priority value
                                (`either int symbol`) to an int.
    - `entryPriorities` — the canonical symbol → int table
                                (used by Phase 3 to identify the
                                pre/post-dispatch cutoff values
                                without hardcoding ints).

  Used by the compile pipeline to resolve `entryPriority` values
  into pure integers before sorting cells. Chain priority
  resolution is a separate concern and is delegated to
  `nftypes.resolvePriority` (family-aware).

  ===== resolvePriority =====

  Input:  a priority value — either an int or one of the symbol
          strings below.
  Output: the corresponding int. Ints pass through unchanged.

  Symbol → int mapping:

  | symbol         | int |
  |----------------|-----|
  | `first`        | 1   |  earliest
  | `preDispatch`  | 50  |  before child-dispatch jumps
  | `postDispatch` | 100 |  after child-dispatch jumps
  | `default`      | 500 |  main user rules (also post-dispatch)
  | `last`         | 999 |  latest

  The cutoff at 100 splits a sub-chain's `preChildCells` slot
  (< 100, emitted before child-dispatch jumps) from
  `postChildCells` (≥ 100, emitted after). Symbol names are
  historical — see `lib/types/primitives.nix` for the long form.
*/
{ inputs }:
let
  entryPriorities = {
    first = 1;
    preDispatch = 50;
    postDispatch = 100;
    default = 500;
    last = 999;
  };

  resolvePriority = p: if builtins.isInt p then p else entryPriorities.${p};
in
{
  inherit resolvePriority entryPriorities;
}
