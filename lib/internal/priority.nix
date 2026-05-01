/*
  internal/priority — exposes priority-resolution helpers under
  `nftzones.internal.priority`.

  Exported:
    - `resolvePriority` — resolve a rule priority value
                                (`either int symbol`) to an int.

  Used by the compile pipeline to resolve `rulePriority` values
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
  | `preDispatch`  | 50  |  before per-zone dispatch jumps
  | `postDispatch` | 100 |  after per-zone dispatch jumps
  | `default`      | 500 |  main user rules
  | `last`         | 999 |  latest

  The cutoff at 100 splits cells into pre-dispatch (< 100, emitted
  before zone matchers) and post-dispatch (>= 100, emitted after).
*/
{ inputs }:
let
  rulePrioritySymbols = {
    first = 1;
    preDispatch = 50;
    postDispatch = 100;
    default = 500;
    last = 999;
  };

  resolvePriority = p: if builtins.isInt p then p else rulePrioritySymbols.${p};
in
{
  inherit resolvePriority;
}
