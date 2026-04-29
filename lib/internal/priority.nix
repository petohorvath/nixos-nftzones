/*
  internal/priority — exposes the rule-priority symbol table under
  `nftzones.internal.priority`.

  Exported:
    - `rulePrioritySymbols` — symbol → int mapping for ordering
                              rules within a chain.

  Used by the compile pipeline to resolve `rulePriority` values
  (which are `either symbol int`) into pure integers before
  sorting cells. Chain priority resolution is a separate concern
  and is delegated to `nftypes.resolvePriority` (family-aware).

  ===== rulePrioritySymbols =====

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
in
{
  inherit rulePrioritySymbols;
}
