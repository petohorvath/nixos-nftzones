# Cross-zone validation runs in compile Phase 1

Checks that need the whole table (parent references and cycles, name
collisions, interface/CIDR overlap, object references, chain placement,
and so on) run as pure validators in Phase 1 of the compile pipeline.
They don't run as NixOS module `assertions`. Every validator appends to
one error list and the orchestrator throws once, so no validator
short-circuits the others. The idiomatic NixOS pattern is module
`assertions`, but the library must also validate when used without the
module (`mkTable` / `mkRuleset`), and pure validators are testable in
isolation.

## Consequences

Some validators append warnings rather than errors, for placements or
shapes that can be deliberate. Overlap checks skip ancestor/descendant
pairs, because that containment is intentional.

## Amended

[#22](https://github.com/petohorvath/nixos-nftzones/issues/22) keeps
the decision: pure validators, one aggregated error list, and a throw
instead of module assertions. It changes how the validators are reached
and tested:

- The validators are private. Phase 1 exports only `diagnose` and
  `normalizeTable`, which share one pipeline run.
- Errors and warnings are both Diagnostics, records of a tag, a path
  and a message. `diagnose` returns them as data, sorted by path, then
  tag. `normalizeTable` throws with every error, or emits each warning
  through `lib.warn`, rendered as `[tag] path: message`.
- Tests write a table body and compare the `{ tag; path; }` lists from
  `diagnose`; they don't call validators or assert on message text.
  "No validator short-circuits" is tested by one table whose mistakes
  produce errors from several validators.

The NixOS module still calls the throwing pipeline. Because `diagnose`
returns data, the module could later report diagnostics through
`assertions` and `warnings` without changing the validators.
