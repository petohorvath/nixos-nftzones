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

`checkRpfilterOverride` is the one exception: it appends a warning
rather than an error. Overlap checks skip ancestor/descendant pairs,
because that containment is intentional.
