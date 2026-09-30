# Zone-derived sets are referenceable from rule bodies

A rule body may reference a zone's generated sets (`@<zone>_iifs`,
`@<zone>_v4`, `@<zone>_v6`) directly. `checkObjectRefs` resolves names
against the union of `objects.sets` keys and the predictable
zone-derived names, even though those sets are only emitted in Phase 4.
This keeps an escape hatch for raw matches against zone membership.

## Considered options

- **Parallel namespace (chosen).** Cheap, with no schema change.
- **Pre-seed synthetic sets** into a virtual `objects.sets` view before
  validation. Cleaner separation, but more pipeline machinery.
- **Reject references to zone-derived names**, making `from` / `to` the
  only way to express membership. Same cost as the chosen option, but
  removes the escape hatch.

Pinned by `tests/integration/scenarios/zone-set-ref.nix`.
