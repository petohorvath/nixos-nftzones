# Zone parent support — implementation plan

## Outcome

`zone.parent` becomes load-bearing on the **from**-side of zone-pair
dispatch. Each parent zone's sub-chain wraps its children's
sub-chains via dispatch jumps, with the parent's own rules acting
as pre-child or post-child slots around the dispatch point. The
to-side stays flat (deferred for a future iteration).

`node.zone` continues to set the lowered zone's `parent`, finally
making node-zone affiliation observable in the compiled output.

## Decisions

1. **Wildcard expansion (`from = [ "all" ]`).** Expand to root
   zones only (zones with `parent == null`) plus the localZone
   sentinel. Descendants inherit via dispatch fallback.
   Breaking change accepted — pre-1.0 release, no consumers yet.
2. **Default-priority placement.** Two-slot model. Cells with
   `priority < 100` land in the parent sub-chain's
   pre-child-dispatch slot; cells with `priority >= 100` (including
   the default 500) land in post-child-dispatch. Default priority
   becomes the natural fallback after children. Keeps the existing
   priority symbol set; reuses the cutoff at 100.
3. **Migration.** Hard switch — single commit, behavioural change
   noted in the commit body and the spec. No opt-in flag.
4. **localZone in hierarchy.** Forbidden as a parent (sentinel,
   not a real zone) and as a child (parent of localZone is
   meaningless). Validated.
5. **Policy ordering inside hierarchical sub-chains.** Tail of the
   sub-chain, exactly as today. Layered fallback semantics emerge
   for free (specific child policy wins; parent policy fires only
   if child sub-chain returned without verdict).

## Behavioural shift

| Today                                                          | After                                                                                  |
|----------------------------------------------------------------|----------------------------------------------------------------------------------------|
| All `(from, to)` sub-chains jump from the base chain           | Only **root** from-zones jump from the base chain                                      |
| Sub-chain dispatch order: alphabetical                         | Sub-chain dispatch order: hierarchical (root → child recursion)                        |
| Priority cutoff at 100 = base-chain pre/post slots             | Priority cutoff at 100 = per-sub-chain pre/post slots around child-dispatch jumps      |
| `from = [ "all" ]` expands to every zone                       | `from = [ "all" ]` expands to roots + localZone                                        |
| `node.zone` validated but inert                                | `node.zone` establishes hierarchy in the compiled output                               |
| Base chain has explicit pre/post slots from `priority < 100` / `>= 100` (special) | Base chain has only boilerplate + jumps to root sub-chains                             |

Existing rulesets that don't declare `parent` and don't use
`nodes.*` continue to compile unchanged — every zone has
`parent == null`, so every zone is a root, and root-only base-chain
jumps are the same as today's flat dispatch.

## Phases

### Phase 1 — Normalize (`lib/internal/normalize.nix`)

- New validator `checkParentRefs`: each zone's `parent` (if
  non-null) must resolve to a known merged zone. Forbid
  `parent == localZone` explicitly.
- New validator `checkParentCycles`: walks each zone's parent
  chain, errors on revisit with the cycle path (rotated dups
  acceptable for v1; document as a known caveat).
- New sub-phase `computeChildrenOf`: writes
  `ctx.childrenOf = { <parentName> = [ <child1> <child2> ... ]; }`
  (alphabetically sorted).
- New sub-phase `computeRootZoneNames`: writes
  `ctx.rootZoneNames = [ <root1> ... <rootN>, <localZone> ]`.
- Modify `expandWildcardZones`: from-side wildcard expands to
  `rootZoneNames`; to-side wildcard keeps `allZoneNames`.
- Phase ordering: parent validators run after `convertNodesToZones`
  (mergedZones available) but before `expandWildcardZones` (which
  now needs `rootZoneNames`).

### Phase 2 — Expand (`lib/internal/expand.nix`)

No structural change. Cells still cartesian-product `from × to`.

### Phase 3 — Dispatch (`lib/internal/dispatch.nix`)

- Drop `slotFor` 3-way classification. All cells go to sub-chains.
  The base chain bucket no longer carries top-level `preDispatch`
  / `postDispatch` slots.
- Each sub-chain entry gains `preChildCells` and `postChildCells`
  fields, replacing the prior `cells` field. Partition rule:
  cells with `priority < 100` → `preChildCells`; cells with
  `priority >= 100` (and policies, no priority) → `postChildCells`.
  Each list pre-sorted by `(priority asc, name asc)`; policies
  appended last to `postChildCells`.

### Phase 4 — Emit (`lib/internal/emit.nix`)

- `mkBaseChain.rules`: drop the prior `preDispatch` / `postDispatch`
  cell-rendering lines. Output is now stateful + loopback +
  rpfilter preludes + jumpRules only.
- `mkBaseChains` jumpRules emit jumps only for **root** from-zones
  whose subtree has content for the relevant to-zone (uses new
  `subtreeHasContent` helper that recurses through `childrenOf`).
- `mkSubChain` becomes hierarchy-aware: emits `preChildCells` →
  child-dispatch jumps → `postChildCells`. Each child-dispatch
  jump is one rule per variant of the child's from-side match
  (interfaces / cidrs / matchOverride), targeting
  `__<child>-to-<to>`.
- New `mkChildDispatchJumps` helper, factored out from the
  base-chain `mkJumpRules` with the from-side match builder reused.
- Recursive empty-chain pruning: a sub-chain with neither cells
  of its own nor a descendant with content is omitted entirely
  (and its parent emits no dispatch jump to it).
- Intermediate parents with no own cells but with content-bearing
  descendants emit as transparent dispatchers (just child-dispatch
  jumps in the body).

### Phase 5 — Tests

Unit:
- `tests/unit/internal/normalize.nix`: validators (parent refs,
  parent cycles, localZone-as-parent), `computeChildrenOf`,
  `computeRootZoneNames`, modified `expandWildcardZones`.
- `tests/unit/internal/dispatch.nix`: pre/post-child cell split.
- `tests/unit/internal/emit.nix`: child-dispatch jump emission,
  root-only base-chain jumps.

Integration:
- `parent-basic.nix` — lan with web-server node; verify hierarchy.
- `parent-priorities.nix` — pre vs post relative to child dispatch.
- `parent-deep-nesting.nix` — three or more levels.
- `parent-empty-intermediate.nix` — intermediate parent has no
  rules; child has content; transparent dispatcher emitted.

Cycle detection: unit test only (the throw fires before
`nft --check` ever sees the ruleset).

### Phase 6 — Docs

- `lib/types/zone.nix`: rewrite the `parent` docstring; document
  the load-bearing semantics, the localZone restriction, and that
  `to`-side hierarchy is not yet supported.
- `lib/internal/{node,normalize,dispatch,emit}.nix`: update
  docstrings touched by the implementation.
- `docs/compile-pipeline-draft.md`: §1 (lowering + parent
  validators), §3 (dispatch hierarchy), §4 (emit hierarchy).
- `docs/validation-zones-draft.md`: mark `checkParents` /
  `checkCycles` as landed; remove the "deferred" text.
- `docs/specs/zone-parent.md` (new): full spec, including the
  comparison to thelegy/petohorvath approaches and rationale for
  the chosen model.
- `README.md`: brief mention of parent support and node-zone
  affiliation now being load-bearing.

## Files touched

```
docs/plans/zone-parent-support.md          NEW (this file)
docs/specs/zone-parent.md                  NEW (full spec)
docs/compile-pipeline-draft.md             EDIT
docs/validation-zones-draft.md             EDIT
README.md                                  EDIT (brief)

lib/types/zone.nix                         EDIT (parent docstring)
lib/internal/normalize.nix                 EDIT (+validators, +childrenOf, +rootZoneNames, modified wildcard)
lib/internal/dispatch.nix                  EDIT (drop base-slot 3-way, new sub-chain shape)
lib/internal/emit.nix                      EDIT (root-only jumps, hierarchical sub-chains)

tests/unit/internal/normalize.nix          EDIT (+parent tests)
tests/unit/internal/dispatch.nix           EDIT (sub-chain shape tests)
tests/unit/internal/emit.nix               EDIT (root-only / child-dispatch tests)

tests/integration/scenarios/parent-basic.nix              NEW
tests/integration/scenarios/parent-priorities.nix         NEW
tests/integration/scenarios/parent-deep-nesting.nix       NEW
tests/integration/scenarios/parent-empty-intermediate.nix NEW
```

## Out of scope

- `to`-side hierarchy (matrix expansion).
- thelegy-style match-clause composition into descendant rules.
- Multi-table parent references.
- Parent inheritance across rule groups (e.g., a node inheriting
  its parent zone's NAT rule). Each rule group still keys by its
  own `(from, to)`.
