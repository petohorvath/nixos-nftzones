# Compile Pipeline (Draft)

This document captures the design of the nftzones compile pipeline — the function chain that takes a `nftzones.types.table` value and produces an nftables ruleset suitable for `nft -f`.

## Motivation

The user-facing types under `nftzones.types` (zone, node, filter, snat, dnat, sroute, droute, policy, table) form an *input language* for declaratively describing a zone-based firewall. The compile pipeline is the function that *interprets* that language: lowering it to the libnftables-json shapes the kernel consumes.

Without the pipeline, the type system catches structural errors but nothing produces a runnable firewall. The compile pipeline closes that gap.

## Terminology

The pipeline (and the surrounding code) names the data-model levels consistently:

- **Group** — one of the rule-bearing collections on a table: `filters`, `policies`, `snats`, `dnats`, `sroutes`, `droutes`. Each group is `attrsOf <kind-submodule>`. *Not* used for `zones` and `nodes` — those are zone-level declarations and have their own terminology ("zone declaration", "node declaration").
- **Entry** — one item inside a group, keyed by name. `table.filters.allow-ssh` is an entry; the body field on it (`entry.rule`, the list of nftypes statements) is unambiguous because the wrapper is an *entry*, not a *rule*.
- **Direction** — `from` or `to`, the zone-name fields on an entry. Some groups are bidirectional (filters, policies, snats — both `from` and `to`); others are single-direction (`dnats`, `sroutes` have only `from`; `droutes` only `to`).

The trio shows up directly in `internal/normalize.nix`'s helpers:

```
expandWildcardZones          # table -> table
  └─ expandGroup             # one group's collection
       └─ expandEntry        # one entry, multiple directions
            └─ expandDirection  # one direction's zone list
```

## Public API

Two functions, both pure:

- `mkTable :: nftzones.types.table -> nftypes-table-value` — produces a composable single-table value (insertable into a larger user-defined ruleset).
- `mkRuleset :: nftzones.types.table -> nftypes-ruleset-value` — wraps `mkTable`'s output in the canonical `{ nftables = [ … ]; }` envelope ready for `nft -f -j`.

Both consume one table at a time. Multi-table consumers compose externally — e.g. `nftypes.dsl.ruleset { tables = [ (mkTable x) (mkTable y) ]; }`.

## Pipeline phases

Four phases, each a pure transformation:

```
table
  ↓ Phase 1: normalize       lower nodes, resolve wildcards, validate
normalizedTable
  ↓ Phase 2: expand          cartesian product per rule (zone-pair.genExpansions)
expandedTable
  ↓ Phase 3: dispatch+sort   chain bucketing, priority sort
chainBuckets
  ↓ Phase 4: emit            per-zone sets, base chains, sub-chains, rules
nftypesTable
  ↓ wrap                      (optional) ruleset envelope
nftypesRuleset
```

Each phase has clear input and output shapes. Testable phase-by-phase.

## Phase 1: normalize

Three sub-steps, in order: lower nodes → resolve wildcards → validate.

### 1.1 Node lowering

`internal.node.toZone` converts each node to a zone definition:

```
{ name = "web-server"; zone = "dmz";
  address = { ipv4 = "10.0.0.5"; ipv6 = null; }; }
↓
{ parent = "dmz"; interfaces = [ ]; cidrs = [ "10.0.0.5/32" ]; }
```

Lowered zones merge into `table.zones`; `table.nodes` is cleared. After this step the rest of the pipeline operates on a single zone namespace.

### 1.2 Wildcard resolution

`internal.wildcard.expandWildcard` substitutes the wildcard zone (default `"all"`) in every rule's `from` / `to` list with the full set of in-scope zones (declared zones plus `settings.localZone`):

```
wildcard = "all"
allZones = [ "lan" "wan" "dmz" "local" ]
[ "lan" "all" "guest" ]  →  [ "lan" "wan" "dmz" "local" "guest" ]
```

`allZones` is computed once per table after node lowering, so nodes-as-zones are included.

### 1.3 Validation

Cross-reference checks before expansion:

- **`internal.validate.checkNameCollisions`** — node names must not collide with zone names (lowering would silently overwrite).
- **`internal.validate.checkZoneRefs`** — every zone reference (in `from`, `to`, `node.zone`) must resolve to a known zone.

Each returns `[ String ]` of error messages. The orchestrator aggregates and throws if any error appears, surfacing all problems in one pass.

Validations deferred to later phases:

- **Policy uniqueness** — at most one policy per `(from-cell, to-cell)` pair after expansion. Needs Phase 2's output.
- **Named-object refs** — `counter name "X"`, `set @X`, `ct helper "X"` references in rule bodies must match `objects.<kind>` keys. Implementation will be a special-case extractor pattern-matching on the variants that can carry named refs (counter, limit, quota, ct helper, ct timeout, ct expectation, secmark, synproxy, tunnel, plus set/map lookups inside match expressions). See open question 3 for the design discussion.

## Phase 2: expand

`internal.zonePair.genExpansions` does the cartesian product of `from × to` per rule. The orchestrator maps over each rule group's collection:

```
filters.web-out = {
  from = [ "lan" "guest" ]; to = [ "wan" "vpn" ];
  rule = …; priority = "default"; …;
};
↓ genExpansions
[
  { from = "lan";   to = "wan"; rule = …; priority = "default"; … }
  { from = "lan";   to = "vpn"; rule = …; priority = "default"; … }
  { from = "guest"; to = "wan"; rule = …; priority = "default"; … }
  { from = "guest"; to = "vpn"; rule = …; priority = "default"; … }
]
```

Each cell preserves the original rule's body (`rule`, `priority`, `comment`, etc.) but with singular `from` / `to`. Output is a flat list per rule group: `{ filter, snat, dnat, sroute, droute, policy } = [ cells … ]`.

## Phase 3: dispatch + sort

### 3.1 Dispatch

Each cell goes to a chain based on its group:

| Group    | Chain dispatch                                                                          |
|----------|-----------------------------------------------------------------------------------------|
| `filter` | `internal.filter.groupExpansionsByChain` — input/forward/output via host-position rule. |
| `policy` | Same as filter — policies become tail rules in the same per-pair sub-chains.            |
| `snat`   | Always postrouting (`type nat hook postrouting priority srcnat`).                        |
| `dnat`   | Always prerouting (`type nat hook prerouting priority dstnat`).                          |
| `sroute` | Always prerouting (`type route hook prerouting priority mangle`).                        |
| `droute` | Always output (`type route hook output priority mangle`).                                |

The per-rule `chain` override submodule on filter / snat / dnat redirects a cell to a custom hook + priority chain (e.g., rpfilter at `prerouting + raw`).

Output is a 2D buckets attrset: `{ <chainKey> = [ <cells>... ]; ... }`.

### 3.2 Sort

`internal.priority.resolvePrioritySymbol` resolves rule priority symbols (`first` / `preDispatch` / `postDispatch` / `default` / `last`) to ints (Phase 1 runs this for every entry; the pre-resolved values land in `ctx.resolvedPriorities`). Each chain bucket sorts by `(priority asc, name asc)`. Name is the attrset key from the original collection; it acts as a stable tiebreaker.

The cutoff at `100` (between `preDispatch=50` and `postDispatch=100`) splits cells into pre-dispatch (emit before the per-pair dispatch jump) and post-dispatch (emit after) — see Phase 4.

## Phase 4: emit

Composes the chain buckets and the rest of the table state into one `nftypes.dsl.table` value.

### 4.1 Per-zone sets

For each zone, generate up to three sets:

- `<name>_iifs` — `type ifname` set of interface names.
- `<name>_v4` — `type ipv4_addr; flags interval` of v4 CIDRs.
- `<name>_v6` — `type ipv6_addr; flags interval` of v6 CIDRs.

Empty sets are skipped. The compiler uses `internal.zone.genMatch` (already exists) to compute the per-direction match expressions used by jumps.

### 4.2 Base chains

Per the table's `family` and `settings`:

- **Filter base chains** — `input`, `forward`, `output`. Each has `type filter hook <name> priority filter; policy <chainPolicy>;`.
- **NAT base chains** — `prerouting` (DNAT) at `dstnat`, `postrouting` (SNAT) at `srcnat`.
- **Route base chains** — `prerouting_route` at `mangle` (sroute), `output_route` at `mangle` (droute).
- **Optional `rpfilter` chain** — emitted only when `settings.rpfilter = true`. `type filter hook prerouting priority raw;` with one rule: `fib saddr . iif oif eq 0 drop`.

Boilerplate prepended to filter base chains per `settings`:

- `iif lo accept` in `input` if `settings.loopback` (default true).
- `ct state established,related accept; ct state invalid drop;` at the top of each filter chain if `settings.stateful` (default true).

### 4.3 Per-pair sub-chains

For each non-empty `(chain, from, to)` bucket, emit one chain. Inside it: sorted rules + tail rule from the matching policy (if any). Suggested naming convention:

- `fwd-<from>-to-<to>` for forward.
- `in-<from>` for input.
- `out-<to>` for output.
- NAT and route get analogous prefixes (`nat-pre-…`, `mangle-pre-…`, etc.).

### 4.4 Jumps

In each base chain, emit one jump per non-empty `(from, to)` bucket. Match condition is built from per-zone sets (`iifname @lan_iifs ip saddr @lan_v4 …`); verdict is `jump <sub-chain>`. Pre-dispatch user rules (priority `< 100`) emit *before* the jump block; post-dispatch user rules (priority `≥ 100`) emit *after*.

### 4.5 User objects

`table.objects.<kind>.<name>` values pass through to the table's nftypes object containers. The compile pipeline fills in the `family` / `name` / `table` fields stripped at the type layer (the `asUserBody` helper in `lib/types/table.nix`).

### 4.6 Assemble

`nftypes.dsl.table family name body` produces the marker-tagged table value. The body assembles:

- `chains` — base chains + per-pair sub-chains.
- `sets` — per-zone interface and CIDR sets.
- `counters`, `quotas`, `limits`, `ctHelpers`, … from `table.objects`.
- `comment` — from `table.comment`.

## File structure (proposed)

```
lib/
  default.nix                — exposes mkTable, mkRuleset alongside types/internal
  internal/
    # Phase 1 helpers (implemented)
    node.nix                 — toZone (node → zone lowering)
    wildcard.nix             — expandWildcard
    validate.nix             — checkNameCollisions, checkZoneRefs

    # Existing helpers used by Phases 2/3/4 (implemented)
    zone.nix                 — genMatch (per-zone match expressions)
    zone-pair.nix            — genExpansions (cartesian product)
    filter.nix               — groupExpansionsByChain (host-position dispatch)
    priority.nix             — resolvePrioritySymbol (symbol → int)

    # Phase 4 helpers (TBD)
    emit-sets.nix            — per-zone interface / CIDR sets
    emit-chains.nix          — base chain skeletons + boilerplate
    emit-rules.nix           — rule body emission per cell
    emit-table.nix           — table assembly
    emit-ruleset.nix         — ruleset envelope wrapper

    # Orchestrator (TBD)
    compile.nix              — wires the four phases together
  types/                     — (existing)
```

Each new internal module gets a unit-test file. Orchestrator and emit modules also get integration tests with realistic configs that diff against expected JSON fixtures.

## Open questions

1. **DSL helpers vs hand-rolled nftypes shapes.** Use `nftypes.dsl.*` builders (with marker validation) or construct nftypes-typed attrs directly? DSL is cleaner; hand-roll gives more control. Lean DSL.
2. **Chain naming convention.** Sketched above (`fwd-<from>-to-<to>`, `in-<from>`, etc.); bikeshed before implementation lands.
3. **Cross-reference walking.** Named-object reference validation requires walking statement trees (counter / limit / quota / ct-helper / ct-timeout / ct-expectation / secmark / synproxy / tunnel references inside `entry.rule` bodies, plus set / map lookups inside `match` expressions). Two paths:

   - **Special-case extractor** — pattern-match on the ~12 statement variants that can carry named-object refs, plus the expression-level set/map lookups inside matches. Smaller surface; brittle to nftypes adding variants.
   - **Generic walker** — recurse over any statement / expression tree, parameterized by a per-node visitor. Schema knowledge (which sub-fields of each variant are sub-statements / sub-expressions) lives naturally in nftypes alongside the schemas, so the walker would be upstreamed there (`nftypes.lib.walk.statements` / `walk.expressions` / `walk.rule`) rather than living in `internal/statements.nix`.

   `nftypes` currently doesn't expose a walker. Its `lib/dsl/structure/render.nix` walks the *table* tree (table → chains → rules) with stock `lib.concatMap` iteration but never recurses into statement bodies; `lib/dsl/internal/validate.nix` runs bodies through `lib.evalModules` for shape checking, which doesn't traverse content. What `nftypes` *does* hand us is the inputs both approaches need: `nftypes.lib.types.statements` enumerates the variant tags, the `attrTag` shape (single-key attrset where the key is the tag) makes dispatch a one-liner, and `<variant>Body` schemas tell us where references live in each body.

   **Decision:** implement the special-case extractor in nftzones first. One consumer, small surface, no speculative API design. If a second use case appears (Phase 4 emit doing structural transforms, a future linter, etc.), upstream the generalized walker to nftypes then — designing the walker API with a single consumer risks the wrong abstraction.
4. **Error aggregation strategy.** Phase 1 validators return error lists. Should Phase 4 emission also return errors, or is "we got here, so emission can't fail" reasonable? The latter assumes Phases 1-3 fully validate.
5. **Single-table vs multi-table compile.** `mkTable` takes one table; multi-table consumers compose externally. Reconsider only if a real consumer wants a single function call.

## Status

Phase 1 helpers (`node`, `wildcard`, `validate`) are implemented and unit-tested. The orchestrator and Phases 2-4 emission helpers are not yet written.

Next concrete milestones:

1. Orchestrator skeleton that calls Phase 1 helpers and produces a normalized intermediate value.
2. Phase 4 minimum-viable emit — empty base chains with settings boilerplate, no rules. Verifies the output shape via `nft -c -j`.
3. Rule emission for filter and policy.
4. NAT and route emission.
5. Named-object passthrough and reference validation.
