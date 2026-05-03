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
- **Cell** — a concrete `(from, to)` instance of an entry produced by Phase 2's cartesian product. Same shape as the entry but with the listed directions as scalars instead of lists. An entry with `from = [ "lan" "guest" ]; to = [ "wan" "vpn" ]` produces four cells. For single-direction groups, a cell has only the relevant scalar (e.g., a `dnat` cell has `from = "wan"` and no `to`).
- **Slot** — one of three positions a cell occupies within its chain bucket, decided by the cell's resolved priority: `preDispatch` (emit in the base chain *before* the per-pair dispatch jumps), `subChains` (emit inside a per-`(from, to)` sub-chain — the default), or `postDispatch` (emit in the base chain *after* the dispatch jumps). Phase 3 buckets cells by `(chain, slot)`; Phase 4 emits each slot in order.
- **Bucket** — Phase 3 container holding all cells destined for one `(hook, priority)` placement, organized by slot. `ctx.chainBuckets.<baseChainName> = { hook; priority; preDispatch; subChains; postDispatch; }`. Phase 4 emits one base chain per bucket.
- **Variant** — one match-clause list within a `match.<ingress|egress>` direction (or in a Phase 4 jump rule). Multiple variants → multiple emitted rules. `internal.zone.genMatch` documents the 8-case variant table for zones; `mkDirectionVariants` mirrors it for jump-match construction.

### nftables vocabulary

These are nftables's own concepts; we adopt the same terms verbatim:

- **Hook** — netfilter attachment point. One of `prerouting` / `input` / `forward` / `output` / `postrouting` / `ingress` / `egress`. Field name in code: `hook`.
- **Chain priority** — orders chains attached to the same hook. Symbol (`raw` / `mangle` / `dstnat` / `filter` / `security` / `srcnat`) or int. NOT to be confused with **entry priority**. Field name: `chainAttrs.priority`.
- **Entry priority** — orders entries within their slot in a sub-chain (or pre/postDispatch in a base chain). Symbol (`first` / `preDispatch` / `postDispatch` / `default` / `last`) or int. Resolved by `internal.priority.resolvePriority`. Type: `primitives.entryPriority`.
- **Chain type** — `filter` / `nat` / `route`. Phase 4 derives this from `(hook, priority)` via `chainTypeOf`.
- **Base chain** — chain attached to a hook (carries `type` / `hook` / `priority` / `policy`).
- **Sub-chain** — regular chain (only reachable via `jump`). One per `(from, to)` pair in our model.

### Naming convention for chain identifiers

The same string travels from Phase 3 (as an attrset key) through to Phase 4 (as the actual nftables chain name):

- **`baseChainName`** = `"<hook>-at-<priority>"` (e.g. `"forward-at-filter"`). Computed by `internal.dispatch.baseChainNameOf`. Used as the bucket key in `chainBuckets` *and* as the base chain's name in the emitted nftables output.
- **`subChainKey`** — local key within `bucket.subChains` (e.g. `"lan-to-wan"` / `"wan"` / `"lan"`). Computed by `internal.dispatch.subChainKeyOf` from a cell's `from` / `to`.
- **`subChainName`** — full sub-chain name in the nftables output, `"<baseChainName>__<subChainKey>"` (e.g. `"forward-at-filter__lan-to-wan"`). Computed by `internal.emit.subChainNameOf`.

### Two framings of `(hook, priority)`

The pair shows up under two names depending on context:

- **Chain placement** — user-facing term, used in type docstrings (`filterChain`, `snatChain`, `dnatChain` overrides). Describes what the override *does*: pins the entry to a specific base chain.
- **Chain attrs** — implementation term, used in `internal.dispatch` / `internal.emit`. Describes the attrset shape `{ hook; priority; }` carried alongside cells.

Same concept, different framings.

The Group / Entry / Direction trio shows up directly in `internal/normalize.nix`'s helpers:

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
  ↓ Phase 2: expand          cartesian product per entry (entry.toCells)
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

Phase 1 substitutes the wildcard zone (default `"all"`) in every rule's `from` / `to` list with the full set of in-scope zones (declared zones plus `settings.localZone`). The substitution + dedup is inlined inside `internal.normalize.expandWildcardZones` since it has no other consumer:

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

- **Named-object refs** — `counter name "X"`, `set @X`, `ct helper "X"` references in rule bodies must match `objects.<kind>` keys. Implementation will be a special-case extractor pattern-matching on the variants that can carry named refs (counter, limit, quota, ct helper, ct timeout, ct expectation, secmark, synproxy, tunnel, plus set/map lookups inside match expressions). See open question 3 for the design discussion.

## Phase 2: expand

`internal.entry.toCells` does the cartesian product across an entry's directions. Directions present on the entry (`from` and / or `to`) are auto-detected, so the same call works for bidirectional and single-direction groups uniformly. The orchestrator maps over each rule group's collection:

```
filters.web-out = {
  from = [ "lan" "guest" ]; to = [ "wan" "vpn" ];
  rule = …; priority = "default"; …;
};
↓ toCells
[
  { from = "lan";   to = "wan"; rule = …; priority = "default"; … }
  { from = "lan";   to = "vpn"; rule = …; priority = "default"; … }
  { from = "guest"; to = "wan"; rule = …; priority = "default"; … }
  { from = "guest"; to = "vpn"; rule = …; priority = "default"; … }
]
```

Each cell preserves the original entry's body (`rule`, `priority`, `comment`, etc.) but with singular direction values. Single-direction entries (`dnats` / `sroutes` carry only `from`; `droutes` only `to`) produce one cell per scalar value of the direction they have. Output is a flat list per rule group: `{ filter, snat, dnat, sroute, droute, policy } = [ cells … ]`.

## Phase 3: dispatch + sort

### 3.1 Dispatch

Each cell goes to a chain based on its group:

| Group | Chain dispatch |
|---|---|
| `filters` | `internal.dispatch.filterChainHook` — input / forward / output via host-position rule. |
| `policies` | Same as `filters` — policies become tail rules in the same per-pair sub-chains. |
| `snats` | Always postrouting (`type nat hook postrouting priority srcnat`). |
| `dnats` | Always prerouting (`type nat hook prerouting priority dstnat`). |
| `sroutes` | Always prerouting (`type route hook prerouting priority mangle`). |
| `droutes` | Always output (`type route hook output priority mangle`). |

The per-entry `chain` override submodule on `filters` / `snats` / `dnats` redirects a cell to a custom hook + priority chain (e.g., rpfilter at `prerouting + raw`).

Output is a 2D buckets attrset: `{ <baseChainName> = [ <cells>... ]; ... }`.

### 3.2 Sort

`internal.priority.resolvePriority` resolves entry priority symbols (`first` / `preDispatch` / `postDispatch` / `default` / `last`) to ints (Phase 1 runs this for every entry; the pre-resolved values land in `ctx.resolvedPriorities`). Each chain bucket sorts by `(priority asc, name asc)`. Name is the attrset key from the original collection; it acts as a stable tiebreaker.

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

One base chain per `(hook, priority)` bucket from `ctx.chainBuckets` (Phase 3). Default placements:

- **Filter base chains** — `input`, `forward`, `output` at `priority filter`. Header: `type filter hook <name> priority filter; policy <chainPolicy>;`.
- **NAT base chains** — `prerouting` (DNAT) at `dstnat`, `postrouting` (SNAT) at `srcnat`.
- **Route base chains** — `prerouting` at `mangle` (sroute), `output` at `mangle` (droute).
- **Optional `rpfilter` chain** — emitted only when `settings.rpfilter = true`. `type filter hook prerouting priority raw;` with one rule: `fib saddr . iif oif eq 0 drop`.

**Chain type derivation.** `chainAttrs` carries `(hook, priority)` only; `type` is derived locally in `emit.nix`. nftypes does *not* expose this mapping (only `nftypes.enums.chainType = [ "filter" "nat" "route" ]` and `nftypes.compatibility.familiesByChainType` for validation). Rule:

```nix
chainTypeOf = chainAttrs:
  let p = if builtins.isInt chainAttrs.priority
          then chainAttrs.priority
          else priorityIntsDefault.${chainAttrs.priority};
  in
    if p == priorityIntsDefault.srcnat || p == priorityIntsDefault.dstnat then "nat"
    else if p == priorityIntsDefault.mangle
         && (chainAttrs.hook == "prerouting" || chainAttrs.hook == "output") then "route"
    else "filter";
```

Covers all default placements (snat → `nat`, dnat → `nat`, sroute / droute → `route`, filter / policy → `filter`, rpfilter override → `filter`) and any user override that doesn't deliberately land on `srcnat` / `dstnat` / special-`mangle`. If users ever need to pick chain type explicitly, add an optional `type` field to the chain-override schema later.

**Rule order in a base chain:**

1. (filter only) stateful boilerplate (`ct state established,related accept; ct state invalid drop`) if `settings.stateful` (default true).
2. (filter input only) loopback boilerplate (`iif lo accept`) if `settings.loopback` (default true).
3. `preDispatch` cells from this bucket, sorted.
4. **Jump block** — one jump per sub-chain (see §4.4).
5. `postDispatch` cells from this bucket, sorted.

Chain `policy <chainPolicy>` is declared on the chain header (filter chains only), not as a rule.

### 4.3 Per-pair sub-chains

For each non-empty `(chain, from, to)` bucket, emit one chain. Inside it: sorted cells (filter / snat / dnat / sroute / droute rules) plus the tail rule from the matching policy if any.

**Naming convention:** `<baseChainName>__<subChainKey>` (double-underscore separator), reusing Phase 3's `chainBuckets` keys verbatim. The `baseChainName` is the bucket key from Phase 3 (`"<hook>-at-<priority>"`); the `subChainKey` is the local key within `bucket.subChains` (`"<from>-to-<to>"`, `"<from>"`, or `"<to>"`):

| Group / scenario | Sub-chain name |
|---|---|
| Filter `lan → wan` (forward) | `forward-at-filter__lan-to-wan` |
| Filter `wan → local` (input) | `input-at-filter__wan-to-local` |
| Filter `local → wan` (output) | `output-at-filter__local-to-wan` |
| Snat `lan → wan` | `postrouting-at-srcnat__lan-to-wan` |
| Dnat `wan` (single-direction `from`) | `prerouting-at-dstnat__wan` |
| Droute `vpn` (single-direction `to`) | `output-at-mangle__vpn` |
| rpfilter override `(prerouting, raw)`, `wan → local` | `prerouting-at-raw__wan-to-local` |

Verbose but unambiguous: each name is a literal concat of `chainBuckets` keys, so the name → `(hook, priority, from, to)` mapping is mechanical and auditable in the generated JSON.

**Body:** sorted cells (per `(priority asc, name asc)` from Phase 3) followed by the policy tail rule (if any).

**Rule body emission per group:**

- **filter / sroute / droute** — `cell.rule` is `list-of-statements`; splice as one rule.
- **snat** — `cell.rule.snat = { addr; port?; ... }` or `cell.rule.masquerade = { ... }` → single statement.
- **dnat** — `cell.rule.match = [...]; cell.rule.action.{dnat|redirect} = { ... }` → match conditions ++ action statement.
- **policy** — `cell.verdict = "accept" | "drop" | ...` → single verdict statement (always the tail rule).

### 4.4 Jumps

In each base chain, emit one or more jumps per non-empty sub-chain in that bucket's `subChains`. Match conditions select packets belonging to the `(from, to)` pair using per-zone sets from §4.1; verdict is `jump <sub-chain-name>`.

**Per-direction variants — *not* a single ANDed clause list.** In `inet` family, `ip <addr>` and `ip6 <addr>` clauses cannot be ANDed in the same rule: a v4 packet hitting `ip6 saddr ...` skips the rule entirely (and vice versa). So each direction emits **one variant per address family** that has a non-empty set, plus the optional interface prefix when the hook allows it.

The variant table mirrors `internal.zone.genMatch` (8 cases), with named-set references in place of inline lists:

| Zone has        | Variants emitted (per direction) |
|---|---|
| empty           | `[ ]` *(Phase 1 `checkZoneMatchable` should prevent reaching this)* |
| iface only      | `[[ <ifField> @<zone>_iifs ]]` |
| v4 only         | `[[ <ipFamily> <addrField> @<zone>_v4 ]]` |
| v6 only         | `[[ ip6 <addrField> @<zone>_v6 ]]` |
| v4 + v6         | 2 variants — one v4, one v6 |
| iface + v4      | 1 variant — iface prefix + v4 |
| iface + v6      | 1 variant — iface prefix + v6 |
| iface + v4 + v6 | 2 variants — each with iface prefix |

Where `<ifField>` is `iifname` (from-direction) or `oifname` (to-direction), and `<addrField>` is `saddr` / `daddr` likewise.

**Cartesian product across directions.** For each sub-chain, take the cartesian product of `from`-variants and `to`-variants. Each pair becomes one jump rule:

```nix
fromVariant ++ toVariant ++ [ (jump (subChainNameOf baseChainName subChainKey)) ]
```

**Family-mismatch waste (deferred optimization).** When both directions are `(v4 + v6)` zones, the cartesian product produces `(v4-from, v6-to)` and `(v6-from, v4-to)` jumps in addition to the matched-family pairs. These are harmless (skip on family mismatch) but bloat the chain. Optimization deferred — variants would need a family tag for the consumer to filter mismatched pairs. Revisit if chain sizes ever matter.

**Hook-direction semantics** — interface fields are not always available; use `nftypes.compatibility.hooksWithOifname` (`[ "forward" "output" "postrouting" ]`) to gate the `oifname` clause. `iifname` is valid at every hook except `output`. The interface prefix is suppressed when the hook makes the field unavailable; address clauses are always allowed.

| Hook | `iifname` valid? | `oifname` valid? |
|---|---|---|
| `prerouting` | ✓ | ✗ |
| `input` | ✓ | ✗ |
| `forward` | ✓ | ✓ |
| `output` | ✗ | ✓ |
| `postrouting` | ✓ | ✓ |

When the hook makes the only available field unavailable AND the zone has no addr sets, the direction produces 0 variants. This case shouldn't reach Phase 4 because `checkChainOverridePlacement` (Phase 1) flags it; if it does (defense), the empty cartesian product drops the entire jump for that sub-chain — sub-chain becomes unreachable rather than over-permissive.

**localZone references.** Phase 4 emits no match clauses for the `localZone` direction (it's a sentinel — never has a `mergedZones` entry, never has zone sets). The chain dispatch already used `localZone` for chain selection; once dispatched, the sentinel direction adds no further constraint. Single-direction sub-chains (dnat / sroute have no `to`; droute has no `from`) get the same wildcard treatment for the missing direction.

Helper signatures:

```nix
mkDirectionVariants = { hook, direction, zoneName, zoneSets, localZone }:
  <list-of-variants>;  # each variant is a list of statements

mkJumpRules = { hook, baseChainName, subChains, zoneSets, localZone }:
  <list-of-rules>;  # each rule = direction variants ++ [ jump-stmt ]
```

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
    normalize.nix            — phase orchestrator + all Phase 1 phases
                               (convertNodesToZones, collectAllZoneNames,
                               expandWildcardZones, resolvePriorities,
                               collectZoneRefs, checkNameCollisions,
                               checkSettings, checkZoneRefs)

    # Phase 2 helpers (implemented)
    expand.nix               — expandTable (entry → cells per group)

    # Phase 3 helpers (implemented)
    dispatch.nix             — phase orchestrator (dispatchAndSort)
                               + groupCellsByChain, buildChainBuckets
                               (cells → chainBuckets keyed by
                               `<hook>-at-<priority>`, slotted into
                               preDispatch / subChains / postDispatch)

    # Existing helpers used by Phases 2/4 (implemented)
    zone.nix                 — genMatch (per-zone match expressions)
    entry.nix                — toCells (entry → list of cells)
    priority.nix             — resolvePriority (symbol → int),
                               entryPriorities (canonical symbol → int
                               table consumed by Phase 3)

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

All four phases are implemented, unit-tested, and wired through the public API (`nftzones.mkTable name body` / `nftzones.mkRuleset name body`).

The pipeline end-to-end:

```nix
final = lib.pipe table [
  # Phase 1 — normalize
  convertNodesToZones collectAllZoneNames expandWildcardZones
  resolvePriorities  collectZoneRefs
  checkNameCollisions checkSettings checkZoneRefs
  checkZoneMatchable checkChainOverridePlacement checkPolicyUniqueness
  # Phase 2 — expand
  expandTable
  # Phase 3 — dispatch + sort
  dispatchAndSort  # = groupCellsByChain |> buildChainBuckets
  # Phase 4 — emit
  emitTable        # = emitZoneSets |> emitBaseChains |> emitSubChains
                   #   |> emitUserObjects |> assembleOutput
];
# final.ctx.output = nftypes.dsl.table value, exposed as
#   nftzones.mkTable name body  →  table value
#   nftzones.mkRuleset name body →  { nftables = [ ... ] }
```

Pending follow-ups:

1. `checkSetNameCollisions` Phase 1 validator — catches user `objects.sets.<name>` colliding with auto-generated zone-set names (`<zone>_iifs` / `<zone>_v4` / `<zone>_v6`); see TODO in `internal.emit.assembleOutput`.
2. Named-object reference validation (open question 3) — Phase 1 validator.
3. Drop `internal.zone.genMatch` from the pipeline — only `checkZoneMatchable` in Phase 1 reads `zone.match` (Phase 4 emit reads raw `interfaces` / `cidrs` directly). Rewrite the validator to inspect raw fields + `matchOverride` (mirroring `checkChainOverridePlacement`); see TODO above `checkZoneMatchable` in `internal.normalize`. The `match` field stays on the public `zone` / `node` types for external consumers.
