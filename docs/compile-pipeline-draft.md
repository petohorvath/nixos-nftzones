# Compile Pipeline (Draft)

This document captures the design of the nftzones compile pipeline — the function chain that takes a `nftzones.types.table` value and produces an nftables ruleset suitable for `nft -f`.

## Motivation

The user-facing types under `nftzones.types` (zone, node, filter, snat, dnat, sroute, droute, policy, table) form an *input language* for declaratively describing a zone-based firewall. The compile pipeline is the function that *interprets* that language: lowering it to the libnftables-json shapes the kernel consumes.

Without the pipeline, the type system catches structural errors but nothing produces a runnable firewall. The compile pipeline closes that gap.

## Terminology

The pipeline (and the surrounding code) names the data-model levels consistently:

- **Group** — one of the rule-bearing collections on a table: `filters`, `policies`, `snats`, `dnats`, `sroutes`, `droutes`. Each group is `attrsOf <kind-submodule>`. *Not* used for `zones` and `nodes` — those are zone-level declarations and have their own terminology ("zone declaration", "node declaration").
- **Entry** — one item inside a group, keyed by name. `table.filters.allow-ssh` is an entry; the body field on it (`entry.rule`, the list of nftypes statements) is unambiguous because the wrapper is an *entry*, not a *rule*.
- **Direction** — `from` or `to`, the zone-name fields on an entry. Some groups are bidirectional (filters, policies, snats — both `from` and `to`); others are single-direction (`dnats`, `sroutes` have only `from`; `droutes` only `to`). Direction is the *entry's* perspective on the source/destination axis.
- **Side** — `ingress` or `egress`, the per-axis match fields on a zone (`zone.matchOverride.<side>`). Side is the *zone's* perspective on the same axis: a packet entering the firewall matches a zone's `ingress` side; a packet leaving matches its `egress` side. Mapped from direction via `internal.normalize.directionToSide`: `from → ingress`, `to → egress`. Two terms exist because each reads naturally only in its native frame ("entry's from-direction" / "zone's ingress side"); collapsing produces awkward constructs like "the to side" or "the egress direction".
- **Cell** — a concrete `(from, to)` instance of an entry produced by Phase 2's cartesian product. Same shape as the entry but with the listed directions as scalars instead of lists. An entry with `from = [ "lan" "guest" ]; to = [ "wan" "vpn" ]` produces four cells. For single-direction groups, a cell has only the relevant scalar (e.g., a `dnat` cell has `from = "wan"` and no `to`).
- **Slot** — one of three positions a cell occupies within its chain bucket, decided by the cell's resolved priority: `preDispatch` (emit in the base chain *before* the per-pair dispatch jumps), `subChains` (emit inside a per-`(from, to)` sub-chain — the default), or `postDispatch` (emit in the base chain *after* the dispatch jumps). Phase 3 buckets cells by `(chain, slot)`; Phase 4 emits each slot in order.
- **Bucket** — Phase 3 container holding all cells destined for one `(hook, priority)` placement, organized by slot. `ctx.chainBuckets.<baseChainName> = { hook; priority; preDispatch; subChains; postDispatch; }`. Phase 4 emits one base chain per bucket.
- **Variant** — one match-clause list within a `matchOverride.<side>` (or in a Phase 4 jump rule). Multiple variants → multiple emitted rules. `internal.emit.mkDirectionVariants` documents the 8-case variant table for jump-match construction.

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

- **`baseChainName`** = `"<hook>-at-<priority>"` (e.g. `"forward-at-filter"`). Computed internally by `internal.dispatch`. Used as the bucket key in `chainBuckets` *and* as the base chain's name in the emitted nftables output.
- **`subChainKey`** — local key within `bucket.subChains` (e.g. `"lan-to-wan"` / `"wan"` / `"lan"`). Computed internally by `internal.dispatch` from a cell's `from` / `to`.
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

- `mkTable :: String -> body -> nftypes-table-value` — produces a composable single-table value (insertable into a larger user-defined ruleset). The `String` arg is the nftables table name; `body` is a raw `nftzones.types.table` body (evaluated internally via `evalModules`).
- `mkRuleset :: String -> body -> nftypes-ruleset-value` — wraps `mkTable`'s output in the canonical `{ nftables = [ … ]; }` envelope ready for `nft -f -j`.

Both consume one table at a time. Multi-table consumers compose externally — e.g. `nftypes.dsl.ruleset [ (mkTable "fw-a" body-a) (mkTable "fw-b" body-b) ]`.

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

Phase 1 substitutes the wildcard zone (default `"all"`) in every entry's `from` / `to` list with the full set of in-scope zones (declared zones plus `settings.localZone`). The substitution + dedup is inlined inside `internal.normalize.expandWildcardZones` since it has no other consumer:

```
wildcard = "all"
allZones = [ "lan" "wan" "dmz" "local" ]
[ "lan" "all" "guest" ]  →  [ "lan" "wan" "dmz" "local" "guest" ]
```

`allZones` is computed once per table after node lowering, so nodes-as-zones are included.

### 1.3 Validation

Eight validators run after the compute phases, all in `internal/normalize.nix`. Each appends `lib.nameValuePair "<errorTag>" <message>` records to `ctx.errors`; the orchestrator aggregates them and throws a single message listing every error, so users see all problems in one pass.

- **`checkNameCollisions`** — node names must not collide with zone names (lowering would silently overwrite).
- **`checkSettings`** — `settings.localZone` and `settings.wildcardZone` must differ from each other and from any declared zone / node name.
- **`checkZoneRefs`** — every zone reference (in `from`, `to`, `node.zone`) must resolve to a known zone or `settings.localZone`.
- **`checkZoneMatchable`** — every direction-bound zone ref (`from` → ingress, `to` → egress) must point at a zone whose computed `match` is non-empty on the relevant side.
- **`checkChainOverridePlacement`** — entries with a `chain` override must land at a hook where their `from` / `to` zones are actually matchable (interface fields aren't valid at every hook).
- **`checkPolicyUniqueness`** — at most one policy applies per `(from, to)` cell after wildcard expansion.
- **`checkSetNameCollisions`** — user `objects.sets.<name>` must not collide with auto-generated zone-derived set names (`<zone>_iifs|v4|v6`).
- **`checkObjectRefs`** — every named-object reference in entry rule bodies, zone matchOverride content, and object bodies must resolve to a key in `table.objects.<kind>` (or — for `kind == "sets"` — a zone-derived set name). The walker lives in `internal/refs.nix`.

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
| `filters` | Computed internally by `internal.dispatch` — input / forward / output based on whether `from` / `to` reference `settings.localZone`. |
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

Empty sets are skipped. Per-direction match expressions used by jumps are constructed by `internal.emit.mkDirectionVariants` from these set names.

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
- **policy** — `cell.verdict = "accept" | "drop"` → single verdict statement (always the tail rule).

### 4.4 Jumps

In each base chain, emit one or more jumps per non-empty sub-chain in that bucket's `subChains`. Match conditions select packets belonging to the `(from, to)` pair using per-zone sets from §4.1 — or via `zone.matchOverride.<side>` slot content where the user supplied an override — and the verdict is `jump <sub-chain-name>`.

**Per-direction variants — *not* a single ANDed clause list.** In `inet` family, `ip <addr>` and `ip6 <addr>` clauses cannot be ANDed in the same rule: a v4 packet hitting `ip6 saddr ...` skips the rule entirely (and vice versa). So each direction emits **one variant per address family** that has a non-empty contribution, plus the optional interface prefix when the hook allows it, plus any `extra` section content the user supplied.

**Section resolution.** `mkDirectionVariants` resolves four sections per direction, in this order: override wins if contributing, else fall back to the auto path.

| Section      | Auto path                              | Override path                  |
|--------------|----------------------------------------|--------------------------------|
| `interfaces` | `inSet <ifField> @<zone>_iifs`         | `override.<side>.interfaces`   |
| `ipv4`       | `inSet <addrField> @<zone>_v4`         | `override.<side>.ipv4`         |
| `ipv6`       | `inSet ip6.<addr> @<zone>_v6`          | `override.<side>.ipv6`         |
| `extra`      | (none — no auto path)                  | `override.<side>.extra`        |

A section "contributes" when it's non-null AND non-empty. Empty list (`[ ]`) and `null` are equivalent — both mean "no constraint here" and let the auto path take over.

The `interfaces` section is **hook-gated**: dropped when the relevant `iifname` / `oifname` field isn't valid at the hook (defense; `checkChainOverridePlacement` should have caught it). The other sections are hook-agnostic.

> Note — *section* here is unrelated to the *bucket slot* concept defined in the Terminology section above. Bucket slots (`preDispatch` / `subChains` / `postDispatch`) are Phase 3 cell placements within a chain bucket; override sections are per-direction match-clause containers within `matchOverride`. Different concepts, same generic vocabulary; they never appear together in code.

**Variant construction.**

```
prefix   = ifsAtHook ++ extraSection
variants = optional (v4Section ≠ [ ]) (prefix ++ v4Section)
        ++ optional (v6Section ≠ [ ]) (prefix ++ v6Section)
result   = if variants ≠ [ ] then variants
           else if prefix ≠ [ ] then [ prefix ]
           else [ ]
```

The 8-case auto-path table (section-resolution simplified to "no override anywhere"):

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

Where `<ifField>` is `iifname` (from-direction) or `oifname` (to-direction), and `<addrField>` is `saddr` / `daddr` likewise. With overrides in play, every cell can be replaced by user content; `extra` adds an extra family-agnostic prefix to every variant (e.g. `meta mark @<zone>_marks` for fwmark-defined zone membership).

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

## File structure

```
lib/
  default.nix                — public surface: mkTable, mkRuleset,
                               version + re-exports of `types` and
                               `internal`.
  internal/
    # Layer 0 — leaves (no inter-module deps)
    zone.nix                 — genSets (per-zone nftables sets,
                               consumed by both Phase 1 validators and
                               Phase 4 emit).
    entry.nix                — toCells (one entry → list of cells per
                               cartesian product of from / to).
    priority.nix             — resolvePriority (symbol → int),
                               entryPriorities (canonical symbol → int
                               table consumed by Phase 3).
    node.nix                 — toZone (node → zone lowering).
    refs.nix                 — extractRefs (recursive walker that
                               extracts named-object refs from any
                               rule body or expression; consumed by
                               Phase 1's checkObjectRefs).

    # Layer 1 — phase orchestrators (consume the leaves above)
    normalize.nix            — Phase 1 orchestrator + 14 phases:
                               convertNodesToZones, computeZoneSets,
                               collectAllZoneNames, expandWildcardZones,
                               resolvePriorities, collectZoneRefs,
                               checkNameCollisions, checkSettings,
                               checkZoneRefs, checkZoneMatchable,
                               checkChainOverridePlacement,
                               checkPolicyUniqueness,
                               checkSetNameCollisions, checkObjectRefs.
    expand.nix               — Phase 2 orchestrator: expandTable
                               (cartesian product per entry into cells).
    dispatch.nix             — Phase 3 orchestrator: dispatchAndSort
                               (groupCellsByChain → chain buckets
                               keyed by `<hook>-at-<priority>`,
                               slotted into preDispatch / subChains
                               / postDispatch).
    emit.nix                 — Phase 4 orchestrator: emitTable
                               (emitBaseChains → emitSubChains →
                               emitUserObjects → assembleOutput) plus
                               every helper used by those phases
                               (mkBaseChain, mkSubChain, mkRuleBody,
                               mkJumpRules, mkDirectionVariants, etc.).

    # Layer 2 — top-level orchestrator (consumes all phases above)
    compile.nix              — pipes Phase 1-4 together; exposes
                               compile, mkTable, mkRuleset (the
                               internal entry points wrapped by the
                               public API in lib/default.nix).

    default.nix              — composes the three layers and threads
                               each layer into the next via the
                               `internal` arg.
  types/                     — option submodules; consumed by both the
                               public API surface and tests' evalModules.
```

Each internal module has a unit-test file under `tests/unit/internal/<module>.nix`. End-to-end coverage lives in `tests/unit/internal/compile.nix`.

## Open questions

1. **DSL helpers vs hand-rolled nftypes shapes.** Use `nftypes.dsl.*` builders (with marker validation) or construct nftypes-typed attrs directly? DSL is cleaner; hand-roll gives more control.

   **Decision: DSL helpers only.** All rule-body / statement construction goes through `nftypes.dsl.*`; hand-rolled libnftables-json shapes like `{ match = …; }` / `{ accept = null; }` are forbidden. Tests enforce this via the shapes they generate.

2. **Chain naming convention.** Sketched as `fwd-<from>-to-<to>`, `in-<from>` etc. in the original draft; bikeshed before implementation landed.

   **Decision: `<hook>-at-<priority>` for base chains, `<base>__<key>` for sub-chains.** See "Naming convention for chain identifiers" in the Terminology section above. The original sketch (`fwd-…`) was abandoned — the `<hook>-at-<priority>` form generalizes across hooks (filter / nat / route / mangle / raw / security) and matches the bucket key in `chainBuckets`.
3. **Cross-reference walking.** Named-object reference validation requires walking statement trees (counter / limit / quota / ct-helper / ct-timeout / ct-expectation / secmark / synproxy / tunnel references inside `entry.rule` bodies, plus set / map lookups inside `match` expressions). Two paths:

   - **Special-case extractor** — pattern-match on the ~12 statement variants that can carry named-object refs, plus the expression-level set/map lookups inside matches. Smaller surface; brittle to nftypes adding variants.
   - **Generic walker** — recurse over any statement / expression tree, parameterized by a per-node visitor. Schema knowledge (which sub-fields of each variant are sub-statements / sub-expressions) lives naturally in nftypes alongside the schemas, so the walker would be upstreamed there (`nftypes.lib.walk.statements` / `walk.expressions` / `walk.rule`) rather than living in `internal/statements.nix`.

   `nftypes` currently doesn't expose a walker. Its `lib/dsl/structure/render.nix` walks the *table* tree (table → chains → rules) with stock `lib.concatMap` iteration but never recurses into statement bodies; `lib/dsl/internal/validate.nix` runs bodies through `lib.evalModules` for shape checking, which doesn't traverse content. What `nftypes` *does* hand us is the inputs both approaches need: `nftypes.lib.types.statements` enumerates the variant tags, the `attrTag` shape (single-key attrset where the key is the tag) makes dispatch a one-liner, and `<variant>Body` schemas tell us where references live in each body.

   **Decision:** implement the special-case extractor in nftzones first. One consumer, small surface, no speculative API design. If a second use case appears (Phase 4 emit doing structural transforms, a future linter, etc.), upstream the generalized walker to nftypes then — designing the walker API with a single consumer risks the wrong abstraction.
4. **Error aggregation strategy.** Phase 1 validators return error lists. Should Phase 4 emission also return errors, or is "we got here, so emission can't fail" reasonable? The latter assumes Phases 1-3 fully validate.
5. **Single-table vs multi-table compile.** `mkTable` takes one table; multi-table consumers compose externally. Reconsider only if a real consumer wants a single function call.
6. **Zone-derived auto-sets in user rule bodies.** Phase 1's `computeZoneSets` materializes `<zone>_iifs` / `<zone>_v4` / `<zone>_v6` into `ctx.zoneSets`, which Phase 4 emits into `table.objects.sets` at output time. A user could in principle reference one of those names from a `match` clause inside their own rule body (e.g. `right = "@lan_v4"`). At Phase 1 validation time those names are not yet in `table.objects.sets` — they're synthesized later — so a naive `checkObjectRefs` would falsely flag them as unknown.

    Three options:

    - **(a) Parallel namespace** — `checkObjectRefs` resolves names against both `objects.sets.<name>` keys and the predictable `<zone>_{iifs,v4,v6}` names derived from `mergedZones`. No schema change; gives users an escape hatch when raw `match` against zone membership is more natural than `from` / `to`.
    - **(b) Pre-seed synthetic sets** — add a Phase 1 sub-phase that materializes zone-derived sets into a virtual `objects.sets` view before validation. Cleaner separation but more pipeline machinery.
    - **(c) Disallow user refs to zone-derived names** — document `from` / `to` as the only sanctioned way to express zone membership in match clauses; explicitly reject `@<zone>_{iifs,v4,v6}` shapes inside rule bodies.

    **Decision: (a)** — same cost as (c), but preserves the escape hatch for users who need raw `match` against zone membership. `checkObjectRefs` will resolve names against the union of `objects.sets.<name>` keys and the predictable `<zone>_{iifs,v4,v6}` names derived from `mergedZones`.

## Status

All four phases are implemented, unit-tested, and wired through the public API (`nftzones.mkTable name body` / `nftzones.mkRuleset name body`).

The pipeline end-to-end:

`compile` pipes four sub-orchestrators; each one is itself a `lib.pipe` over per-phase steps:

```nix
compile = table:
  lib.pipe table [
    normalizeTable     # Phase 1
    expandTable        # Phase 2
    dispatchAndSort    # Phase 3
    emitTable          # Phase 4
  ];

# Phase 1 — internal/normalize.nix
normalizeTable = lib.pipe (mkInitialState table) [
  convertNodesToZones      # ctx.mergedZones
  computeZoneSets          # ctx.zoneSets   (consumed in P1 + P4)
  collectAllZoneNames      # ctx.allZoneNames
  expandWildcardZones      # ctx.expandedGroups
  resolvePriorities        # ctx.resolvedPriorities
  collectZoneRefs          # ctx.zoneRefs
  checkNameCollisions      # ─┐
  checkSettings            #  │
  checkZoneRefs            #  │
  checkZoneMatchable       #  │ all append to ctx.errors;
  checkChainOverridePlacement  # orchestrator throws if non-empty
  checkPolicyUniqueness    #  │
  checkSetNameCollisions   #  │
  checkObjectRefs          # ─┘
];

# Phase 3 — internal/dispatch.nix
dispatchAndSort = lib.pipe state [
  groupCellsByChain        # ctx.groupedByChain
  buildChainBuckets        # ctx.chainBuckets
];

# Phase 4 — internal/emit.nix (reads ctx.zoneSets from Phase 1)
emitTable = lib.pipe state [
  emitBaseChains           # ctx.baseChains
  emitSubChains            # ctx.subChains
  emitUserObjects          # ctx.userObjects
  assembleOutput           # ctx.output  (nftypes.dsl.table value)
];
```

Public wrappers in `lib/default.nix` call `internal.compile.{mkTable,mkRuleset}` after running the user's body through `evalModules`:

```
nftzones.mkTable   name body  →  nftypes-table-value     (composable)
nftzones.mkRuleset name body  →  { nftables = [ ... ]; } (ready for `nft -f -j`)
```

Pending follow-ups:

1. Validate chain references in rule bodies. `checkObjectRefs` covers named-object refs (counter / set / map / etc.) but does NOT validate `dsl.jump <name>` / `dsl.goto <name>` targets. Two reasons today: (i) the chain-name surface in nftzones is internal (`<hook>-at-<priority>__<key>`) and not part of the public API, so users writing raw jumps to those names are working off-script; (ii) chains are synthesized in Phase 4, so Phase 1 doesn't yet know which names exist. Options if/when this matters: (a) add a Phase 4 post-emit validator that walks emitted rules and checks every `jump` / `goto` against the synthesized chain set, or (b) provide a public chain-name builder helper and validate at Phase 1 against that. Defer until a real consumer needs raw chain jumps.

2. ~~`sroute` emits an invalid chain type~~ **Resolved.** Upstream nftypes added `hooksByChainType` and the family-aware `chainTypeFor`; `internal.emit.chainTypeOf` is gone, replaced by a direct call to `nftypes.chainTypeFor`. Sroute now compiles to `type filter` at `prerouting + mangle` (mark-set then `ip rule` policy routing). Covered end-to-end by `tests/integration/scenarios/sroute-mark.nix`.

3. ~~`bridge` family rulesets silently misbehave~~ **Resolved.** Upstream nftypes added `priorityNameOf` and `chainTypeFor` with family-aware dispatch via `priorityIntsByFamily`; `internal.dispatch.canonicalPriority` is gone, replaced by `nftypes.priorityNameOf`. Bridge's priority constants (`filter = -200`, `srcnat = 300`, …) now canonicalize correctly. The Phase 1 family-allowlist (`checkSupportedFamily`) was replaced by the more general `checkChainPlacement`, which uses `nftypes.validChainPlacement` to reject any `(family, chainType, hook)` triple the kernel would refuse — catches bridge nat (no nat support), bridge sroute/droute (no mangle priority), and route at non-output hooks. Bridge filter+policy is covered by `tests/integration/scenarios/bridge-filter.nix`.
