# Compile Pipeline

This document describes the nftzones compile pipeline — the function chain that takes a `nftzones.types.table` value and produces an nftables ruleset suitable for `nft -f`.

## Motivation

The user-facing types under `nftzones.types` (zone, node, filter, snat, dnat, sroute, droute, policy, table) form an *input language* for declaratively describing a zone-based firewall. The compile pipeline is the function that *interprets* that language: lowering it to the libnftables-json shapes the kernel consumes.

Without the pipeline, the type system catches structural errors but nothing produces a runnable firewall. The compile pipeline closes that gap.

## Terminology

Domain terms (group, entry, direction, side, cell, slot, section,
variant, base chain, sub-chain, chain placement, entry priority vs.
chain priority) are defined in [`CONTEXT.md`](../CONTEXT.md). This
section covers only how the pipeline names things internally.

A **bucket** is the Phase 3 container holding all cells destined for
one base chain: `ctx.chainBuckets.<baseChainName> = { hook; priority;
subChains; }`, where each sub-chain carries its own `preChildCells` /
`postChildCells` slots. The direction-to-side mapping lives in
`internal.zone.directionToSide`; entry priorities resolve through
`internal.priority.resolvePriority`.

### Naming convention for chain identifiers

The same string travels from Phase 3 (as an attrset key) through to Phase 4 (as the actual nftables chain name):

- **`baseChainName`** = `"<hook>-at-<priority>"` (e.g. `"forward-at-filter"`). Computed by `internal.placement.baseChainNameOf`, with family-aware canonicalization of integer and symbol priorities. Used as the bucket key in `chainBuckets` *and* as the base chain's name in the emitted nftables output.
- **`subChainKey`** — local key within `bucket.subChains` (e.g. `"lan-to-wan"` / `"wan"` / `"lan"`). Computed by `internal.placement.subChainKeyOf` from a cell's `from` / `to`.
- **`subChainName`** — full sub-chain name in the nftables output, `"<baseChainName>__<subChainKey>"` (e.g. `"forward-at-filter__lan-to-wan"`). Computed by `internal.emit.subChainNameOf`.

### Two framings of `(hook, priority)`

The pair shows up under two names depending on context:

- **Chain placement** — user-facing term, used in type docstrings (the `chain` override on `filters` / `snats` / `dnats`, typed as `primitives.chainOverride`). Describes what the override *does*: pins the entry to a specific base chain.
- **Chain attrs** — implementation term, used in `internal.dispatch` / `internal.emit`. Describes the attrset shape `{ hook; priority; }` carried alongside cells.

Same concept, different framings.

`internal.placement` owns override precedence, local-zone hook selection, group defaults, and canonical chain names. Its two selection functions share that precedence:

- `chainAttrsForEntry group localZone entry` returns validation candidates as a list of chain attrs. The entry's directions must already be wildcard-expanded and deduplicated. It inspects the direction lists without materializing their Cartesian product.
- `chainAttrsForCell group localZone cell` returns one concrete cell's chain attrs, with scalar directions. An override wins; otherwise filters and policies prefer input when `to == localZone`, then output when `from == localZone`, then forward. Other groups use their defaults.

Entry analysis preserves conservative validation: fixed group placements and overrides are checked even for empty direction lists, and a local-zone reference contributes its hook independently of the opposite direction. A local-to-local entry therefore checks both input and output, while its cell dispatches to input. `normalize.checkChainPlacement` adds entry names and aggregates compatibility errors; `dispatch` buckets cells using their selected attrs. Priority values keep their original integer or symbol form until `baseChainNameOf` canonicalizes the name.

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
  ↓ Phase 3: dispatch + sort chain bucketing, priority sort
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

### Zone membership

After node lowering, `computeZoneMembership` calls
`internal.zone.resolveMembership { zones = ctx.mergedZones; localZone; }`
once. The resulting `ctx.zoneMembership` is the shared interface used by
validation and emission. Callers supply zone names, sides or dispatch
contexts; they never pair declarations with separately fabricated sets.

- `sets` and `setOwners` describe generated transitive sets and their provenance.
- `childrenOf`, `rootZoneNames`, `ancestorsOf` and `related` answer hierarchy questions.
- `activeOverrides` returns the contributing sections for reference validation.
- `hasOwnMatch` and `reachableAt` validate a zone's own declarations and overrides, excluding descendants.
- `directionVariants` produces dispatch clauses with hook visibility and own/descendant composition handled internally.
- `crossAxisPairs` identifies unrelated, anchored zones split across effective from-side axes. It retains the warning's accepted to-side and sibling residuals, ignores overrides, and excludes unanchored grouping zones.

Own, descendant and ancestor meanings stay distinct: an empty grouping
zone can carry a synthetic dispatcher and transitive sets while remaining
invalid as a direct rule reference. Ancestor gates affect the from-side
path; ancestor content is never copied down into a child's sets.

### 1.2 Wildcard resolution

Phase 1 substitutes the wildcard zone (default `"all"`) in every entry's `from` / `to` list with the full set of in-scope zones (declared zones plus `settings.localZone`). The substitution + dedup is inlined inside `internal.normalize.expandWildcardZones` since it has no other consumer:

```
wildcard = "all"
allZones = [ "lan" "wan" "dmz" "local" ]
[ "lan" "all" "guest" ]  →  [ "lan" "wan" "dmz" "local" "guest" ]
```

`allZones` is computed once per table after node lowering, so nodes-as-zones are included.

### 1.3 Validation

Validators run after the compute phases, all in `internal/normalize.nix`. Each appends `lib.nameValuePair "<errorTag>" <message>` records to `ctx.errors` (or warning strings to `ctx.warnings`); the orchestrator aggregates errors and throws a single message listing every one, so users see all problems in one pass.

- **`checkParentRefs`** — every non-null `zone.parent` must resolve to a zone in `ctx.mergedZones` and must not equal `settings.localZone`.
- **`checkParentCycles`** — the parent chain must be acyclic.
- **`checkNameCollisions`** — node names must not collide with zone names (lowering would silently overwrite).
- **`checkSettings`** — `settings.localZone` and `settings.wildcardZone` must differ from each other and from any declared zone / node name.
- **`checkZoneRefs`** — every zone reference (in `from`, `to`, `node.zone`) must resolve to a known zone or `settings.localZone`.
- **`checkZoneMatchable`** — every direction-bound zone ref (`from` → ingress, `to` → egress) must point at a zone with its own interfaces, CIDRs or active override on the relevant side. Descendant sets do not make an empty grouping zone directly referenceable.
- **`checkChainOverridePlacement`** — entries with a `chain` override must land at a hook where their `from` / `to` zones are actually matchable (interface fields aren't valid at every hook).
- **`checkChainPlacement`** — every entry's resolved `(family, chainType, hook)` triple must be one the kernel accepts (via `nftypes.validChainPlacement`); rejects bridge nat, bridge sroute / droute (no `mangle` on bridge), route at non-output hooks, etc.
- **`checkRpfilterOverride`** — emits a warning (not an error) when `settings.rpfilter = true` but a user chain override already claims `(prerouting, raw)`; the synthesized rpfilter chain is suppressed and the user-authored chain is used as-is.
- **`checkPolicyUniqueness`** — at most one policy applies per `(from, to)` cell after wildcard expansion.
- **`checkSetNameCollisions`** — user `objects.sets.<name>` must not collide with auto-generated zone-derived set names (`<zone>_iifs|v4|v6`).
- **`checkInterfaceOverlap`** — distinct zones must not claim the same interface (ambiguous dispatch); ancestor/descendant pairs are skipped (intentional sharing in a zone hierarchy), and intra-zone duplicates in the `interfaces` list are also flagged.
- **`checkCidrOverlap`** — distinct zones must not have overlapping CIDR prefixes (ambiguous dispatch); ancestor/descendant pairs are skipped (intentional containment, e.g. a node lowered into its parent zone), and intra-zone overlapping CIDRs are also flagged. Family-aware via `libnet.cidr.overlaps` (v4 vs v6 never overlap).
- **`checkCrossAxisOverlap`** — warning, not an error: flags pairs of unrelated zones whose effective from-side dispatch axes are strictly split — one interface-only, the other CIDR-only — since both may match the same packet and alphabetical jump order then silently shadows the loser. Effective axes are a zone's own fields plus every strict ancestor's (from-side descendant dispatch rides through ancestor sub-chains), so a CIDR-only node under an interface-bound parent is multi-axis rather than an accidental split; multi-axis zones, ancestor/descendant pairs, and zones with no own axis (empty grouping zones) are not flagged.
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
| `filters` | Selected by `internal.placement.chainAttrsForCell` — input / forward / output based on whether `from` / `to` reference `settings.localZone`. |
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

- `<name>_iifs` — `type ifname` set of interface names (deduped by `lib.unique`).
- `<name>_v4` — `type ipv4_addr; flags interval` of v4 CIDRs (coalesced by `libnet.cidr.summarize`).
- `<name>_v6` — `type ipv6_addr; flags interval` of v6 CIDRs (coalesced by `libnet.cidr.summarize`).

Each set carries the union of the zone's own interfaces/CIDRs **plus every descendant's, transitively**. A child zone is a refinement of its parent, so anything that matches the child must also match the parent's base-chain dispatch jump (the child is reached from there via the parent's child-dispatch sub-rule). Within one family the union only ever widens the parent's match (OR inside the set); a set whose content comes **only** from descendants must not be ANDed into the parent's own gate, which is why jump construction classifies each section by own-ness (§4.4) — adding a descendant never shrinks what an ancestor matches. CIDR sets are coalesced at compile time: exact duplicates collapse, subset overlaps drop (descendant `10.0.0.5/32` inside parent `10.0.0.0/24` → just `10.0.0.0/24`), and adjacent sibling prefixes fuse (`10.0.0.0/24` + `10.0.1.0/24` → `10.0.0.0/23`). The rendered set matches the live kernel state without relying on the kernel-side `auto-merge` flag. Empty sets are skipped. Per-direction match expressions used by jumps are constructed by `zoneMembership.directionVariants` from these set names.

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
3. **Root-zone dispatch jumps** — one jump per root sub-chain (see §4.4). Built by `internal.emit.mkRootJumpRules`. Descendant sub-chains are reached through their parent's child-dispatch, not the base chain.

Chain `policy <chainPolicy>` is declared on the chain header (filter chains only), not as a rule. Cells with `preDispatch` / `postDispatch` priority symbols land in their sub-chain's `preChildCells` / `postChildCells` slot — *not* in the base chain.

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

**Section resolution.** `zoneMembership.directionVariants` resolves four sections per direction, in this order: override wins if contributing, else fall back to the auto path.

| Section      | Auto path                              | Override path                  |
|--------------|----------------------------------------|--------------------------------|
| `interfaces` | `inSet <ifField> @<zone>_iifs`         | `override.<side>.interfaces`   |
| `ipv4`       | `inSet <addrField> @<zone>_v4`         | `override.<side>.ipv4`         |
| `ipv6`       | `inSet ip6.<addr> @<zone>_v6`          | `override.<side>.ipv6`         |
| `extra`      | (none — no auto path)                  | `override.<side>.extra`        |

A section "contributes" when it's non-null AND non-empty. Empty list (`[ ]`) and `null` are equivalent — both mean "no constraint here" and let the auto path take over.

The `interfaces` section is **hook-gated**: dropped when the relevant `iifname` / `oifname` field isn't valid at the hook (defense; `checkChainOverridePlacement` should have caught it). The other sections are hook-agnostic.

**Own-ness.** The auto-path sets are transitive unions (§4.1), so each section is additionally classified as **own** (anchored by the zone's raw `interfaces` / `cidrs` as classified privately by the zone module, or by an active override — overrides are own by definition) vs **inherited** (present in the union set only through descendants). Only own sections AND together. An inherited section ANDed into the gate would narrow the ancestor's dispatch to just the descendant's traffic — e.g. an address-only node under an interface-only zone would turn the zone's `iifname @<zone>_iifs` gate into `iifname @<zone>_iifs ip saddr @<zone>_v4`, cutting off every other host in the zone. Inherited sections widen the gate instead: inherited v4/v6 each become one extra OR variant behind the own prefix (unless the own gate is interface/extra-only, which is family-agnostic and already covers the subtree), and inherited interfaces become one standalone family-agnostic variant. Pinned by the `parent-mixed-sections` / `parent-mixed-sections-mirror` integration scenarios.

> Note — *section* here is unrelated to the *bucket slot* concept defined in the Terminology section above. Bucket slots (`preDispatch` / `subChains` / `postDispatch`) are Phase 3 cell placements within a chain bucket; override sections are per-direction match-clause containers within `matchOverride`. Different concepts, same generic vocabulary; they never appear together in code.

**Variant construction.**

```
prefix    = (ifsAtHook if interfaces own) ++ extraSection
ownFams   = optional (v4 own  && v4Section ≠ [ ]) (prefix ++ v4Section)
         ++ optional (v6 own  && v6Section ≠ [ ]) (prefix ++ v6Section)
inhFams   = optional (v4 inherited && v4Section ≠ [ ]) (prefix ++ v4Section)
         ++ optional (v6 inherited && v6Section ≠ [ ]) (prefix ++ v6Section)
inhIfs    = optional (interfaces inherited && ifsAtHook ≠ [ ]) ifsAtHook
result    = if ownFams ≠ [ ] then ownFams ++ inhFams ++ inhIfs
            else if prefix ≠ [ ] then [ prefix ]
            else inhFams ++ inhIfs
```

The reachable cases (auto-path only — section-resolution simplified to "no override anywhere"; "inh" = inherited, i.e. present in the union set only through descendants; the empty-zone case below is unreachable in practice because `checkZoneMatchable` rejects it in Phase 1):

| Zone has        | Variants emitted (per direction) |
|---|---|
| own iface only  | `[[ <ifField> @<zone>_iifs ]]` |
| own iface + inh v4/v6 | 1 variant — iface only (family-agnostic; the subtree rides the own gate) |
| own v4 only     | `[[ <ipFamily> <addrField> @<zone>_v4 ]]` |
| own v6 only     | `[[ ip6 <addrField> @<zone>_v6 ]]` |
| own v4 + own v6 | 2 variants — one v4, one v6 |
| own iface + own v4 | 1 variant — iface prefix + v4 |
| own iface + own v6 | 1 variant — iface prefix + v6 |
| own iface + own v4 + own v6 | 2 variants — each with iface prefix |
| own v4 + inh v6 | 2 variants — v4, v6 (no cross-AND) |
| own v4 + inh iface | 2 variants — v4; standalone iface (family-agnostic) |
| all inherited (grouping zone) | 1 standalone variant per present section |
| empty *(unreachable)* | `[ ]` — defense only; `checkZoneMatchable` rejects empty zones at Phase 1 |

Where `<ifField>` is `iifname` (from-direction) or `oifname` (to-direction), and `<addrField>` is `saddr` / `daddr` likewise. With overrides in play, every cell can be replaced by user content; `extra` adds an extra family-agnostic prefix to every variant (e.g. `meta mark @<zone>_marks` for fwmark-defined zone membership).

**Cartesian product across directions.** For each sub-chain, take the cartesian product of `from`-variants and `to`-variants. Each pair becomes one jump rule:

```nix
fromVariant ++ toVariant ++ [ (jump (subChainNameOf baseChainName subChainKey)) ]
```

**Family-mismatch filtering.** When both directions are `(v4 + v6)` zones, the cartesian product produces `(v4-from, v6-to)` and `(v6-from, v4-to)` pairs in addition to the matched-family ones. These would be harmless at runtime (the kernel skips rules whose payload protocol doesn't match) but bloat the chain. `variantFamily` (in `internal.emit`) classifies each variant as `"ip"` / `"ip6"` / `null` (family-agnostic) by inspecting payload protocols on the variant's match statements, and `mkRootJumpRules` drops cross-family `(from, to)` pairs in the cartesian filter. Pinned by `tests/unit/internal/emit.nix`'s `testMkRootJumpRulesCartesian` — a `lan → wan` pair with both zones dual-stack emits 2 jumps, not 4.

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
zoneMembership = internal.zone.resolveMembership { zones = mergedZones; localZone; };
zoneMembership.directionVariants { hook; direction; zoneName; }
  # -> list of DSL statement lists; null/localZone -> [ [ ] ]

mkRootJumpRules = { hook, baseChainName, effectiveSubChains, zoneMembership }:
  <list-of-rules>;  # base-chain jumps to root from-zones only

mkChildDispatchJumpRules = { hook, baseChainName, parentFromZone, toZone,
                             effectiveSubChains, zoneMembership }:
  <list-of-rules>;  # in-sub-chain jumps to from-side descendants
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
                               version, snippets + re-exports of
                               `types` and `internal`.
  snippets.nix               — nftzones.snippets.* rule-body
                               shorthand (verdict × protocol grid);
                               helpers under snippets/.
  internal/
    # Layer 0 — leaves (no inter-module deps)
    zone.nix                 — resolveMembership (zone interpretation
                               shared by Phase 1 validators and Phase 4
                               emit: sets, hierarchy, validation and
                               dispatch variants).
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
    placement.nix            — chainAttrsForEntry + chainAttrsForCell
                               (override / local-zone / default
                               selection for Phase 1 validation and
                               Phase 3 dispatch); baseChainNameOf +
                               subChainKeyOf (shared chain naming);
                               walkParents + hooksWithIifname.

    # Layer 1 — phase orchestrators (consume the leaves above)
    normalize.nix            — Phase 1 orchestrator: pipes compute
                               phases (convertNodesToZones,
                               computeZoneMembership,
                               collectAllZoneNames,
                               expandWildcardZones, resolvePriorities,
                               collectZoneRefs) followed by
                               validators (checkParentRefs,
                               checkParentCycles, checkNameCollisions,
                               checkSettings, checkZoneRefs,
                               checkZoneMatchable,
                               checkChainOverridePlacement,
                               checkChainPlacement,
                               checkRpfilterOverride,
                               checkPolicyUniqueness,
                               checkSetNameCollisions,
                               checkInterfaceOverlap, checkCidrOverlap,
                               checkObjectRefs).
    expand.nix               — Phase 2 orchestrator: expandTable
                               (cartesian product per entry into cells).
    dispatch.nix             — Phase 3 orchestrator: dispatchAndSort
                               (groupCellsByChain → chain buckets
                               keyed by `<hook>-at-<priority>`, then
                               buildChainBuckets partitioning cells
                               into per-(from, to) sub-chains with
                               pre/post-child slots).
    emit.nix                 — Phase 4 orchestrator: emitTable
                               (emitBaseChains → emitSubChains →
                               emitUserObjects → assembleOutput) plus
                               every helper used by those phases
                               (mkBaseChain, mkSubChain, mkRuleBody,
                               mkRootJumpRules, mkChildDispatchJumpRules,
                               mkDirectionVariants, etc.).

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

## Design decisions

Recorded as ADRs in [`docs/adr/`](adr/): DSL-only rule construction
(0001), chain naming (0002), the object-reference extractor (0003),
zone-derived sets in rule bodies (0004), single-table compile (0005),
and Phase 1 validation (0009). Whether Phase 4 should report errors
is open as [#10](https://github.com/petohorvath/nixos-nftzones/issues/10).

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
  computeZoneMembership    # ctx.zoneMembership (consumed in P1 + P4)
  collectAllZoneNames      # ctx.allZoneNames
  expandWildcardZones      # ctx.expandedGroups
  resolvePriorities        # ctx.resolvedPriorities
  collectZoneRefs          # ctx.zoneRefs
  checkParentRefs          # ─┐
  checkParentCycles        #  │
  checkNameCollisions      #  │
  checkSettings            #  │
  checkZoneRefs            #  │
  checkZoneMatchable       #  │ all append to ctx.errors;
  checkChainOverridePlacement  # orchestrator throws if non-empty.
  checkChainPlacement      #  │ checkRpfilterOverride is the one
  checkRpfilterOverride    #  │ exception — appends to ctx.warnings
  checkPolicyUniqueness    #  │ instead, surfaced via lib.warn.
  checkSetNameCollisions   #  │
  checkInterfaceOverlap    #  │
  checkCidrOverlap         #  │
  checkObjectRefs          # ─┘
];

# Phase 3 — internal/dispatch.nix
dispatchAndSort = lib.pipe state [
  groupCellsByChain        # ctx.groupedByChain
  buildChainBuckets        # ctx.chainBuckets
];

# Phase 4 — internal/emit.nix (reads ctx.zoneMembership.sets from Phase 1)
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

Open design gaps are tracked as GitHub issues, for example
[#6](https://github.com/petohorvath/nixos-nftzones/issues/6)
(validating jump/goto targets).
