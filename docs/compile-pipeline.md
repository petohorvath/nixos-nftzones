# Compile Pipeline

This document describes the nftzones compile pipeline — the function chain that takes a `nftzones.types.table` value and produces an nftables ruleset suitable for `nft -f`.

## Motivation

The user-facing types under `nftzones.types` (zone, node, filter, snat, dnat, sroute, droute, policy, table) form an _input language_ for declaratively describing a zone-based firewall. The compile pipeline is the function that _interprets_ that language: lowering it to the libnftables-json shapes the kernel consumes.

Without the pipeline, the type system catches structural errors but nothing produces a runnable firewall. The compile pipeline closes that gap.

## Terminology

Domain terms (group, entry, direction, side, cell, slot, section,
variant, base chain, sub-chain, chain placement, entry priority vs.
chain priority) are defined in [`GLOSSARY.md`](../GLOSSARY.md). This
section covers only how the pipeline names things internally.

A **dispatch tree** (see the glossary) is the Phase 3 value for one
base chain: `ctx.dispatchTrees.<baseChainName> = { hook; priority;
roots; subChains; }`, where each sub-chain carries its own
`preChildCells` / `postChildCells` slots and its `children`. `roots`
and `children` hold sub-chain names. The direction-to-side mapping lives in
`internal.zone.directionToSide`; entry priorities resolve through
`internal.priority.resolvePriority`.

### Naming convention for chain identifiers

The same string travels from Phase 3 (as an attrset key) through to Phase 4 (as the actual nftables chain name):

- **`baseChainName`** = `"<hook>-at-<priority>"` (e.g. `"forward-at-filter"`). Computed by `internal.placement.baseChainNameOf`, with family-aware canonicalization of integer and symbol priorities. Used as the key in `dispatchTrees` _and_ as the base chain's name in the emitted nftables output.
- **`subChainName`** — `"<baseChainName>__<from>-TO-<to>"`, `"<baseChainName>__<from>"` or `"<baseChainName>__<to>"` (e.g. `"forward-at-filter__lan-TO-wan"`). Computed by `internal.placement.subChainNameOf` from the base chain name and a cell's `from` / `to`. Used as the key in a dispatch tree's `subChains`, `roots` and `children` _and_ as the sub-chain's name in the emitted nftables output.

### Two framings of `(hook, priority)`

The pair shows up under two names depending on context:

- **Chain placement** — user-facing term, used in type docstrings (the `chain` override on `filters` / `snats` / `dnats`, typed as `primitives.chainOverride`). Describes what the override _does_: pins the entry to a specific base chain.
- **Chain attrs** — implementation term, used in `internal.dispatch` / `internal.emit`. Describes the attrset shape `{ hook; priority; }` carried alongside cells.

Same concept, different framings.

`internal.placement` owns override precedence, local-zone hook selection, group defaults, and canonical chain names. Its two selection functions share that precedence:

- `chainAttrsForEntry group localZone entry` returns validation candidates as a list of chain attrs. The entry's directions must already be wildcard-expanded and deduplicated. It inspects the direction lists without materializing their Cartesian product.
- `chainAttrsForCell group localZone cell` returns one concrete cell's chain attrs, with scalar directions. An override wins; otherwise filters and policies prefer input when `to == localZone`, then output when `from == localZone`, then forward. Other groups use their defaults.

Entry analysis preserves conservative validation: fixed group placements and overrides are checked even for empty direction lists, and a local-zone reference contributes its hook independently of the opposite direction. A local-to-local entry therefore checks both input and output, while its cell dispatches to input. Phase 1 reports each incompatible candidate as a `chainPlacementInvalid` error on its entry; `dispatch` groups cells by their selected attrs. Priority values keep their original integer or symbol form until `baseChainNameOf` canonicalizes the name.

The Group / Entry / Direction trio shows up directly in `internal/normalize.nix`'s private helpers:

```
expandWildcardZones          # fills ctx.expandedGroups
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
  ↓ Phase 3: dispatch + sort dispatch trees, priority sort
dispatchTrees
  ↓ Phase 4: emit            per-zone sets, base chains, sub-chains, rules
nftypesTable
  ↓ wrap                      (optional) ruleset envelope
nftypesRuleset
```

Each phase has clear input and output shapes. Testable phase-by-phase.

## Phase 1: normalize

Phase 1 lowers nodes, resolves zone membership, wildcards and priorities, and validates the table. `internal.normalize` exports two functions over an evaluated `nftzones.types.table`, and both share one private pipeline run:

- `diagnose table` returns every Diagnostic as data, as `{ errors; warnings; }`. It never throws or warns.
- `normalizeTable table` is the throwing adapter the compile orchestrator calls. With errors, it throws once with all of them. With only warnings, it emits each through `lib.warn`. Otherwise it returns `{ table; ctx; }` for Phase 2.

Every compute step and validator is private, so steps can be reordered, merged or split without touching a test. Unit tests assert the `{ tag; path; }` projection of `diagnose`'s lists ([ADR-0009](adr/0009-cross-zone-validation-in-phase-1.md)).

### Output for later phases

`normalizeTable` returns the input `table` untouched, and a `ctx` with exactly the three keys later phases read:

| Key                  | Holds                                                                                | Read by        |
| -------------------- | ------------------------------------------------------------------------------------ | -------------- |
| `zoneMembership`     | The zone interpretation from `internal.zone.resolveMembership`                       | Phases 3 and 4 |
| `expandedGroups`     | Each entry's wildcard-expanded `from` / `to` lists, as `<group>.<entry>.<direction>` | Phase 2        |
| `resolvedPriorities` | Each entry's priority as an integer, as `<group>.<entry>`                            | Phase 2        |

The merged zone namespace, the in-scope zone names, the collected zone references and the raw diagnostic lists are scratch values. They stay inside the pipeline run.

### 1.1 Node lowering

`internal.node.toZone` converts each node to a zone definition:

```
{ name = "web-server"; parent = "dmz";
  address = { ipv4 = "10.0.0.5"; ipv6 = null; }; }
↓
{ parent = "dmz"; interfaces = [ ]; cidrs = [ "10.0.0.5/32" ]; }
```

Lowered nodes merge with the declared zones into one zone namespace, which the rest of Phase 1 reads. `table.zones` and `table.nodes` are left as declared.

### Zone membership

After node lowering, Phase 1 calls `internal.zone.resolveMembership { zones; localZone; }` once over the merged namespace. The resulting `ctx.zoneMembership` is the shared interface used by validation and emission. Callers supply zone names, sides or dispatch contexts; they never pair declarations with separately fabricated sets.

- `sets` and `setOwners` describe generated transitive sets and their provenance.
- `childrenOf`, `rootZoneNames`, `ancestorsOf` and `related` answer hierarchy questions.
- `activeOverrides` returns the contributing sections for reference validation.
- `hasOwnMatch` and `reachableAt` validate a zone's own declarations and overrides, excluding descendants.
- `directionVariants` produces dispatch clauses with hook visibility and own/descendant composition handled internally.
- `crossAxisPairs` identifies unrelated, anchored zones split across effective from-side axes. It retains the warning's accepted to-side and sibling residuals, ignores overrides, and excludes unanchored grouping zones.

Own, descendant and ancestor meanings stay distinct: an empty grouping zone can carry a synthetic dispatcher and transitive sets while remaining invalid as a direct rule reference. Ancestor gates affect the from-side path; ancestor content is never copied down into a child's sets.

### 1.2 Wildcard resolution

Phase 1 substitutes the wildcard zone (default `"all"`) in every entry's `from` / `to` list and deduplicates the result. A from-side wildcard expands to the root zones and `settings.localZone` only, because descendants receive traffic through their parent's sub-chain ([ADR-0007](adr/0007-from-wildcard-expands-to-roots.md)). A to-side wildcard expands to every in-scope zone: declared zones, lowered nodes and `settings.localZone`.

```
wildcard = "all"
allZones = [ "lan" "wan" "dmz" "local" ]
to = [ "lan" "all" "guest" ]  →  [ "lan" "wan" "dmz" "local" "guest" ]
```

The result lands in `ctx.expandedGroups`; `table` keeps the lists as written.

### 1.3 Validation

Validators run after the compute steps. Each appends Diagnostics to an error or a warning list, and none short-circuits, so a user sees every problem in one pass.

A **Diagnostic** is a record `{ tag; path; message; }`:

- `tag` is a camelCase string naming the kind of problem, in `<subject><problem>` form, such as `zoneParentUnknown` or `cidrOverlap`. Give a new validator's tags the same form.
- `path` is a list of strings naming the one declaration the diagnostic concerns: attribute names, and list indices as strings, such as `[ "filters" "ssh" "from" "0" ]`.
- `message` is human prose. It never repeats the path.

A diagnostic about several declarations, such as an overlap, a collision or a cycle, carries one path and names the others in its message. The path is the lexically first declaration involved, unless one is clearly the one to edit: a zone/node name collision blames the node, and a parent cycle blames the `parent` of its lexically smallest zone. Diagnostics about a zone lowered from a node use a path under the lowered zone, `zones.<node>`, which the user never wrote ([#31](https://github.com/petohorvath/nixos-nftzones/issues/31)).

`diagnose` sorts both lists by path, then tag, and its tests rely on that order, but the order is not part of the stable surface. Path elements, list indices included, are strings and sort as text, so `extra.10` sorts before `extra.2`. `normalizeTable` renders each diagnostic as `[tag] path.joined.with.dots: message`:

```text
nftzones.normalize: validation failed:
  - [zoneRefUnknown] filters.f.from.0: references unknown zone 'nowhere' (known: lan, local)
  - [zoneParentUnknown] zones.lan.parent: references unknown zone 'ghost'
```

Warnings go through `lib.warn` as `nftzones.normalize: [tag] path: message`.

Checks enforced by the table type fail during module evaluation, before Phase 1 runs, and are not diagnostics.

#### Stability

Users see a diagnostic as the rendered `[tag] path: message` line of a failed evaluation or a warning. From 0.1.0, its tag and path are a stable interface:

- **Stable:** each tag's name, the path each tag is reported at, and whether a tag is an error or a warning. Changing any of them is a breaking change with a CHANGELOG entry.
- **Not stable:** the message prose, and the order of diagnostics in a failure. Match on the tag and the path, not on the prose or the position of a line.

A node's address is the exception. `cidrOverlap` and `crossAxisOverlap` report a node at the zone it lowers to, under `zones.<node>`, a path the user never wrote, and a node with no address also makes each `from` or `to` reference to it `zoneNotMatchable` ([#31](https://github.com/petohorvath/nixos-nftzones/issues/31)). Those paths, and the second diagnostic, change when #31 is fixed. A node's `parent` is reported at `nodes.<node>.parent`, as a zone's is at `zones.<zone>.parent`.

`internal.normalize.diagnose` returns the same records as data, but like the rest of `internal` it has no semver guarantee.

#### Errors

| Tag                        | Path                                                                                             | Rejects                                                                                                                                                                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `zoneParentUnknown`        | `zones.<zone>.parent` or `nodes.<node>.parent`                                                   | A `parent` that names no zone or node.                                                                                                                                                                                                               |
| `zoneParentLocalZone`      | `zones.<zone>.parent` or `nodes.<node>.parent`                                                   | A `parent` equal to `settings.localZone`.                                                                                                                                                                                                            |
| `zoneParentCycle`          | `zones.<zone>.parent` or `nodes.<node>.parent`                                                   | A cycle in the parent chain.                                                                                                                                                                                                                         |
| `zoneNameCollision`        | `nodes.<node>`                                                                                   | A node named like a zone; lowering would overwrite the zone.                                                                                                                                                                                         |
| `nameKeyMismatch`          | `<group>.<key>.name`                                                                             | An explicit `name` that differs from its attribute key, in `zones`, `nodes` or a rule group.                                                                                                                                                         |
| `settingsConflict`         | `settings.localZone`, or the `zones.<zone>` or `nodes.<node>` that shadows a setting             | `localZone` equal to `wildcardZone`, or a zone or node named like either one.                                                                                                                                                                        |
| `zoneRefUnknown`           | `<group>.<entry>.<direction>.<index>`                                                            | A `from` / `to` reference that names no zone, node or `settings.localZone`.                                                                                                                                                                          |
| `zoneNotMatchable`         | `<group>.<entry>.<direction>.<index>`                                                            | A `from` / `to` reference to a zone with no interfaces, CIDRs or active override of its own on that side. Descendant sets do not make an empty grouping zone directly referenceable.                                                                 |
| `chainOverrideUnreachable` | `<group>.<entry>.<direction>`                                                                    | A `chain` override at a hook where a referenced zone has no usable match, because interface fields are unavailable there.                                                                                                                            |
| `chainPlacementInvalid`    | `<group>.<entry>`                                                                                | A `(family, chain type, hook)` triple the kernel refuses (via `nftypes.compatibility.validChainPlacement`), such as bridge nat, bridge sroute / droute (no `mangle` priority), or a `srcnat` / `dstnat` priority at a hook where `nat` can't attach. |
| `nodeAddressMissing`       | `nodes.<node>`                                                                                   | A node with neither `address.ipv4` nor `address.ipv6`.                                                                                                                                                                                               |
| `natAddrMissing`           | `snats.<entry>.rule.action.snat.addr` or `dnats.<entry>.rule.action.dnat.addr`                   | A `snat` / `dnat` body without `addr`.                                                                                                                                                                                                               |
| `policyConflict`           | `policies.<entry>`                                                                               | Two policies for the same `(from, to)` cell after wildcard expansion.                                                                                                                                                                                |
| `setNameCollision`         | `objects.sets.<name>`                                                                            | A user set named like a zone-derived set (`<zone>_iifs`, `_v4`, `_v6`).                                                                                                                                                                              |
| `interfaceOverlap`         | `zones.<zone>.interfaces`                                                                        | An interface claimed twice by one zone, or by two zones without an ancestor/descendant relationship.                                                                                                                                                 |
| `cidrOverlap`              | `zones.<zone>.cidrs`                                                                             | Overlapping CIDRs in one zone, or in two zones without an ancestor/descendant relationship. Family-aware via `libnet.cidr.overlaps`.                                                                                                                 |
| `objectRefUnknown`         | `<group>.<entry>.rule`, `zones.<zone>.matchOverride.<side>.<section>` or `objects.<kind>.<name>` | A named-object reference that resolves to no `table.objects.<kind>` key, or for sets, to no zone-derived set. The walker lives in `internal/refs.nix`.                                                                                               |

Overlap checks skip ancestor/descendant pairs, because that sharing is intentional in a zone hierarchy.

#### Warnings

| Tag                          | Path                                              | Flags                                                                                                                                                                                                                                               |
| ---------------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `rpfilterChainSuppressed`    | `settings.rpfilter`                               | `settings.rpfilter = true` while a user chain override claims `(prerouting, raw)`; the synthesized rpfilter chain is suppressed.                                                                                                                    |
| `filterAtPostrouting`        | `filters.<entry>.chain`                           | A filter at the postrouting hook, where `iifname` may not reflect the `from` zone.                                                                                                                                                                  |
| `dnatAtOutput`               | `dnats.<entry>.chain`                             | A dnat at the output hook, which rewrites locally-originated traffic.                                                                                                                                                                               |
| `snatOffSrcnat`              | `snats.<entry>.chain`                             | A snat at a priority other than `srcnat`, where conntrack misses the translation.                                                                                                                                                                   |
| `extraSectionInterfaceMatch` | `zones.<zone>.matchOverride.<side>.extra.<index>` | An interface `meta` match in the hook-agnostic `extra` section; it belongs in `interfaces`.                                                                                                                                                         |
| `wildcardZoneMixed`          | `<group>.<entry>.<direction>`                     | A `from` / `to` list that names an explicit zone the wildcard beside it already covers: a root zone or the local zone on the `from` side, any zone on the `to` side.                                                                                |
| `crossAxisOverlap`           | `zones.<zone>`                                    | Two unrelated zones whose effective from-side axes are strictly split, one interface-only and the other CIDR-only, so alphabetical jump order may shadow one. Multi-axis zones, ancestor/descendant pairs and empty grouping zones are not flagged. |

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

| Group      | Chain dispatch                                                                                                                               |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `filters`  | Selected by `internal.placement.chainAttrsForCell` — input / forward / output based on whether `from` / `to` reference `settings.localZone`. |
| `policies` | Same as `filters` — policies become tail rules in the same per-pair sub-chains.                                                              |
| `snats`    | Always postrouting (`type nat hook postrouting priority srcnat`).                                                                            |
| `dnats`    | Always prerouting (`type nat hook prerouting priority dstnat`).                                                                              |
| `sroutes`  | Always prerouting (`type filter hook prerouting priority mangle`).                                                                           |
| `droutes`  | Always output (`type route hook output priority mangle`).                                                                                    |

The per-entry `chain` override submodule on `filters` / `snats` / `dnats` redirects a cell to a custom hook + priority chain (e.g., rpfilter at `prerouting + raw`).

Cells are grouped per base chain (`ctx.groupedByChain`), and each group becomes one dispatch tree (`ctx.dispatchTrees.<baseChainName>`):

- **`subChains`** — one sub-chain per `(from, to)` with cells, plus a **transparent dispatcher** with empty slots for every ancestor of a from-zone that has cells. Only root zones jump from the base chain, so a descendant is reachable only through its ancestors' sub-chains. A cell-bearing sub-chain wins over a transparent dispatcher of the same name.
- **`roots`** — the sub-chains the base chain jumps to: those whose `from` is a root zone, plus those without a `from` (droutes), which dispatch flat. Sorted by name.
- **`children`** (per sub-chain) — the sub-chains its child-dispatch jumps target: for each child of the sub-chain's from-zone, in lexical order, the child's sub-chain for the same to-zone, if it exists.

### 3.2 Sort

`internal.priority.resolvePriority` resolves entry priority symbols (`first` / `preDispatch` / `postDispatch` / `default` / `last`) to ints (Phase 1 runs this for every entry; the pre-resolved values land in `ctx.resolvedPriorities`). Each sub-chain's slots sort by `(priority asc, name asc)`. Name is the attrset key from the original collection; it acts as a stable tiebreaker.

The cutoff at `100` (between `preDispatch=50` and `postDispatch=100`) splits each sub-chain's cells into two slots: before the child-dispatch jumps and after them — see Phase 4.

## Phase 4: emit

Renders the dispatch trees and the rest of the table state into one `nftypes.dsl.table` value.

### 4.1 Per-zone sets

For each zone, generate up to three sets:

- `<name>_iifs` — `type ifname` set of interface names (deduped by `lib.unique`).
- `<name>_v4` — `type ipv4_addr; flags interval` of v4 CIDRs (coalesced by `libnet.cidr.summarize`).
- `<name>_v6` — `type ipv6_addr; flags interval` of v6 CIDRs (coalesced by `libnet.cidr.summarize`).

Each set carries the union of the zone's own interfaces/CIDRs **plus every descendant's, transitively**. A child zone is a refinement of its parent, so anything that matches the child must also match the parent's base-chain dispatch jump (the child is reached from there via the parent's child-dispatch sub-rule). Within one family the union only ever widens the parent's match (OR inside the set); a set whose content comes **only** from descendants must not be ANDed into the parent's own gate, which is why jump construction classifies each section by own-ness (§4.4) — adding a descendant never shrinks what an ancestor matches. CIDR sets are coalesced at compile time: exact duplicates collapse, subset overlaps drop (descendant `10.0.0.5/32` inside parent `10.0.0.0/24` → just `10.0.0.0/24`), and adjacent sibling prefixes fuse (`10.0.0.0/24` + `10.0.1.0/24` → `10.0.0.0/23`). The rendered set matches the live kernel state without relying on the kernel-side `auto-merge` flag. Empty sets are skipped. Per-direction match expressions used by jumps are constructed by `zoneMembership.directionVariants` from these set names.

### 4.2 Base chains

One base chain per dispatch tree in `ctx.dispatchTrees` (Phase 3). Default placements:

- **Filter base chains** — `input`, `forward`, `output` at `priority filter`. Header: `type filter hook <name> priority filter; policy <chainPolicy>;`.
- **NAT base chains** — `prerouting` (DNAT) at `dstnat`, `postrouting` (SNAT) at `srcnat`.
- **Route base chains** — `prerouting` at `mangle` (sroute), `output` at `mangle` (droute).
- **Optional `rpfilter` chain** — emitted only when `settings.rpfilter = true`. `type filter hook prerouting priority raw;` with one rule: `fib saddr . iif oif eq 0 drop`.

**Chain type derivation.** `chainAttrs` carries `(hook, priority)` only; `emit.nix` derives the chain type with `internal.compatibility.chainTypeFor family hook priority`. A `srcnat` or `dstnat` priority gives `nat`, a `mangle` priority gives `route`, and any other priority gives `filter`. Where the kernel can't attach that type, such as `route` at `prerouting` (sroute's default), `chainTypeFor` returns `filter`.

That fallback would turn a NAT placement the kernel refuses into a filter chain holding NAT statements, which `nft -f` rejects. Phase 1's `chainPlacementInvalid` check therefore requires a `nat` chain to attach wherever the priority is `srcnat` or `dstnat`. If users ever need to pick chain type explicitly, add an optional `type` field to the chain-override schema later.

**Rule order in a base chain:**

1. (filter only) stateful boilerplate (`ct state established,related accept; ct state invalid drop`) if `settings.stateful` (default true).
2. (filter input only) loopback boilerplate (`iif lo accept`) if `settings.loopback` (default true).
3. **Root-zone dispatch jumps** — one jump per root sub-chain (see §4.4). Built by `internal.emit.mkRootJumpRules`. Descendant sub-chains are reached through their parent's child-dispatch, not the base chain.

Chain `policy <chainPolicy>` is declared on the chain header (filter chains only), not as a rule. Cells with `preDispatch` / `postDispatch` priority symbols land in their sub-chain's `preChildCells` / `postChildCells` slot — _not_ in the base chain.

### 4.3 Per-pair sub-chains

For each sub-chain in a dispatch tree, emit one chain. Inside it: sorted cells (filter / snat / dnat / sroute / droute rules) plus the tail rule from the matching policy if any.

**Naming convention:** `<baseChainName>__<from>-TO-<to>`, `<baseChainName>__<from>` or `<baseChainName>__<to>` (double-underscore separator), built by `internal.placement.subChainNameOf`. Phase 3 already keys each dispatch tree's `subChains` by these names, so Phase 4 emits them verbatim. The `baseChainName` is the dispatch tree's key from Phase 3 (`"<hook>-at-<priority>"`). Zone names can't contain the uppercase `-TO-`, so no two zone pairs, and no zone pair and single zone, share a name (ADR-0011). A from-only and a to-only sub-chain for the same zone still can (#20):

| Group / scenario                                     | Sub-chain name                      |
| ---------------------------------------------------- | ----------------------------------- |
| Filter `lan → wan` (forward)                         | `forward-at-filter__lan-TO-wan`     |
| Filter `wan → local` (input)                         | `input-at-filter__wan-TO-local`     |
| Filter `local → wan` (output)                        | `output-at-filter__local-TO-wan`    |
| Snat `lan → wan`                                     | `postrouting-at-srcnat__lan-TO-wan` |
| Dnat `wan` (single-direction `from`)                 | `prerouting-at-dstnat__wan`         |
| Droute `vpn` (single-direction `to`)                 | `output-at-mangle__vpn`             |
| rpfilter override `(prerouting, raw)`, `wan → local` | `prerouting-at-raw__wan-TO-local`   |

Verbose but readable: each name joins the base chain name and the zones, so the name → `(hook, priority, from, to)` mapping is mechanical and auditable in the generated JSON.

**Body:** pre-child cells, one child-dispatch jump per child × from-side variant of the child's match, then post-child cells and the policy tail rule (if any). The cells arrive sorted from Phase 3; transparent dispatchers hold only the jumps.

**Rule body emission per group.** Each cell records its `group`, and emission picks the body's shape by group, not by which keys the body has:

- **filter / sroute / droute** — `cell.rule` is `list-of-statements`; splice as one rule.
- **snat** — `cell.rule.match = [...]; cell.rule.action.{snat|masquerade} = { ... }` → match conditions ++ action statement.
- **dnat** — `cell.rule.match = [...]; cell.rule.action.{dnat|redirect} = { ... }` → match conditions ++ action statement.
- **policy** — `cell.verdict = "accept" | "drop"` → single verdict statement (always the tail rule).

### 4.4 Jumps

In each base chain, emit one or more jumps per sub-chain in its dispatch tree's `roots`. Match conditions select packets belonging to the `(from, to)` pair using per-zone sets from §4.1 — or via `zone.matchOverride.<side>` slot content where the user supplied an override — and the verdict is `jump <sub-chain-name>`.

**Per-direction variants — _not_ a single ANDed clause list.** In `inet` family, `ip <addr>` and `ip6 <addr>` clauses cannot be ANDed in the same rule: a v4 packet hitting `ip6 saddr ...` skips the rule entirely (and vice versa). So each direction emits **one variant per address family** that has a non-empty contribution, plus the optional interface prefix when the hook allows it, plus any `extra` section content the user supplied.

**Section resolution.** `zoneMembership.directionVariants` resolves four sections per direction, in this order: override wins if contributing, else fall back to the auto path.

| Section      | Auto path                      | Override path                |
| ------------ | ------------------------------ | ---------------------------- |
| `interfaces` | `inSet <ifField> @<zone>_iifs` | `override.<side>.interfaces` |
| `ipv4`       | `inSet <addrField> @<zone>_v4` | `override.<side>.ipv4`       |
| `ipv6`       | `inSet ip6.<addr> @<zone>_v6`  | `override.<side>.ipv6`       |
| `extra`      | (none — no auto path)          | `override.<side>.extra`      |

A section "contributes" when it's non-null AND non-empty. Empty list (`[ ]`) and `null` are equivalent — both mean "no constraint here" and let the auto path take over.

The `interfaces` section is **hook-gated**: dropped when the relevant `iifname` / `oifname` field isn't valid at the hook (defense; Phase 1's `chainOverrideUnreachable` check should have caught it). The other sections are hook-agnostic.

**Own-ness.** The auto-path sets are transitive unions (§4.1), so each section is additionally classified as **own** (anchored by the zone's raw `interfaces` / `cidrs` as classified privately by the zone module, or by an active override — overrides are own by definition) vs **inherited** (present in the union set only through descendants). Only own sections AND together. An inherited section ANDed into the gate would narrow the ancestor's dispatch to just the descendant's traffic — e.g. an address-only node under an interface-only zone would turn the zone's `iifname @<zone>_iifs` gate into `iifname @<zone>_iifs ip saddr @<zone>_v4`, cutting off every other host in the zone. Inherited sections widen the gate instead: inherited v4/v6 each become one extra OR variant behind the own prefix (unless the own gate is interface/extra-only, which is family-agnostic and already covers the subtree), and inherited interfaces become one standalone family-agnostic variant. Pinned by the `parent-mixed-sections` / `parent-mixed-sections-mirror` scenario tests.

> Note — _section_ here is unrelated to the _slot_ concept defined in the glossary. Slots (`preChildCells` / `postChildCells`) are Phase 3 cell placements within a sub-chain; override sections are per-direction match-clause containers within `matchOverride`. Different concepts, same generic vocabulary; they never appear together in code.

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

The reachable cases (auto-path only — section-resolution simplified to "no override anywhere"; "inh" = inherited, i.e. present in the union set only through descendants; the empty-zone case below is unreachable in practice because Phase 1 rejects it with `zoneNotMatchable`):

| Zone has                      | Variants emitted (per direction)                                          |
| ----------------------------- | ------------------------------------------------------------------------- |
| own iface only                | `[[ <ifField> @<zone>_iifs ]]`                                            |
| own iface + inh v4/v6         | 1 variant — iface only (family-agnostic; the subtree rides the own gate)  |
| own v4 only                   | `[[ <ipFamily> <addrField> @<zone>_v4 ]]`                                 |
| own v6 only                   | `[[ ip6 <addrField> @<zone>_v6 ]]`                                        |
| own v4 + own v6               | 2 variants — one v4, one v6                                               |
| own iface + own v4            | 1 variant — iface prefix + v4                                             |
| own iface + own v6            | 1 variant — iface prefix + v6                                             |
| own iface + own v4 + own v6   | 2 variants — each with iface prefix                                       |
| own v4 + inh v6               | 2 variants — v4, v6 (no cross-AND)                                        |
| own v4 + inh iface            | 2 variants — v4; standalone iface (family-agnostic)                       |
| all inherited (grouping zone) | 1 standalone variant per present section                                  |
| empty _(unreachable)_         | `[ ]` — defense only; Phase 1 rejects empty zones with `zoneNotMatchable` |

Where `<ifField>` is `iifname` (from-direction) or `oifname` (to-direction), and `<addrField>` is `saddr` / `daddr` likewise. With overrides in play, every cell can be replaced by user content; `extra` adds an extra family-agnostic prefix to every variant (e.g. `meta mark @<zone>_marks` for fwmark-defined zone membership).

**Cartesian product across directions.** For each sub-chain, take the cartesian product of `from`-variants and `to`-variants. Each pair becomes one jump rule:

```nix
fromVariant ++ toVariant ++ [ (jump subChainName) ]
```

**Family-mismatch filtering.** When both directions are `(v4 + v6)` zones, the cartesian product produces `(v4-from, v6-to)` and `(v6-from, v4-to)` pairs in addition to the matched-family ones. These would be harmless at runtime (the kernel skips rules whose payload protocol doesn't match) but bloat the chain. `variantFamily` (in `internal.emit`) classifies each variant as `"ip"` / `"ip6"` / `null` (family-agnostic) by inspecting payload protocols on the variant's match statements, and `mkRootJumpRules` drops cross-family `(from, to)` pairs in the cartesian filter. Pinned by `tests/unit/internal/emit.nix`'s `testMkRootJumpRulesCartesian` — a `lan → wan` pair with both zones dual-stack emits 2 jumps, not 4.

**Hook-direction semantics** — interface fields are not always available; use `internal.compatibility.hooksWithOifname` (`[ "forward" "output" "postrouting" ]`) to gate the `oifname` clause. `iifname` is valid at every hook except `output`. The interface prefix is suppressed when the hook makes the field unavailable; address clauses are always allowed.

| Hook          | `iifname` valid? | `oifname` valid? |
| ------------- | ---------------- | ---------------- |
| `prerouting`  | ✓                | ✗                |
| `input`       | ✓                | ✗                |
| `forward`     | ✓                | ✓                |
| `output`      | ✗                | ✓                |
| `postrouting` | ✓                | ✓                |

When the hook makes the only available field unavailable AND the zone has no addr sets, the direction produces 0 variants. This case shouldn't reach Phase 4 because Phase 1 flags it with `chainOverrideUnreachable`; if it does (defense), the empty cartesian product drops the entire jump for that sub-chain — sub-chain becomes unreachable rather than over-permissive.

**localZone references.** Phase 4 emits no match clauses for the `localZone` direction (it's a sentinel — never a declared zone, never has zone sets). The chain dispatch already used `localZone` for chain selection; once dispatched, the sentinel direction adds no further constraint. Single-direction sub-chains (dnat / sroute have no `to`; droute has no `from`) get the same wildcard treatment for the missing direction.

Helper signatures:

```nix
zoneMembership = internal.zone.resolveMembership { zones; localZone; };
  # zones: declared zones plus lowered nodes
zoneMembership.directionVariants { hook; direction; zoneName; }
  # -> list of DSL statement lists; null/localZone -> [ [ ] ]

mkRootJumpRules = { tree, zoneMembership }:
  <list-of-rules>;  # base-chain jumps to the tree's roots

mkSubChain = { hook, subChain, subChains, zoneMembership }:
  { rules; };       # slots around jumps to the sub-chain's children
```

### 4.5 User objects

`table.objects.<kind>.<name>` values go to the table's nftypes object containers. The object options reuse nftypes' schema bodies, so they keep nft's JSON field names, such as `elem` and `rate_unit`; `nftypes.dsl.table` takes the DSL names, so emit renames those fields (`dslObjectFieldNames` in `lib/internal/emit.nix`). The compile pipeline fills in the `family` / `name` / `table` fields stripped at the type layer (the `asUserBody` helper in `lib/types/table.nix`).

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
    # Layer 0 — leaves (only zone and placement depend on
    # compatibility)
    compatibility.nix        — nftzones' chain-placement conventions
                               over nftypes' compatibility tables:
                               family-wide priority symbols,
                               chainTypeFor, hooksWithOifname.
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
                               Phase 1's objectRefUnknown check).
    placement.nix            — chainAttrsForEntry + chainAttrsForCell
                               (override / local-zone / default
                               selection for Phase 1 validation and
                               Phase 3 dispatch); baseChainNameOf +
                               subChainNameOf (shared chain naming).

    # Layer 1 — phase orchestrators (consume the leaves above)
    normalize.nix            — Phase 1: exports diagnose (every
                               Diagnostic as data) and
                               normalizeTable (throwing adapter for
                               the compile pipeline); compute steps
                               and validators are private.
    expand.nix               — Phase 2 orchestrator: expandTable
                               (cartesian product per entry into cells).
    dispatch.nix             — Phase 3 orchestrator: dispatchAndSort
                               (groupCellsByChain → cells per base
                               chain keyed by `<hook>-at-<priority>`,
                               then buildDispatchTrees: per-(from, to)
                               sub-chains with pre/post-child slots,
                               transparent dispatchers, roots and
                               children).
    emit.nix                 — Phase 4 orchestrator: emitTable
                               (emitBaseChains → emitSubChains →
                               emitUserObjects → assembleOutput) plus
                               every helper used by those phases
                               (mkBaseChain, mkSubChain, mkRuleBody,
                               mkRootJumpRules, mkSubChains,
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
normalizeTable = table:      # throws on errors, lib.warn per warning
  { inherit table;
    ctx = { zoneMembership; expandedGroups; resolvedPriorities; };
  };
diagnose = table:            # same pipeline run, as data
  { errors = [ { tag; path; message; } … ]; warnings = [ … ]; };

# Phase 3 — internal/dispatch.nix
dispatchAndSort = lib.pipe state [
  groupCellsByChain        # ctx.groupedByChain
  buildDispatchTrees       # ctx.dispatchTrees
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
