# Zone parent: hierarchical from-side dispatch

## Problem

A zone-based firewall often needs to express "this host belongs to
this zone": a single web server inside a DMZ, an admin laptop inside
the LAN. Without hierarchy, the only way to say "rule X applies to
the whole DMZ including its hosts" is to either repeat the rule on
every node-zone, or rely on the parent's match-set being a superset
of every child's. Both approaches are fragile — the first scales
poorly, the second silently breaks when a node's match diverges
from the zone's.

## Solution

`zone.parent` is load-bearing on the **from**-side of zone-pair
dispatch. Each parent zone's sub-chain wraps its children's
sub-chains via dispatch jumps. Rules attached to the parent run as
fallbacks if no child handles the packet first.

The to-side stays flat — to-zone is a per-pair match clause as
today, with no hierarchy. Future work could extend hierarchy to
both sides; this initial implementation keeps the model
asymmetric.

## Terminology

- **Root zone**: a zone with `parent == null`. Roots get jumps from
  the base chain. The `localZone` sentinel is always treated as a
  root.
- **Child zone**: a zone with `parent != null`. Children get jumps
  only from inside their parent's sub-chain (child-dispatch jumps).
- **Subtree**: a zone plus all its transitive descendants.
- **Effective sub-chain**: the union of all `(from, to)` sub-chains
  that need to exist in a base chain bucket — direct cell-bearing
  sub-chains plus synthetic intermediate-parent dispatchers along
  each cell-bearing sub-chain's parent chain.

## Semantics

### Dispatch model

For each base chain (`<hook>-at-<priority>`):

1. The base chain emits boilerplate (stateful, loopback, rpfilter)
   plus jumps to root from-zones whose subtree contains content
   for the relevant to-zone.
2. Each parent sub-chain `__<parent>-to-<to>` contains:
   1. Pre-child cells (priority < 100), sorted by
      `(priority asc, name asc)`.
   2. Child-dispatch jumps to `__<child>-to-<to>` for each child
      whose subtree has content (one jump per from-side variant of
      the child's match).
   3. Post-child cells (priority >= 100, plus policies as tail
      rules), sorted by `(priority asc, name asc)` then policies
      by name.
3. Leaf sub-chains (zones with no children) carry just
   `preChildCells ++ postChildCells`.
4. Intermediate parents with no own cells but with content-bearing
   descendants emit as transparent dispatchers — just child-jumps.

### Priority cutoff

The cutoff at 100 controls whether a cell lands in
`preChildCells` (before child dispatch) or `postChildCells` (after,
fallback). Default priority (500) lands in `postChildCells`
naturally — rules attached to a parent zone become fallbacks for
descendant traffic, which matches the user mental model of
"specific child wins, parent is the catch-all."

### Wildcard expansion

`from = [ "all" ]` expands to root zones (zones with
`parent == null`) plus the `localZone` sentinel. Descendants
receive traffic via parent dispatch — they don't need a separate
cell. This is a behavioural change from a flat-dispatch model
where `all` expanded to every zone.

`to = [ "all" ]` keeps expanding to every zone (declared zones +
localZone), since to-side hierarchy is not modelled.

### Validation

Two Phase 1 validators (`internal.normalize.checkParentRefs` and
`checkParentCycles`) enforce:

- Every non-null `zone.parent` resolves to a zone in
  `mergedZones` (declared zones + lowered nodes).
- `zone.parent != localZone` — the localZone sentinel cannot be a
  parent.
- No cycles in the parent chain.

## Worked example

(Assumes `inherit (nftypes.lib.dsl) eq accept limit;` and
`inherit (nftypes.lib.dsl.fields) tcp;` are in scope.)

```nix
zones.dmz = {
  interfaces = [ "dmz0" ];
  cidrs = [ "10.0.0.0/24" ];
};

nodes.web-server = {
  zone = "dmz";              # → lowered zone with parent = "dmz"
  address.ipv4 = "10.0.0.5";
};

filters.dmz-rate-limit = {
  from = [ "dmz" ];
  to = [ "local" ];
  rule = [ (eq tcp.dport 22) (limit { rate = 100; per = "second"; }) accept ];
};

filters.web-server-http = {
  from = [ "web-server" ];
  to = [ "local" ];
  rule = [ (eq tcp.dport 80) accept ];
};
```

Compiles to (sketched):

```
chain input-at-filter {
  type filter hook input priority filter; policy drop;
  ct state established,related accept
  ct state invalid drop
  iif lo accept
  iifname @dmz_iifs ip saddr @dmz_v4 jump input-at-filter__dmz-to-local
}

chain input-at-filter__dmz-to-local {
  ip saddr @web-server_v4 jump input-at-filter__web-server-to-local
  tcp dport 22 limit rate 100/second accept
}

chain input-at-filter__web-server-to-local {
  tcp dport 80 accept
}
```

Per-packet:

| Packet                            | Path                                                                 |
|-----------------------------------|----------------------------------------------------------------------|
| `10.0.0.7 → fw:22` (LAN, not web) | dmz jump → SSH rate-limit → accept                                   |
| `10.0.0.5 → fw:80` (web, HTTP)    | dmz jump → web-server jump → port 80 → accept                        |
| `10.0.0.5 → fw:22` (web, SSH)     | dmz jump → web-server chain (no match) → returns → SSH rate-limit → accept |
| `10.0.0.99 → fw:80` (other DMZ)   | dmz jump → web-server jump misses → SSH rate-limit misses → policy drop |

## Rejected alternatives

Two prior-art models were considered:

### thelegy/nixos-nftables-firewall (rejected)

Composes parent matches into descendant rules: every rule on
`web-server` re-states all of `dmz`'s match clauses ANDed in. Flat
chain topology, no recursive dispatch. Rejected for two reasons:

1. **Match-clause duplication scales poorly** — deep nesting
   produces long composite rules.
2. **Combinatorial chain emission** — their `traversalChains`
   builds 4 chain variants per `(fromZone, toZone, ruleType)`
   tuple; with N zones × M rule types, output is `O(N² × M × 4)`.

### Hand-rolled per-zone rule duplication (rejected)

Without parent at all, a "DMZ-wide" rule would have to be repeated
on every node inside DMZ. Doesn't scale, breaks silently when a
node is added without copying every parent-level rule.

## Why petohorvath-style "child first, parent fallback" wins

- **No match duplication** — each rule states only its own zone's
  conditions; the parent's match is implicit because traffic only
  reached the parent sub-chain by satisfying it at the chain-jump
  point.
- **Natural fallback semantics** — the most-specific child claims
  the packet; the parent runs only if the child returned without
  verdict.
- **Linear chain count** — one sub-chain per zone-with-content,
  recursion handles nesting.
- **Override-friendly** — pre-child slot for "before child
  dispatch" rules (e.g., bogon drops on the entire subtree),
  post-child slot for fallback rules.

## Out of scope

- **`to`-side hierarchy** — to-zone stays flat. A future iteration
  could extend hierarchy to both sides at the cost of a 4-chain
  matrix per `(from, to, ruleType)` (the thelegy approach).
- **thelegy-style match composition** — not adopted; see rejected
  alternatives.
- **Multi-table parent references** — parents are scoped to one
  table.
- **Parent inheritance across rule groups** — each rule group
  (filter, snat, dnat, sroute, droute, policy) keys by its own
  `(from, to)`; a node's parent doesn't automatically inherit the
  parent's NAT rule into the node.

## Implementation references

- `lib/types/zone.nix` — `parent` option declaration.
- `lib/internal/normalize.nix`:
  - `checkParentRefs` — resolution validator.
  - `checkParentCycles` — cycle validator.
  - `computeChildrenOf` — inverse parent map.
  - `computeRootZoneNames` — list of root zones + localZone.
  - `expandWildcardZones` — from-side wildcard expands to roots.
- `lib/internal/dispatch.nix`:
  - `subChainOf` — partitions cells into pre/post-child slots.
- `lib/internal/emit.nix`:
  - `mkSubChainKey` — key composition from `(fromZone, toZone)`.
  - `isRootFrom` — root predicate.
  - `buildEffectiveSubChains` — synthesize transparent
    intermediate-parent dispatchers.
  - `mkChildDispatchJumpRules` — child-dispatch jumps inside a
    parent sub-chain.
  - `mkRootJumpRules` — base-chain jumps for root zones only.
- `tests/integration/scenarios/parent-*.nix` — end-to-end
  scenarios covering basic, priorities, deep nesting, and empty
  intermediates.
