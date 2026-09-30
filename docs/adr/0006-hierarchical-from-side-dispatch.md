# Hierarchical from-side dispatch: child first, parent fallback

`zone.parent` is load-bearing on the from side only. Each parent's
sub-chain holds child-dispatch jumps into its children's sub-chains, and
rules attached to the parent act as fallbacks when no child returns a
verdict. A zone's generated sets include all descendant interfaces and
CIDRs, so the parent's jump also catches descendant traffic. The to side
stays flat: the to-zone is a per-pair match clause with no hierarchy.

This gives natural "specific child wins" semantics without duplicating
matches, and one sub-chain per zone with content.

## Considered options

- **Match composition (thelegy/nixos-nftables-firewall).** Every
  descendant rule re-states all ancestor matches. Rejected: composite
  rules grow with nesting depth, and its four chain variants per
  `(from, to, ruleType)` tuple scale as `O(N² × M × 4)`.
- **No hierarchy, with rules duplicated on every node.** Rejected: it
  doesn't scale, and it silently breaks when a node is added without
  copying the parent-level rules.
- **Hierarchy on both sides.** Deferred: it needs a chain matrix per
  `(from, to, ruleType)`, the same blow-up as the thelegy model.

## Consequences

- Rule groups don't inherit through parents. A node doesn't pick up its
  parent zone's NAT entries, because each group keys by its own
  `(from, to)`.
- Before descendant membership was folded into the generated sets, a
  wildcard deny combined with `chainPolicy = "accept"` let descendants
  bypass the deny. Descendant membership closes that gap.
