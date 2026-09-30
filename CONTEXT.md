# Zone-based firewall

Zones describe packet membership. Parenting expresses refinement, with
specific child rules evaluated before parent fallback rules.

## Language

### Zones

**Zone membership**:
The interfaces, addresses and explicit match constraints that associate
packets with a zone, interpreted in the context of its hierarchy.

**Section**:
One of the four parts of a zone's match override for one side:
interfaces, IPv4, IPv6 or extra match statements.

**Own section**:
A match section contributed by the zone's own declaration or an active
override. Descendant contributions do not make a section own.

**Variant**:
One match-clause list derived from a zone's active sections. Each
variant becomes one emitted rule.

**Descendant membership**:
The interfaces and addresses contributed by a zone's children and their
descendants. These contributions widen the ancestor's membership.

**Root zone**:
A zone without a parent. The local zone is always a root.

**Child zone**:
A zone with a parent. It refines the parent: anything matching the child
also matches the parent.

**Subtree**:
A zone together with all its transitive descendants.

**Ancestor gate**:
A match constraint encountered on the path through a zone's ancestors.
From-side dispatch traverses these gates; to-side dispatch stays flat.

**Grouping zone**:
A zone without its own match, grouping descendants for hierarchical
dispatch. Descendant membership does not give it an own match.

**Node**:
A named host with an IPv4 address, an IPv6 address, or both, refining a
parent zone.

**Local zone**:
The sentinel zone standing for the firewall host itself. It can be
neither a parent nor a child.

### Rules

**Group**:
One of the rule-bearing collections on a table: filters, policies,
snats, dnats, sroutes or droutes.
_Avoid_: Rule set (for this meaning), collection

**Entry**:
One named item inside a group. Its body is the rule.
_Avoid_: Rule (for the wrapper)

**Direction**:
An entry's source or destination selection, named `from` or `to`.

**Side**:
A zone's ingress or egress match perspective. The `from` direction uses
ingress; the `to` direction uses egress.

**Cell**:
One concrete `(from, to)` instance of an entry, produced by expanding
its direction lists.

**Entry priority**:
The order of an entry within its slot.
_Avoid_: Chain priority (a different concept)

**Slot**:
One of two positions a cell occupies within its sub-chain: before the
child-dispatch jumps (pre-child) or after them (post-child).

### Chains

**Base chain**:
A chain attached to a netfilter hook, named `<hook>-at-<priority>`.

**Sub-chain**:
A chain reachable only by jump, holding the cells of one zone pair.

**Chain placement**:
The `(hook, chain priority)` pair that pins an entry to a base chain.
_Avoid_: Chain attrs (implementation name)

**Chain priority**:
The nftables order of chains attached to the same hook.
_Avoid_: Entry priority (a different concept)

**Child-dispatch jump**:
A jump inside a parent's sub-chain into a child's sub-chain.

**Transparent dispatcher**:
A sub-chain for an intermediate parent with no cells of its own, holding
only child-dispatch jumps.
