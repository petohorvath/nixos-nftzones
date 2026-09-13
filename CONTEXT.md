# Zone-based firewall

Zones describe packet membership. Parenting expresses refinement, with
specific child rules evaluated before parent fallback rules.

## Language

**Zone membership**:
The interfaces, addresses and explicit match constraints that associate
packets with a zone, interpreted in the context of its hierarchy.

**Own section**:
A match section contributed by the zone's own declaration or an active
override. Descendant contributions do not make a section own.

**Descendant membership**:
The interfaces and addresses contributed by a zone's children and their
descendants. These contributions widen the ancestor's membership.

**Ancestor gate**:
A match constraint encountered on the path through a zone's ancestors.
From-side dispatch traverses these gates; to-side dispatch stays flat.

**Grouping zone**:
A zone without its own match, grouping descendants for hierarchical
dispatch. Descendant membership does not give it an own match.

**Node**:
A named host with an IPv4 address, an IPv6 address, or both, refining a
parent zone.

**Direction**:
An entry's source or destination selection, named `from` or `to`.

**Side**:
A zone's ingress or egress match perspective. The `from` direction uses
ingress; the `to` direction uses egress.
