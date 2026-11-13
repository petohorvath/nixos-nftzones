# `from = [ "all" ]` expands to root zones only

A from-side wildcard expands to root zones plus the local zone, not to
every zone. Descendant traffic still reaches the wildcard's cells,
because each root's match covers its subtree (ADR-0006). Expanding to
every zone would emit redundant cells in every descendant sub-chain.
`to = [ "all" ]` still expands to every zone, because the to side has no
hierarchy. This was a deliberate breaking change, accepted before 1.0.

## Amended

[#54](https://github.com/petohorvath/nixos-nftzones/issues/54) keeps
the expansion to root zones and narrows what the wildcard covers. A
wildcard in either direction stands for every declared zone and the
local zone, and nothing else: traffic on an interface or address
outside every zone falls through to the chain policy at every hook.
Before, the local zone's cell matched every packet at input,
postrouting and prerouting, so the wildcard covered that traffic there
by accident, but not at forward. A wildcard also leaves the local zone
out at a hook where ADR-0013 rejects it, such as the `from` side at
prerouting.
