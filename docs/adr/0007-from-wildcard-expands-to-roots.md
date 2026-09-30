# `from = [ "all" ]` expands to root zones only

A from-side wildcard expands to root zones plus the local zone, not to
every zone. Descendant traffic still reaches the wildcard's cells,
because each root's match covers its subtree (ADR-0006). Expanding to
every zone would emit redundant cells in every descendant sub-chain.
`to = [ "all" ]` still expands to every zone, because the to side has no
hierarchy. This was a deliberate breaking change, accepted before 1.0.
