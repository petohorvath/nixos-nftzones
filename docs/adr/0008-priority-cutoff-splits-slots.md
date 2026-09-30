# Entry priority 100 splits pre-child and post-child slots

Inside each sub-chain, cells with resolved entry priority below 100 go
in the pre-child slot, before the child-dispatch jumps. All other cells
go in the post-child slot, after the jumps. Policies are appended to the
post-child slot as tail rules. The default priority (500) therefore
makes parent rules fallbacks for descendant traffic, while
`preDispatch` (50) lets a parent apply a rule to its whole subtree
first, such as a bogon drop.

The cutoff replaced an earlier base-chain pre/post-dispatch split. That
kept the existing priority symbols but changed where they land. Base
chains now hold only boilerplate and jumps to root zones.
