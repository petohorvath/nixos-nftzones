# Compile one table at a time

`mkTable` and `mkRuleset` each take a single table. Consumers that need
several tables compose externally, for example
`nftypes.dsl.ruleset [ (mkTable "a" bodyA) (mkTable "b" bodyB) ]`.
A multi-table entry point would add surface without a known consumer.
Revisit only when a real consumer wants a single call. This also scopes
zone parents to one table.
