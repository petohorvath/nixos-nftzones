# Chain naming: `<hook>-at-<priority>` and `<base>__<key>`

Base chains are named `<hook>-at-<priority>` (for example
`forward-at-filter`), and sub-chains are named
`<baseChainName>__<subChainKey>` (for example
`forward-at-filter__lan-to-wan`). The original sketch used per-hook
names like `fwd-<from>-to-<to>`. The `<hook>-at-<priority>` form covers
every chain type and priority (filter, nat, route, mangle, raw and
security) and doubles as the Phase 3 bucket key, so one string travels
unchanged from dispatch to the emitted ruleset.

Generated chain names are not a stable public surface.
