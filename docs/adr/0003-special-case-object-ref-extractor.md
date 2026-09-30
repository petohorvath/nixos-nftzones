# Validate object references with a special-case extractor

`checkObjectRefs` finds named-object references (counters, limits,
quotas, ct helpers, sets, maps and so on) by pattern-matching the
statement variants that can carry them. The alternative was a generic
statement/expression walker, which would belong upstream in nftypes
(`nftypes.lib.walk.*`), since only nftypes knows which fields of each
variant hold sub-statements. nftypes has no such walker today, and
designing its API around a single consumer risks the wrong abstraction.
Upstream a generic walker once a second consumer appears.

## Consequences

The extractor is brittle to nftypes adding statement variants that
carry references. New variants need an explicit case.
