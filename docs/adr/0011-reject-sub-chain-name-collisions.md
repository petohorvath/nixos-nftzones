# Reject sub-chain name collisions instead of escaping names

Sub-chain names join zone names with `-to-` (ADR-0002), and zone names may contain `-to-`, so two zone pairs, or a zone and a pair, can build the same name: `a-to → b` and `a → to-b` both build `forward-at-filter__a-to-to-b`. Their cells would then share one sub-chain behind one base-chain jump. Phase 1 rejects such a table instead. The check builds the name of every single zone and every ordered pair over all zone names, including nodes and the local zone, and calls the same naming function as dispatch, so the check and the emitted names can't drift.

## Considered options

- **Injective names, such as `a-TO-b`.** Uppercase is the one bare-identifier character zone names can't contain, and quoted chain names are risky. Rejected: it uglifies every chain name and amends ADR-0002.
- **Forbid zone names that end in `-to` or start with `to-`.** Rejected: it breaks tables whose names never collide, and the rule is hard to explain.

## Consequences

The check depends only on zone names, not on which pairs entries use. Adding an entry never makes a valid table invalid, but zones `lan`, `wan` and `lan-to-wan` are rejected even when no entry uses `lan → wan`. The check runs in O(n²) for n zone names.
