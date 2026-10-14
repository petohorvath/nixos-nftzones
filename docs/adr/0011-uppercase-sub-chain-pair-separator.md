# Separate zone pairs in sub-chain names with an uppercase `-TO-`

A zone pair's sub-chain name joins the two zones with `-TO-`, for example `forward-at-filter__lan-TO-wan`. Zone names may contain `-to-`, so with a lowercase separator two pairs, or a pair and a single zone, could build the same name: `a-to → b` and `a → to-b` both built `forward-at-filter__a-to-to-b`, and their cells shared one sub-chain behind one base-chain jump (#18). Uppercase letters are the only characters that nftypes renders unquoted in a chain name (`[A-Za-z_][A-Za-z0-9_-]*`) and that zone names (`[a-z][a-z0-9_-]*`) can't contain. Every pair name therefore splits at its single `-TO-`, and no pair name equals a single zone's.

## Considered options

- **Reject colliding names in Phase 1.** A check builds the name of every single zone and every ordered pair and rejects a table in which two match. Rejected: it also rejects tables such as zones `lan`, `wan` and `lan-to-wan` when no entry uses `lan → wan`, and it costs an O(n²) check and a user-facing error.
- **A separator outside nftypes' bare identifiers, such as `.` or `/`.** nft accepts both unquoted, but nftypes quotes any chain name outside `[A-Za-z_][A-Za-z0-9_-]*`, and nft rejects quoted chain names.
- **Forbid zone names that end in `-to` or start with `to-`.** Rejected: it breaks tables whose names never collide, and the rule is hard to explain.

## Consequences

- Every zone pair's sub-chain is renamed, and the uppercase `TO` reads less naturally than `-to-`. Single-zone sub-chains keep their names. Generated names are not a stable public surface (ADR-0002), but tooling that reads them must follow.
- Root jumps are emitted in sub-chain name order, and `T` sorts before lowercase letters. Root zones such as `lan` and `lan-guest` therefore swap jump order, which matters only when their matches overlap.
- A from-only and a to-only sub-chain for the same zone still share a name (#20).
