# Security audit — 2026-05-19

Audit of the nftzones type layer, Phase 1 validators, dispatch/expand/emit, NixOS module integration, and the upstream `nftypes` schema/text-renderer paths that this library consumes.

## Threat model

The library compiles user-supplied Nix attrsets into nftables ruleset text that nixpkgs activates atomically. The user already controls the Nix config, so the boundary worth defending is not privilege escalation but:

1. Type-system intent vs. emitted ruleset — user writes "deny X" and the compiler emits something that lets X through.
2. nft-grammar injection via comment / identifier fields. nft's block-form lexer has no string-escape grammar: `\` is a literal byte and the next bare `"` ends the token. A comment containing `"` can break out at table scope and inject a `chain bypass { policy accept; }`.
3. Defaults that silently disable security — empty tables compiling to a no-firewall state, accept-by-default chain policies, coexistence with `networking.firewall`.

## Findings

### Retracted

**M1, M2 — comment-injection defense via the `objects` escape hatch.** Initially flagged as a defense-in-depth gap on the assumption that nftypes' `comment` fields used unrestricted `types.nullOr types.str`. Verification against the actual upstream `nftypes` at the pinned rev (`4f87e2400386c59663551d017cb4e91331e847f9`) showed the fix is already in place: `lib/schema/primitives.nix` defines `nftQuotedString` (rejects `"` / `\` / control chars; ≤128 bytes), and it is applied to every object-body `comment`, set/map element `comment`, log-prefix string, and table/chain/rule comment via the shared `commentOption` (`lib/schema/objects.nix:105-115`, applied at lines 119, 181, 226, 243; element form at `lib/schema/expressions.nix:423-427`). The text renderer mirrors the predicate at render time as defense-in-depth.

Empirical confirmation:

```
$ nix eval --impure --expr '
    let f = builtins.getFlake (toString ./.);
        nftzones = f.lib.x86_64-linux;
    in nftzones.mkTable "evil" {
         zones.lan.interfaces = [ "lan0" ];
         objects.counters.x.comment = "foo\"; chain bypass { policy accept; }; #";
       }'

error: A definition for option `evil.objects.counters.x.comment' is not of type
       `null or nft-safe quoted string (no '"', '\', or control characters; ≤128 bytes)'.
```

The docstring at `lib/types/primitives.nix:58-63` (claiming "upstream `nftypes` enforces the same restriction at its schema + renderer layers; this local copy is defense-in-depth") is therefore accurate as of the pinned `nftypes` rev. No action.

### Standing

**M3 — `checkObjectRefs` walks an explicit group list with no defensive comment.** `lib/internal/normalize.nix:1967-1975` lists `filters / snats / dnats / sroutes / droutes` literally rather than deriving them from a shared group-name list. `policies` is correctly omitted (no rule body — verdict only), but the omission has no defensive comment. If a future rule-bearing group lands, refs inside it would silently miss validation and surface only at `nft load` time.

Fix landed in this branch: added a defensive comment above the `allRefs` block explaining the intentional `policies` omission and warning future contributors to add new rule-bearing groups explicitly.

**L1 — Same-name zone/node collision clobbers the original zone in `mergedZones`.** `lib/internal/normalize.nix:603`: `table.zones // lib.mapAttrs (_: toZone) table.nodes` is right-biased, so a node with the same name as a declared zone replaces the zone's interfaces / CIDRs before `checkNameCollisions` flags the issue. The final aggregated throw still fires (`checkNameCollisions` runs in the same pass), but secondary validators (overlap, matchable) run against the clobbered shape and may emit confusing errors. Not exploitable. Defense-in-depth fix would be to skip the merge for already-claimed names or use a left-biased merge.

**L2 — `matchOverride.<side>.interfaces` is conventional, not enforced.** The type restricts the section to match-statements via `nftypes.types.matchStatement` but doesn't require statements to carry iif/oif content. `checkChainOverridePlacement` (`normalize.nix:1539`) gates the section on hook iif/oif availability but cannot enforce semantic intent of the field name. Result: a hook-incompatible match silently applies at hooks that DO have iif. No security impact.

### Info — defense-in-depth opportunities

- `extractRefs` only validates refs in singleton attrTag statements. Hand-rolled multi-key statement shapes would slip the ref check, but `nftypes.types.statement` (attrTag) rejects such shapes upstream — theoretical unless the DSL surface broadens.
- A user can `(jump "input-at-filter__lan-to-wan")` to a generated sub-chain by name, bypassing zone dispatch. Generated names aren't a stable public surface but aren't sealed either. Documented as out-of-scope in `normalize.nix:482-487`.
- The module's `enable && tables == {}` assertion (`modules/nftzones.nix:102-117`) guards against accidental no-firewall state. Consider extending the same posture to `chainPolicy = "accept" && filters == {}`.
- VM tests don't cover the comment-injection vector. A fixture with a counter whose `comment` contains `";` (asserting it's rejected at compile time) would lock the defense down.

## What's solid

- The pipeline is a pure-function chain; no shell-out, no file IO, no string concatenation directly into nft text outside the type-restricted `renderTableMetadata` in `modules/nftzones.nix:42-49` (which only renders `tableComment` — already `primitives.comment`-restricted — and `tableFlags` — enum-restricted).
- Identifiers, hooks, priorities, families, flags, and policy verdicts are all enum- or regex-restricted at the type layer. No path was found from user input into rule-body or chain-name text that doesn't go through `nftypes.dsl.*` (attrTag-validated) or `primitives.identifier`.
- CIDR-overlap math is family-correct, handles intra-zone duplicates, and correctly skips ancestor-pair overlaps.
- Phase 1 aggregates all errors into a single throw — no validator short-circuits the rest.
- The collision detection in the NixOS module correctly counts pre-merge contributions, sidestepping the naive "key present?" false-positive when the module's own contribution lands in `definitions`.
- Default chain policy is `drop`; default `rpfilter` is `false` (opt-in); stateful and loopback shortcuts default to `true`.

## Process note

This audit's initial M1 and M2 findings were drawn from a stale checkout of `nix-nftypes` under `/tmp/`. The flake-lock-pinned rev under `/home/dev/projects/nix-nftypes` was substantially newer and already carried the relevant fix. For future cross-repo audits: resolve the actual sibling repo via `flake.lock`'s `rev` field before drawing conclusions about upstream behaviour.
