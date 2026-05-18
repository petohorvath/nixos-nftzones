/*
  types/primitives — shared low-level atoms used by the named types
  in this directory (`zone`, `filter`, …).

  Internal to `lib/types/`: this module is not merged into the public
  `nftzones.types` namespace. Consumers should reach for the named
  types (`zoneName`, `filterName`, `zoneComment`, `filterComment`,
  `filterRule`, `filterPriority`, …) that build on these primitives,
  not for the bare names below.

  Exported types:
    - `identifier`    — `[a-z][a-z0-9_-]*` string. Shared shape for
                        zone names and filter names.
    - `comment`       — optional nft-safe quoted string (`null` means
                        no comment). Shared shape for object-level
                        comments. Restricted character set + length
                        cap because nft has no string-escape grammar.
    - `rule`          — list of nftypes statements forming one rule
                        body. Shared shape for `filterRule` and the
                        inner list of `zoneMatchVariants`.
    - `matchRule`     — list restricted to match-clause statements
                        only (`{ match = ...; }`). Shape for
                        `zoneMatchOverrideSide`'s section types,
                        which get spliced as prefix-match clauses
                        into dispatch rules — verdicts and side-
                        effects there would short-circuit dispatch
                        or fire on every zone packet.
    - `entryPriority` — symbol-or-int sort key for ordering an
                        entry's emitted rules within its chain
                        (nftzones-internal; not the nftables chain
                        priority).
    - `chainPriority` — symbol-or-int for the nftables chain
                        priority (the netfilter `priority` attribute
                        on a base chain).
    - `chainOverride` — optional `{ hook; priority; }` submodule.
                        Pins a filter / snat / dnat entry to a
                        specific base chain instead of the group's
                        default placement. `null` (the default at
                        each consumer) keeps the default.
*/
{ inputs }:
let
  inherit (inputs) lib nftypes;

  identifier = lib.types.strMatching "[a-z][a-z0-9_-]*";

  /*
    nft's lexer has no string-escape grammar: `\` is a literal byte
    inside quoted strings, and the next bare `"` ends the token.
    A comment containing `"` would terminate early and trailing
    content would parse as further nft constructs — at table scope
    that includes nested `chain` blocks, which is a real firewall
    bypass (verified PoC: `comment "X"; chain bypass { ... }"`
    injects a chain with `policy accept` ahead of the user's
    chain).

    We can't render-escape our way out (no escape syntax to render
    into), so the type rejects `"`, `\`, and control chars at
    eval time, plus the kernel's NFTNL_UDATA_COMMENT_MAXLEN cap
    (128 bytes). Upstream `nftypes` enforces the same restriction
    at its schema + renderer layers; this local copy is defense-
    in-depth and surfaces the rejection earlier (at user input
    parse time, not render time) for a clearer error.
  */
  comment = lib.types.nullOr (
    lib.types.addCheck (lib.types.strMatching ''[^"\\[:cntrl:]]*'') (s: builtins.stringLength s <= 128)
  );

  /*
    A list of nftypes statements spliced conjunctively into a
    single nftables rule. Each leaf passes through nftypes'
    attrTag validation, so consumers cannot smuggle hand-rolled
    libnftables-json shapes.
  */
  rule = lib.types.listOf nftypes.types.statement;

  /*
    Match-only counterpart to `rule`. Each leaf must be a
    `{ match = ...; }` statement (the `eq` / `inSet` / `within`
    shape from `nftypes.dsl`); verdicts (accept/drop/jump/goto)
    and side-effecting statements (counter/log/limit/mark-set/
    NAT/mangle) are rejected at evalModules time by
    `nftypes.types.matchStatement`.

    Used by `zoneMatchOverrideSide` — those sections are spliced
    as prefix-match clauses into every dispatch rule for the
    zone, so a verdict would short-circuit dispatch before the
    per-pair sub-chain jump fires (security audit C2, verified
    PoC) and a side-effect would fire on every zone-matching
    packet rather than just the user's targeted ones.
  */
  matchRule = lib.types.listOf nftypes.types.matchStatement;

  /*
    Entry priority — nftzones-internal sort key for ordering an
    entry's emitted rules within its sub-chain. NOT the nftables
    chain priority (that's `chainPriority`). Symbols and their
    resolved int values:

      first        → 1    earliest
      preDispatch  → 50   before child-dispatch jumps in the
                          enclosing sub-chain
      postDispatch → 100  after child-dispatch jumps in the
                          enclosing sub-chain
      default      → 500  main user rules (also post-dispatch)
      last         → 999  latest

    Or any int directly. Compile pipeline sorts cells by
    `(resolved-priority asc, name asc)`. The cutoff at 100 splits
    a sub-chain's `preChildCells` slot (< 100, emitted before
    child-dispatch jumps) from `postChildCells` (≥ 100, emitted
    after). The symbol names are historical — originally cells
    landed in the *base chain* on either side of zone-dispatch
    jumps; after zone-parent landed, cells always live inside
    sub-chains and the slot is relative to *child*-dispatch.

    Symbol → int resolution lives in `internal.priority`;
    consumers don't need to do it themselves at type-check time.
  */
  entryPriority = lib.types.either (lib.types.enum [
    "first"
    "preDispatch"
    "postDispatch"
    "default"
    "last"
  ]) lib.types.int;

  /*
    Chain priority — the nftables-native `priority` attribute on a
    base chain. Symbols are netfilter conventions:

      raw      → -300
      mangle   → -150
      dstnat   → -100
      filter   →  0
      security →  50
      srcnat   →  100

    Symbol values come from `nftypes.compatibility.priorityIntsDefault`
    (inet/ip/ip6/arp/netdev family). Bridge family has different
    mappings; if multi-family ever lands, broaden to
    `attrNames priorityIntsDefault ++ attrNames priorityIntsBridge`
    and let `nftypes.resolvePriority` pick the right table at compile
    time. Or pass any int directly.
  */
  chainPriority = lib.types.either (lib.types.enum (builtins.attrNames nftypes.compatibility.priorityIntsDefault)) lib.types.int;

  /*
    Optional chain-placement override — `null` (the default at
    each consumer) keeps the group's default placement. A
    submodule with `hook` + `priority` pins the entry to a
    specific base chain. Shared shape for filters / snats / dnats;
    sroutes / droutes have no override path (their placement is
    fixed by group semantics).
  */
  chainOverride = lib.types.nullOr (
    lib.types.submodule {
      options = {
        hook = lib.mkOption {
          type = nftypes.types.hook;
          example = "prerouting";
          description = ''
            nftables hook the chain attaches to.
          '';
        };
        priority = lib.mkOption {
          type = chainPriority;
          example = "raw";
          description = ''
            Chain priority. Either an nftables symbol (`raw`,
            `mangle`, `dstnat`, `filter`, `security`, `srcnat`)
            or any int.
          '';
        };
      };
    }
  );
in
{
  inherit
    identifier
    comment
    rule
    matchRule
    entryPriority
    chainPriority
    chainOverride
    ;
}
