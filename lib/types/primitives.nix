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
    - `comment`       — optional free-form string (`null` means no
                        comment). Shared shape for object-level
                        comments.
    - `rule`          — list of nftypes statements forming one rule
                        body. Shared shape for `filterRule` and the
                        inner list of `zoneMatchVariants`.
    - `entryPriority` — symbol-or-int sort key for ordering an
                        entry's emitted rules within its chain
                        (nftzones-internal; not the nftables chain
                        priority).
    - `chainPriority` — symbol-or-int for the nftables chain
                        priority (the netfilter `priority` attribute
                        on a base chain).
*/
{ inputs }:
let
  inherit (inputs) lib nftypes;

  identifier = lib.types.strMatching "[a-z][a-z0-9_-]*";

  comment = lib.types.nullOr lib.types.str;

  /*
    A list of nftypes statements spliced conjunctively into a
    single nftables rule. Each leaf passes through nftypes'
    attrTag validation, so consumers cannot smuggle hand-rolled
    libnftables-json shapes.
  */
  rule = lib.types.listOf nftypes.types.statement;

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
in
{
  inherit
    identifier
    comment
    rule
    entryPriority
    chainPriority
    ;
}
