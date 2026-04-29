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
    - `rulePriority`  — symbol-or-int sort key for ordering rules
                        within a chain (nftzones-internal; not the
                        nftables chain priority).
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
    Rule priority — nftzones-internal sort key for ordering rules
    within a chain. NOT the nftables chain priority (that's
    `chainPriority`). Symbols and their resolved int values:

      first        → 1    earliest
      preDispatch  → 50   before per-zone dispatch jumps
      postDispatch → 100  after per-zone dispatch jumps
      default      → 500  main user rules
      last         → 999  latest

    Or any int directly. Compile pipeline sorts cells by
    `(resolved-priority asc, name asc)`. The cutoff at 100 splits
    pre-dispatch (< 100) from post-dispatch (>= 100) in the
    generated chain layout.

    Symbol → int resolution lives in `internal.priority`;
    consumers don't need to do it themselves at type-check time.
  */
  rulePriority = lib.types.either (lib.types.enum [
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
    rulePriority
    chainPriority
    ;
}
