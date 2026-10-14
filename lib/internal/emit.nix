/*
  internal/emit — Phase 4 of the compile pipeline.

  Builds nftables base chains, per-pair sub-chains and table output
  with nftypes DSL builders. Zone semantics come from the resolved
  `ctx.zoneMembership` value produced in Phase 1. Emit supplies only
  the hook, direction and zone name when requesting match variants.

  Renders the dispatch trees from Phase 3 (`ctx.dispatchTrees`). The
  tree decides which sub-chains exist, which the base chain jumps to,
  and which a parent jumps to; emit only turns those decisions into
  rules. Each sub-chain emits pre-child cells, child jumps, then
  post-child cells (including policy tails). Child jumps re-check
  only the child's from-side match. Root jumps form the cartesian
  product of direction variants and drop incompatible IPv4/IPv6 pairs
  before adding the DSL jump statement.

  Pure helpers accept `zoneMembership` wherever sets, hierarchy or
  dispatch clauses are needed; callers do not coordinate raw zone
  declarations, active overrides and generated sets.
*/
{ inputs, internal }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes.dsl)
    accept
    dnat
    drop
    eq
    expr
    inSet
    jump
    masquerade
    redirect
    snat
    ;
  inherit (nftypes.dsl.fields)
    ct
    meta
    ;
  inherit (nftypes) chainTypeFor priorityNameOf;
  inherit (internal.placement) baseChainNameOf;

  # Boilerplate rule constants (each rule = list of statements).
  statefulRules = [
    [
      (inSet ct.state [
        "established"
        "related"
      ])
      accept
    ]
    [
      (eq ct.state "invalid")
      drop
    ]
  ];

  loopbackRules = [
    [
      (eq meta.iif "lo")
      accept
    ]
  ];

  rpfilterRules = [
    [
      (eq (expr.fib {
        result = "oif";
        flags = [
          "saddr"
          "iif"
        ];
      }) 0)
      drop
    ]
  ];

  /*
    Map a policy verdict string to its DSL verdict statement.
    Policies are limited to "accept" / "drop" by `policyVerdict`
    (see `lib/types/policy.nix`); attribute access fails fast
    for any other value.
  */
  policyVerdictStmts = { inherit accept drop; };

  /*
    Emit one cell's rule entry. A non-null `cell.comment` wraps the
    statement list as `{ expr; comment; }` — the alternate rule-list
    element shape per nftypes' `dsl/structure/table.nix`.

    Cell shape dispatch:
      - `cell ? verdict`            → policy
      - `cell.rule ? snat`          → snat with address translation
      - `cell.rule ? masquerade`    → snat masquerade
      - `cell.rule ? action`        → dnat (action.dnat | action.redirect)
      - else (`cell.rule` is list)  → filter / sroute / droute
  */
  mkRuleBody =
    cell:
    let
      stmts =
        if cell ? verdict then
          [ policyVerdictStmts.${cell.verdict} ]
        else if cell.rule ? snat then
          [ (snat cell.rule.snat) ]
        else if cell.rule ? masquerade then
          [ (masquerade cell.rule.masquerade) ]
        else if cell.rule ? action then
          cell.rule.match
          ++ [
            (if cell.rule.action ? dnat then dnat cell.rule.action.dnat else redirect cell.rule.action.redirect)
          ]
        else
          cell.rule;
    in
    if cell.comment != null then
      {
        expr = stmts;
        inherit (cell) comment;
      }
    else
      stmts;

  /*
    Build one sub-chain body. Body shape: a regular (non-base)
    chain with just a `rules` field. Rule order:

      1. preChildCells   — sorted (priority asc, name asc).
      2. child-dispatch jumps, one rule per child × from-side
         variant of the child's match.
      3. postChildCells  — sorted (priority asc, name asc;
                            policies appended last as tail rules).

    To-side is implicit: traffic inside a `__<parent>-TO-<to>`
    sub-chain already matched the to-side at the jump into it, so a
    child-dispatch jump only re-checks the from-side.
  */
  mkSubChain =
    {
      hook,
      subChain,
      subChains,
      zoneMembership,
    }:
    let
      mkChildJumps =
        childSubChainName:
        map (variant: variant ++ [ (jump childSubChainName) ]) (
          zoneMembership.directionVariants {
            inherit hook;
            direction = "from";
            zoneName = subChains.${childSubChainName}.from;
          }
        );
    in
    {
      rules =
        (map mkRuleBody subChain.preChildCells)
        ++ lib.concatMap mkChildJumps subChain.children
        ++ (map mkRuleBody subChain.postChildCells);
    };

  # Render every sub-chain of every dispatch tree, keyed by its full
  # name (see `placement.subChainNameOf`).
  mkSubChains =
    {
      dispatchTrees,
      zoneMembership,
    }:
    lib.foldlAttrs (
      acc: _baseChainName: tree:
      acc
      // lib.mapAttrs (
        _subChainName: subChain:
        mkSubChain {
          inherit (tree) hook subChains;
          inherit subChain zoneMembership;
        }
      ) tree.subChains
    ) { } dispatchTrees;

  /*
    Classify a variant (list of match statements) by network-layer
    family in a single fold: `"ip"` / `"ip6"` if any statement
    carries that payload protocol, `null` (family-agnostic) for
    interface-only, extra-only, or empty variants. Used by
    `mkRootJumpRules` to drop cross-family cartesian-product pairs
    that nft rejects with "conflicting network layer protocols
    specified".
  */
  variantFamily =
    variant:
    builtins.foldl' (
      acc: stmt: if acc != null then acc else stmt.match.left.payload.protocol or null
    ) null variant;

  /*
    Build the base-chain jumps for one dispatch tree, one per root
    sub-chain. Each root's from/to direction variants produce one
    jump per variant pair, dropping cross-family combinations (e.g.
    v4-from × v6-to) that nft refuses to compile in `inet` tables.
  */
  mkRootJumpRules =
    {
      tree,
      zoneMembership,
    }:
    let
      tagFamily = variant: {
        inherit variant;
        family = variantFamily variant;
      };

      variantsOf =
        direction: zoneName:
        map tagFamily (
          zoneMembership.directionVariants {
            inherit (tree) hook;
            inherit direction zoneName;
          }
        );

      mkJumpsForRoot =
        subChainName:
        let
          subChain = tree.subChains.${subChainName};
        in
        lib.pipe
          {
            from = variantsOf "from" (subChain.from or null);
            to = variantsOf "to" (subChain.to or null);
          }
          [
            lib.cartesianProduct
            (builtins.filter (
              { from, to }: from.family == null || to.family == null || from.family == to.family
            ))
            (map ({ from, to }: from.variant ++ to.variant ++ [ (jump subChainName) ]))
          ];
    in
    lib.concatMap mkJumpsForRoot tree.roots;

  mkBaseChain =
    {
      family,
      settings,
      tree,
      zoneMembership,
    }:
    let
      chainType = chainTypeFor family tree.hook tree.priority;
      priorityName = priorityNameOf family tree.priority;

      # `isFilterBaseChain` is the narrower predicate that gates
      # stateful + loopback boilerplate: chain at the canonical
      # `filter` priority specifically, not other filter-type
      # placements (`raw` for rpfilter, `security`, …). Compares
      # canonical names so bridge filter (-200) and ip filter (0)
      # both qualify.
      isFilterBaseChain = chainType == "filter" && priorityName == "filter";
      isInput = tree.hook == "input";

      statefulPrelude = lib.optionals (isFilterBaseChain && settings.stateful) statefulRules;
      loopbackPrelude = lib.optionals (isFilterBaseChain && isInput && settings.loopback) loopbackRules;

      jumpRules = mkRootJumpRules { inherit tree zoneMembership; };

      rules = statefulPrelude ++ loopbackPrelude ++ jumpRules;
    in
    {
      type = chainType;
      inherit (tree) hook;
      # `prio` is the JSON / nftypes-schema field name; internally
      # we use `priority` everywhere else.
      prio = nftypes.resolvePriority family tree.priority;
      inherit rules;
    }
    // lib.optionalAttrs isFilterBaseChain {
      policy = settings.chainPolicy;
    };

  mkBaseChains =
    {
      family,
      settings,
      dispatchTrees,
      zoneMembership,
    }:
    let
      fromTrees = lib.mapAttrs (
        _baseChainName: tree:
        mkBaseChain {
          inherit
            family
            settings
            tree
            zoneMembership
            ;
        }
      ) dispatchTrees;

      # rpfilter chain lives entirely here so user overrides at
      # `(prerouting, raw)` aren't silently mutated. Synthesized
      # only when the user hasn't already claimed the slot —
      # Phase 1's `checkRpfilterOverride` warns when both are
      # set so the user knows their override took precedence.
      # The key is built via `baseChainNameOf` (same helper Phase 3
      # uses) so int and symbol priority forms collapse to the same
      # key regardless of which form the user wrote.
      rpfilterBaseChainName = baseChainNameOf family {
        hook = "prerouting";
        priority = "raw";
      };
      needsRpfilter = settings.rpfilter && !(fromTrees ? ${rpfilterBaseChainName});
      synthesizedRpfilterChain = {
        type = "filter";
        hook = "prerouting";
        prio = nftypes.resolvePriority family "raw";
        rules = rpfilterRules;
      };
      rpfilterAddition = lib.optionalAttrs needsRpfilter {
        ${rpfilterBaseChainName} = synthesizedRpfilterChain;
      };
    in
    fromTrees // rpfilterAddition;

  assembleTable =
    {
      family,
      name,
      body,
    }:
    nftypes.dsl.table family name body;

  emitBaseChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        baseChains = mkBaseChains {
          inherit (table) family settings;
          inherit (ctx) dispatchTrees zoneMembership;
        };
      };
    };

  emitSubChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        subChains = mkSubChains {
          inherit (ctx) dispatchTrees zoneMembership;
        };
      };
    };

  /*
    Pure passthrough: `table.objects.<kind>.<name>` maps directly to
    `body.<kind>.<name>` in the assembled `nftypes.dsl.table` value.
    The type layer's `asUserBody` (in `lib/types/table.nix`) has
    already stripped `family` / `name` / `table` / `handle`; the
    nftypes renderer fills them back in from the parent table.
  */
  emitUserObjects =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        userObjects = table.objects;
      };
    };

  assembleOutput =
    { table, ctx }:
    let
      # Base chains and sub-chains share the body's `chains` field;
      # keys won't collide because base chains use the bare
      # `<chain-key>` and sub-chains use `<chain-key>__<sub-key>`.
      allChains = ctx.baseChains // ctx.subChains;

      # User-defined sets merge with the auto-generated zone sets
      # under one `body.sets` field. Collisions are rejected
      # upstream by `internal.normalize.checkSetNameCollisions`,
      # so this merge is always safe — `//` semantics don't matter.
      allSets = ctx.zoneMembership.sets // (ctx.userObjects.sets or { });

      # Other user-object kinds pass through as their own body
      # field. Empty kinds are skipped so the output stays clean.
      otherUserObjectKinds = lib.filterAttrs (_: v: v != { }) (removeAttrs ctx.userObjects [ "sets" ]);

      body =
        lib.optionalAttrs (table.flags != [ ]) { inherit (table) flags; }
        // lib.optionalAttrs (table.comment != null) { inherit (table) comment; }
        // lib.optionalAttrs (allSets != { }) { sets = allSets; }
        // lib.optionalAttrs (allChains != { }) { chains = allChains; }
        // otherUserObjectKinds;
    in
    {
      inherit table;
      ctx = ctx // {
        output = assembleTable {
          inherit (table) family name;
          inherit body;
        };
      };
    };

  emitTable =
    state:
    lib.pipe state [
      emitBaseChains
      emitSubChains
      emitUserObjects
      assembleOutput
    ];
in
{
  inherit
    assembleOutput
    assembleTable
    emitBaseChains
    emitSubChains
    emitTable
    emitUserObjects
    mkBaseChain
    mkBaseChains
    mkRootJumpRules
    mkRuleBody
    mkSubChain
    mkSubChains
    ;
}
