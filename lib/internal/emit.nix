/*
  internal/emit — Phase 4 of the compile pipeline.

  Builds nftables base chains, per-pair sub-chains and table output
  with nftypes DSL builders. Zone semantics come from the resolved
  `ctx.zoneMembership` value produced in Phase 1. Emit supplies only
  the hook, direction and zone name when requesting match variants.

  From-side dispatch is hierarchical: roots jump from base chains;
  descendants jump from their parents' sub-chains. Missing intermediate
  sub-chains are synthesized along the ancestor path. Each sub-chain
  emits pre-child cells, child jumps, then post-child cells (including
  policy tails), preserving child-first dispatch and parent fallback.
  To-side dispatch remains flat and is not repeated in child jumps.
  Root jumps form the cartesian product of direction variants and drop
  incompatible IPv4/IPv6 pairs before adding the DSL jump statement.

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
    Build the full nftables sub-chain name from a base chain name
    and a sub-chain key (Phase 3's local key within
    `bucket.subChains`). Output is the `<base>__<sub>` form per
    design doc §4.3 — used as the chain attribute in
    `body.chains` for sub-chains and as the `jump` target in base
    chains.
  */
  subChainNameOf = baseChainName: subChainKey: "${baseChainName}__${subChainKey}";

  /*
    Compose a sub-chain key from explicit `(fromZone, toZone)`
    components — mirrors `placement.subChainKeyOf` but operates on
    the unpacked pair instead of a cell. Used by
    `buildEffectiveSubChains` to generate intermediate-parent
    keys without re-parsing strings.
  */
  mkSubChainKey =
    fromZone: toZone:
    if fromZone != null && toZone != null then
      "${fromZone}-to-${toZone}"
    else if fromZone != null then
      fromZone
    else
      toZone;

  /*
    For one base chain bucket, compute the full set of sub-chain
    records to emit — direct cell-bearing sub-chains plus
    transparent intermediate-parent dispatchers synthesized along
    each cell-bearing sub-chain's parent chain. Returns an
    attrset keyed by `subChainKey`.

    Why intermediates: only root from-zones jump from the base
    chain. A descendant zone with cells (e.g., `web-server`) is
    only reachable through a chain of parent dispatch jumps
    starting at its root ancestor. If any ancestor lacks its own
    cells, an empty placeholder chain still has to exist so the
    parent can dispatch into it.

    Direct sub-chain records carry `preChildCells` and
    `postChildCells` from Phase 3. Synthesized intermediates are
    seeded with empty cell lists; Phase 4 emit fills them with
    just the child-dispatch jumps.

    `bucket.subChains` overrides any intermediate placeholder
    that turned out to share its key with a cell-bearing
    sub-chain.
  */
  buildEffectiveSubChains =
    bucket: zoneMembership:
    let
      mkEmptyRecord =
        fromZone: toZone:
        lib.optionalAttrs (fromZone != null) { from = fromZone; }
        // lib.optionalAttrs (toZone != null) { to = toZone; }
        // {
          preChildCells = [ ];
          postChildCells = [ ];
        };

      intermediatesOf =
        record:
        let
          fromZone = record.from or null;
          toZone = record.to or null;
        in
        lib.foldl' (
          acc: ancestor:
          let
            key = mkSubChainKey ancestor toZone;
          in
          if acc ? ${key} then acc else acc // { ${key} = mkEmptyRecord ancestor toZone; }
        ) { } (zoneMembership.ancestorsOf fromZone);

      allIntermediates = lib.foldlAttrs (
        acc: _subChainKey: record:
        acc // intermediatesOf record
      ) { } bucket.subChains;
    in
    allIntermediates // bucket.subChains;

  /*
    Build child-dispatch jumps for one parent sub-chain. For each
    child of `parentFromZone` whose subtree has content for this
    `(baseChainName, toZone)`, emit one jump per from-side
    variant of the child's match.

    To-side is implicit: by the time we're inside a
    `__<parent>-to-<to>` sub-chain, traffic already matched the
    to-side at the chain-jump point. Child-dispatch only re-checks
    the from-side, narrowing into the more specific child match.
  */
  mkChildDispatchJumpRules =
    {
      hook,
      parentFromZone,
      toZone,
      baseChainName,
      effectiveSubChains,
      zoneMembership,
    }:
    let
      children =
        if parentFromZone == null then [ ] else zoneMembership.childrenOf.${parentFromZone} or [ ];

      mkJumpsForChild =
        childName:
        let
          childKey = mkSubChainKey childName toZone;
        in
        if !(effectiveSubChains ? ${childKey}) then
          [ ]
        else
          let
            fromVariants = zoneMembership.directionVariants {
              inherit hook;
              direction = "from";
              zoneName = childName;
            };
            jumpStmt = jump (subChainNameOf baseChainName childKey);
          in
          map (variant: variant ++ [ jumpStmt ]) fromVariants;
    in
    lib.concatMap mkJumpsForChild children;

  /*
    Build one sub-chain body. Body shape: a regular (non-base)
    chain with just a `rules` field. Rule order:

      1. preChildCells   — sorted (priority asc, name asc).
      2. child-dispatch jumps to children with content (one rule
         per child × from-side variant).
      3. postChildCells  — sorted (priority asc, name asc;
                            policies appended last as tail rules).

    Sub-chains with no `from` field (droute-style) carry no
    child-dispatch (hierarchy is from-side only); their body
    reduces to `preChildCells ++ postChildCells`.
  */
  mkSubChain =
    {
      hook,
      subChain,
      baseChainName,
      effectiveSubChains,
      zoneMembership,
    }:
    let
      parentFromZone = subChain.from or null;
      toZone = subChain.to or null;

      childJumps = mkChildDispatchJumpRules {
        inherit
          baseChainName
          effectiveSubChains
          hook
          parentFromZone
          toZone
          zoneMembership
          ;
      };
    in
    {
      rules =
        (map mkRuleBody subChain.preChildCells) ++ childJumps ++ (map mkRuleBody subChain.postChildCells);
    };

  /*
    Walk every base chain bucket's effective sub-chains,
    producing one sub-chain entry per `(baseChainName,
    subChainKey)` pair, keyed by the full sub-chain name (see
    `subChainNameOf`).
  */
  mkSubChains =
    {
      chainBuckets,
      effectiveSubChainsByBucket,
      zoneMembership,
    }:
    lib.foldlAttrs (
      acc: baseChainName: bucket:
      let
        effectiveSubChains = effectiveSubChainsByBucket.${baseChainName};
      in
      acc
      // lib.mapAttrs' (
        subChainKey: subChain:
        lib.nameValuePair (subChainNameOf baseChainName subChainKey) (mkSubChain {
          inherit (bucket) hook;
          inherit
            baseChainName
            effectiveSubChains
            subChain
            zoneMembership
            ;
        })
      ) effectiveSubChains
    ) { } chainBuckets;

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
    Build the root-zone dispatch jumps for one base chain bucket.
    Walks each effective sub-chain; emits jumps only for
    sub-chains whose `from` is a root from-zone (or whose
    sub-chain has no `from` at all, like droute-style entries
    which still flat-dispatch from the base chain).

    Non-root (descendant) sub-chains are reachable only via their
    parent's child-dispatch; they don't get base-chain jumps.

    For each emitted sub-chain, computes the from/to direction
    variants and produces one jump per variant pair, dropping
    cross-family combinations (e.g. v4-from × v6-to) that nft
    refuses to compile in `inet` tables.
  */
  mkRootJumpRules =
    {
      hook,
      baseChainName,
      effectiveSubChains,
      zoneMembership,
    }:
    let
      tagFamily = variant: {
        inherit variant;
        family = variantFamily variant;
      };

      mkJumpsForSubChain =
        subChainKey: subChain:
        let
          fromZone = subChain.from or null;
          toZone = subChain.to or null;
          isRoot = fromZone == null || builtins.elem fromZone zoneMembership.rootZoneNames;
        in
        if !isRoot then
          [ ]
        else
          let
            fromVariants = map tagFamily (
              zoneMembership.directionVariants {
                inherit hook;
                direction = "from";
                zoneName = fromZone;
              }
            );
            toVariants = map tagFamily (
              zoneMembership.directionVariants {
                inherit hook;
                direction = "to";
                zoneName = toZone;
              }
            );
            jumpStmt = jump (subChainNameOf baseChainName subChainKey);
          in
          lib.pipe
            {
              from = fromVariants;
              to = toVariants;
            }
            [
              lib.cartesianProduct
              (builtins.filter (
                { from, to }: from.family == null || to.family == null || from.family == to.family
              ))
              (map ({ from, to }: from.variant ++ to.variant ++ [ jumpStmt ]))
            ];
    in
    lib.concatLists (lib.mapAttrsToList mkJumpsForSubChain effectiveSubChains);

  mkBaseChain =
    {
      family,
      settings,
      bucket,
      baseChainName,
      effectiveSubChains,
      zoneMembership,
    }:
    let
      chainType = chainTypeFor family bucket.hook bucket.priority;
      priorityName = priorityNameOf family bucket.priority;

      # `isFilterBaseChain` is the narrower predicate that gates
      # stateful + loopback boilerplate: chain at the canonical
      # `filter` priority specifically, not other filter-type
      # placements (`raw` for rpfilter, `security`, …). Compares
      # canonical names so bridge filter (-200) and ip filter (0)
      # both qualify.
      isFilterBaseChain = chainType == "filter" && priorityName == "filter";
      isInput = bucket.hook == "input";

      statefulPrelude = lib.optionals (isFilterBaseChain && settings.stateful) statefulRules;
      loopbackPrelude = lib.optionals (isFilterBaseChain && isInput && settings.loopback) loopbackRules;

      jumpRules = mkRootJumpRules {
        inherit (bucket) hook;
        inherit
          baseChainName
          effectiveSubChains
          zoneMembership
          ;
      };

      rules = statefulPrelude ++ loopbackPrelude ++ jumpRules;
    in
    {
      type = chainType;
      inherit (bucket) hook;
      # `prio` is the JSON / nftypes-schema field name; internally
      # we use `priority` everywhere else.
      prio = nftypes.resolvePriority family bucket.priority;
      inherit rules;
    }
    // lib.optionalAttrs isFilterBaseChain {
      policy = settings.chainPolicy;
    };

  mkBaseChains =
    {
      family,
      settings,
      chainBuckets,
      effectiveSubChainsByBucket,
      zoneMembership,
    }:
    let
      fromBuckets = lib.mapAttrs (
        baseChainName: bucket:
        mkBaseChain {
          inherit
            baseChainName
            bucket
            family
            settings
            zoneMembership
            ;
          effectiveSubChains = effectiveSubChainsByBucket.${baseChainName};
        }
      ) chainBuckets;

      # rpfilter chain lives entirely here so user overrides at
      # `(prerouting, raw)` aren't silently mutated. Synthesized
      # only when the user hasn't already claimed the slot —
      # Phase 1's `checkRpfilterOverride` warns when both are
      # set so the user knows their override took precedence.
      # Bucket key is built via `baseChainNameOf` (same helper Phase
      # 3 uses) so int and symbol priority forms collapse to the
      # same key regardless of which form the user wrote.
      rpfilterBucketKey = baseChainNameOf family {
        hook = "prerouting";
        priority = "raw";
      };
      needsRpfilter = settings.rpfilter && !(fromBuckets ? ${rpfilterBucketKey});
      synthesizedRpfilterChain = {
        type = "filter";
        hook = "prerouting";
        prio = nftypes.resolvePriority family "raw";
        rules = rpfilterRules;
      };
      rpfilterAddition = lib.optionalAttrs needsRpfilter {
        ${rpfilterBucketKey} = synthesizedRpfilterChain;
      };
    in
    fromBuckets // rpfilterAddition;

  assembleTable =
    {
      family,
      name,
      body,
    }:
    nftypes.dsl.table family name body;

  /*
    Materialize each base chain bucket's effective sub-chains
    (direct + intermediate dispatchers) once at the start of
    Phase 4, before anything reads them. Both `mkBaseChain` (for
    root-jump emission) and `mkSubChain` (for child-dispatch
    emission and chain body construction) consume the same
    artifact — caching avoids the parent-chain walks happening
    twice per bucket.

    Mirrors the `ctx.zoneMembership.sets` precedent: one fold in Phase 1
    feeds two Phase 1 validators and Phase 4 emit.
  */
  computeEffectiveSubChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        effectiveSubChainsByBucket = lib.mapAttrs (
          _baseChainName: bucket: buildEffectiveSubChains bucket ctx.zoneMembership
        ) ctx.chainBuckets;
      };
    };

  emitBaseChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        baseChains = mkBaseChains {
          inherit (table) family settings;
          inherit (ctx)
            chainBuckets
            effectiveSubChainsByBucket
            zoneMembership
            ;
        };
      };
    };

  emitSubChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        subChains = mkSubChains {
          inherit (ctx)
            chainBuckets
            effectiveSubChainsByBucket
            zoneMembership
            ;
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
      computeEffectiveSubChains
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
    buildEffectiveSubChains
    computeEffectiveSubChains
    emitBaseChains
    emitSubChains
    emitTable
    emitUserObjects
    mkBaseChain
    mkBaseChains
    mkChildDispatchJumpRules
    mkRootJumpRules
    mkRuleBody
    mkSubChain
    mkSubChainKey
    mkSubChains
    subChainNameOf
    ;
}
