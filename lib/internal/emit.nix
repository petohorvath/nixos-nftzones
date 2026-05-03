/*
  internal/emit — Phase 4 of the compile pipeline, exposed under
  `nftzones.internal.emit`.

  Composes the rest of the pipeline state into one
  `nftypes.dsl.table` value via small focused helpers. Output is
  written to `ctx.output`.

  Pipeline pattern: each phase takes `{ table; ctx }` and returns
  the same shape, mirroring earlier phases.

  Phase pipeline (Phase 4, post-step-5 — every sub-phase below
  contributes one `ctx` artifact; `assembleOutput` rolls them
  into the final table body):

      { table; ctx (post-Phase 3) }
        ↓ emitBaseChains   ctx.baseChains    (reads ctx.zoneSets for jumps)
        ↓ emitSubChains    ctx.subChains
        ↓ emitUserObjects  ctx.userObjects
        ↓ assembleOutput   ctx.output        (nftypes.dsl.table value)
      { table; ctx }

  `ctx.zoneSets` is materialized once in Phase 1
  (`internal.normalize.computeZoneSets`) — the same artifact
  serves both Phase 1 validators (`checkSetNameCollisions`,
  `checkObjectRefs`) and Phase 4 emit (jump construction +
  `assembleOutput`'s final body), avoiding redundant evaluation.

  ===== assembleTable =====

  Input:  `{ family; name; body; }`
  Output: an `nftypes.dsl.table` marker value.

  Thin wrapper around `nftypes.dsl.table family name body` so
  callers stay on the named-attrset shape. `body` may carry
  `sets`, `chains`, object containers, and table-level options
  (`flags`, `comment`); all are optional. As Phase 4 grows the
  body expands.

  ===== chainTypeOf =====

  Pure helper: derives the nftables chain *type* (`filter` / `nat`
  / `route`) from a chain's `(hook, priority)`. nftypes does not
  expose this mapping — `nftypes.enums.chainType` lists the three
  values and `nftypes.compatibility.familiesByChainType` validates
  family compatibility, but neither derives type from priority.
  See `docs/compile-pipeline-draft.md` §4.2 for the rule.

  Currently uses `priorityIntsDefault` (inet/ip/ip6/arp/netdev
  family) for the comparison; bridge family has different priority
  ints and is a documented limitation.

  ===== mkRuleBody =====

  Pure helper: emit one cell's rule body (list of nftypes
  statements). Dispatches on cell shape — no explicit group arg
  needed. See the `===== Output shape =====` section in
  `lib/internal/expand.nix` for the per-group cell shapes this
  consumes:
    - `cell ? verdict`         → policy (single verdict statement)
    - `cell.rule ? snat`       → snat with address translation
    - `cell.rule ? masquerade` → snat masquerade
    - `cell.rule ? action`     → dnat (match clauses + dnat /
                                 redirect action)
    - else                     → filter / sroute / droute (cell.rule
                                 is already a list of statements)

  All NAT/verdict statements are constructed via `nftypes.dsl.*`
  builders so they pass the marker-validation that prevents raw
  libnftables-json shapes from leaking through.

  ===== mkSubChain =====

  Pure helper: build one sub-chain body (regular non-base chain
  with a `rules` field) from a list of cells. Cells are already
  sorted by Phase 3 (priority asc, name asc; policies last as
  tail rules) so this just maps `mkRuleBody` over them in order.

  ===== subChainNameOf =====

  Pure helper: build the full nftables sub-chain name from a
  `baseChainName` (`"<hook>-at-<priority>"` from Phase 3) and a
  `subChainKey` (Phase 3's local key within `bucket.subChains`,
  e.g. `"lan-to-wan"` / `"wan"`). Output is `"<base>__<sub>"` per
  design doc §4.3 — used both as the chain attribute in
  `body.chains` for sub-chains and as the `jump` target in base
  chains.

  ===== mkSubChains =====

  Walks `ctx.chainBuckets.<baseChainName>.subChains.<subChainKey>`
  producing one sub-chain entry per `(baseChainName, subChainKey)`
  pair, keyed by the full sub-chain name (see `subChainNameOf`).
  Reuses Phase 3 keys verbatim so the name → `(hook, priority,
  from, to)` mapping is mechanical and auditable in the generated
  JSON.

  ===== mkDirectionVariants =====

  Pure helper: build the match-clause variants for one direction
  (`from` / `to`) of one sub-chain at a given hook. Returns a
  list of variants — each variant is a list of statements ANDed
  within a single rule. The cartesian product across both
  directions is taken in `mkJumpRules`.

  Why per-variant rather than ANDed clauses: in `inet` family,
  `ip <addr>` and `ip6 <addr>` clauses can't be ANDed in the
  same rule — packets of the wrong family skip the rule entirely.
  So one variant per address family with a non-empty set, plus
  the optional interface prefix when the hook allows it.

  Variant count per direction (where both interfaces and CIDRs
  are family-segregated by `internal.zone.genSets`):

    zone has        | variants emitted
    ----------------|-----------------------
    empty           | 0
    iface only      | 1 (family-agnostic)
    v4 only         | 1
    v6 only         | 1
    v4 + v6         | 2
    iface + v4      | 1 (iface prefix + v4)
    iface + v6      | 1 (iface prefix + v6)
    iface + v4 + v6 | 2 (each with iface prefix)

  Set references (`@<zone>_iifs`, `@<zone>_v4`, `@<zone>_v6`)
  point at the zone-derived sets emitted by Phase 1's
  `computeZoneSets`.

  Wildcard cases:
    - `zoneName == null` (single-direction sub-chain — dnat /
      sroute have no `to`, droute has no `from`).
    - `zoneName == localZone` (sentinel; matched by the chain
      dispatch already, no further constraint).
  Both return `[ [ ] ]` (one empty variant, contributing nothing
  to the cartesian product).

  ===== mkJumpRules =====

  Pure helper: build the jump rules for one base chain bucket.
  For each sub-chain, computes the `from` / `to` direction
  variants and emits one jump per variant pair (cartesian
  product). Each jump = `<from-stmts> ++ <to-stmts> ++ [ jump
  (subChainNameOf baseChainName subChainKey) ]`.

  Family-mismatch waste: in `inet` with both v4 and v6 sets on
  each direction, the cartesian product produces (v4-from,
  v6-to) and (v6-from, v4-to) jumps in addition to the
  matched-family pairs. They're harmless (skip on family
  mismatch) but bloat the chain. Optimization deferred — see
  `docs/compile-pipeline-draft.md` §4.4.

  ===== mkBaseChain =====

  Pure helper: produces one base chain attrset (chainBody shape per
  `nftypes.dsl.table` docstring) for a given `{ family; settings;
  bucket; baseChainName; zoneSets; }`. Includes:
    - `type` derived via `chainTypeOf`.
    - `hook`, `prio` (priority resolved to int via
      `nftypes.resolvePriority`).
    - `policy` (filter chains only) from `settings.chainPolicy`.
    - `rules` — boilerplate for filter chains, plus user cells
      from `bucket.preDispatch` / `bucket.postDispatch` (each
      cell emitted via `mkRuleBody`), plus sub-chain dispatch
      jumps (via `mkJumpRules`):
        1. stateful   (`ct state established,related accept`,
                       `ct state invalid drop`) when filter chain
                       and `settings.stateful`.
        2. loopback   (`iif lo accept`) when filter input chain
                       and `settings.loopback`.
        3. rpfilter   (`fib saddr . iif oif eq 0 drop`) when
                       chain is `prerouting-at-raw` and
                       `settings.rpfilter`.
        4. preDispatch  cells — `map mkRuleBody bucket.preDispatch`.
        5. sub-chain jumps    — `mkJumpRules` (one rule per
                                 sub-chain × variant pair).
        6. postDispatch cells — `map mkRuleBody bucket.postDispatch`.

  ===== mkBaseChains =====

  Walks `ctx.chainBuckets` producing the chain attrset for the
  table body. Threads `baseChainName` (the bucket attr name) and
  `zoneSets` to `mkBaseChain` for jump-rule construction. If
  `settings.rpfilter` is enabled and no user override has
  produced a `prerouting-at-raw` bucket, synthesizes one so the
  rpfilter rule has a chain to live in.

  ===== emitBaseChains =====

  Reads:  ctx.chainBuckets, ctx.zoneSets, table.{family, settings}
  Writes: ctx.baseChains

  Pipeline phase that wraps `mkBaseChains` and stashes the chain
  attrset on `ctx`. Reads `ctx.zoneSets` (produced in Phase 1 by
  `internal.normalize.computeZoneSets`) to construct the jump-match
  clauses.

  ===== emitSubChains =====

  Reads:  ctx.chainBuckets
  Writes: ctx.subChains

  Pipeline phase that wraps `mkSubChains` and stashes the sub-chain
  attrset on `ctx`.

  ===== mkUserObjects =====

  Pure passthrough: `table.objects.<kind>.<name>` flows into
  `body.<kind>.<name>` of the assembled table value. The type
  layer's `asUserBody` (in `lib/types/table.nix`) has already
  stripped `family` / `name` / `table` / `handle`; the nftypes
  renderer fills them back in from the parent table.

  Identity for now — placeholder for future kind-aware transforms.
  Named-object reference validation lives upstream in Phase 1's
  `internal.normalize.checkObjectRefs`.

  ===== emitUserObjects =====

  Reads:  table.objects
  Writes: ctx.userObjects

  Pipeline phase that wraps `mkUserObjects`.

  ===== assembleOutput =====

  Reads:  ctx.zoneSets, ctx.baseChains, ctx.subChains,
          ctx.userObjects, table.{family, name}
  Writes: ctx.output

  Final pipeline phase: rolls the per-artifact ctx fields into
  one `nftypes.dsl.table` value via `assembleTable`.

  Body composition rules:
    - Base chains and sub-chains share `body.chains` — keys don't
      collide because base chains use the bare `<baseChainName>`
      and sub-chains use `<baseChainName>__<subChainKey>`.
    - User-defined sets merge with auto-generated zone sets under
      `body.sets`. Name collisions resolve user-wins; a future
      Phase 1 validator should flag these at compile time.
    - Other user-object kinds (counters / quotas / limits / …)
      pass through as their own body field. Empty kinds are
      skipped so the output JSON stays minimal.

  ===== emitTable =====

  Orchestrator: pipes `emitBaseChains`, `emitSubChains`,
  `emitUserObjects`, then `assembleOutput`. Returns `{ table; ctx }`
  with `ctx.output` set. `ctx.zoneSets` is consumed (produced in
  Phase 1 by `internal.normalize.computeZoneSets`).
*/
{ inputs, internal }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes.dsl)
    expr
    eq
    inSet
    accept
    drop
    snat
    masquerade
    dnat
    redirect
    jump
    ;
  inherit (nftypes.dsl.fields)
    meta
    ct
    ip
    ip6
    ;
  inherit (nftypes.compatibility) priorityIntsDefault;

  /*
    Resolve a chain priority value (int or symbol) to its int
    counterpart, family-default-table only. Used by `chainTypeOf`
    to compare against canonical srcnat / dstnat / mangle values
    — for the chain-header `prio` field we use
    `nftypes.resolvePriority` (family-aware) instead.
  */
  resolveDefaultPriority =
    priority: if builtins.isInt priority then priority else priorityIntsDefault.${priority};

  chainTypeOf =
    chainAttrs:
    let
      priority = resolveDefaultPriority chainAttrs.priority;
    in
    if priority == priorityIntsDefault.srcnat || priority == priorityIntsDefault.dstnat then
      "nat"
    else if
      priority == priorityIntsDefault.mangle
      && (chainAttrs.hook == "prerouting" || chainAttrs.hook == "output")
    then
      "route"
    else
      "filter";

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
    Emit the rule-body statement list for one cell. Dispatches on
    cell shape (no explicit group arg needed):
      - `cell ? verdict`            → policy
      - `cell.rule ? snat`          → snat with address translation
      - `cell.rule ? masquerade`    → snat masquerade
      - `cell.rule ? action`        → dnat (action.dnat | action.redirect)
      - else (`cell.rule` is list)  → filter / sroute / droute
  */
  mkRuleBody =
    cell:
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

  /*
    Build one sub-chain body: a regular (non-base) chain with
    just a `rules` field. Cells are already sorted by Phase 3
    (priority asc, name asc; policies last as tail rules), so we
    just map `mkRuleBody` over them in order.
  */
  mkSubChain = cells: {
    rules = map mkRuleBody cells;
  };

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
    Walk `chainBuckets.<baseChainName>.subChains.<subChainKey>`
    producing one sub-chain entry per `(baseChainName,
    subChainKey)` pair, keyed by the full sub-chain name (see
    `subChainNameOf`).
  */
  mkSubChains =
    chainBuckets:
    lib.foldlAttrs (
      acc: baseChainName: bucket:
      acc
      // lib.mapAttrs' (
        subChainKey: subChain:
        lib.nameValuePair (subChainNameOf baseChainName subChainKey) (mkSubChain subChain.cells)
      ) bucket.subChains
    ) { } chainBuckets;

  /*
    Build the match-clause variants for one direction of one
    sub-chain at a given hook. Returns a list of variants — each
    variant is a list of statements ANDed within a single rule.
    Multiple variants → multiple rules (the cartesian product is
    taken in `mkJumpRules`).

    Why per-variant rather than ANDed clauses: in `inet` family,
    `ip <addr>` and `ip6 <addr>` cannot be ANDed in the same
    rule — packets of the wrong family skip the rule entirely.
    So one variant per address family that has a non-empty set,
    plus the optional interface prefix when the hook allows it.

    Special cases:
      - `zoneName == null` (single-direction sub-chain — dnat /
        sroute have no `to`, droute has no `from`)         → `[ [ ] ]`.
      - `zoneName == localZone` (sentinel; never matchable as a
        zone — the chain dispatch already used it)         → `[ [ ] ]`.

    Phase 1's `checkChainOverridePlacement` guarantees a referenced
    zone has at least one matchable variant at its hook, so the
    `[ ]` empty-result branch shouldn't fire for non-localZone
    refs. If it does (defense), the cartesian product in
    `mkJumpRules` drops the entire jump for that sub-chain — the
    sub-chain becomes unreachable rather than over-permissive.
  */
  mkDirectionVariants =
    {
      hook,
      direction,
      zoneName,
      zoneSets,
      localZone,
    }:
    if zoneName == null || zoneName == localZone then
      [ [ ] ]
    else
      let
        isFromDirection = direction == "from";
        iifAvailable = builtins.elem hook [
          "prerouting"
          "input"
          "forward"
          "postrouting"
        ];
        oifAvailable = builtins.elem hook nftypes.compatibility.hooksWithOifname;
        ifAvailable = if isFromDirection then iifAvailable else oifAvailable;

        ifField = if isFromDirection then meta.iifname else meta.oifname;
        addrFieldV4 = if isFromDirection then ip.saddr else ip.daddr;
        addrFieldV6 = if isFromDirection then ip6.saddr else ip6.daddr;

        iifsName = "${zoneName}_iifs";
        v4Name = "${zoneName}_v4";
        v6Name = "${zoneName}_v6";

        hasIf = ifAvailable && (zoneSets ? ${iifsName});
        hasV4 = zoneSets ? ${v4Name};
        hasV6 = zoneSets ? ${v6Name};

        ifClause = inSet ifField (expr.set iifsName);
        v4Clause = inSet addrFieldV4 (expr.set v4Name);
        v6Clause = inSet addrFieldV6 (expr.set v6Name);

        ifPrefix = lib.optional hasIf ifClause;
      in
      if hasV4 || hasV6 then
        lib.optional hasV4 (ifPrefix ++ [ v4Clause ]) ++ lib.optional hasV6 (ifPrefix ++ [ v6Clause ])
      else if hasIf then
        [ [ ifClause ] ]
      else
        [ ];

  /*
    Build the jump rules for one base chain bucket. For each
    sub-chain, computes the from/to direction variants and emits
    one jump per variant pair (cartesian product).

    Family-mismatch waste: in `inet` with both v4 and v6 sets on
    each side, the cartesian product produces (v4-from, v6-to) and
    (v6-from, v4-to) jumps in addition to the matched-family
    pairs. They're harmless (skip on family mismatch) but bloat
    the chain. Optimization deferred — see the Phase 4 design
    notes in `docs/compile-pipeline-draft.md` §4.4.
  */
  mkJumpRules =
    {
      hook,
      baseChainName,
      subChains,
      zoneSets,
      localZone,
    }:
    let
      mkJumpsForSubChain =
        subChainKey: subChain:
        let
          fromVariants = mkDirectionVariants {
            inherit hook zoneSets localZone;
            direction = "from";
            zoneName = subChain.from or null;
          };
          toVariants = mkDirectionVariants {
            inherit hook zoneSets localZone;
            direction = "to";
            zoneName = subChain.to or null;
          };
          jumpStmt = jump (subChainNameOf baseChainName subChainKey);
        in
        map ({ from, to }: from ++ to ++ [ jumpStmt ]) (
          lib.cartesianProduct {
            from = fromVariants;
            to = toVariants;
          }
        );
    in
    lib.concatLists (lib.mapAttrsToList mkJumpsForSubChain subChains);

  mkBaseChain =
    {
      family,
      settings,
      bucket,
      baseChainName,
      zoneSets,
    }:
    let
      inherit (settings) localZone;

      chainType = chainTypeOf bucket;
      chainPriority = resolveDefaultPriority bucket.priority;

      # `isFilterBaseChain` is the narrower predicate that gates
      # stateful + loopback boilerplate: chain at the canonical
      # `filter` priority specifically, not other filter-type
      # placements (`raw` for rpfilter, `security`, …).
      isFilterBaseChain = chainType == "filter" && chainPriority == priorityIntsDefault.filter;
      isInput = bucket.hook == "input";
      isPreroutingRaw = bucket.hook == "prerouting" && chainPriority == priorityIntsDefault.raw;

      statefulPrelude = lib.optionals (isFilterBaseChain && settings.stateful) statefulRules;
      loopbackPrelude = lib.optionals (isFilterBaseChain && isInput && settings.loopback) loopbackRules;
      rpfilterPrelude = lib.optionals (isPreroutingRaw && settings.rpfilter) rpfilterRules;

      preDispatchRules = map mkRuleBody bucket.preDispatch;
      postDispatchRules = map mkRuleBody bucket.postDispatch;
      jumpRules = mkJumpRules {
        inherit (bucket) hook;
        inherit baseChainName zoneSets localZone;
        subChains = bucket.subChains;
      };

      rules =
        statefulPrelude
        ++ loopbackPrelude
        ++ rpfilterPrelude
        ++ preDispatchRules
        ++ jumpRules
        ++ postDispatchRules;
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
      zoneSets,
    }:
    let
      fromBuckets = lib.mapAttrs (
        baseChainName: bucket:
        mkBaseChain {
          inherit
            family
            settings
            bucket
            baseChainName
            zoneSets
            ;
        }
      ) chainBuckets;

      # Synthesize a prerouting-at-raw bucket if rpfilter is enabled
      # and no user override has produced one already.
      needsRpfilter = settings.rpfilter && !(fromBuckets ? "prerouting-at-raw");
      synthesizedRpfilterBucket = {
        hook = "prerouting";
        priority = "raw";
        preDispatch = [ ];
        subChains = { };
        postDispatch = [ ];
      };
      rpfilterAddition = lib.optionalAttrs needsRpfilter {
        "prerouting-at-raw" = mkBaseChain {
          inherit family settings zoneSets;
          bucket = synthesizedRpfilterBucket;
          baseChainName = "prerouting-at-raw";
        };
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

  emitBaseChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        baseChains = mkBaseChains {
          inherit (table) family settings;
          inherit (ctx) chainBuckets zoneSets;
        };
      };
    };

  emitSubChains =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        subChains = mkSubChains ctx.chainBuckets;
      };
    };

  /*
    Pure passthrough: `table.objects.<kind>.<name>` maps directly to
    `body.<kind>.<name>` in the assembled `nftypes.dsl.table` value.
    The type layer's `asUserBody` (in `lib/types/table.nix`) has
    already stripped `family` / `name` / `table` / `handle`; the
    nftypes renderer fills them back in from the parent table.

    Identity for now — placeholder for future kind-aware transforms
    (e.g., named-object reference validation per design doc open
    question 3).
  */
  mkUserObjects = objects: objects;

  emitUserObjects =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        userObjects = mkUserObjects table.objects;
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
      allSets = ctx.zoneSets // (ctx.userObjects.sets or { });

      # Other user-object kinds pass through as their own body
      # field. Empty kinds are skipped so the output stays clean.
      otherUserObjectKinds = lib.filterAttrs (_: v: v != { }) (
        builtins.removeAttrs ctx.userObjects [ "sets" ]
      );

      body =
        lib.optionalAttrs (allSets != { }) { sets = allSets; }
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
    chainTypeOf
    mkRuleBody
    subChainNameOf
    mkSubChain
    mkSubChains
    mkDirectionVariants
    mkJumpRules
    mkBaseChain
    mkBaseChains
    mkUserObjects
    assembleTable
    emitBaseChains
    emitSubChains
    emitUserObjects
    assembleOutput
    emitTable
    ;
}
