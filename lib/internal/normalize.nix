/*
  internal/normalize — Phase 1 of the compile pipeline, exposed
  under `nftzones.internal.normalize`.

  Lowers nodes into zones, resolves wildcards in rule groups'
  `from` / `to`, and runs cross-reference validations to produce a
  single normalized table value consumed by downstream phases
  (expand, dispatch+sort, emit).

  Pipeline pattern: each phase takes `{ table; ctx }` and
  returns the same shape. `table` is the original
  `nftzones.types.table` value and stays *untouched* through the
  pipeline; phases only contribute keys to `ctx`. The
  orchestrator (`normalizeTable`) pipes the phases and then
  assembles the final normalized table from `table` + `ctx`.

  Phase pipeline:

      { table; ctx = { errors = [ ]; warnings = [ ]; }; }
        ↓ convertNodesToZones           ctx.mergedZones
        ↓ computeZoneMembership         ctx.zoneMembership
        ↓ collectAllZoneNames           ctx.allZoneNames
        ↓ expandWildcardZones           ctx.expandedGroups
        ↓ resolvePriorities             ctx.resolvedPriorities
        ↓ collectZoneRefs               ctx.zoneRefs
        ↓ checkParentRefs               ctx.errors   (appends)
        ↓ checkParentCycles             ctx.errors   (appends)
        ↓ checkNameCollisions           ctx.errors   (appends)
        ↓ checkNameKeyMismatch          ctx.errors   (appends)
        ↓ checkSettings                 ctx.errors   (appends)
        ↓ checkZoneRefs                 ctx.errors   (appends)
        ↓ checkZoneMatchable            ctx.errors   (appends)
        ↓ checkChainOverridePlacement   ctx.errors   (appends)
        ↓ checkChainPlacement           ctx.errors   (appends)
        ↓ checkRpfilterOverride         ctx.warnings (appends)
        ↓ checkChainOverrideSemantics   ctx.warnings (appends)
        ↓ checkExtraSectionFields       ctx.warnings (appends)
        ↓ checkWildcardZoneMix          ctx.warnings (appends)
        ↓ checkNodeAddresses            ctx.errors   (appends)
        ↓ checkNatBodies                ctx.errors   (appends)
        ↓ checkPolicyUniqueness         ctx.errors   (appends)
        ↓ checkSetNameCollisions        ctx.errors   (appends)
        ↓ checkInterfaceOverlap         ctx.errors   (appends)
        ↓ checkCidrOverlap              ctx.errors   (appends)
        ↓ checkCrossAxisOverlap         ctx.warnings (appends)
        ↓ checkObjectRefs               ctx.errors   (appends)
      { table;
        ctx = {
          mergedZones; zoneMembership;
          allZoneNames; expandedGroups; resolvedPriorities;
          zoneRefs; errors; warnings;
        };
      }

  Output: `normalizeTable` returns the final pipeline context
    `{ table; ctx }` directly — no assembly. `table` is the
    untouched user input; `ctx` contains everything Phase 1
    computed. Downstream phases (Phase 2 expand, Phase 3 dispatch,
    Phase 4 emit) consume both. The final nftables table shape is
    assembled at Phase 4.

  Path stability: `collectZoneRefs` walks the *original* table.
  Reference paths in error messages therefore point at the user's
  input slot, not at indices in the post-expansion list.

  Wired into the surface from `lib/internal/default.nix`.

  Output shape note: lowered nodes are completed to the full
  `nftzones.types.zone` submodule shape (`name`, `parent`,
  `interfaces`, `cidrs`, `matchOverride`), mirroring the
  submodule's defaults. Declared zones already have this shape
  from submodule evaluation, so `ctx.mergedZones` is uniformly
  shaped — downstream phases can consume it without re-evaluation.
*/
{ inputs, internal }:
let
  inherit (inputs) lib libnet nftypes;
  inherit (internal.node) toZone;
  inherit (internal.zone) directionToSide resolveMembership;

  /*
    Build the pipeline's initial `{ table; ctx }` from a fresh
    table value. The `ctx` is seeded with empty `errors` and
    `warnings` lists so validating phases can append
    unconditionally without `or [ ]` defensiveness. Errors abort
    the build via `throw`; warnings surface via `lib.warn` and
    let evaluation continue.
  */
  mkInitialState = table: {
    inherit table;
    ctx = {
      errors = [ ];
      warnings = [ ];
    };
  };

  # Rule-bearing groups paired with the direction fields each one
  # carries (`from` and/or `to`). Single source of truth for the
  # per-group direction config — `expandWildcardZones`,
  # `resolvePriorities`, `checkChainOverridePlacement`,
  # `checkWildcardZoneMix`, and `keyedNameGroups` consume it, so a new
  # group means updating this one constant.
  groupDirections = {
    filters = [
      "from"
      "to"
    ];
    policies = [
      "from"
      "to"
    ];
    snats = [
      "from"
      "to"
    ];
    dnats = [ "from" ];
    sroutes = [ "from" ];
    droutes = [ "to" ];
  };

  groupNames = builtins.attrNames groupDirections;

  # Subset of `groupNames` whose entry types expose a `chain`
  # override field (filters / snats / dnats). Sroutes, droutes,
  # policies have fixed placements with no override path.
  chainOverrideGroups = [
    "filters"
    "snats"
    "dnats"
  ];

  collectAllZoneNames =
    { table, ctx }:
    let
      allZoneNames = (builtins.attrNames ctx.mergedZones) ++ [ table.settings.localZone ];
    in
    {
      inherit table;
      ctx = ctx // {
        inherit allZoneNames;
      };
    };

  convertNodesToZones =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        mergedZones = table.zones // lib.mapAttrs (_: toZone) table.nodes;
      };
    };

  computeZoneMembership =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        zoneMembership = resolveMembership {
          zones = ctx.mergedZones;
          inherit (table.settings) localZone;
        };
      };
    };

  /*
    `parentOf zone` reads `zone.parent or null` — accommodating
    raw test fixtures that bypass the type system. Submodule-
    evaluated zones always have `parent` defaulted to null.
  */
  parentOf = zone: zone.parent or null;

  checkParentRefs =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) mergedZones;

      newErrors = lib.foldlAttrs (
        acc: zoneName: zone:
        let
          parent = parentOf zone;
        in
        if parent == null then
          acc
        else if parent == localZone then
          acc
          ++ [
            (lib.nameValuePair "zoneParentLocalZone" "zones.${zoneName}.parent is '${parent}' (the localZone sentinel) — localZone cannot be a parent")
          ]
        else if !(mergedZones ? ${parent}) then
          acc
          ++ [
            (lib.nameValuePair "zoneParentUnknown" "zones.${zoneName}.parent references unknown zone '${parent}'")
          ]
        else
          acc
      ) [ ] mergedZones;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkParentCycles =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      indexOf =
        needle: list:
        let
          matches = builtins.filter (item: item.value == needle) (
            lib.imap0 (index: value: { inherit index value; }) list
          );
        in
        (builtins.head matches).index;

      /*
        Walk the parent chain starting at `start`. Returns the
        cycle proper (just the cycle members, no leading tail and
        no closing duplicate) iff a cycle is found, empty list
        otherwise. The walk stops at unresolved or null parents —
        those are handled by `checkParentRefs` and are not cycles.
      */
      walkChain =
        start:
        let
          step =
            visited: name:
            let
              zone = mergedZones.${name} or null;
              parent = if zone == null then null else parentOf zone;
            in
            if parent == null || !(mergedZones ? ${parent}) then
              [ ]
            else if builtins.elem parent visited then
              # Drop the leading tail (anything before parent's
              # first occurrence) so callers see only the cycle
              # members.
              lib.drop (indexOf parent visited) visited
            else
              step (visited ++ [ parent ]) parent;
        in
        step [ start ] start;

      /*
        Rotate `nodes` so the lex-smallest member leads. Two
        walks of the same cycle (e.g., `[a, b, c]` and `[b, c, a]`)
        canonicalize to the same list, so `lib.unique` collapses
        them after formatting.
      */
      canonicalRotation =
        nodes:
        let
          minNode = lib.foldl' lib.min (builtins.head nodes) nodes;
          minIndex = indexOf minNode nodes;
        in
        (lib.drop minIndex nodes) ++ (lib.take minIndex nodes);

      formatCycle = nodes: lib.concatStringsSep " → " (nodes ++ [ (builtins.head nodes) ]);

      cycles = lib.pipe (builtins.attrNames mergedZones) [
        (map walkChain)
        (builtins.filter (chain: chain != [ ]))
        (map canonicalRotation)
        (map formatCycle)
        lib.unique
      ];

      newErrors = map (cycle: lib.nameValuePair "zoneParentCycle" "zone parent cycle: ${cycle}") cycles;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  expandWildcardZones =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone;
      inherit (ctx) allZoneNames;
      inherit (ctx.zoneMembership) rootZoneNames;

      /*
        From-side wildcard expands to root zones only: descendants
        receive traffic via parent dispatch (Phase 4 emits child
        sub-chain jumps inside each parent's sub-chain). Expanding
        to every zone would emit redundant cells in every leaf.

        To-side wildcard keeps the full zone list because to-side
        hierarchy is not modelled — `to = [ "all" ]` means "any
        destination zone" and each unique destination needs its
        own sub-chain.
      */
      expandFrom =
        zones:
        lib.unique (lib.concatMap (zone: if zone == wildcardZone then rootZoneNames else [ zone ]) zones);
      expandTo =
        zones:
        lib.unique (lib.concatMap (zone: if zone == wildcardZone then allZoneNames else [ zone ]) zones);

      expandDirection =
        direction: entry: if direction == "from" then expandFrom entry.from else expandTo entry.to;

      expandEntry =
        directions: entry: lib.genAttrs directions (direction: expandDirection direction entry);

      expandGroup = directions: lib.mapAttrs (_: expandEntry directions);

      expandedGroups = lib.mapAttrs (
        group: directions: expandGroup directions table.${group}
      ) groupDirections;
    in
    {
      inherit table;
      ctx = ctx // {
        inherit expandedGroups;
      };
    };

  resolvePriorities =
    { table, ctx }:
    let
      inherit (internal.priority) resolvePriority;

      resolveGroup = lib.mapAttrs (_: entry: resolvePriority entry.priority);

      # Every group except policies — policies have no `priority`
      # field (they're tail rules with implicit `last` priority).
      priorityGroups = lib.removeAttrs groupDirections [ "policies" ];

      resolvedPriorities = lib.mapAttrs (group: _: resolveGroup table.${group}) priorityGroups;
    in
    {
      inherit table;
      ctx = ctx // {
        inherit resolvedPriorities;
      };
    };

  collectZoneRefs =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone;

      collectDirectionRefs =
        groupName: direction: entryName: entry:
        let
          prefix = "${groupName}.${entryName}.${direction}";
        in
        lib.concatLists (
          lib.imap0 (
            i: zone:
            if zone == wildcardZone then
              [ ]
            else
              [
                {
                  inherit direction zone;
                  path = "${prefix}[${toString i}]";
                }
              ]
          ) entry.${direction}
        );

      collectEntryRefs =
        groupName: directions: entryName: entry:
        lib.concatMap (direction: collectDirectionRefs groupName direction entryName entry) directions;

      collectGroupRefs =
        groupName: directions: group:
        lib.concatLists (
          lib.mapAttrsToList (entryName: entry: collectEntryRefs groupName directions entryName entry) group
        );

      collectNodeParentRefs =
        nodes:
        lib.mapAttrsToList (entryName: entry: {
          inherit (entry) zone;
          path = "nodes.${entryName}.zone";
        }) nodes;

      zoneRefs = lib.concatLists [
        (collectGroupRefs "filters" [ "from" "to" ] table.filters)
        (collectGroupRefs "policies" [ "from" "to" ] table.policies)
        (collectGroupRefs "snats" [ "from" "to" ] table.snats)
        (collectGroupRefs "dnats" [ "from" ] table.dnats)
        (collectGroupRefs "sroutes" [ "from" ] table.sroutes)
        (collectGroupRefs "droutes" [ "to" ] table.droutes)
        (collectNodeParentRefs table.nodes)
      ];
    in
    {
      inherit table;
      ctx = ctx // {
        inherit zoneRefs;
      };
    };

  checkNameCollisions =
    { table, ctx }:
    let
      collisions = lib.intersectLists (builtins.attrNames table.zones) (builtins.attrNames table.nodes);
      newErrors = map (
        name:
        lib.nameValuePair "zoneNameCollision" "name collision: '${name}' is declared as both a zone and a node"
      ) collisions;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  # Object groups keyed by attribute name, each entry carrying a
  # key-derived `name`: the two zone-namespace groups (`zones` /
  # `nodes`) plus every rule group. Reusing `groupNames` (derived
  # from `groupDirections`) rather than re-listing the rule groups
  # keeps this in step with that single source of truth — a new rule
  # group is name-checked automatically. The table type is absent by
  # design: it has no enclosing key by the time the pipeline sees it
  # (see `checkNameKeyMismatch`).
  keyedNameGroups = [
    "zones"
    "nodes"
  ]
  ++ groupNames;

  checkNameKeyMismatch =
    { table, ctx }:
    let
      checkGroup =
        group:
        lib.concatLists (
          lib.mapAttrsToList (
            key: object:
            # `object.name or key` mirrors the defensive reads elsewhere
            # in this file (`parentOf`): raw fixtures that bypass the
            # type system may omit `name`, and an absent name can't
            # diverge from its key. `object.name` in the message is only
            # forced when the guard already proved it present and
            # divergent, so this never trips the missing-attr path.
            lib.optional ((object.name or key) != key) (
              lib.nameValuePair "nameKeyMismatch" "${group}.${key}.name is '${object.name}' but must equal its attribute key '${key}' — the compile pipeline references this object by '${key}'. Drop the explicit `name` (it defaults to the key) or rename the attribute to '${object.name}'."
            )
          ) (table.${group} or { })
        );

      newErrors = lib.concatMap checkGroup keyedNameGroups;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  /*
    Reject placements the kernel will refuse, before they reach
    `nft -f`. Each rule group dispatches into a `(hook, priority)`
    pair; combined with `table.family`, the implied chain type
    (via `nftypes.chainTypeFor`) is what the kernel sees. If
    `nftypes.validChainPlacement` says the triple is rejected,
    we error out with the offending placement.

    Catches three failure modes uncovered by the audit:
      - `bridge` snat/dnat — bridge family doesn't support `nat`
        chains at all.
      - `bridge` sroute/droute — bridge has no `mangle` priority,
        so `chainTypeFor` returns null and we surface the gap
        rather than throwing in emit.
      - `route` chain at non-`output` hooks (kernel restriction
        encoded in `hooksByChainType.route = [ "output" ]`).

    `internal.placement` owns entry-level placement analysis and
    Phase 3's cell placement. This validator classifies its
    results and attaches entry names to the aggregated errors.
  */
  checkChainPlacement =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (table.settings) localZone;
      inherit (nftypes) chainTypeFor validChainPlacement;
      inherit (internal.placement) chainAttrsForEntry;

      placementsForEntry =
        group: entryName: entry:
        map (placement: placement // { inherit entryName; }) (
          chainAttrsForEntry group localZone (entry // ctx.expandedGroups.${group}.${entryName})
        );

      placementsForGroup =
        group: lib.concatLists (lib.mapAttrsToList (placementsForEntry group) (table.${group} or { }));

      mkError =
        group: placement: reason:
        lib.nameValuePair "invalidChainPlacement" "${group}.${placement.entryName} would emit a base chain at (family=${family}, hook=${placement.hook}, priority=${toString placement.priority}) — ${reason}";

      classify =
        group: placement:
        let
          chainType = chainTypeFor family placement.hook placement.priority;
        in
        if chainType == null then
          [
            (mkError group placement
              "priority symbol '${toString placement.priority}' has no value in family '${family}'"
            )
          ]
        else if !(validChainPlacement family chainType placement.hook) then
          [
            (mkError group placement
              "kernel rejects chain type '${chainType}' on hook '${placement.hook}' for family '${family}'"
            )
          ]
        else
          [ ];

      newErrors = lib.concatMap (
        group: lib.concatMap (classify group) (placementsForGroup group)
      ) groupNames;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  /*
    Warn (don't error) when `settings.rpfilter = true` and a user
    override at `(prerouting, raw)` already claims the slot.
    Phase 4 keeps the user's chain intact and skips synthesizing
    the rpfilter chain — without this warning, the rpfilter rule
    would silently disappear and the user would have no signal
    that their override took precedence.
  */
  checkRpfilterOverride =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (nftypes) priorityNameOf;

      claimsRawPrerouting =
        entry:
        let
          chain = entry.chain or null;
        in
        chain != null && chain.hook == "prerouting" && priorityNameOf family chain.priority == "raw";

      groupClaims = group: lib.any claimsRawPrerouting (lib.attrValues table.${group});

      newWarnings =
        lib.optional (table.settings.rpfilter && lib.any groupClaims chainOverrideGroups)
          "settings.rpfilter is enabled but a user chain override already claims (prerouting, raw); the synthesized rpfilter chain is suppressed and the user-authored chain is used as-is. Add `fib saddr . iif oif eq 0 drop` to the override manually if you want rpfilter behavior in that chain.";
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Soft checks for kernel-valid chain overrides that are
    semantically suspect. checkChainPlacement already rejects
    placements the kernel refuses (e.g. nat at non-nat hooks);
    this validator catches the layer above — placements the
    kernel accepts but the user almost certainly didn't mean.

    Three cases the audit flagged:

      - filter at hook=postrouting: `iifname` reflects the *input*
        device, which after routing may not match user intent
        ("source zone"), especially for locally-originated
        traffic where iifname is "lo" or empty.

      - dnat at hook=output: from-side dispatches on saddr, which
        for output is the local interface address. A from-zone
        bound by a wide CIDR (0/0) would silently rewrite every
        locally-originated packet.

      - snat at priority != srcnat: stateful SNAT must run at
        srcnat (100) so conntrack records the translation. At any
        other priority the rewrite happens but conntrack misses
        it — return traffic breaks.

    All three are warnings (not errors) because each *can* be the
    user's deliberate intent in edge cases.
  */
  checkChainOverrideSemantics =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (nftypes) priorityNameOf;

      entryHasChain = entry: (entry.chain or null) != null;

      mkWarning =
        kind: entryName: message:
        "${kind}.${entryName}.chain: ${message}";

      # Filter at postrouting — iifname semantics differ from
      # pre-routing dispatch.
      filterPostroutingWarnings = lib.concatLists (
        lib.mapAttrsToList (
          entryName: entry:
          if entryHasChain entry && entry.chain.hook == "postrouting" then
            [
              (mkWarning "filters" entryName
                "hook=postrouting is kernel-valid but `iifname` here reflects the input device pre-routing, which may not match what `from` zones mean (especially for locally-originated traffic where iifname is 'lo' or empty). Confirm this is intentional, or place the filter at the default `(forward|input|output, filter)` instead."
              )
            ]
          else
            [ ]
        ) (table.filters or { })
      );

      # Dnat at output — from-side at output is local, not external.
      dnatOutputWarnings = lib.concatLists (
        lib.mapAttrsToList (
          entryName: entry:
          if entryHasChain entry && entry.chain.hook == "output" then
            [
              (mkWarning "dnats" entryName
                "hook=output rewrites locally-originated traffic. The `from` side dispatches on saddr, which at output is the local interface address — a from-zone with a wide CIDR (e.g. 0.0.0.0/0) would silently rewrite every locally-originated packet. Confirm this is what you want, or keep the default `(prerouting, dstnat)` for external-traffic DNAT."
              )
            ]
          else
            [ ]
        ) (table.dnats or { })
      );

      # Snat at non-srcnat priority — breaks conntrack.
      snatPriorityWarnings = lib.concatLists (
        lib.mapAttrsToList (
          entryName: entry:
          if entryHasChain entry && priorityNameOf family entry.chain.priority != "srcnat" then
            [
              (mkWarning "snats" entryName
                "priority='${toString entry.chain.priority}' is not srcnat (100). Stateful SNAT must run at the srcnat priority so conntrack records the translation; at any other priority the rewrite happens but conntrack misses it and return traffic breaks. Either use priority='srcnat' (or 100), or accept that this NAT is one-way."
              )
            ]
          else
            [ ]
        ) (table.snats or { })
      );

      newWarnings = filterPostroutingWarnings ++ dnatOutputWarnings ++ snatPriorityWarnings;
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Warn when a `matchOverride.<side>.extra` section references
    an interface-typed `meta` field (`iif`, `iifname`, `iifgroup`,
    `iiftype` and the `oif*` counterparts). These belong in the
    `matchOverride.<side>.interfaces` section instead: that
    section is hook-gated correctly by
    `checkChainOverridePlacement` and `mkDirectionVariants` (the
    iif/oif clause is dropped at hooks where the field is
    unavailable). The `extra` section is hook-agnostic by design
    — it's inlined into every variant of every direction the
    zone appears in, regardless of hook. An iif clause in extra
    landing at the `output` hook silently becomes a no-op
    (`iifname` is unavailable there), turning a chain the user
    expected to be restrictive into a permissive one.

    Per-statement check: extract `stmt.match.left.meta.key` (the
    field name) and flag if it's an iif/oif variant. Walks
    only the `extra` section; the `interfaces` / `ipv4` / `ipv6`
    sections are hook-gated already.

    Warning-level (not error) — a user with a config that only
    ever uses the zone at hooks where the field IS valid would
    see a false positive. The warning text names the slot and
    the recommended fix (move to `matchOverride.<side>.interfaces`).
  */
  checkExtraSectionFields =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      interfaceMetaKeys = [
        "iif"
        "iifname"
        "iifgroup"
        "iiftype"
        "oif"
        "oifname"
        "oifgroup"
        "oiftype"
      ];

      sides = [
        "ingress"
        "egress"
      ];

      # nftypes match shape: `{ match = { left = { meta = {
      # key = "iif"; }; }; op; right; }; }`. Returns the meta
      # key if the statement's left side is a `meta` field;
      # null otherwise (payload matches, non-match statements,
      # etc.).
      metaKeyOf = stmt: stmt.match.left.meta.key or null;

      checkBody =
        zoneName: side: body:
        lib.concatLists (
          lib.imap0 (
            i: stmt:
            let
              key = metaKeyOf stmt;
            in
            if key != null && builtins.elem key interfaceMetaKeys then
              [
                "zones.${zoneName}.matchOverride.${side}.extra[${toString i}] matches on `meta.${key}` — interface fields belong in `matchOverride.${side}.interfaces` instead. The `extra` section is inlined hook-agnostically and would silently become a no-op at hooks where ${key} is unavailable (e.g. iif* at output). The `interfaces` section is hook-gated correctly by `checkChainOverridePlacement` and `mkDirectionVariants`."
              ]
            else
              [ ]
          ) body
        );

      checkSide =
        zoneName: side:
        let
          active = ctx.zoneMembership.activeOverrides zoneName side;
        in
        if active ? extra then checkBody zoneName side active.extra else [ ];

      checkZone = zoneName: lib.concatMap (checkSide zoneName) sides;

      newWarnings = lib.concatMap checkZone (builtins.attrNames mergedZones);
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Warn when an entry's `from` or `to` list mixes the wildcard
    zone with explicit zone names — e.g. `from = [ "all" "wan" ]`.
    The wildcard alone already expands to every in-scope zone
    (`expandFrom` / `expandTo` substitute the wildcard sentinel),
    so explicit zones appearing alongside it are either already
    covered (no-op) or, more likely, a typo / leftover from an
    earlier config shape. The user almost certainly meant `[
    "all" ]` alone or `[ "wan" ]` alone, not both.

    Walks the raw `from` / `to` lists before wildcard expansion —
    by the time `expandWildcardZones` runs, the wildcard sentinel
    is gone. Iterates over `groupDirections` for the per-group
    direction set (filters/policies have both, dnats has `from`
    only, droutes has `to` only).

    Warning-level: the behaviour isn't wrong (expansion produces
    the right zone set either way), it's just a misleading config
    shape that suggests user confusion.
  */
  checkWildcardZoneMix =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone;

      checkEntryDirection =
        groupName: entryName: direction: zones:
        if builtins.elem wildcardZone zones && builtins.length zones > 1 then
          let
            explicitZones = builtins.filter (zone: zone != wildcardZone) zones;
            quotedZones = lib.concatStringsSep ", " (map (zone: "'${zone}'") explicitZones);
          in
          [
            "${groupName}.${entryName}.${direction}: list contains the wildcard zone '${wildcardZone}' alongside explicit zone(s) ${quotedZones}. The wildcard alone already expands to every in-scope zone — the explicit names are either redundant or a leftover. Use `[ \"${wildcardZone}\" ]` or list the explicit zones without the wildcard."
          ]
        else
          [ ];

      checkEntry =
        groupName: directions: entryName: entry:
        lib.concatMap (
          direction: checkEntryDirection groupName entryName direction (entry.${direction} or [ ])
        ) directions;

      checkGroup =
        groupName: directions:
        lib.concatLists (lib.mapAttrsToList (checkEntry groupName directions) (table.${groupName} or { }));

      newWarnings = lib.concatLists (lib.mapAttrsToList checkGroup groupDirections);
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  /*
    Reject `nodes.<name>.address` shapes with both `ipv4` and
    `ipv6` set to `null`. The type accepts the all-null shape
    (both fields are `nullOr str` defaulting to `null`), but a
    node with no address can't produce any CIDR for its lowered
    zone — `internal.node.toZone` would emit `cidrs = [ ]` and
    the zone would be unmatchable at every direction.

    Surfaced here (rather than at type `apply` time) so the error
    aggregates with the rest of Phase 1's findings instead of
    halting on the first node.
  */
  checkNodeAddresses =
    { table, ctx }:
    let
      newErrors = lib.concatLists (
        lib.mapAttrsToList (
          name: node:
          lib.optional (node.address.ipv4 == null && node.address.ipv6 == null) (
            lib.nameValuePair "nodeAddressMissing" "nodes.${name}: address must set at least one of `ipv4` / `ipv6` — a node with no address contributes no CIDR to its lowered zone."
          )
        ) (table.nodes or { })
      );
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  /*
    Reject `snats.<x>.rule.snat = { }` and
    `dnats.<x>.rule.action.dnat = { }` where `addr` is null. nftypes'
    `natBody` lets every field default to `null` (so the user-shape
    validates), but the rendered `snat to` / `dnat to` statement with
    no target is invalid nftables syntax and `nft -f` rejects it at
    activation. Catches the empty-body case here with a clear error
    pointing to `masquerade` / `redirect` as the no-target alternative.
  */
  checkNatBodies =
    { table, ctx }:
    let
      snatErrors = lib.concatLists (
        lib.mapAttrsToList (
          name: entry:
          lib.optional ((entry.rule ? snat) && entry.rule.snat.addr == null) (
            lib.nameValuePair "natBodyMissingAddr" "snats.${name}: rule.snat.addr is null — `snat` requires a target address. Use `rule.masquerade = { }` for auto-target via the outgoing interface, or set `rule.snat.addr` explicitly."
          )
        ) (table.snats or { })
      );

      dnatErrors = lib.concatLists (
        lib.mapAttrsToList (
          name: entry:
          lib.optional ((entry.rule.action ? dnat) && entry.rule.action.dnat.addr == null) (
            lib.nameValuePair "natBodyMissingAddr" "dnats.${name}: rule.action.dnat.addr is null — `dnat` requires a target address. Use `rule.action.redirect = { port = N; }` for redirect-to-localhost, or set `rule.action.dnat.addr` explicitly."
          )
        ) (table.dnats or { })
      );

      newErrors = snatErrors ++ dnatErrors;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkSettings =
    { table, ctx }:
    let
      inherit (table.settings) localZone wildcardZone;
      zoneNames = builtins.attrNames ctx.mergedZones;

      conflict = message: lib.nameValuePair "settingsConflict" message;

      pairConflict = lib.optional (wildcardZone == localZone) (
        conflict "settings.wildcardZone and settings.localZone are both '${wildcardZone}' — they must differ"
      );

      wildcardShadowed = lib.optional (builtins.elem wildcardZone zoneNames) (
        conflict "settings.wildcardZone '${wildcardZone}' collides with a declared zone or node"
      );

      localShadowed = lib.optional (builtins.elem localZone zoneNames) (
        conflict "settings.localZone '${localZone}' collides with a declared zone or node"
      );

      newErrors = pairConflict ++ wildcardShadowed ++ localShadowed;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkPolicyUniqueness =
    { table, ctx }:
    let
      /*
        Enumerate (entryName, from, to) triples from each policy
        entry's expanded directions. A policy with `from = [a b]`
        and `to = [x y]` contributes four triples — one per
        cartesian-product cell.
      */
      triples = lib.concatLists (
        lib.mapAttrsToList (
          entryName: directions:
          lib.concatMap (from: map (to: { inherit entryName from to; }) directions.to) directions.from
        ) ctx.expandedGroups.policies
      );

      keyOf = triple: "(${triple.from} → ${triple.to})";
      grouped = lib.groupBy keyOf triples;
      duplicates = lib.filterAttrs (_: cellTriples: builtins.length cellTriples > 1) grouped;

      newErrors = lib.mapAttrsToList (
        key: cellTriples:
        lib.nameValuePair "policyConflict" "duplicate policy for ${key}: ${
          lib.concatStringsSep ", " (map (triple: triple.entryName) cellTriples)
        }"
      ) duplicates;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkZoneRefs =
    { table, ctx }:
    let
      inherit (ctx) allZoneNames zoneRefs;
      invalidZoneRefs = builtins.filter (ref: !(builtins.elem ref.zone allZoneNames)) zoneRefs;
      knownZoneNames = lib.concatStringsSep ", " (lib.sort (a: b: a < b) allZoneNames);
      newErrors = map (
        ref:
        lib.nameValuePair "invalidZoneRef" "${ref.path} references unknown zone '${ref.zone}' (known: ${knownZoneNames})"
      ) invalidZoneRefs;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkChainOverridePlacement =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) expandedGroups mergedZones;

      interfaceFieldName = direction: if direction == "from" then "iifname" else "oifname";
      addressFieldName = direction: if direction == "from" then "saddr" else "daddr";

      # Unknown refs are reported by checkZoneRefs; the sentinel
      # contributes no match. Membership owns hook visibility.
      reachable =
        zoneName: hook: direction:
        zoneName == localZone
        || !(mergedZones ? ${zoneName})
        || ctx.zoneMembership.reachableAt zoneName { inherit hook direction; };

      /*
        Per-group iteration over the groups whose entry types
        expose a `chain` override field. Filter the file-level
        `groupDirections` by `chainOverrideGroups` so sroute /
        droute / policy (no override path) are skipped.
      */
      chainOverrideDirections = lib.filterAttrs (
        groupName: _: builtins.elem groupName chainOverrideGroups
      ) groupDirections;

      /*
        Walk one entry and emit a flat record per (direction,
        zoneName) the validator must check. Entries without a
        `chain` override are skipped.
      */
      enumerateEntry =
        groupName: directions: entryName: entry:
        if (entry.chain or null) == null then
          [ ]
        else
          let
            inherit (entry.chain) hook priority;
            expandedDirections = expandedGroups.${groupName}.${entryName};
          in
          lib.concatMap (
            direction:
            map (zoneName: {
              inherit
                direction
                entryName
                groupName
                hook
                priority
                zoneName
                ;
            }) expandedDirections.${direction}
          ) directions;

      enumerateGroup =
        groupName: directions:
        lib.concatLists (
          lib.mapAttrsToList (entryName: enumerateEntry groupName directions entryName) table.${groupName}
        );

      mkError =
        record:
        let
          side = directionToSide.${record.direction};
          addressField = addressFieldName record.direction;
          interfaceField = interfaceFieldName record.direction;
        in
        lib.nameValuePair "chainOverrideUnreachable" "${record.groupName}.${record.entryName}.${record.direction} references zone '${record.zoneName}' which has no ${side} match expressible at chain (hook=${record.hook}, priority=${toString record.priority}) — zone has no ${addressField} CIDRs and no hook-agnostic matchOverride.${side} sections (ipv4 / ipv6 / extra) set, and ${interfaceField} is unavailable in ${record.hook}";

      newErrors = lib.pipe chainOverrideDirections [
        (lib.mapAttrsToList enumerateGroup)
        lib.concatLists
        (builtins.filter (record: !(reachable record.zoneName record.hook record.direction)))
        (map mkError)
      ];
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkZoneMatchable =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) mergedZones zoneRefs;

      # Skip refs without a `direction` (node parent refs), refs to
      # the localZone sentinel (no `mergedZones` entry by design),
      # and refs to unknown zones (already flagged by checkZoneRefs).
      directionBoundRefs = builtins.filter (
        ref: ref ? direction && ref.zone != localZone && mergedZones ? ${ref.zone}
      ) zoneRefs;

      unmatchableRefs = builtins.filter (
        ref: !(ctx.zoneMembership.hasOwnMatch ref.zone directionToSide.${ref.direction})
      ) directionBoundRefs;

      newErrors = map (
        ref:
        let
          side = directionToSide.${ref.direction};
        in
        lib.nameValuePair "zoneNotMatchable" "${ref.path} references zone '${ref.zone}' which has no ${side} match (no interfaces, no CIDRs, and no matchOverride sections set on the ${side} side)"
      ) unmatchableRefs;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkSetNameCollisions =
    { table, ctx }:
    let
      userSetNames = builtins.attrNames table.objects.sets;
      zoneSetNames = builtins.attrNames ctx.zoneMembership.sets;

      collisions = lib.intersectLists userSetNames zoneSetNames;

      newErrors = map (
        setName:
        let
          sourceZone = ctx.zoneMembership.setOwners.${setName};
          suffix = lib.removePrefix "${sourceZone}_" setName;
        in
        lib.nameValuePair "setNameCollision" "objects.sets.${setName} collides with the auto-generated set name from zone '${sourceZone}' (suffix '${suffix}'); rename one"
      ) collisions;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  checkInterfaceOverlap =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      # All (zoneName, iface) pairs across every merged zone, in
      # zone-then-list order.
      allEntries = lib.concatMap (
        zoneName: map (iface: { inherit iface zoneName; }) mergedZones.${zoneName}.interfaces
      ) (builtins.attrNames mergedZones);

      entryCount = builtins.length allEntries;

      /*
        Compare unordered pairs (i, j) with i < j. Flag same
        interface in two cases:
          - same zone (intra-zone duplicate in `interfaces` list)
          - different zones not in ancestor/descendant relation
            (overlap with intentional parent/child sharing skipped)
      */
      pairErrors = lib.concatMap (
        i:
        lib.concatMap (
          j:
          let
            a = builtins.elemAt allEntries i;
            b = builtins.elemAt allEntries j;
            sameZone = a.zoneName == b.zoneName;
            sameIface = a.iface == b.iface;
            shouldFlag = sameIface && (sameZone || !(ctx.zoneMembership.related a.zoneName b.zoneName));
          in
          if shouldFlag then
            [
              (lib.nameValuePair "interfaceOverlap" (
                if sameZone then
                  "zone '${a.zoneName}' lists interface '${a.iface}' more than once"
                else
                  "interface '${a.iface}' is claimed by zones '${a.zoneName}' and '${b.zoneName}' (no ancestor/descendant relationship)"
              ))
            ]
          else
            [ ]
        ) (lib.range (i + 1) (entryCount - 1))
      ) (lib.range 0 (entryCount - 1));
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ pairErrors;
      };
    };

  checkCidrOverlap =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      # All (zoneName, cidr string, parsed cidr) triples across every
      # merged zone. Parsing is lazy per entry, forced only by the
      # overlap check below.
      allEntries = lib.concatMap (
        zoneName:
        map (cidr: {
          inherit cidr zoneName;
          parsed = libnet.cidr.parse cidr;
        }) mergedZones.${zoneName}.cidrs
      ) (builtins.attrNames mergedZones);

      entryCount = builtins.length allEntries;

      /*
        Same pair-wise pattern as `checkInterfaceOverlap`. Flag
        overlap when:
          - same zone (intra-zone overlap, e.g. `[ "10.0.0.0/24"
            "10.0.0.0/28" ]`)
          - different zones not in ancestor/descendant relation
        `libnet.cidr.overlaps` is family-aware: v4 vs v6 always
        returns false.
      */
      pairErrors = lib.concatMap (
        i:
        lib.concatMap (
          j:
          let
            a = builtins.elemAt allEntries i;
            b = builtins.elemAt allEntries j;
            sameZone = a.zoneName == b.zoneName;
            shouldCheck = sameZone || !(ctx.zoneMembership.related a.zoneName b.zoneName);
          in
          if shouldCheck && libnet.cidr.overlaps a.parsed b.parsed then
            [
              (lib.nameValuePair "cidrOverlap" (
                if sameZone then
                  "zone '${a.zoneName}' has overlapping CIDRs '${a.cidr}' and '${b.cidr}'"
                else
                  "zone '${a.zoneName}' CIDR '${a.cidr}' overlaps zone '${b.zoneName}' CIDR '${b.cidr}' (no ancestor/descendant relationship)"
              ))
            ]
          else
            [ ]
        ) (lib.range (i + 1) (entryCount - 1))
      ) (lib.range 0 (entryCount - 1));
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ pairErrors;
      };
    };

  checkCrossAxisOverlap =
    { table, ctx }:
    let
      pairWarnings = map (
        { a, b }:
        "zones '${a}' and '${b}' may match the same packet across different axes (one is interface-bound, the other is CIDR-bound). If both appear in the same chain, dispatch order is alphabetical attribute-key order — the losing zone's rules are silently shadowed. Restructure both zones onto the same axis, or make one a child of the other if it's a refinement."
      ) ctx.zoneMembership.crossAxisPairs;
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ pairWarnings;
      };
    };

  checkObjectRefs =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;
      inherit (internal.refs) extractRefs;

      /*
        Zone-derived set names resolved in `ctx.zoneMembership.sets` by
        `computeZoneMembership`, also consumed by Phase 4 emit's
        `assembleOutput`.

        Collisions between `objects.sets.<name>` and zone-derived
        names are caught upstream by `checkSetNameCollisions`, so
        the union here is unambiguous when the table reaches this
        validator (or the table is rejected before it gets here).
      */
      zoneSetNames = builtins.attrNames ctx.zoneMembership.sets;

      knownNames = {
        counters = builtins.attrNames table.objects.counters;
        quotas = builtins.attrNames table.objects.quotas;
        limits = builtins.attrNames table.objects.limits;
        ctHelpers = builtins.attrNames table.objects.ctHelpers;
        ctTimeouts = builtins.attrNames table.objects.ctTimeouts;
        ctExpectations = builtins.attrNames table.objects.ctExpectations;
        secmarks = builtins.attrNames table.objects.secmarks;
        synproxies = builtins.attrNames table.objects.synproxies;
        tunnels = builtins.attrNames table.objects.tunnels;
        sets = (builtins.attrNames table.objects.sets) ++ zoneSetNames;
        maps = builtins.attrNames table.objects.maps;
        flowtables = builtins.attrNames table.objects.flowtables;
      };

      /*
        Walk every entry's `rule` body across all rule groups,
        annotating each ref with its source path for the error
        message.
      */
      refsFromGroup =
        groupName: group:
        lib.concatLists (
          lib.mapAttrsToList (
            entryName: entry:
            map (ref: ref // { path = "${groupName}.${entryName}.rule"; }) (extractRefs entry.rule)
          ) group
        );

      /*
        Walk every zone's active matchOverride sections via
        `zoneMembership.activeOverrides`. Inactive sections (null or
        empty) carry no refs by definition — filtering at the
        helper boundary skips them cleanly. Section name is
        included in the ref's source path so error messages point
        at the exact field (e.g.
        `zones.lan.matchOverride.ingress.ipv4`).
      */
      refsFromMatchOverrides = lib.concatLists (
        lib.mapAttrsToList (
          zoneName: _zone:
          lib.concatMap
            (
              side:
              lib.concatLists (
                lib.mapAttrsToList (
                  section: body:
                  map (
                    ref:
                    ref
                    // {
                      path = "zones.${zoneName}.matchOverride.${side}.${section}";
                    }
                  ) (extractRefs body)
                ) (ctx.zoneMembership.activeOverrides zoneName side)
              )
            )
            [
              "ingress"
              "egress"
            ]
        ) mergedZones
      );

      /*
        Walk every `table.objects.<kind>.<name>` body. Most object
        kinds (counters, limits, quotas, synproxies, …) are
        config-only leaves and contribute no refs. Sets and maps
        may carry refs in element-attached stateful statements
        (`dsl.expr.elem { val; stmt; }`); the recursive walker
        picks those up uniformly.
      */
      refsFromObjectKind =
        kindName: kindAttrs:
        lib.concatLists (
          lib.mapAttrsToList (
            objectName: body:
            map (ref: ref // { path = "objects.${kindName}.${objectName}"; }) (extractRefs body)
          ) kindAttrs
        );

      refsFromObjects = lib.concatLists (lib.mapAttrsToList refsFromObjectKind table.objects);

      /*
        Rule-bearing groups are listed explicitly rather than
        derived from a shared group-name list. `policies` is
        intentionally absent — the type has only a `verdict`
        field and no rule body, so it carries no named refs. If a
        future group gains a rule body, add it here too; silent
        omission would mean refs inside it never get resolved
        against `table.objects.<kind>` and would surface only at
        `nft load` time instead of compile time.
      */
      allRefs = lib.concatLists [
        (refsFromGroup "filters" table.filters)
        (refsFromGroup "snats" table.snats)
        (refsFromGroup "dnats" table.dnats)
        (refsFromGroup "sroutes" table.sroutes)
        (refsFromGroup "droutes" table.droutes)
        refsFromMatchOverrides
        refsFromObjects
      ];

      unresolvedRefs = builtins.filter (
        ref: !(builtins.elem ref.name (knownNames.${ref.kind} or [ ]))
      ) allRefs;

      newErrors = map (
        ref:
        lib.nameValuePair "objectRefUnknown" "${ref.path} references unknown ${ref.kind} object '${ref.name}'"
      ) unresolvedRefs;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  normalizeTable =
    table:
    let
      final = lib.pipe (mkInitialState table) [
        # Compute phases — populate ctx with derived state.
        convertNodesToZones
        computeZoneMembership
        collectAllZoneNames
        expandWildcardZones
        resolvePriorities
        collectZoneRefs
        # Validators — every phase below appends to ctx.errors
        # (or ctx.warnings); the orchestrator throws once at the
        # end if any errors fired.
        checkParentRefs
        checkParentCycles
        checkNameCollisions
        checkNameKeyMismatch
        checkSettings
        checkZoneRefs
        checkZoneMatchable
        checkChainOverridePlacement
        checkChainPlacement
        checkRpfilterOverride
        checkChainOverrideSemantics
        checkExtraSectionFields
        checkWildcardZoneMix
        checkNodeAddresses
        checkNatBodies
        checkPolicyUniqueness
        checkSetNameCollisions
        checkInterfaceOverlap
        checkCidrOverlap
        checkCrossAxisOverlap
        checkObjectRefs
      ];

      withWarnings =
        result:
        builtins.foldl' (
          acc: warning: lib.warn "nftzones.normalize: ${warning}" acc
        ) result final.ctx.warnings;
    in
    if final.ctx.errors == [ ] then
      withWarnings final
    else
      throw (
        "nftzones.normalize: validation failed:\n"
        + lib.concatMapStringsSep "\n" (error: "  - [${error.name}] ${error.value}") final.ctx.errors
      );
in
{
  inherit
    checkChainOverridePlacement
    checkChainOverrideSemantics
    checkChainPlacement
    checkCidrOverlap
    checkCrossAxisOverlap
    checkExtraSectionFields
    checkInterfaceOverlap
    checkNameCollisions
    checkNameKeyMismatch
    checkNatBodies
    checkNodeAddresses
    checkObjectRefs
    checkParentCycles
    checkParentRefs
    checkPolicyUniqueness
    checkRpfilterOverride
    checkSetNameCollisions
    checkSettings
    checkWildcardZoneMix
    checkZoneMatchable
    checkZoneRefs
    collectAllZoneNames
    collectZoneRefs
    computeZoneMembership
    convertNodesToZones
    expandWildcardZones
    normalizeTable
    resolvePriorities
    ;
}
