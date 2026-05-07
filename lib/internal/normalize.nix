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
        ↓ computeZoneSets               ctx.zoneSets
        ↓ computeChildrenOf             ctx.childrenOf
        ↓ computeRootZoneNames          ctx.rootZoneNames
        ↓ collectAllZoneNames           ctx.allZoneNames
        ↓ expandWildcardZones           ctx.expandedGroups
        ↓ resolvePriorities             ctx.resolvedPriorities
        ↓ collectZoneRefs               ctx.zoneRefs
        ↓ checkParentRefs               ctx.errors   (appends)
        ↓ checkParentCycles             ctx.errors   (appends)
        ↓ checkNameCollisions           ctx.errors   (appends)
        ↓ checkSettings                 ctx.errors   (appends)
        ↓ checkZoneRefs                 ctx.errors   (appends)
        ↓ checkZoneMatchable            ctx.errors   (appends)
        ↓ checkChainOverridePlacement   ctx.errors   (appends)
        ↓ checkChainPlacement           ctx.errors   (appends)
        ↓ checkRpfilterOverride         ctx.warnings (appends)
        ↓ checkPolicyUniqueness         ctx.errors   (appends)
        ↓ checkSetNameCollisions        ctx.errors   (appends)
        ↓ checkInterfaceOverlap         ctx.errors   (appends)
        ↓ checkCidrOverlap              ctx.errors   (appends)
        ↓ checkObjectRefs               ctx.errors   (appends)
      { table;
        ctx = {
          mergedZones; zoneSets; childrenOf; rootZoneNames;
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

  ===== computeZoneSets =====

  Reads:  ctx.mergedZones
  Writes: ctx.zoneSets

  Folds `internal.zone.genSets` over every merged zone. The
  resulting attrset is the single source of truth for zone-derived
  set names and bodies, consumed by:
    - `checkSetNameCollisions` (just keys)
    - `checkObjectRefs` (just keys, for the resolution union)
    - Phase 4 emit (full bodies, for `assembleOutput`)

  Materializing once in Phase 1 avoids redundant evaluation in
  three downstream consumers.

  ===== convertNodesToZones =====

  Reads:  table.zones, table.nodes
  Writes: ctx.mergedZones

  Lowers each node via `node.toZone`, completes it to the full
  `nftzones.types.zone` submodule shape (filling in `name`,
  `matchOverride` defaults), then merges into the declared zones.
  Result is a uniformly-shaped attrset.

  ===== checkParentRefs =====

  Reads:  ctx.mergedZones, table.settings.localZone
  Writes: ctx.errors (appends)

  Verifies every non-null `zone.parent` resolves to a key in
  `ctx.mergedZones`. The `localZone` sentinel is forbidden as a
  parent — it isn't a real zone, has no ingress match, and can't
  participate in chain dispatch. Each error is
  `lib.nameValuePair "zoneParentUnknown" <message>` for unresolved
  parents, or `"zoneParentLocalZone" <message>` for the localZone
  case.

  ===== checkParentCycles =====

  Reads:  ctx.mergedZones
  Writes: ctx.errors (appends)

  Walks each zone's parent chain; if a name is revisited within
  the same walk, emits a cycle error. Each cycle is canonicalized
  by rotating its node list so the lex-smallest member leads,
  then formatted — so the same cycle discovered from different
  starting points produces one error per cycle rather than one
  per starting point.

  Each error is `lib.nameValuePair "zoneParentCycle" <message>`
  with the cycle path joined by `" → "`.

  ===== computeChildrenOf =====

  Reads:  ctx.mergedZones
  Writes: ctx.childrenOf

  Inverse map of `parent`: for each parent name that appears in
  any `zone.parent` field, lists the children that point at it.
  Roots (zones with `parent == null`) are not present in
  `childrenOf`'s keys; consumers read with `or [ ]`. Children
  lists are alphabetically sorted for stable jump emission order
  in Phase 4 emit.

  ===== computeRootZoneNames =====

  Reads:  ctx.mergedZones, table.settings.localZone
  Writes: ctx.rootZoneNames

  Computes the list of root zones: zones in `mergedZones` whose
  `parent == null`, plus the `localZone` sentinel. Used in two
  places:
    - Wildcard from-side expansion (`from = [ "all" ]`) substitutes
      this list rather than every zone, since descendants reach
      traffic via parent dispatch.
    - Phase 4 emit's `mkBaseChain` jump-rule construction emits
      base-chain jumps only for root from-zones whose subtree has
      content for the relevant to-zone.

  ===== checkNameCollisions =====

  Reads:  table.zones, table.nodes
  Writes: ctx.errors (appends)

  Detects names declared as both a zone and a node — node-to-zone
  lowering would silently overwrite the zone otherwise. Each error
  is `lib.nameValuePair "zoneNameCollision" <message>`.

  ===== collectAllZoneNames =====

  Reads:  ctx.mergedZones, table.settings.localZone
  Writes: ctx.allZoneNames

  Computes the in-scope zone-name list — declared zones, lowered
  nodes, and `settings.localZone`. Consumed by both
  `expandWildcardZones` and `checkZoneRefs`.

  ===== expandWildcardZones =====

  Reads:  ctx.allZoneNames, table.{filters,...,droutes},
          table.settings.wildcardZone
  Writes: ctx.expandedGroups

  Produces the wildcard-expanded `from` / `to` per
  (group, entry, direction). Substitution + dedup is inlined as a
  local helper since this is the only consumer.

  Output shape:
    expandedGroups = {
      filters  = { <entry-name> = { from = [...]; to = [...]; }; ... };
      policies = { ... };
      snats    = { ... };
      dnats    = { <entry-name> = { from = [...]; }; ... };
      sroutes  = { <entry-name> = { from = [...]; }; ... };
      droutes  = { <entry-name> = { to   = [...]; }; ... };
    };

  ===== resolvePriorities =====

  Reads:  table.{filters, snats, dnats, sroutes, droutes}
  Writes: ctx.resolvedPriorities

  Resolves each entry's `priority` (which is `either int symbol`)
  to a plain int via `internal.priority.resolvePriority`.
  Stored per-group, per-entry. Consumed by Phase 3 (dispatch + sort)
  so sorting compares ints, not mixed values. Policies skip this
  phase because they don't carry a `priority` field — they are
  always tail rules.

  Output shape:
    resolvedPriorities = {
      filters = { <entry-name> = <int>; … };
      snats   = { <entry-name> = <int>; … };
      dnats   = { <entry-name> = <int>; … };
      sroutes = { <entry-name> = <int>; … };
      droutes = { <entry-name> = <int>; … };
    };

  ===== collectZoneRefs =====

  Reads:  table.{filters,...,droutes,nodes,settings.wildcardZone}
  Writes: ctx.zoneRefs

  Walks the *original* table and emits one record per zone-name
  reference, skipping wildcard placeholders (those are not
  unresolved references — they're a directive). Paths use
  user-input slot indices.

  Record shapes:
    - Group-side ref:  `{ zone; path; direction; }`
                       (`direction` ∈ `{ "from" "to" }`)
    - Node parent ref: `{ zone; path; }` (no `direction`)

  `direction` lets `checkZoneMatchable` know which side of the
  zone's `matchOverride` (and raw `interfaces` / `cidrs`) to
  validate against.

  ===== checkSettings =====

  Reads:  table.settings.{wildcardZone, localZone}, ctx.mergedZones
  Writes: ctx.errors (appends)

  Sanity checks on the settings-driven zone names:
    - `settings.wildcardZone` and `settings.localZone` must differ
      (otherwise dispatch and wildcard expansion conflict).
    - Neither may shadow a declared zone or node name (the declared
      name would be unreachable by user rules).
  Each error is `lib.nameValuePair "settingsConflict" <message>`.

  ===== checkZoneRefs =====

  Reads:  ctx.zoneRefs, ctx.allZoneNames
  Writes: ctx.errors (appends)

  Verifies every collected zone reference resolves to a known
  zone (declared zone, lowered node, or `settings.localZone`).
  Each error is `lib.nameValuePair "invalidZoneRef" <message>`.

  ===== checkZoneMatchable =====

  Reads:  ctx.zoneRefs, ctx.mergedZones, table.settings.localZone
  Writes: ctx.errors (appends)

  Verifies that every group-side zone reference (`from` / `to` on
  filter / policy / snat / dnat / sroute / droute entries) hits a
  zone whose match is non-empty *on the side actually used*:
  `from` → ingress, `to` → egress.

  Inspects raw `zone.interfaces` / `cidrs` / `matchOverride`
  directly. Phase 4 emit reads the same raw fields via
  `internal.zone.genSets`.

  Without this check, a zone declared as `zones.foo = { };` (empty
  interfaces, empty CIDRs, no `matchOverride`) — or one with an
  asymmetric `matchOverride` that populates only one side — would
  silently produce unconditional jumps in Phase 4, almost certainly
  not what the user wanted.

  Skipped:
    - Refs without `direction` (node parent refs — naming, not
      matching).
    - Refs to `settings.localZone` (sentinel, no `mergedZones`
      entry by design — Phase 4 skips that side's match too).
    - Refs to unknown zones (already flagged by `checkZoneRefs`,
      no need to double-error).

  Each error is `lib.nameValuePair "zoneNotMatchable" <message>`.

  ===== checkChainOverridePlacement =====

  Reads:  ctx.expandedGroups, ctx.mergedZones,
          table.{filters, snats, dnats, settings.localZone}
  Writes: ctx.errors (appends)

  Verifies that filter / snat / dnat entries with a `chain`
  override land at a hook where their `from` / `to` zones can
  actually be matched. Without this check, an entry overridden to
  e.g. `(prerouting, raw)` with a `to` zone that's interface-only
  would silently emit a jump *without* any to-direction constraint
  (oifname is unavailable in prerouting), broadening the entry's
  scope far beyond what the user wrote.

  A zone direction is reachable at hook H if any of:
    - the zone is `localZone` (always wildcard);
    - `zone.cidrs` is non-empty (addr matching always works);
    - `zone.matchOverride.<side>.{ipv4,ipv6,extra}` has a
      contributing section (always reachable — these sections are
      hook-agnostic by construction);
    - `zone.matchOverride.<side>.interfaces` is contributing
      AND the relevant interface field is valid at H (the
      interfaces section is treated as iif/oif content by
      convention);
    - `zone.interfaces` is non-empty AND the relevant interface
      field (`iifname` for `from`, `oifname` for `to`) is valid
      at H. `oifname` validity uses
      `nftypes.compatibility.hooksWithOifname`; `iifname` is
      valid at every hook except `output`.

  "Contributing" means the section is non-null AND non-empty.

  Operates on `ctx.expandedGroups` so wildcard expansions like
  `from = [ "all" ]` are checked per resolved zone.

  Each error is `lib.nameValuePair "chainOverrideUnreachable"
  <message>`.

  ===== checkPolicyUniqueness =====

  Reads:  ctx.expandedGroups.policies
  Writes: ctx.errors (appends)

  At most one policy may apply per `(from, to)` cell after
  expansion. A policy entry like `from = [ "all" ]; to = [ "wan" ]`
  fans out to a cell per in-scope source zone; if a second, more
  specific policy targets one of those same `(from, to)` pairs,
  the resulting nftables ruleset's tail rule for that pair would
  have an undefined winner. This validator catches the conflict
  at compile time by enumerating `(entryName, from, to)` triples
  from `ctx.expandedGroups.policies` and flagging any `(from, to)`
  pair claimed by more than one entry.

  Each error is `lib.nameValuePair "policyConflict" <message>`,
  with the message naming the `(from, to)` pair and every entry
  whose expansion produced a cell for it.

  ===== checkSetNameCollisions =====

  Reads:  table.objects.sets, ctx.mergedZones
  Writes: ctx.errors (appends)

  Catches collisions between user-declared `objects.sets.<name>`
  and auto-generated zone-derived set names (`<zone>_iifs` /
  `<zone>_v4` / `<zone>_v6` from `internal.zone.genSets`). Phase 4
  emit merges the two namespaces under `body.sets` and the user's
  body wins on collision — silently overwriting the zone-derived
  set, breaking every jump rule that referenced it.

  Runs before `checkObjectRefs` so that validator can resolve
  refs against the union of both namespaces without ambiguity:
  by the time `checkObjectRefs` runs, no collision exists.

  Each error is `lib.nameValuePair "setNameCollision" <message>`.

  ===== checkInterfaceOverlap =====

  Reads:  ctx.mergedZones
  Writes: ctx.errors (appends)

  Two distinct zones declaring the same interface produce
  ambiguous dispatch — packets matching `@<zoneA>_iifs` also
  match `@<zoneB>_iifs`, and whichever zone's jump fires first
  wins. The losing zone's rules never apply, silently breaking
  the intended policy.

  Pair-wise comparison over every (zoneName, iface) pair from
  `ctx.mergedZones`. Skips pairs whose zones are in an
  ancestor/descendant relation (parent/child sharing an
  interface is intentional — child traffic is dispatched into
  the parent's chain first, then the parent's chain dispatches
  to the child). Same-zone duplicates in the `interfaces` list
  are also flagged as a separate misconfiguration class.

  Each error is `lib.nameValuePair "interfaceOverlap" <message>`.

  ===== checkCidrOverlap =====

  Reads:  ctx.mergedZones
  Writes: ctx.errors (appends)

  Same ambiguous-dispatch failure mode as `checkInterfaceOverlap`,
  for CIDR prefixes. Pair-wise comparison over every
  (zoneName, cidr) entry from `ctx.mergedZones`. Skips zone pairs
  in an ancestor/descendant relation — a child zone's CIDR is
  intentionally inside its parent's (the canonical case is a
  node lowered into its parent zone, e.g. `web-server` with
  address `10.0.0.5` inside `dmz` with `10.0.0.0/24`).

  Family-aware via `libnet.cidr.overlaps`: v4 vs v6 prefixes
  always return false. Intra-zone overlaps (e.g.
  `cidrs = [ "10.0.0.0/24" "10.0.0.0/28" ]`) are also flagged
  as a separate misconfiguration class.

  Each error is `lib.nameValuePair "cidrOverlap" <message>`.

  ===== checkObjectRefs =====

  Reads:  table.{filters,snats,dnats,sroutes,droutes}.<entry>.rule,
          ctx.mergedZones.<zone>.matchOverride.{ingress,egress},
          table.objects.<kind>.<name> (full bodies, recursively),
          table.objects.<kind> (key list, for resolution)
  Writes: ctx.errors (appends)

  Walks every place where a user can supply nftables-DSL content
  with named refs:
    - entry rule bodies (all five rule groups)
    - non-null zone matchOverride content (ingress + egress)
    - object bodies (sets / maps may carry refs in element-
      attached stateful statements via `dsl.expr.elem { val;
      stmt; }`; other object kinds are config-only leaves and
      contribute no refs)

  Each ref is resolved against `table.objects.<kind>` (plus
  zone-derived set names for `kind == "sets"`). Unknowns become
  `objectRefUnknown` errors with the source path; users see
  typos at compile time instead of at `nft load` time.

  Not covered: chain refs from raw `dsl.jump <name>` /
  `dsl.goto <name>` inside rule bodies. nftzones generates chain
  names internally (`<hook>-at-<priority>__<key>`) and does not
  document them as a stable surface, so manually-written jumps
  to those names are not validated. See follow-up #1 in
  `docs/compile-pipeline-draft.md` for the design discussion.

  Resolves names against the union of two namespaces:
    - `table.objects.<kind>` keys (user-declared named objects)
    - For `kind == "sets"` only: predictable zone-derived set
      names (`<zone>_iifs` / `<zone>_v4` / `<zone>_v6`) emitted
      by Phase 4. This lets users write raw `match` clauses
      against zone membership when `from` / `to` mechanics
      aren't expressive enough — see open question 6 (decision
      (a)) in `docs/compile-pipeline-draft.md`.

  Each error is `lib.nameValuePair "objectRefUnknown" <message>`.

  ===== normalizeTable =====

  Input:  A `nftzones.types.table` value.

  Output: `{ table; ctx }` — the pipeline context. `table` is
          the original input; `ctx` carries every artifact
          Phase 1 computed (`mergedZones`, `allZoneNames`,
          `expandedGroups`, `zoneRefs`, `errors`). Consumed by
          downstream phases.

  Errors: `ctx.errors` is a list of `{ name; value; }` records
          where `name` is the error tag (e.g. `"zoneNameCollision"`,
          `"invalidZoneRef"`) and `value` is the human-readable
          message. If non-empty after the pipeline, throws a single
          aggregated message listing every error.
*/
{ inputs, internal }:
let
  inherit (inputs) lib libnet nftypes;
  inherit (internal.node) toZone;
  inherit (internal.zone) genSets getActiveMatchOverrides;

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

  /*
    Maps a group-side direction (`from` / `to`) to the zone's
    matchOverride side it consults. `from` matches inbound
    packets → ingress; `to` matches outbound → egress. Used by
    `checkChainOverridePlacement` and `checkZoneMatchable`.
  */
  directionToSide = {
    from = "ingress";
    to = "egress";
  };

  # Rule-bearing groups, in pipeline-canonical order. Used by
  # validators and bookkeeping that need to iterate every group.
  groupNames = [
    "filters"
    "policies"
    "snats"
    "dnats"
    "sroutes"
    "droutes"
  ];

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

  computeZoneSets =
    { table, ctx }:
    {
      inherit table;
      ctx = ctx // {
        zoneSets = lib.foldlAttrs (
          acc: name: zone:
          acc // genSets name zone
        ) { } ctx.mergedZones;
      };
    };

  /*
    `parentOf zone` reads `zone.parent or null` — accommodating
    raw test fixtures that bypass the type system. Submodule-
    evaluated zones always have `parent` defaulted to null.
  */
  parentOf = zone: zone.parent or null;

  /*
    `strictAncestorsOf mergedZones name` returns the strict
    ancestor chain of `name` (its parent, grandparent, …),
    excluding `name` itself. Walks until reaching a null parent
    or an unresolved one. Cycle-safe via `visited` membership —
    `checkParentCycles` rejects cycles upstream, but the walk
    short-circuits anyway so the helper works on raw fixtures.
  */
  strictAncestorsOf =
    mergedZones: name:
    let
      step =
        visited: cur:
        let
          zone = mergedZones.${cur} or null;
          parent = if zone == null then null else parentOf zone;
        in
        if parent == null || builtins.elem parent visited || !(mergedZones ? ${parent}) then
          visited
        else
          step (visited ++ [ parent ]) parent;
    in
    step [ ] name;

  /*
    Are zones `a` and `b` in an ancestor/descendant relation in
    `mergedZones`? True iff one is in the other's strict ancestor
    chain. Used by overlap validators to skip pairs whose overlap
    is intentional (parent CIDR contains child CIDR).
  */
  relatedByHierarchy =
    mergedZones: a: b:
    builtins.elem a (strictAncestorsOf mergedZones b)
    || builtins.elem b (strictAncestorsOf mergedZones a);

  checkParentRefs =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) mergedZones;

      newErrors = lib.foldlAttrs (
        acc: zoneName: zone:
        let
          p = parentOf zone;
        in
        if p == null then
          acc
        else if p == localZone then
          acc
          ++ [
            (lib.nameValuePair "zoneParentLocalZone" "zones.${zoneName}.parent is '${p}' (the localZone sentinel) — localZone cannot be a parent")
          ]
        else if !(mergedZones ? ${p}) then
          acc
          ++ [
            (lib.nameValuePair "zoneParentUnknown" "zones.${zoneName}.parent references unknown zone '${p}'")
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
          matches = builtins.filter (e: e.v == needle) (lib.imap0 (i: v: { inherit i v; }) list);
        in
        (builtins.head matches).i;

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
          minIdx = indexOf minNode nodes;
        in
        (lib.drop minIdx nodes) ++ (lib.take minIdx nodes);

      formatCycle = nodes: lib.concatStringsSep " → " (nodes ++ [ (builtins.head nodes) ]);

      cycles = lib.pipe (builtins.attrNames mergedZones) [
        (map walkChain)
        (builtins.filter (chain: chain != [ ]))
        (map canonicalRotation)
        (map formatCycle)
        lib.unique
      ];

      newErrors = map (msg: lib.nameValuePair "zoneParentCycle" "zone parent cycle: ${msg}") cycles;
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ newErrors;
      };
    };

  computeChildrenOf =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;

      childrenOf = lib.mapAttrs (_: lib.sort (a: b: a < b)) (
        lib.foldlAttrs (
          acc: zoneName: zone:
          let
            p = parentOf zone;
          in
          if p == null then
            acc
          else
            acc
            // {
              ${p} = (acc.${p} or [ ]) ++ [ zoneName ];
            }
        ) { } mergedZones
      );
    in
    {
      inherit table;
      ctx = ctx // {
        inherit childrenOf;
      };
    };

  computeRootZoneNames =
    { table, ctx }:
    let
      inherit (table.settings) localZone;
      inherit (ctx) mergedZones;

      rootsFromZones = lib.pipe mergedZones [
        (lib.filterAttrs (_: zone: parentOf zone == null))
        builtins.attrNames
      ];

      rootZoneNames = rootsFromZones ++ [ localZone ];
    in
    {
      inherit table;
      ctx = ctx // {
        inherit rootZoneNames;
      };
    };

  expandWildcardZones =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone;
      inherit (ctx) allZoneNames rootZoneNames;

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
        zones: lib.unique (lib.concatMap (z: if z == wildcardZone then rootZoneNames else [ z ]) zones);
      expandTo =
        zones: lib.unique (lib.concatMap (z: if z == wildcardZone then allZoneNames else [ z ]) zones);

      expandDirection =
        direction: entry: if direction == "from" then expandFrom entry.from else expandTo entry.to;

      expandEntry =
        directions: entry: lib.genAttrs directions (direction: expandDirection direction entry);

      expandGroup = directions: lib.mapAttrs (_: expandEntry directions);

      expandedGroups = {
        filters = expandGroup [ "from" "to" ] table.filters;
        policies = expandGroup [ "from" "to" ] table.policies;
        snats = expandGroup [ "from" "to" ] table.snats;
        dnats = expandGroup [ "from" ] table.dnats;
        sroutes = expandGroup [ "from" ] table.sroutes;
        droutes = expandGroup [ "to" ] table.droutes;
      };
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

      resolvedPriorities = {
        filters = resolveGroup table.filters;
        snats = resolveGroup table.snats;
        dnats = resolveGroup table.dnats;
        sroutes = resolveGroup table.sroutes;
        droutes = resolveGroup table.droutes;
      };
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
                  inherit zone direction;
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
        n:
        lib.nameValuePair "zoneNameCollision" "name collision: '${n}' is declared as both a zone and a node"
      ) collisions;
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

    Default placements are sourced from `internal.placement`,
    the same module Phase 3 dispatch reads — single source of
    truth for the per-group `(hook, priority)` constants.
  */
  checkChainPlacement =
    { table, ctx }:
    let
      inherit (table) family;
      inherit (table.settings) localZone;
      inherit (nftypes) chainTypeFor validChainPlacement;
      inherit (internal.placement) defaultGroupChainAttrs filterChainPriority;

      /*
        For a filter/policy entry, derive every hook the dispatch
        could land on. Hook depends solely on whether `localZone`
        appears on the from / to side, so a membership check beats
        materializing the full cartesian.
      */
      filterHooks =
        dirs:
        let
          fromHasLocal = builtins.elem localZone dirs.from;
          toHasLocal = builtins.elem localZone dirs.to;
          nonLocalFrom = builtins.length dirs.from > (if fromHasLocal then 1 else 0);
          nonLocalTo = builtins.length dirs.to > (if toHasLocal then 1 else 0);
        in
        lib.optional toHasLocal "input"
        ++ lib.optional fromHasLocal "output"
        ++ lib.optional (nonLocalFrom && nonLocalTo) "forward";

      placementsForEntry =
        group: entryName: entry:
        if (entry.chain or null) != null then
          [
            {
              inherit entryName;
              inherit (entry.chain) hook priority;
            }
          ]
        else if group == "filters" || group == "policies" then
          map (hook: {
            inherit entryName hook;
            priority = filterChainPriority;
          }) (filterHooks ctx.expandedGroups.${group}.${entryName})
        else
          [
            (defaultGroupChainAttrs.${group}
              // {
                inherit entryName;
              }
            )
          ];

      placementsForGroup =
        group:
        lib.concatLists (
          lib.mapAttrsToList (placementsForEntry group) (table.${group} or { })
        );

      mkError =
        group: p: reason:
        lib.nameValuePair "invalidChainPlacement" (
          "${group}.${p.entryName} would emit a base chain at "
          + "(family=${family}, hook=${p.hook}, priority=${toString p.priority}) "
          + "— ${reason}"
        );

      classify =
        group: p:
        let
          chainType = chainTypeFor family p.hook p.priority;
        in
        if chainType == null then
          [
            (mkError group p
              "priority symbol '${toString p.priority}' has no value in family '${family}'"
            )
          ]
        else if !(validChainPlacement family chainType p.hook) then
          [
            (mkError group p
              "kernel rejects chain type '${chainType}' on hook '${p.hook}' for family '${family}'"
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

      newWarnings = lib.optional (table.settings.rpfilter && lib.any groupClaims chainOverrideGroups) (
        "settings.rpfilter is enabled but a user chain override "
        + "already claims (prerouting, raw); the synthesized rpfilter "
        + "chain is suppressed and the user-authored chain is used "
        + "as-is. Add `fib saddr . iif oif eq 0 drop` to the override "
        + "manually if you want rpfilter behavior in that chain."
      );
    in
    {
      inherit table;
      ctx = ctx // {
        warnings = ctx.warnings ++ newWarnings;
      };
    };

  checkSettings =
    { table, ctx }:
    let
      inherit (table.settings) wildcardZone localZone;
      zoneNames = builtins.attrNames ctx.mergedZones;

      conflict = msg: lib.nameValuePair "settingsConflict" msg;

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
          entryName: dirs: lib.concatMap (from: map (to: { inherit entryName from to; }) dirs.to) dirs.from
        ) ctx.expandedGroups.policies
      );

      keyOf = t: "(${t.from} → ${t.to})";
      grouped = lib.groupBy keyOf triples;
      duplicates = lib.filterAttrs (_: ts: builtins.length ts > 1) grouped;

      newErrors = lib.mapAttrsToList (
        key: ts:
        lib.nameValuePair "policyConflict" "duplicate policy for ${key}: ${
          lib.concatStringsSep ", " (map (t: t.entryName) ts)
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
      inherit (ctx) zoneRefs allZoneNames;
      invalidZoneRefs = builtins.filter (r: !(builtins.elem r.zone allZoneNames)) zoneRefs;
      allZoneNamesStr = lib.concatStringsSep ", " (lib.sort (a: b: a < b) allZoneNames);
      newErrors = map (
        r:
        lib.nameValuePair "invalidZoneRef" "${r.path} references unknown zone '${r.zone}' (known: ${allZoneNamesStr})"
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
      inherit (ctx) mergedZones expandedGroups;

      iifAvailableAtHook =
        hook:
        builtins.elem hook [
          "prerouting"
          "input"
          "forward"
          "postrouting"
        ];
      oifAvailableAtHook = hook: builtins.elem hook nftypes.compatibility.hooksWithOifname;

      ifFieldName = direction: if direction == "from" then "iifname" else "oifname";

      addrFieldName = direction: if direction == "from" then "saddr" else "daddr";

      /*
        For one (zone reference, hook, direction), is the zone
        matchable at that placement? `localZone` and unknown zones
        are skipped (handled by other validators / wildcard
        sentinel).

        With the structured matchOverride, the sections that always
        produce a hook-agnostic clause (`ipv4` / `ipv6` / `extra`)
        make the zone reachable at any hook. The `interfaces`
        section is treated as iif/oif content by convention, so it
        still depends on hook validity.
      */
      reachable =
        zoneName: hook: direction:
        if zoneName == localZone || !(mergedZones ? ${zoneName}) then
          true
        else
          let
            zone = mergedZones.${zoneName};
            side = directionToSide.${direction};
            active = getActiveMatchOverrides zone side;
            ifAvailable = if direction == "from" then iifAvailableAtHook hook else oifAvailableAtHook hook;
          in
          zone.cidrs != [ ]
          || active ? ipv4
          || active ? ipv6
          || active ? extra
          || (active ? interfaces && ifAvailable)
          || (zone.interfaces != [ ] && ifAvailable);

      /*
        Per-group iteration. Only filter / snat / dnat carry a
        `chain` override field; sroute / droute / policy don't.
      */
      groupDirections = {
        filters = [
          "from"
          "to"
        ];
        snats = [
          "from"
          "to"
        ];
        dnats = [ "from" ];
      };

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
            expandedDirs = expandedGroups.${groupName}.${entryName};
          in
          lib.concatMap (
            direction:
            map (zoneName: {
              inherit
                groupName
                entryName
                hook
                priority
                direction
                zoneName
                ;
            }) expandedDirs.${direction}
          ) directions;

      enumerateGroup =
        groupName: directions:
        lib.concatLists (
          lib.mapAttrsToList (entryName: enumerateEntry groupName directions entryName) table.${groupName}
        );

      mkError =
        r:
        let
          side = directionToSide.${r.direction};
          addrField = addrFieldName r.direction;
          ifField = ifFieldName r.direction;
          msg =
            "${r.groupName}.${r.entryName}.${r.direction} references zone '${r.zoneName}'"
            + " which has no ${side} match expressible at chain"
            + " (hook=${r.hook}, priority=${toString r.priority})"
            + " — zone has no ${addrField} CIDRs and no hook-agnostic matchOverride.${side} sections"
            + " (ipv4 / ipv6 / extra) set, and ${ifField} is unavailable in ${r.hook}";
        in
        lib.nameValuePair "chainOverrideUnreachable" msg;

      newErrors = lib.pipe groupDirections [
        (lib.mapAttrsToList enumerateGroup)
        lib.concatLists
        (builtins.filter (r: !(reachable r.zoneName r.hook r.direction)))
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
      inherit (ctx) zoneRefs mergedZones;

      /*
        A zone is matchable on a given side iff EITHER the user set
        any non-empty override section for that side, OR (in the
        compute path) the zone declares any interfaces or CIDRs.
      */
      isMatchable =
        zone: side: getActiveMatchOverrides zone side != { } || zone.interfaces != [ ] || zone.cidrs != [ ];

      # Skip refs without a `direction` (node parent refs), refs to
      # the localZone sentinel (no `mergedZones` entry by design),
      # and refs to unknown zones (already flagged by checkZoneRefs).
      directionBoundRefs = builtins.filter (
        r: r ? direction && r.zone != localZone && mergedZones ? ${r.zone}
      ) zoneRefs;

      unmatchableRefs = builtins.filter (
        r:
        let
          side = directionToSide.${r.direction};
        in
        !(isMatchable mergedZones.${r.zone} side)
      ) directionBoundRefs;

      newErrors = map (
        r:
        let
          side = directionToSide.${r.direction};
          msg =
            "${r.path} references zone '${r.zone}' which has no ${side} match"
            + " (no interfaces, no CIDRs, and no matchOverride sections set on the ${side} side)";
        in
        lib.nameValuePair "zoneNotMatchable" msg
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
      zoneSetNames = builtins.attrNames ctx.zoneSets;

      collisions = lib.intersectLists userSetNames zoneSetNames;

      # Reverse map { setName -> sourceZone } so error messages
      # name the responsible zone. Lazy: never forced when
      # `collisions` is empty (the happy path).
      zoneSetSource = lib.foldlAttrs (
        acc: zoneName: zone:
        acc // lib.mapAttrs (_: _: zoneName) (genSets zoneName zone)
      ) { } ctx.mergedZones;

      newErrors = map (
        n:
        let
          sourceZone = zoneSetSource.${n};
          suffix = lib.removePrefix "${sourceZone}_" n;
        in
        lib.nameValuePair "setNameCollision" (
          "objects.sets.${n} collides with the auto-generated set name "
          + "from zone '${sourceZone}' (suffix '${suffix}'); rename one"
        )
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

      /*
        All (zoneName, iface) pairs across every merged zone, in
        zone-then-list order. Pair-wise comparison below flags
        same-iface conflicts.
      */
      allEntries = lib.concatMap (
        zoneName:
        map (iface: { inherit zoneName iface; }) mergedZones.${zoneName}.interfaces
      ) (builtins.attrNames mergedZones);

      n = builtins.length allEntries;

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
            shouldFlag =
              sameIface
              && (sameZone || !(relatedByHierarchy mergedZones a.zoneName b.zoneName));
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
        ) (lib.range (i + 1) (n - 1))
      ) (lib.range 0 (n - 1));
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

      /*
        All (zoneName, cidr-as-string, cidr-parsed) triples across
        every merged zone. Parse is lazy per entry — only forced
        on overlap check below.
      */
      allEntries = lib.concatMap (
        zoneName:
        map (cidrStr: {
          inherit zoneName cidrStr;
          parsed = libnet.cidr.parse cidrStr;
        }) mergedZones.${zoneName}.cidrs
      ) (builtins.attrNames mergedZones);

      n = builtins.length allEntries;

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
            shouldCheck =
              sameZone || !(relatedByHierarchy mergedZones a.zoneName b.zoneName);
          in
          if shouldCheck && libnet.cidr.overlaps a.parsed b.parsed then
            [
              (lib.nameValuePair "cidrOverlap" (
                if sameZone then
                  "zone '${a.zoneName}' has overlapping CIDRs '${a.cidrStr}' and '${b.cidrStr}'"
                else
                  "zone '${a.zoneName}' CIDR '${a.cidrStr}' overlaps zone '${b.zoneName}' CIDR '${b.cidrStr}' (no ancestor/descendant relationship)"
              ))
            ]
          else
            [ ]
        ) (lib.range (i + 1) (n - 1))
      ) (lib.range 0 (n - 1));
    in
    {
      inherit table;
      ctx = ctx // {
        errors = ctx.errors ++ pairErrors;
      };
    };

  checkObjectRefs =
    { table, ctx }:
    let
      inherit (ctx) mergedZones;
      inherit (internal.refs) extractRefs;

      /*
        Zone-derived set names cached in `ctx.zoneSets` by
        `computeZoneSets`, also consumed by Phase 4 emit's
        `assembleOutput`.

        Collisions between `objects.sets.<name>` and zone-derived
        names are caught upstream by `checkSetNameCollisions`, so
        the union here is unambiguous when the table reaches this
        validator (or the table is rejected before it gets here).
      */
      zoneSetNames = builtins.attrNames ctx.zoneSets;

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
        `getActiveMatchOverrides`. Inactive sections (null or
        empty) carry no refs by definition — filtering at the
        helper boundary skips them cleanly. Section name is
        included in the ref's source path so error messages point
        at the exact field (e.g.
        `zones.lan.matchOverride.ingress.ipv4`).
      */
      refsFromMatchOverrides = lib.concatLists (
        lib.mapAttrsToList (
          zoneName: zone:
          lib.concatMap
            (
              dir:
              lib.concatLists (
                lib.mapAttrsToList (
                  section: body:
                  map (
                    ref:
                    ref
                    // {
                      path = "zones.${zoneName}.matchOverride.${dir}.${section}";
                    }
                  ) (extractRefs body)
                ) (getActiveMatchOverrides zone dir)
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

      allRefs = lib.concatLists [
        (refsFromGroup "filters" table.filters)
        (refsFromGroup "snats" table.snats)
        (refsFromGroup "dnats" table.dnats)
        (refsFromGroup "sroutes" table.sroutes)
        (refsFromGroup "droutes" table.droutes)
        refsFromMatchOverrides
        refsFromObjects
      ];

      unresolvedRefs = builtins.filter (r: !(builtins.elem r.name (knownNames.${r.kind} or [ ]))) allRefs;

      newErrors = map (
        r: lib.nameValuePair "objectRefUnknown" "${r.path} references unknown ${r.kind} object '${r.name}'"
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
        computeZoneSets
        computeChildrenOf
        computeRootZoneNames
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
        checkSettings
        checkZoneRefs
        checkZoneMatchable
        checkChainOverridePlacement
        checkChainPlacement
        checkRpfilterOverride
        checkPolicyUniqueness
        checkSetNameCollisions
        checkInterfaceOverlap
        checkCidrOverlap
        checkObjectRefs
      ];

      withWarnings =
        result: builtins.foldl' (acc: msg: lib.warn "nftzones.normalize: ${msg}" acc) result final.ctx.warnings;
    in
    if final.ctx.errors == [ ] then
      withWarnings final
    else
      throw (
        "nftzones.normalize: validation failed:\n"
        + lib.concatMapStringsSep "\n" (e: "  - [${e.name}] ${e.value}") final.ctx.errors
      );
in
{
  inherit
    convertNodesToZones
    computeZoneSets
    checkParentRefs
    checkParentCycles
    computeChildrenOf
    computeRootZoneNames
    checkNameCollisions
    checkPolicyUniqueness
    checkSettings
    collectAllZoneNames
    expandWildcardZones
    resolvePriorities
    collectZoneRefs
    checkZoneRefs
    checkZoneMatchable
    checkChainOverridePlacement
    checkChainPlacement
    checkRpfilterOverride
    checkSetNameCollisions
    checkInterfaceOverlap
    checkCidrOverlap
    checkObjectRefs
    normalizeTable
    ;
}
