/*
  internal/zone — resolves zone membership once for validation and
  emission. `resolveMembership { zones; localZone; }` accepts the
  merged declarations (including lowered nodes). Callers never pair
  raw declarations with synthetic sets or preselected overrides.

  The resolved value exposes distinct answers:
    sets / setOwners     — transitive, coalesced sets and their owners;
    childrenOf / rootZoneNames / ancestorsOf / related
                         — hierarchy for wildcard expansion, overlap
                           validation and from-side dispatch topology;
    activeOverrides      — contributing sections for reference checks;
    hasOwnMatch          — whether a declared zone can be referenced
                           on a side (descendants deliberately excluded);
    reachableAt          — own matchability at a hook and direction;
    directionVariants    — DSL-built dispatch clauses, with own sections
                           ANDed and descendant-only sections widening
                           the gate as OR variants;
    crossAxisPairs       — unrelated, anchored zones split across the
                           effective from-side interface/address axes.

  Own declarations, descendant membership and ancestor gates retain
  separate meanings. Empty grouping zones can dispatch to descendants
  but cannot be referenced directly without an own match. Hierarchy
  applies only to from-side dispatch; to-side dispatch remains flat.

  Hierarchy walks are cycle-safe because this value is constructed
  before Phase 1 reports invalid parent references and cycles. Missing
  zone names are filtered by validators, never invented by emission.
*/
{ inputs }:
let
  inherit (inputs) lib libnet nftypes;
  inherit (nftypes.dsl) expr inSet;
  inherit (nftypes.dsl.fields) ip ip6 meta;

  directionToSide = {
    from = "ingress";
    to = "egress";
  };

  # Locally generated output has no input device. Device-bound
  # ingress chains are outside nftzones' zone-firewall model.
  interfaceAvailable =
    hook: direction:
    builtins.elem hook (
      if direction == "from" then
        [
          "prerouting"
          "input"
          "forward"
          "postrouting"
        ]
      else
        nftypes.compatibility.hooksWithOifname
    );

  cidrToPrefix =
    isV4: parsed:
    let
      addressString =
        if isV4 then libnet.ipv4.toString parsed.address else libnet.ipv6.toString parsed.address;
    in
    expr.prefix addressString parsed.prefix;

  /*
    Transitive descendants of `name`. DFS over `childrenOf`, not
    including `name` itself. Order is parent-before-child (each
    level appears before its children's children).

    Defensive cycle guard: `resolveMembership` runs before Phase 1's
    `checkParentCycles` in the validator pipeline, so a cycle
    here would stack-overflow before the dedicated validator
    reports it. The `visited` set short-circuits any revisit so
    a cyclic input fails the eventual `checkParentCycles` check
    with a clean error rather than hitting Nix's max-call-depth.
  */
  descendantsOf =
    childrenOf: name:
    let
      step =
        visited: current:
        let
          direct = builtins.filter (c: !(builtins.elem c visited)) (childrenOf.${current} or [ ]);
          visited' = visited ++ direct;
        in
        direct ++ lib.concatMap (step visited') direct;
    in
    step [ name ] name;

  genSets =
    mergedZones: childrenOf: name:
    let
      contributingZones = [ name ] ++ descendantsOf childrenOf name;
      contributing = map (z: mergedZones.${z}) contributingZones;

      # Interfaces: dedup at the string level — `lib.unique`
      # preserves first-occurrence order, so parent's interfaces
      # come before descendants' (matching the contribution
      # order). nft's ifname set has no notion of overlap; exact
      # duplicates are the only thing to remove.
      allInterfaces = lib.unique (lib.concatMap (z: z.interfaces or [ ]) contributing);

      # CIDRs: `libnet.cidr.summarize` handles family separation,
      # canonicalisation (network bits masked), and the full
      # set-coalescing algebra — exact duplicates, subset overlaps
      # (a descendant CIDR contained in an ancestor), and sibling
      # fusion (two adjacent same-prefix blocks → one supernet).
      # Doing this at compile time means the rendered set equals
      # the live kernel state — no `auto-merge` post-processing
      # needed.
      summarised = libnet.cidr.summarize (
        map libnet.cidr.parse (lib.concatMap (z: z.cidrs or [ ]) contributing)
      );
      parsedV4 = builtins.filter libnet.cidr.isIpv4 summarised;
      parsedV6 = builtins.filter libnet.cidr.isIpv6 summarised;
    in
    lib.optionalAttrs (allInterfaces != [ ]) {
      "${name}_iifs" = {
        type = "ifname";
        elements = allInterfaces;
      };
    }
    // lib.optionalAttrs (parsedV4 != [ ]) {
      "${name}_v4" = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = map (cidrToPrefix true) parsedV4;
      };
    }
    // lib.optionalAttrs (parsedV6 != [ ]) {
      "${name}_v6" = {
        type = "ipv6_addr";
        flags = [ "interval" ];
        elements = map (cidrToPrefix false) parsedV6;
      };
    };

  /*
    Returns the active sections of `zone.matchOverride.<side>` —
    sections whose value is non-null AND non-empty. Sections set
    to `null` (default) or `[ ]` (explicitly empty) are filtered
    out. Both encode "no constraint contributed by this section".

    Result is an attrset keyed by the surviving section names
    (`interfaces` / `ipv4` / `ipv6` / `extra`). Callers test
    presence with `?` (`active ? ipv4`) or read with defaults
    (`active.ipv4 or autoV4`).
  */
  getActiveMatchOverrides =
    zone: side:
    lib.filterAttrs (_: section: section != null && section != [ ]) (zone.matchOverride.${side} or { });

  /*
    Classify which sections `zone` anchors with its own raw
    fields, ignoring descendants. Family split mirrors `genSets`
    (libnet parse + isIpv4/isIpv6) so the two never disagree on
    what counts as a v4/v6 contribution.
  */
  ownSectionsOf =
    zone:
    let
      parsed = map libnet.cidr.parse (zone.cidrs or [ ]);
    in
    {
      interfaces = (zone.interfaces or [ ]) != [ ];
      v4 = builtins.any libnet.cidr.isIpv4 parsed;
      v6 = builtins.any libnet.cidr.isIpv6 parsed;
    };

  # Strict ancestors, nearest first. Stop at unknown parents and cycles;
  # Phase 1 owns diagnostics for those invalid declarations.
  walkParents =
    mergedZones: name:
    let
      step =
        visited: current:
        if current == null then
          [ ]
        else
          let
            zone = mergedZones.${current} or null;
            parent = if zone == null then null else zone.parent or null;
          in
          if parent == null || builtins.elem parent visited || !(mergedZones ? ${parent}) then
            [ ]
          else
            [ parent ] ++ step (visited ++ [ parent ]) parent;
    in
    step [ name ] name;

  # One list of DSL statements per OR branch; statements within a
  # branch AND together. Section provenance stays private here.
  mkDirectionVariants =
    {
      hook,
      direction,
      zoneName,
      active,
      own,
      zoneSets,
      localZone,
    }:
    if zoneName == null || zoneName == localZone then
      [ [ ] ]
    else
      let
        isFromDirection = direction == "from";
        interfaceIsAvailable = interfaceAvailable hook direction;

        interfaceField = if isFromDirection then meta.iifname else meta.oifname;
        addressFieldV4 = if isFromDirection then ip.saddr else ip.daddr;
        addressFieldV6 = if isFromDirection then ip6.saddr else ip6.daddr;

        interfaceSetName = "${zoneName}_iifs";
        v4SetName = "${zoneName}_v4";
        v6SetName = "${zoneName}_v6";

        autoInterfaces = lib.optional (zoneSets ? ${interfaceSetName}) (
          inSet interfaceField (expr.setRef interfaceSetName)
        );
        autoV4 = lib.optional (zoneSets ? ${v4SetName}) (inSet addressFieldV4 (expr.setRef v4SetName));
        autoV6 = lib.optional (zoneSets ? ${v6SetName}) (inSet addressFieldV6 (expr.setRef v6SetName));

        # Active section wins if present; else fall back to auto.
        interfacesSection = active.interfaces or autoInterfaces;
        v4Section = active.ipv4 or autoV4;
        v6Section = active.ipv6 or autoV6;
        extraSection = active.extra or [ ];

        # Interfaces section is hook-gated: drop it when the relevant
        # iif/oif field isn't valid at the hook.
        # checkChainOverridePlacement should have flagged this case, so
        # this is defensive.
        interfacesAtHook = if interfaceIsAvailable then interfacesSection else [ ];

        # An active override is always own, including on grouping zones.
        interfacesOwn = active ? interfaces || own.interfaces;
        v4Own = active ? ipv4 || own.v4;
        v6Own = active ? ipv6 || own.v6;

        # Own-anchored prefix, ANDed into every family variant.
        # `extra` is override-only and therefore always own;
        # inherited interfaces never join (see inheritedInterfacesVariant).
        prefix = (if interfacesOwn then interfacesAtHook else [ ]) ++ extraSection;

        ownFamilyVariants =
          lib.optional (v4Own && v4Section != [ ]) (prefix ++ v4Section)
          ++ lib.optional (v6Own && v6Section != [ ]) (prefix ++ v6Section);

        # Descendant-contributed families widen the gate with one
        # OR variant each: the own family anchors are family-blind,
        # so without these a descendant of another family could
        # never enter the ancestor's sub-chain.
        inheritedFamilyVariants =
          lib.optional (!v4Own && v4Section != [ ]) (prefix ++ v4Section)
          ++ lib.optional (!v6Own && v6Section != [ ]) (prefix ++ v6Section);

        # Descendant-contributed interfaces stand alone as one
        # family-agnostic variant — ANDing them into the prefix
        # would narrow the zone's own variants to descendant
        # traffic.
        inheritedInterfacesVariant = lib.optional (
          !interfacesOwn && interfacesAtHook != [ ]
        ) interfacesAtHook;
      in
      if ownFamilyVariants != [ ] then
        # Family-anchored own gate, widened by whatever the
        # descendants contribute on top.
        ownFamilyVariants ++ inheritedFamilyVariants ++ inheritedInterfacesVariant
      else if prefix != [ ] then
        # Interface/extra-only own gate — family-agnostic, so the
        # whole subtree (including inherited families) already
        # rides it; nothing to widen.
        [ prefix ]
      else
        # Nothing own (grouping zone): every present section is
        # descendant-contributed and stands alone.
        inheritedFamilyVariants ++ inheritedInterfacesVariant;

  resolveMembership =
    { zones, localZone }:
    let
      # foldlAttrs visits names in lexical order, keeping child dispatch
      # deterministic without a separately supplied or sorted child map.
      childrenOf = lib.foldlAttrs (
        acc: name: zone:
        let
          parent = zone.parent or null;
        in
        if parent == null then acc else acc // { ${parent} = (acc.${parent} or [ ]) ++ [ name ]; }
      ) { } zones;

      rootZoneNames =
        builtins.attrNames (lib.filterAttrs (_: zone: (zone.parent or null) == null) zones)
        ++ [ localZone ];
      ancestors = lib.mapAttrs (name: _: walkParents zones name) zones;
      ancestorsOf = name: if name == null then [ ] else ancestors.${name} or [ ];
      related = a: b: builtins.elem a (ancestorsOf b) || builtins.elem b (ancestorsOf a);

      setsByZone = lib.mapAttrs (name: _: genSets zones childrenOf name) zones;
      sets = lib.foldlAttrs (
        acc: _: value:
        acc // value
      ) { } setsByZone;
      setOwners = lib.foldlAttrs (
        acc: name: value:
        acc // lib.mapAttrs (_: _: name) value
      ) { } setsByZone;
      ownSections = lib.mapAttrs (_: ownSectionsOf) zones;
      overrides = lib.mapAttrs (_: zone: {
        ingress = getActiveMatchOverrides zone "ingress";
        egress = getActiveMatchOverrides zone "egress";
      }) zones;
      activeOverrides = name: side: overrides.${name}.${side};

      # Validation asks about own declarations, not the transitive
      # sets. This preserves rejection of direct grouping-zone refs.
      hasOwnMatch =
        name: side:
        let
          zone = zones.${name};
        in
        activeOverrides name side != { } || (zone.interfaces or [ ]) != [ ] || (zone.cidrs or [ ]) != [ ];

      reachableAt =
        name:
        { hook, direction }:
        let
          zone = zones.${name};
          active = activeOverrides name directionToSide.${direction};
        in
        (zone.cidrs or [ ]) != [ ]
        || active ? ipv4
        || active ? ipv6
        || active ? extra
        || (interfaceAvailable hook direction && (active ? interfaces || (zone.interfaces or [ ]) != [ ]));

      directionVariants =
        {
          zoneName,
          hook,
          direction,
        }:
        mkDirectionVariants {
          inherit
            direction
            hook
            localZone
            zoneName
            ;
          zoneSets = sets;
          active = activeOverrides zoneName directionToSide.${direction};
          own = ownSections.${zoneName};
        };

      # This warning model uses raw fields only, ignoring overrides.
      # Parenting signals an intentional refinement. Ancestor axes
      # describe the from-side path; to-side shadowing and same-parent
      # sibling shadowing remain accepted residuals of the warning.
      # Grouping zones have no own axis and stay unclassified, avoiding
      # duplicate warnings for gates already audited at an ancestor.
      axisClass = lib.mapAttrs (
        name: zone:
        let
          anchored = (zone.interfaces or [ ]) != [ ] || (zone.cidrs or [ ]) != [ ];
          path = map (n: zones.${n}) ([ name ] ++ ancestorsOf name);
          hasInterfaces = lib.any (z: (z.interfaces or [ ]) != [ ]) path;
          hasCidrs = lib.any (z: (z.cidrs or [ ]) != [ ]) path;
        in
        if !anchored || hasInterfaces == hasCidrs then
          null
        else if hasInterfaces then
          "interface"
        else
          "cidr"
      ) zones;
      zoneNames = builtins.attrNames zones;
      crossAxisPairs = lib.concatLists (
        lib.imap0 (
          i: a:
          lib.concatMap (
            b:
            lib.optional (
              axisClass.${a} != null
              && axisClass.${b} != null
              && axisClass.${a} != axisClass.${b}
              && !(related a b)
            ) { inherit a b; }
          ) (lib.drop (i + 1) zoneNames)
        ) zoneNames
      );
    in
    {
      inherit
        activeOverrides
        ancestorsOf
        childrenOf
        crossAxisPairs
        directionVariants
        hasOwnMatch
        reachableAt
        related
        rootZoneNames
        setOwners
        sets
        ;
    };
in
{
  inherit directionToSide resolveMembership;
}
