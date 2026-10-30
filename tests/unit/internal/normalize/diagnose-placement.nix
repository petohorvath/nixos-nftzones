# Unit tests for Phase 1's placement and entry-body validators, through
# `diagnose`: chain placement, chain-override placement and semantics,
# the rpfilter override, `extra` section fields, the wildcard-zone mix,
# NAT bodies and object references. Each test writes a table body and
# compares the `{ tag; path; }` lists of errors and warnings.
{
  helpers,
  nftypes,
  ...
}:
let
  inherit (nftypes) dsl;

  inherit (helpers) diagnosticsFor;

  clean = {
    errors = [ ];
    warnings = [ ];
  };

  # Two interface-only zones, enough for most entries.
  lanWan = {
    lan.interfaces = [ "lan0" ];
    wan.interfaces = [ "wan0" ];
  };

  rawPrerouting = {
    hook = "prerouting";
    priority = "raw";
  };

  dnatTo443 = {
    match = [ ];
    action.dnat = {
      addr = "10.0.0.5";
      port = 443;
    };
  };
in
{
  # ===== chain placement =====

  testChainPlacementInetDefaultsAccepted = {
    expr = diagnosticsFor {
      family = "inet";
      zones = lanWan;
      filters.allow = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
      };
      snats.masq = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
      };
    };
    expected = clean;
  };

  # Bridge has no `nat` chain type, so the default snat placement at
  # (postrouting, srcnat) is rejected.
  testChainPlacementBridgeRejectsSnat = {
    expr = diagnosticsFor {
      family = "bridge";
      zones = lanWan;
      snats.masq = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidChainPlacement";
          path = [
            "snats"
            "masq"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # A srcnat priority needs a `nat` chain, which can't attach at
  # forward. `chainTypeFor` falls back to `filter` there, so the
  # placement is checked as `nat` and rejected.
  testChainPlacementNatPriorityAtForwardRejected = {
    expr = diagnosticsFor {
      family = "inet";
      zones = lanWan;
      snats.masq = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
        chain = {
          hook = "forward";
          priority = "srcnat";
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidChainPlacement";
          path = [
            "snats"
            "masq"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # Bridge has no `mangle` priority, so the default sroute placement
  # has no chain type; reported here rather than thrown by emit.
  testChainPlacementBridgeSrouteUnknownPriority = {
    expr = diagnosticsFor {
      family = "bridge";
      zones.lan.interfaces = [ "lan0" ];
      sroutes.mark = {
        from = [ "lan" ];
        rule = [ (dsl.mangle dsl.fields.meta.mark 1) ];
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidChainPlacement";
          path = [
            "sroutes"
            "mark"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testChainPlacementBridgeFilterAccepted = {
    expr = diagnosticsFor {
      family = "bridge";
      zones.lan.interfaces = [ "lan0" ];
      filters.allow = {
        from = [ "lan" ];
        to = [ "lan" ];
        rule = [ dsl.accept ];
      };
    };
    expected = clean;
  };

  # Overridden and default placements are both checked, across groups.
  testChainPlacementChecksOverridesAndDefaults = {
    expr = diagnosticsFor {
      family = "bridge";
      settings.localZone = "host";
      zones.lan.interfaces = [ "br0" ];
      filters.early = {
        from = [ "lan" ];
        to = [ "host" ];
        rule = [ dsl.accept ];
        chain = {
          hook = "prerouting";
          priority = "mangle";
        };
      };
      snats.masq = {
        from = [ "lan" ];
        to = [ "host" ];
        rule.action.masquerade = { };
      };
      droutes.mark = {
        to = [ "lan" ];
        rule = [ (dsl.mangle dsl.fields.meta.mark 1) ];
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidChainPlacement";
          path = [
            "droutes"
            "mark"
          ];
        }
        {
          tag = "invalidChainPlacement";
          path = [
            "filters"
            "early"
          ];
        }
        {
          tag = "invalidChainPlacement";
          path = [
            "snats"
            "masq"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== chain-override placement =====

  testChainOverrideAtDefaultPlacementAccepted = {
    expr = diagnosticsFor {
      zones = lanWan;
      filters.f = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
        chain = {
          hook = "forward";
          priority = "filter";
        };
      };
    };
    expected = clean;
  };

  # `daddr` works at every hook, so a CIDR zone stays reachable at
  # prerouting, where `oifname` is unavailable. Both zones use CIDRs to
  # avoid a cross-axis overlap warning.
  testChainOverrideCidrZoneReachableAtPrerouting = {
    expr = diagnosticsFor {
      zones = {
        lan.cidrs = [ "10.0.0.0/24" ];
        wan.cidrs = [ "203.0.113.0/24" ];
      };
      filters.f = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
        chain = rawPrerouting;
      };
    };
    expected = clean;
  };

  # An interface-only `to` zone needs `oifname`, which prerouting lacks.
  testChainOverrideInterfaceZoneUnreachableAtPrerouting = {
    expr = diagnosticsFor {
      zones = {
        wan.interfaces = [ "wan0" ];
        host.interfaces = [ "lo" ];
      };
      filters.early-drop = {
        from = [ "wan" ];
        to = [ "host" ];
        rule = [ dsl.accept ];
        chain = rawPrerouting;
      };
    };
    expected = {
      errors = [
        {
          tag = "chainOverrideUnreachable";
          path = [
            "filters"
            "early-drop"
            "to"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testChainOverrideLocalZoneAlwaysReachable = {
    expr = diagnosticsFor {
      zones.wan.interfaces = [ "wan0" ];
      filters.f = {
        from = [ "wan" ];
        to = [ "local" ];
        rule = [ dsl.accept ];
        chain = rawPrerouting;
      };
    };
    expected = clean;
  };

  # A hook-agnostic `matchOverride.egress.extra` section makes the zone
  # reachable at any hook.
  testChainOverrideHookAgnosticMatchOverrideReachable = {
    expr = diagnosticsFor {
      zones = {
        wan.interfaces = [ "wan0" ];
        host = {
          interfaces = [ "lo" ];
          matchOverride.egress.extra = [ (dsl.eq dsl.fields.meta.mark 256) ];
        };
      };
      filters.f = {
        from = [ "wan" ];
        to = [ "host" ];
        rule = [ dsl.accept ];
        chain = rawPrerouting;
      };
    };
    expected = clean;
  };

  # The wildcard is checked per resolved zone: `host` fails, `wan`
  # (with CIDRs) and `local` pass, so one error lands on the direction.
  testChainOverrideWildcardChecksEachResolvedZone = {
    expr = diagnosticsFor {
      zones = {
        wan = {
          interfaces = [ "wan0" ];
          cidrs = [ "203.0.113.0/24" ];
        };
        host.interfaces = [ "lo" ];
      };
      filters.f = {
        from = [ "wan" ];
        to = [ "all" ];
        rule = [ dsl.accept ];
        chain = rawPrerouting;
      };
    };
    expected = {
      errors = [
        {
          tag = "chainOverrideUnreachable";
          path = [
            "filters"
            "f"
            "to"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== chain-override semantics =====

  testChainOverrideSemanticsDefaultsSilent = {
    expr = diagnosticsFor {
      zones = lanWan;
      filters.allow-ssh = {
        from = [ "wan" ];
        to = [ "local" ];
        rule = [ dsl.accept ];
      };
      snats.masq = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
      };
      dnats.fwd = {
        from = [ "wan" ];
        rule = dnatTo443;
      };
    };
    expected = clean;
  };

  testChainOverrideSemanticsFilterAtPostroutingWarns = {
    expr = diagnosticsFor {
      zones = lanWan;
      filters.late = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
        chain = {
          hook = "postrouting";
          priority = "srcnat";
        };
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "filterAtPostrouting";
          path = [
            "filters"
            "late"
            "chain"
          ];
        }
      ];
    };
  };

  testChainOverrideSemanticsDnatAtOutputWarns = {
    expr = diagnosticsFor {
      dnats.local-rewrite = {
        from = [ "local" ];
        rule = dnatTo443;
        chain = {
          hook = "output";
          priority = "dstnat";
        };
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "dnatAtOutput";
          path = [
            "dnats"
            "local-rewrite"
            "chain"
          ];
        }
      ];
    };
  };

  testChainOverrideSemanticsSnatOffSrcnatWarns = {
    expr = diagnosticsFor {
      zones = lanWan;
      snats.early = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
        chain = {
          hook = "postrouting";
          priority = "mangle";
        };
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "snatOffSrcnat";
          path = [
            "snats"
            "early"
            "chain"
          ];
        }
      ];
    };
  };

  # Both the symbolic and the int form (100) of srcnat are accepted.
  testChainOverrideSemanticsSnatAtSrcnatSilent = {
    expr = diagnosticsFor {
      zones = lanWan;
      snats.s1 = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
        chain = {
          hook = "postrouting";
          priority = "srcnat";
        };
      };
      snats.s2 = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
        chain = {
          hook = "postrouting";
          priority = 100;
        };
      };
    };
    expected = clean;
  };

  testChainOverrideSemanticsWarningsAggregate = {
    expr = diagnosticsFor {
      zones = lanWan;
      filters.f = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
        chain = {
          hook = "postrouting";
          priority = "srcnat";
        };
      };
      dnats.d = {
        from = [ "local" ];
        rule = dnatTo443;
        chain = {
          hook = "output";
          priority = "dstnat";
        };
      };
      snats.s = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
        chain = {
          hook = "postrouting";
          priority = "filter";
        };
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "dnatAtOutput";
          path = [
            "dnats"
            "d"
            "chain"
          ];
        }
        {
          tag = "filterAtPostrouting";
          path = [
            "filters"
            "f"
            "chain"
          ];
        }
        {
          tag = "snatOffSrcnat";
          path = [
            "snats"
            "s"
            "chain"
          ];
        }
      ];
    };
  };

  # ===== rpfilter override =====

  # The overrides below sit at (prerouting, raw), so `wan` uses CIDRs
  # to stay reachable there.

  testRpfilterWithoutOverrideSilent = {
    expr = diagnosticsFor {
      settings.rpfilter = true;
      zones.lan.interfaces = [ "lan0" ];
    };
    expected = clean;
  };

  testRpfilterOffWithRawPreroutingOverrideSilent = {
    expr = diagnosticsFor {
      zones.wan.cidrs = [ "203.0.113.0/24" ];
      filters.early-drop = {
        from = [ "wan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
        chain = rawPrerouting;
      };
    };
    expected = clean;
  };

  # A user chain at (prerouting, raw) suppresses the synthesized
  # rpfilter chain in Phase 4; the warning keeps that from being silent.
  testRpfilterSuppressedByRawPreroutingOverride = {
    expr = diagnosticsFor {
      settings.rpfilter = true;
      zones.wan.cidrs = [ "203.0.113.0/24" ];
      filters.early-drop = {
        from = [ "wan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
        chain = rawPrerouting;
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "rpfilterChainSuppressed";
          path = [
            "settings"
            "rpfilter"
          ];
        }
      ];
    };
  };

  # -300 is the int form of `raw`.
  testRpfilterSuppressedByIntPriorityOverride = {
    expr = diagnosticsFor {
      settings.rpfilter = true;
      zones.wan.cidrs = [ "203.0.113.0/24" ];
      filters.early-drop = {
        from = [ "wan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
        chain = {
          hook = "prerouting";
          priority = -300;
        };
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "rpfilterChainSuppressed";
          path = [
            "settings"
            "rpfilter"
          ];
        }
      ];
    };
  };

  # ===== extra section fields =====

  testExtraSectionNonInterfaceFieldsSilent = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        matchOverride.ingress.extra = [
          (dsl.eq dsl.fields.meta.mark 256)
          (dsl.eq dsl.fields.meta.cgroup 100)
        ];
      };
    };
    expected = clean;
  };

  testExtraSectionIifWarns = {
    expr = diagnosticsFor {
      zones.lan.matchOverride.ingress.extra = [ (dsl.eq dsl.fields.meta.iif "lo") ];
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "extraSectionInterfaceMatch";
          path = [
            "zones"
            "lan"
            "matchOverride"
            "ingress"
            "extra"
            "0"
          ];
        }
      ];
    };
  };

  # The path carries the index of the offending statement.
  testExtraSectionOifnameWarnsAtItsIndex = {
    expr = diagnosticsFor {
      zones.wan.matchOverride.egress.extra = [
        (dsl.eq dsl.fields.meta.mark 256)
        (dsl.eq dsl.fields.meta.oifname "wan0")
      ];
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "extraSectionInterfaceMatch";
          path = [
            "zones"
            "wan"
            "matchOverride"
            "egress"
            "extra"
            "1"
          ];
        }
      ];
    };
  };

  testExtraSectionWarnsOnBothSides = {
    expr = diagnosticsFor {
      zones.lan.matchOverride = {
        ingress.extra = [ (dsl.eq dsl.fields.meta.iif "lan0") ];
        egress.extra = [ (dsl.eq dsl.fields.meta.oif "lan0") ];
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "extraSectionInterfaceMatch";
          path = [
            "zones"
            "lan"
            "matchOverride"
            "egress"
            "extra"
            "0"
          ];
        }
        {
          tag = "extraSectionInterfaceMatch";
          path = [
            "zones"
            "lan"
            "matchOverride"
            "ingress"
            "extra"
            "0"
          ];
        }
      ];
    };
  };

  testExtraSectionWarnsAcrossZones = {
    expr = diagnosticsFor {
      zones = {
        lan.matchOverride.ingress.extra = [ (dsl.eq dsl.fields.meta.iifname "lan0") ];
        wan.matchOverride.egress.extra = [ (dsl.eq dsl.fields.meta.oifname "wan0") ];
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "extraSectionInterfaceMatch";
          path = [
            "zones"
            "lan"
            "matchOverride"
            "ingress"
            "extra"
            "0"
          ];
        }
        {
          tag = "extraSectionInterfaceMatch";
          path = [
            "zones"
            "wan"
            "matchOverride"
            "egress"
            "extra"
            "0"
          ];
        }
      ];
    };
  };

  # The `interfaces` section is the right place for iif/oif matches:
  # it is hook-gated, so nothing is flagged there.
  testExtraSectionIgnoresInterfacesSection = {
    expr = diagnosticsFor {
      zones.lan.matchOverride.ingress.interfaces = [
        (dsl.eq dsl.fields.meta.iifname "lan0")
      ];
    };
    expected = clean;
  };

  # ===== wildcard-zone mix =====

  testWildcardAloneSilent = {
    expr = diagnosticsFor {
      zones = lanWan;
      policies.deny-all = {
        from = [ "all" ];
        to = [ "wan" ];
        verdict = "drop";
      };
    };
    expected = clean;
  };

  testExplicitZonesWithoutWildcardSilent = {
    expr = diagnosticsFor {
      zones = lanWan;
      policies.allow = {
        from = [
          "lan"
          "wan"
        ];
        to = [ "wan" ];
        verdict = "accept";
      };
    };
    expected = clean;
  };

  testWildcardBesideExplicitZoneWarns = {
    expr = diagnosticsFor {
      zones = lanWan;
      policies.confused = {
        from = [
          "all"
          "wan"
        ];
        to = [ "lan" ];
        verdict = "drop";
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "wildcardZoneMixed";
          path = [
            "policies"
            "confused"
            "from"
          ];
        }
      ];
    };
  };

  testWildcardMixWarnsPerGroupAndDirection = {
    expr = diagnosticsFor {
      zones = lanWan;
      filters.f = {
        from = [
          "all"
          "lan"
        ];
        to = [
          "all"
          "wan"
        ];
        rule = [ dsl.accept ];
      };
      dnats.d = {
        from = [
          "all"
          "wan"
        ];
        rule = dnatTo443;
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "wildcardZoneMixed";
          path = [
            "dnats"
            "d"
            "from"
          ];
        }
        {
          tag = "wildcardZoneMixed";
          path = [
            "filters"
            "f"
            "from"
          ];
        }
        {
          tag = "wildcardZoneMixed";
          path = [
            "filters"
            "f"
            "to"
          ];
        }
      ];
    };
  };

  # A from-side wildcard expands to root zones and the local zone
  # only, so the child zone `guest` listed beside it is not
  # redundant: removing it changes the ruleset.
  testWildcardBesideFromChildZoneSilent = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        guest = {
          interfaces = [ "guest0" ];
          parent = "lan";
        };
        wan.interfaces = [ "wan0" ];
      };
      policies.guest-out = {
        from = [
          "all"
          "guest"
        ];
        to = [ "wan" ];
        verdict = "accept";
      };
    };
    expected = clean;
  };

  # The from-side wildcard's expansion includes the local zone.
  testWildcardBesideFromLocalZoneWarns = {
    expr = diagnosticsFor {
      zones = lanWan;
      filters.from-host = {
        from = [
          "all"
          "local"
        ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "wildcardZoneMixed";
          path = [
            "filters"
            "from-host"
            "from"
          ];
        }
      ];
    };
  };

  # A to-side wildcard expands to every zone, children included.
  testWildcardBesideToChildZoneWarns = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        guest = {
          interfaces = [ "guest0" ];
          parent = "lan";
        };
        wan.interfaces = [ "wan0" ];
      };
      policies.to-guest = {
        from = [ "wan" ];
        to = [
          "all"
          "guest"
        ];
        verdict = "drop";
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "wildcardZoneMixed";
          path = [
            "policies"
            "to-guest"
            "to"
          ];
        }
      ];
    };
  };

  # An unknown zone is no zone the wildcard covers: only the
  # reference error reports it.
  testWildcardBesideUnknownZoneOnlyRejected = {
    expr = diagnosticsFor {
      zones = lanWan;
      policies.typo = {
        from = [ "lan" ];
        to = [
          "all"
          "wna"
        ];
        verdict = "drop";
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidZoneRef";
          path = [
            "policies"
            "typo"
            "to"
            "1"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== NAT bodies =====

  testNatBodySnatWithAddrAccepted = {
    expr = diagnosticsFor {
      zones = lanWan;
      snats.outbound = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.snat.addr = "203.0.113.5";
      };
    };
    expected = clean;
  };

  testNatBodyMasqueradeNeedsNoAddr = {
    expr = diagnosticsFor {
      zones = lanWan;
      snats.outbound = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
      };
    };
    expected = clean;
  };

  # The type accepts a port-only `snat` body, but nftzones requires
  # a target address.
  testNatBodyNoAddrSnatRejected = {
    expr = diagnosticsFor {
      zones = lanWan;
      snats.outbound = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.snat.port = 8080;
      };
    };
    expected = {
      errors = [
        {
          tag = "natBodyMissingAddr";
          path = [
            "snats"
            "outbound"
            "rule"
            "action"
            "snat"
            "addr"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testNatBodyDnatWithAddrAccepted = {
    expr = diagnosticsFor {
      zones.wan.interfaces = [ "wan0" ];
      dnats.web-fwd = {
        from = [ "wan" ];
        rule = dnatTo443;
      };
    };
    expected = clean;
  };

  testNatBodyRedirectNeedsNoAddr = {
    expr = diagnosticsFor {
      zones.wan.interfaces = [ "wan0" ];
      dnats.ssh-redirect = {
        from = [ "wan" ];
        rule = {
          match = [ ];
          action.redirect.port = 22;
        };
      };
    };
    expected = clean;
  };

  testNatBodyNoAddrDnatRejected = {
    expr = diagnosticsFor {
      zones.wan.interfaces = [ "wan0" ];
      dnats.bad-fwd = {
        from = [ "wan" ];
        rule = {
          match = [ ];
          action.dnat.port = 8080;
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "natBodyMissingAddr";
          path = [
            "dnats"
            "bad-fwd"
            "rule"
            "action"
            "dnat"
            "addr"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testNatBodyErrorsAggregateAcrossGroups = {
    expr = diagnosticsFor {
      zones = lanWan;
      snats.bad-s = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule.action.snat.port = 8080;
      };
      dnats.bad-d = {
        from = [ "wan" ];
        rule = {
          match = [ ];
          action.dnat.port = 8080;
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "natBodyMissingAddr";
          path = [
            "dnats"
            "bad-d"
            "rule"
            "action"
            "dnat"
            "addr"
          ];
        }
        {
          tag = "natBodyMissingAddr";
          path = [
            "snats"
            "bad-s"
            "rule"
            "action"
            "snat"
            "addr"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== object references =====

  testObjectRefsEmptyRuleSilent = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      filters.f = {
        from = [ "lan" ];
        to = [ "lan" ];
        rule = [ dsl.accept ];
      };
    };
    expected = clean;
  };

  testObjectRefsDeclaredCounterResolves = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      objects.counters.drops = { };
      filters.f = {
        from = [ "lan" ];
        to = [ "lan" ];
        rule = [
          (dsl.counter.ref "drops")
          dsl.drop
        ];
      };
    };
    expected = clean;
  };

  testObjectRefsUndeclaredCounterRejected = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      filters.f = {
        from = [ "lan" ];
        to = [ "lan" ];
        rule = [ (dsl.counter.ref "missing-counter") ];
      };
    };
    expected = {
      errors = [
        {
          tag = "objectRefUnknown";
          path = [
            "filters"
            "f"
            "rule"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # The table cannot declare a tunnel (nftypes' table tree has no
  # tunnel kind), so a tunnel ref never resolves.
  testObjectRefsTunnelRejected = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      filters.f = {
        from = [ "lan" ];
        to = [ "lan" ];
        rule = [ (dsl.tunnel.ref "vpn") ];
      };
    };
    expected = {
      errors = [
        {
          tag = "objectRefUnknown";
          path = [
            "filters"
            "f"
            "rule"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # A counter ref in a filter rule and a set ref in a dnat match.
  testObjectRefsUnknownKindsAcrossGroups = {
    expr = diagnosticsFor {
      zones = lanWan;
      filters.bad-counter = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ (dsl.counter.ref "ghost") ];
      };
      dnats.bad-set = {
        from = [ "wan" ];
        rule = dnatTo443 // {
          match = [ (dsl.inSet dsl.fields.ip.saddr (dsl.expr.setRef "ghost-set")) ];
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "objectRefUnknown";
          path = [
            "dnats"
            "bad-set"
            "rule"
          ];
        }
        {
          tag = "objectRefUnknown";
          path = [
            "filters"
            "bad-counter"
            "rule"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # Zone-derived sets such as `lan_v4` are synthesized in Phase 4, but
  # rules may reference them by name.
  testObjectRefsZoneDerivedSetResolves = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      filters.use-zone-set = {
        from = [ "lan" ];
        to = [ "lan" ];
        rule = [
          (dsl.inSet dsl.fields.ip.saddr (dsl.expr.setRef "lan_v4"))
          dsl.accept
        ];
      };
    };
    expected = clean;
  };

  # `wan_v6` exists only if `wan` has IPv6 CIDRs, and it has none.
  testObjectRefsZoneDerivedSetNeedsMatchingCidrs = {
    expr = diagnosticsFor {
      zones.wan.interfaces = [ "wan0" ];
      filters.f = {
        from = [ "wan" ];
        to = [ "wan" ];
        rule = [
          (dsl.inSet dsl.fields.ip6.saddr (dsl.expr.setRef "wan_v6"))
          dsl.accept
        ];
      };
    };
    expected = {
      errors = [
        {
          tag = "objectRefUnknown";
          path = [
            "filters"
            "f"
            "rule"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testObjectRefsMatchOverrideUnknownRejected = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        matchOverride.ingress.ipv4 = [
          (dsl.inSet dsl.fields.ip.saddr (dsl.expr.setRef "ghost-set"))
        ];
      };
    };
    expected = {
      errors = [
        {
          tag = "objectRefUnknown";
          path = [
            "zones"
            "lan"
            "matchOverride"
            "ingress"
            "ipv4"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testObjectRefsMatchOverrideDeclaredSetResolves = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        matchOverride.egress.ipv4 = [
          (dsl.inSet dsl.fields.ip.daddr (dsl.expr.setRef "blocklist"))
        ];
      };
      objects.sets.blocklist.type = "ipv4_addr";
    };
    expected = clean;
  };

  testObjectRefsObjectBodiesWithoutRefsSilent = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      objects = {
        counters.drops = { };
        limits.burst-1 = {
          rate = 100;
          per = "second";
        };
        sets.blocklist = {
          type = "ipv4_addr";
          elem = [
            "1.2.3.4"
            "5.6.7.8"
          ];
        };
      };
    };
    expected = clean;
  };

  # A set's statements are inline stateful statements; nftypes
  # rejects a reference there, so they carry no refs.
  testObjectRefsSetStatementInlineSilent = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      objects.sets.tracker = {
        type = "ipv4_addr";
        elem = [ "1.2.3.4" ];
        stmt = [
          (dsl.counter {
            packets = 0;
            bytes = 0;
          })
        ];
      };
    };
    expected = clean;
  };
}
