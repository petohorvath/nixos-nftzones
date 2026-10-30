# Unit tests for Phase 1's hierarchy and namespace validators, through
# `diagnose`: parent references and cycles, zone/node name collisions,
# name/key mismatches, settings, zone references, zone matchability,
# node addresses, set-name collisions and policy uniqueness. Each test
# is a table body and its exact `{ tag; path; }` diagnostic lists.
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

  markIs256 = dsl.eq dsl.fields.meta.mark 256;
in
{
  # ===== Parent references =====

  testParentRefNullReportsNothing = {
    expr = diagnosticsFor { zones.lan.interfaces = [ "lan0" ]; };
    expected = clean;
  };

  testParentRefKnownReportsNothing = {
    expr = diagnosticsFor {
      zones = {
        dmz.interfaces = [ "dmz0" ];
        web = {
          parent = "dmz";
          cidrs = [ "10.0.0.5/32" ];
        };
      };
    };
    expected = clean;
  };

  testParentRefUnknownReportsZoneParentUnknown = {
    expr = diagnosticsFor {
      zones.web = {
        parent = "ghost";
        cidrs = [ "10.0.0.5/32" ];
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneParentUnknown";
          path = [
            "zones"
            "web"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testParentRefLocalZoneReportsZoneParentLocalZone = {
    expr = diagnosticsFor {
      zones.web = {
        parent = "local";
        cidrs = [ "10.0.0.5/32" ];
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneParentLocalZone";
          path = [
            "zones"
            "web"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  /*
    Pinned as is, though wrong: a node lowers into a zone whose parent
    is `node.zone`, so one unknown `nodes.web.zone` is reported twice,
    once at the path the user wrote and once at `zones.web.parent`,
    a path the user never wrote.
  */
  testParentRefUnknownFromNodeCascades = {
    expr = diagnosticsFor {
      nodes.web = {
        zone = "ghost";
        address.ipv4 = "10.0.0.5";
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidZoneRef";
          path = [
            "nodes"
            "web"
            "zone"
          ];
        }
        {
          tag = "zoneParentUnknown";
          path = [
            "zones"
            "web"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== Parent cycles =====

  testParentCycleAbsentReportsNothing = {
    expr = diagnosticsFor {
      zones = {
        a = { };
        b.parent = "a";
        c.parent = "b";
      };
    };
    expected = clean;
  };

  # A cycle is reported once, at the lexically smallest member.
  testParentCycleTwoZonesReportedOnce = {
    expr = diagnosticsFor {
      zones = {
        a.parent = "b";
        b.parent = "a";
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneParentCycle";
          path = [
            "zones"
            "a"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # Walks from a, b and c find the same cycle from different starts.
  testParentCycleThreeZonesReportedOnce = {
    expr = diagnosticsFor {
      zones = {
        a.parent = "c";
        b.parent = "a";
        c.parent = "b";
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneParentCycle";
          path = [
            "zones"
            "a"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # `a` leads into the `b → c → b` cycle without being part of it. It
  # is the lexically smallest zone, so blaming it would mean the tail
  # was kept.
  testParentCycleTailNotBlamed = {
    expr = diagnosticsFor {
      zones = {
        a.parent = "b";
        b.parent = "c";
        c.parent = "b";
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneParentCycle";
          path = [
            "zones"
            "b"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== Zone/node name collisions =====

  testNameCollisionAbsentReportsNothing = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      nodes.web = {
        zone = "lan";
        address.ipv4 = "1.1.1.1";
      };
    };
    expected = clean;
  };

  # The node is the declaration to edit, so the collision blames it.
  testNameCollisionBlamesNode = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        web = { };
      };
      nodes.web = {
        zone = "lan";
        address.ipv4 = "1.1.1.1";
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneNameCollision";
          path = [
            "nodes"
            "web"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testNameCollisionReportsEachNode = {
    expr = diagnosticsFor {
      zones = {
        a = { };
        b = { };
        c = { };
        x = { };
      };
      nodes = {
        a = {
          zone = "x";
          address.ipv4 = "1.1.1.1";
        };
        c = {
          zone = "x";
          address.ipv4 = "2.2.2.2";
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneNameCollision";
          path = [
            "nodes"
            "a"
          ];
        }
        {
          tag = "zoneNameCollision";
          path = [
            "nodes"
            "c"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== Name/key mismatch =====

  testNameKeyMatchReportsNothing = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        name = "lan";
      };
    };
    expected = clean;
  };

  testNameKeyMismatchZone = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        name = "other";
      };
    };
    expected = {
      errors = [
        {
          tag = "nameKeyMismatch";
          path = [
            "zones"
            "lan"
            "name"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testNameKeyMismatchNode = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      nodes.web = {
        name = "other";
        zone = "lan";
        address.ipv4 = "10.0.0.5";
      };
    };
    expected = {
      errors = [
        {
          tag = "nameKeyMismatch";
          path = [
            "nodes"
            "web"
            "name"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testNameKeyMismatchPolicy = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
      };
      policies.lan-to-wan = {
        from = [ "lan" ];
        to = [ "wan" ];
        name = "other";
      };
    };
    expected = {
      errors = [
        {
          tag = "nameKeyMismatch";
          path = [
            "policies"
            "lan-to-wan"
            "name"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== Settings =====

  testSettingsDefaultsReportNothing = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      nodes.web = {
        zone = "lan";
        address.ipv4 = "1.1.1.1";
      };
    };
    expected = clean;
  };

  testSettingsWildcardEqualsLocal = {
    expr = diagnosticsFor {
      settings = {
        wildcardZone = "any";
        localZone = "any";
      };
    };
    expected = {
      errors = [
        {
          tag = "settingsConflict";
          path = [
            "settings"
            "localZone"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # The default wildcardZone is "all".
  testSettingsWildcardShadowsZone = {
    expr = diagnosticsFor { zones.all = { }; };
    expected = {
      errors = [
        {
          tag = "settingsConflict";
          path = [
            "zones"
            "all"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # The default localZone is "local".
  testSettingsLocalShadowsNode = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      nodes.local = {
        zone = "lan";
        address.ipv4 = "1.1.1.1";
      };
    };
    expected = {
      errors = [
        {
          tag = "settingsConflict";
          path = [
            "nodes"
            "local"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== Zone references =====

  testZoneRefsKnownReportNothing = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
      };
      filters.f = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
      };
    };
    expected = clean;
  };

  testZoneRefUnknownReportsInvalidZoneRef = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      filters.f = {
        from = [ "lan" ];
        to = [ "missing" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidZoneRef";
          path = [
            "filters"
            "f"
            "to"
            "0"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== Zone matchability =====

  testZoneMatchableByInterfaces = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
      };
      filters.f = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
      };
    };
    expected = clean;
  };

  testZoneMatchableByCidrs = {
    expr = diagnosticsFor {
      zones = {
        lan.cidrs = [ "10.0.0.0/24" ];
        wan.cidrs = [ "192.0.2.0/24" ];
      };
      filters.f = {
        from = [ "lan" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
      };
    };
    expected = clean;
  };

  # An `extra` section makes a zone matchable without interfaces or
  # CIDRs.
  testZoneMatchableByOverrideOnBothSides = {
    expr = diagnosticsFor {
      zones.custom.matchOverride = {
        ingress.extra = [ markIs256 ];
        egress.extra = [ markIs256 ];
      };
      filters.f = {
        from = [ "custom" ];
        to = [ "custom" ];
        rule = [ dsl.accept ];
      };
    };
    expected = clean;
  };

  testZoneNotMatchableAsFrom = {
    expr = diagnosticsFor {
      zones = {
        empty = { };
        wan.interfaces = [ "wan0" ];
      };
      filters.f = {
        from = [ "empty" ];
        to = [ "wan" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneNotMatchable";
          path = [
            "filters"
            "f"
            "from"
            "0"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testZoneNotMatchableAsTo = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        empty = { };
      };
      filters.f = {
        from = [ "lan" ];
        to = [ "empty" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneNotMatchable";
          path = [
            "filters"
            "f"
            "to"
            "0"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # An ingress-only override serves `from` but not `to`.
  testZoneNotMatchableOnMissingOverrideSide = {
    expr = diagnosticsFor {
      zones.partial.matchOverride.ingress.extra = [ markIs256 ];
      filters.f = {
        from = [ "partial" ];
        to = [ "partial" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneNotMatchable";
          path = [
            "filters"
            "f"
            "to"
            "0"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # An empty section list contributes no match, the same as null.
  testZoneNotMatchableWithEmptySection = {
    expr = diagnosticsFor {
      zones.empty-section.matchOverride.egress.extra = [ ];
      filters.f = {
        from = [ "empty-section" ];
        to = [ "empty-section" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneNotMatchable";
          path = [
            "filters"
            "f"
            "from"
            "0"
          ];
        }
        {
          tag = "zoneNotMatchable";
          path = [
            "filters"
            "f"
            "to"
            "0"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # The localZone sentinel is never declared, and Phase 4 emits no
  # match for its side.
  testZoneMatchableSkipsLocalZone = {
    expr = diagnosticsFor {
      zones.wan.interfaces = [ "wan0" ];
      filters = {
        in-rule = {
          from = [ "wan" ];
          to = [ "local" ];
          rule = [ dsl.accept ];
        };
        out-rule = {
          from = [ "local" ];
          to = [ "wan" ];
          rule = [ dsl.accept ];
        };
      };
    };
    expected = clean;
  };

  # An unknown zone gets only `invalidZoneRef`, not a second error.
  testZoneMatchableSkipsUnknownZone = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      filters.f = {
        from = [ "lan" ];
        to = [ "missing" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidZoneRef";
          path = [
            "filters"
            "f"
            "to"
            "0"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # `nodes.<name>.zone` names a parent; it matches no traffic.
  testZoneMatchableSkipsNodeZone = {
    expr = diagnosticsFor {
      zones.empty = { };
      nodes.api = {
        zone = "empty";
        address.ipv4 = "10.0.0.5";
      };
    };
    expected = clean;
  };

  # ===== Node addresses =====

  testNodeAddressIpv4Only = {
    expr = diagnosticsFor {
      zones.dmz.interfaces = [ "dmz0" ];
      nodes.web = {
        zone = "dmz";
        address.ipv4 = "10.0.0.5";
      };
    };
    expected = clean;
  };

  testNodeAddressIpv6Only = {
    expr = diagnosticsFor {
      zones.dmz.interfaces = [ "dmz0" ];
      nodes.web = {
        zone = "dmz";
        address.ipv6 = "fe80::1";
      };
    };
    expected = clean;
  };

  testNodeAddressMissing = {
    expr = diagnosticsFor {
      zones.dmz.interfaces = [ "dmz0" ];
      nodes.web = {
        zone = "dmz";
        address = { };
      };
    };
    expected = {
      errors = [
        {
          tag = "nodeAddressMissing";
          path = [
            "nodes"
            "web"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testNodeAddressMissingReportsEachNode = {
    expr = diagnosticsFor {
      zones.dmz.interfaces = [ "dmz0" ];
      nodes = {
        a = {
          zone = "dmz";
          address = { };
        };
        b = {
          zone = "dmz";
          address = { };
        };
        c = {
          zone = "dmz";
          address.ipv4 = "10.0.0.5";
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "nodeAddressMissing";
          path = [
            "nodes"
            "a"
          ];
        }
        {
          tag = "nodeAddressMissing";
          path = [
            "nodes"
            "b"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # ===== Set-name collisions =====

  testSetNameDistinctReportsNothing = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      objects.sets.user-blocklist.type = "ipv4_addr";
    };
    expected = clean;
  };

  # Zone `lan` with IPv4 CIDRs generates the set `lan_v4`.
  testSetNameCollisionWithZoneSet = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      objects.sets.lan_v4.type = "ipv4_addr";
    };
    expected = {
      errors = [
        {
          tag = "setNameCollision";
          path = [
            "objects"
            "sets"
            "lan_v4"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # The owning zone `web_app` is named only in the message, which
  # tests don't read; this pins that the collision is still found.
  testSetNameCollisionWithUnderscoreZone = {
    expr = diagnosticsFor {
      zones.web_app = {
        interfaces = [ "wa0" ];
        cidrs = [ "10.1.0.0/24" ];
      };
      objects.sets.web_app_v4.type = "ipv4_addr";
    };
    expected = {
      errors = [
        {
          tag = "setNameCollision";
          path = [
            "objects"
            "sets"
            "web_app_v4"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # Only `<zone>_{iifs,v4,v6}` names are generated.
  testSetNameUnrelatedToZoneSetsReportsNothing = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      objects.sets.lan_other.type = "ipv4_addr";
    };
    expected = clean;
  };

  # ===== Policy uniqueness =====

  testPolicyNoneReportsNothing = {
    expr = diagnosticsFor { };
    expected = clean;
  };

  testPolicySingleReportsNothing = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
      };
      policies.lan-to-wan = {
        from = [ "lan" ];
        to = [ "wan" ];
      };
    };
    expected = clean;
  };

  testPolicyDistinctPairsReportNothing = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
        dmz.interfaces = [ "dmz0" ];
      };
      policies = {
        a = {
          from = [ "lan" ];
          to = [ "wan" ];
        };
        b = {
          from = [ "lan" ];
          to = [ "dmz" ];
        };
      };
    };
    expected = clean;
  };

  # A duplicate pair blames the lexically first policy.
  testPolicyDuplicatePairReportsPolicyConflict = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
      };
      policies = {
        allow = {
          from = [ "lan" ];
          to = [ "wan" ];
        };
        deny = {
          from = [ "lan" ];
          to = [ "wan" ];
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "policyConflict";
          path = [
            "policies"
            "allow"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # `broad` expands to a (zone → wan) cell per root zone, one of which
  # is `specific`'s (lan → wan).
  testPolicyWildcardExpansionReportsPolicyConflict = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
      };
      policies = {
        broad = {
          from = [ "all" ];
          to = [ "wan" ];
        };
        specific = {
          from = [ "lan" ];
          to = [ "wan" ];
        };
      };
    };
    expected = {
      errors = [
        {
          tag = "policyConflict";
          path = [
            "policies"
            "broad"
          ];
        }
      ];
      warnings = [ ];
    };
  };
}
