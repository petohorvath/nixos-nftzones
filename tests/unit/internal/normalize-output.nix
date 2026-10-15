/*
  Unit tests for what Phase 1 computes for later phases: node
  lowering, wildcard expansion and priority resolution, read through
  the `ctx` keys `normalizeTable` hands Phase 2 (`zoneMembership`,
  `expandedGroups`, `resolvedPriorities`).

  Zone-reference collection and the in-scope zone names leave no such
  key; their tests observe them through `invalidZoneRef` Diagnostics.
*/
{ pkgs, nftzones, ... }:
let
  inherit (nftzones.internal.normalize) normalizeTable;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) diagnosticsFor evalTable;

  ctxFor = body: (normalizeTable (evalTable body)).ctx;

  invalidZoneRefAt = path: {
    tag = "invalidZoneRef";
    inherit path;
  };

  prefix = addr: len: { prefix = { inherit addr len; }; };
in
{
  # ===== Node lowering, through zoneMembership =====

  testNodeLoweringEmptyTableHasNoZoneSets = {
    expr =
      let
        membership = (ctxFor { }).zoneMembership;
      in
      {
        inherit (membership) rootZoneNames sets;
      };
    expected = {
      rootZoneNames = [ "local" ];
      sets = { };
    };
  };

  # A lowered node is a child of its zone with only its own
  # addresses, and its addresses join the zone's sets.
  testNodeLoweringDualStackNodeJoinsItsZone = {
    expr =
      let
        membership =
          (ctxFor {
            zones.dmz.interfaces = [ "eth1" ];
            nodes.web = {
              zone = "dmz";
              address = {
                ipv4 = "10.0.0.5";
                ipv6 = "fe80::1";
              };
            };
          }).zoneMembership;
      in
      {
        inherit (membership) childrenOf rootZoneNames setOwners;
        webSets = {
          inherit (membership.sets) web_v4 web_v6;
        };
        webIngressOverrides = membership.activeOverrides "web" "ingress";
      };
    expected = {
      childrenOf.dmz = [ "web" ];
      rootZoneNames = [
        "dmz"
        "local"
      ];
      setOwners = {
        dmz_iifs = "dmz";
        dmz_v4 = "dmz";
        dmz_v6 = "dmz";
        web_v4 = "web";
        web_v6 = "web";
      };
      webSets = {
        web_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ (prefix "10.0.0.5" 32) ];
        };
        web_v6 = {
          type = "ipv6_addr";
          flags = [ "interval" ];
          elements = [ (prefix "fe80::1" 128) ];
        };
      };
      webIngressOverrides = { };
    };
  };

  # Every node keeps its own key, family and parent.
  testNodeLoweringKeepsEachNode = {
    expr =
      let
        membership =
          (ctxFor {
            zones.z1.interfaces = [ "z1" ];
            zones.z2.interfaces = [ "z2" ];
            nodes.a = {
              zone = "z1";
              address.ipv4 = "1.1.1.1";
            };
            nodes.b = {
              zone = "z2";
              address.ipv6 = "fe80::1";
            };
          }).zoneMembership;
      in
      {
        inherit (membership) childrenOf;
        nodeSets = {
          inherit (membership.sets) a_v4 b_v6;
        };
        nodeSetNames = builtins.filter (
          name:
          builtins.elem membership.setOwners.${name} [
            "a"
            "b"
          ]
        ) (builtins.attrNames membership.sets);
      };
    expected = {
      childrenOf = {
        z1 = [ "a" ];
        z2 = [ "b" ];
      };
      nodeSets = {
        a_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ (prefix "1.1.1.1" 32) ];
        };
        b_v6 = {
          type = "ipv6_addr";
          flags = [ "interval" ];
          elements = [ (prefix "fe80::1" 128) ];
        };
      };
      nodeSetNames = [
        "a_v4"
        "b_v6"
      ];
    };
  };

  # Declared zones keep both their interfaces and their CIDRs.
  testNodeLoweringKeepsDeclaredZones = {
    expr =
      (ctxFor {
        zones.lan = {
          interfaces = [ "eth1" ];
          cidrs = [ "10.0.0.0/24" ];
        };
      }).zoneMembership.sets;
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = [ "eth1" ];
      };
      lan_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [ (prefix "10.0.0.0" 24) ];
      };
    };
  };

  # A node replaces a same-named zone outright (last write wins).
  # The declared `web` would overlap `lan` on `lan0`, yet only the
  # collision is reported. Pinned as is: the clobber is #7.
  testNodeLoweringNodeReplacesSameNamedZone = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      zones.web.interfaces = [ "lan0" ];
      nodes.web = {
        zone = "lan";
        address.ipv4 = "10.0.0.5";
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

  # Phase 2 onward reads only these keys; scratch values stay inside
  # Phase 1.
  testNormalizeTableCtxHoldsOnlyKeysLaterPhasesRead = {
    expr = builtins.attrNames (ctxFor {
      zones.lan.interfaces = [ "lan0" ];
    });
    expected = [
      "expandedGroups"
      "resolvedPriorities"
      "zoneMembership"
    ];
  };

  testNormalizeTableReturnsTableUntouched = {
    expr =
      let
        table = evalTable {
          zones.lan.interfaces = [ "lan0" ];
          nodes.web = {
            zone = "lan";
            address.ipv4 = "10.0.0.5";
          };
          filters.f = {
            from = [ "all" ];
            to = [ "lan" ];
          };
        };
      in
      (normalizeTable table).table == table;
    expected = true;
  };

  # ===== Wildcard expansion, through expandedGroups =====

  testWildcardExpansionPassesExplicitZonesThrough = {
    expr =
      (ctxFor {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        filters.f = {
          from = [ "lan" ];
          to = [ "wan" ];
        };
      }).expandedGroups.filters.f;
    expected = {
      from = [ "lan" ];
      to = [ "wan" ];
    };
  };

  # The wildcard expands in place and duplicates are dropped.
  testWildcardExpansionDeduplicates = {
    expr =
      (ctxFor {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        filters.f = {
          from = [
            "lan"
            "all"
          ];
          to = [ "wan" ];
        };
      }).expandedGroups.filters.f;
    expected = {
      from = [
        "lan"
        "wan"
        "local"
      ];
      to = [ "wan" ];
    };
  };

  # The from side expands to root zones only: descendants (here the
  # `web` node) are reached through parent dispatch. The to side has
  # no hierarchy, so it expands to every zone, nodes included.
  testWildcardExpansionFromRootsToEveryZone = {
    expr =
      (ctxFor {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        nodes.web = {
          zone = "lan";
          address.ipv4 = "10.0.0.5";
        };
        filters.f = {
          from = [ "all" ];
          to = [ "all" ];
        };
      }).expandedGroups.filters.f;
    expected = {
      from = [
        "lan"
        "wan"
        "local"
      ];
      to = [
        "lan"
        "wan"
        "web"
        "local"
      ];
    };
  };

  testWildcardExpansionIncludesCustomLocalZone = {
    expr =
      (ctxFor {
        settings.localZone = "host";
        zones.lan.interfaces = [ "lan0" ];
        filters.f = {
          from = [ "all" ];
          to = [ "host" ];
        };
      }).expandedGroups.filters.f.from;
    expected = [
      "lan"
      "host"
    ];
  };

  testWildcardExpansionCoversSingleDirectionGroups = {
    expr =
      let
        inherit
          (ctxFor {
            settings.localZone = "host";
            zones.x.interfaces = [ "x0" ];
            zones.y.interfaces = [ "y0" ];
            dnats.d = {
              from = [ "all" ];
              rule = {
                match = [ ];
                action.redirect.port = 22;
              };
            };
            sroutes.s.from = [ "all" ];
            droutes.dr.to = [ "all" ];
          })
          expandedGroups
          ;
      in
      {
        inherit (expandedGroups) dnats sroutes droutes;
      };
    expected = {
      dnats.d.from = [
        "x"
        "y"
        "host"
      ];
      sroutes.s.from = [
        "x"
        "y"
        "host"
      ];
      droutes.dr.to = [
        "x"
        "y"
        "host"
      ];
    };
  };

  # ===== Priority resolution, through resolvedPriorities =====

  # Policies carry no priority: they are tail rules. Phase 3 relies on
  # `cell ? priority` to tell them apart.
  testPriorityResolutionEmptyGroupsWithoutPolicies = {
    expr = (ctxFor { }).resolvedPriorities;
    expected = {
      dnats = { };
      droutes = { };
      filters = { };
      snats = { };
      sroutes = { };
    };
  };

  testPriorityResolutionResolvesEverySymbol = {
    expr =
      (ctxFor {
        zones.lan.interfaces = [ "lan0" ];
        filters =
          builtins.mapAttrs
            (_: priority: {
              from = [ "lan" ];
              to = [ "local" ];
              inherit priority;
            })
            {
              f-first = "first";
              f-pre = "preDispatch";
              f-post = "postDispatch";
              f-default = "default";
              f-last = "last";
              f-int = 250;
            };
      }).resolvedPriorities.filters;
    expected = {
      f-first = 1;
      f-pre = 50;
      f-post = 100;
      f-default = 500;
      f-last = 999;
      f-int = 250;
    };
  };

  testPriorityResolutionCoversEveryPriorityGroup = {
    expr =
      (ctxFor {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        filters.f = {
          from = [ "lan" ];
          to = [ "wan" ];
          priority = "first";
        };
        snats.s = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule.masquerade = { };
          priority = "default";
        };
        dnats.d = {
          from = [ "wan" ];
          rule = {
            match = [ ];
            action.redirect.port = 22;
          };
          priority = "last";
        };
        sroutes.sr = {
          from = [ "lan" ];
          priority = "preDispatch";
        };
        droutes.dr = {
          to = [ "wan" ];
          priority = "postDispatch";
        };
      }).resolvedPriorities;
    expected = {
      filters.f = 1;
      snats.s = 500;
      dnats.d = 999;
      sroutes.sr = 50;
      droutes.dr = 100;
    };
  };

  # ===== Zone-reference collection, through invalidZoneRef =====

  # Every group and direction that names a zone is collected, each
  # list slot with its own index.
  testZoneRefCollectionCoversEveryGroupAndDirection = {
    expr =
      (diagnosticsFor {
        filters.f = {
          from = [
            "ghost"
            "ghost"
          ];
          to = [ "ghost" ];
        };
        policies.p = {
          from = [ "ghost" ];
          to = [ "ghost" ];
        };
        snats.sn = {
          from = [ "ghost" ];
          to = [ "ghost" ];
          rule.masquerade = { };
        };
        dnats.d = {
          from = [ "ghost" ];
          rule = {
            match = [ ];
            action.redirect.port = 22;
          };
        };
        sroutes.sr.from = [ "ghost" ];
        droutes.dr.to = [ "ghost" ];
      }).errors;
    expected = map invalidZoneRefAt [
      [
        "dnats"
        "d"
        "from"
        "0"
      ]
      [
        "droutes"
        "dr"
        "to"
        "0"
      ]
      [
        "filters"
        "f"
        "from"
        "0"
      ]
      [
        "filters"
        "f"
        "from"
        "1"
      ]
      [
        "filters"
        "f"
        "to"
        "0"
      ]
      [
        "policies"
        "p"
        "from"
        "0"
      ]
      [
        "policies"
        "p"
        "to"
        "0"
      ]
      [
        "snats"
        "sn"
        "from"
        "0"
      ]
      [
        "snats"
        "sn"
        "to"
        "0"
      ]
      [
        "sroutes"
        "sr"
        "from"
        "0"
      ]
    ];
  };

  # Each node's zone is a reference too. The lowered zone's unknown
  # parent cascades into a second error on a path the user never
  # wrote; pinned as is (#22 leaves node-derived paths unfixed).
  testZoneRefCollectionCoversNodeZones = {
    expr =
      (diagnosticsFor {
        nodes.api = {
          zone = "ghost";
          address.ipv4 = "1.1.1.1";
        };
        nodes.web = {
          zone = "ghost";
          address.ipv4 = "2.2.2.2";
        };
      }).errors;
    expected = [
      (invalidZoneRefAt [
        "nodes"
        "api"
        "zone"
      ])
      (invalidZoneRefAt [
        "nodes"
        "web"
        "zone"
      ])
      {
        tag = "zoneParentUnknown";
        path = [
          "zones"
          "api"
          "parent"
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
  };

  # The wildcard is a directive, not a reference. The other slots
  # keep the indices the user wrote.
  testZoneRefCollectionSkipsWildcard = {
    expr =
      (diagnosticsFor {
        filters.f = {
          from = [
            "ghost"
            "all"
            "phantom"
          ];
          to = [ "all" ];
        };
      }).errors;
    expected = map invalidZoneRefAt [
      [
        "filters"
        "f"
        "from"
        "0"
      ]
      [
        "filters"
        "f"
        "from"
        "2"
      ]
    ];
  };

  # ===== In-scope zone names, through invalidZoneRef =====

  # Declared zones, lowered nodes and the local zone are all in scope.
  testZoneNamesIncludeZonesNodesAndLocalZone = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      zones.wan.interfaces = [ "wan0" ];
      nodes.web = {
        zone = "lan";
        address.ipv4 = "10.0.0.5";
      };
      filters.f = {
        from = [
          "lan"
          "web"
        ];
        to = [
          "wan"
          "local"
        ];
      };
    };
    expected = {
      errors = [ ];
      warnings = [ ];
    };
  };

  # A custom local zone replaces the default name.
  testZoneNamesUseCustomLocalZone = {
    expr =
      (diagnosticsFor {
        settings.localZone = "host";
        zones.lan.interfaces = [ "lan0" ];
        filters.f = {
          from = [ "lan" ];
          to = [
            "host"
            "local"
          ];
        };
      }).errors;
    expected = [
      (invalidZoneRefAt [
        "filters"
        "f"
        "to"
        "1"
      ])
    ];
  };
}
