# Unit tests for `lib/internal/normalize.nix` (exposed as
# `nftzones.internal.normalize`). Same `testFoo = { expr; expected; }`
# shape as every other unit test; aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftzones.internal.normalize)
    convertNodesToZones
    computeZoneSets
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
    checkSetNameCollisions
    checkObjectRefs
    normalizeTable
    ;

  dsl = nftypes.dsl;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;

  /*
    Minimal table fixture for direct (non-`evalTable`) phase tests.
    Carries every field the phases destructure; tests overlay what
    they need.
  */
  emptyTable = {
    zones = { };
    nodes = { };
    filters = { };
    policies = { };
    snats = { };
    dnats = { };
    sroutes = { };
    droutes = { };
    settings = {
      wildcardZone = "all";
      localZone = "local";
    };
  };

  emptyCtx = {
    errors = [ ];
  };

  /*
    Run a phase against the supplied (or `emptyTable`) table with a
    fresh `emptyCtx`, returning just the resulting `ctx`
    attrset — what every phase test wants to inspect.
  */
  runPhase =
    phase: table:
    (phase {
      inherit table;
      ctx = emptyCtx;
    }).ctx;

  /*
    Run a sequence of phases, threading the context. Returns the
    final `ctx`. Used to test phases that depend on prior
    phases' outputs (e.g., `expandWildcardZones` reads
    `ctx.mergedZones`).
  */
  runPipeline =
    phases: table:
    (pkgs.lib.pipe {
      inherit table;
      ctx = emptyCtx;
    } phases).ctx;

  /*
    Same as `runPipeline` but accepts a `body` and runs it through
    the table submodule first (via `evalTable`). Use when phases
    read submodule-computed fields like `zone.match`.
  */
  runEvalPipeline = phases: body: runPipeline phases (evalTable body);
in
{
  # ===== convertNodesToZones — empty input =====

  testConvertNodesToZonesEmpty = {
    expr = (runPhase convertNodesToZones emptyTable).mergedZones;
    expected = { };
  };

  # ===== convertNodesToZones — dual-stack node =====

  testConvertNodesToZonesDualStack = {
    expr =
      let
        web =
          (runPhase convertNodesToZones (
            emptyTable
            // {
              nodes.web = {
                name = "web";
                zone = "dmz";
                address = {
                  ipv4 = "10.0.0.5";
                  ipv6 = "fe80::1";
                };
              };
            }
          )).mergedZones.web;
      in
      {
        inherit (web)
          name
          parent
          interfaces
          cidrs
          matchOverride
          comment
          ;
        matchPresent = web ? match;
      };
    expected = {
      name = "web";
      parent = "dmz";
      interfaces = [ ];
      cidrs = [
        "10.0.0.5/32"
        "fe80::1/128"
      ];
      matchOverride = {
        ingress = null;
        egress = null;
      };
      comment = null;
      matchPresent = true;
    };
  };

  # ===== convertNodesToZones — keys preserved across multiple nodes =====

  testConvertNodesToZonesMultiple = {
    expr =
      let
        merged =
          (runPhase convertNodesToZones (
            emptyTable
            // {
              nodes = {
                a = {
                  name = "a";
                  zone = "z1";
                  address = {
                    ipv4 = "1.1.1.1";
                    ipv6 = null;
                  };
                };
                b = {
                  name = "b";
                  zone = "z2";
                  address = {
                    ipv4 = null;
                    ipv6 = "fe80::1";
                  };
                };
              };
            }
          )).mergedZones;
      in
      {
        a = {
          inherit (merged.a)
            name
            parent
            interfaces
            cidrs
            ;
        };
        b = {
          inherit (merged.b)
            name
            parent
            interfaces
            cidrs
            ;
        };
      };
    expected = {
      a = {
        name = "a";
        parent = "z1";
        interfaces = [ ];
        cidrs = [ "1.1.1.1/32" ];
      };
      b = {
        name = "b";
        parent = "z2";
        interfaces = [ ];
        cidrs = [ "fe80::1/128" ];
      };
    };
  };

  # ===== convertNodesToZones — declared zones merged with lowered nodes =====

  testConvertNodesToZonesMergesWithDeclared = {
    expr =
      let
        merged =
          (runPhase convertNodesToZones (
            emptyTable
            // {
              zones.dmz = {
                interfaces = [ "eth1" ];
              };
              nodes.web = {
                name = "web";
                zone = "dmz";
                address = {
                  ipv4 = "10.0.0.5";
                  ipv6 = null;
                };
              };
            }
          )).mergedZones;
      in
      {
        # Declared zone passes through as-is (raw fixture, no
        # submodule eval — only what the user wrote).
        dmz = merged.dmz;
        # Lowered node has the full zone shape.
        web = {
          inherit (merged.web)
            name
            parent
            interfaces
            cidrs
            ;
        };
      };
    expected = {
      dmz = {
        interfaces = [ "eth1" ];
      };
      web = {
        name = "web";
        parent = "dmz";
        interfaces = [ ];
        cidrs = [ "10.0.0.5/32" ];
      };
    };
  };

  # ===== convertNodesToZones — table left untouched =====

  testConvertNodesToZonesTableUntouched = {
    expr =
      let
        input = emptyTable // {
          nodes.web = {
            name = "web";
            zone = "dmz";
            address = {
              ipv4 = "10.0.0.5";
              ipv6 = null;
            };
          };
        };
      in
      (convertNodesToZones {
        table = input;
        ctx = emptyCtx;
      }).table == input;
    expected = true;
  };

  # ===== checkNameCollisions — no collisions =====

  testCheckNameCollisionsNone = {
    expr =
      (runPhase checkNameCollisions (
        emptyTable
        // {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "1.1.1.1";
          };
        }
      )).errors;
    expected = [ ];
  };

  # ===== checkNameCollisions — single collision =====

  testCheckNameCollisionsOne = {
    expr =
      (runPhase checkNameCollisions (
        emptyTable
        // {
          zones.web = { };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "1.1.1.1";
          };
        }
      )).errors;
    expected = [
      {
        name = "zoneNameCollision";
        value = "name collision: 'web' is declared as both a zone and a node";
      }
    ];
  };

  # ===== checkNameCollisions — multiple collisions =====

  testCheckNameCollisionsMultiple = {
    expr =
      (runPhase checkNameCollisions (
        emptyTable
        // {
          zones = {
            a = { };
            b = { };
            c = { };
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
        }
      )).errors;
    expected = [
      {
        name = "zoneNameCollision";
        value = "name collision: 'a' is declared as both a zone and a node";
      }
      {
        name = "zoneNameCollision";
        value = "name collision: 'c' is declared as both a zone and a node";
      }
    ];
  };

  # ===== checkSettings — defaults are conflict-free =====

  testCheckSettingsNoConflict = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            nodes.web = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkSettings — wildcardZone equals localZone =====

  testCheckSettingsWildcardEqualsLocal = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            settings = {
              wildcardZone = "any";
              localZone = "any";
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "settingsConflict";
        value = "settings.wildcardZone and settings.localZone are both 'any' — they must differ";
      }
    ];
  };

  # ===== checkSettings — wildcardZone shadows declared zone =====

  testCheckSettingsWildcardShadowsZone = {
    # Default wildcardZone is "all"; declaring zones.all collides.
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            zones.all = { };
          }
        )
      ).errors;
    expected = [
      {
        name = "settingsConflict";
        value = "settings.wildcardZone 'all' collides with a declared zone or node";
      }
    ];
  };

  # ===== checkSettings — localZone shadows declared node =====

  testCheckSettingsLocalShadowsNode = {
    # Default localZone is "local"; declaring nodes.local collides.
    expr =
      (runPipeline
        [
          convertNodesToZones
          checkSettings
        ]
        (
          emptyTable
          // {
            nodes.local = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "settingsConflict";
        value = "settings.localZone 'local' collides with a declared zone or node";
      }
    ];
  };

  # ===== checkPolicyUniqueness — no policies =====

  testCheckPolicyUniquenessNoPolicies = {
    expr =
      (runPipeline [
        convertNodesToZones
        collectAllZoneNames
        expandWildcardZones
        checkPolicyUniqueness
      ] emptyTable).errors;
    expected = [ ];
  };

  # ===== checkPolicyUniqueness — single policy =====

  testCheckPolicyUniquenessSingle = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            policies.lan-to-wan = {
              from = [ "lan" ];
              to = [ "wan" ];
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkPolicyUniqueness — distinct (from, to) pairs =====

  testCheckPolicyUniquenessDistinct = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
              dmz = {
                interfaces = [ "dmz0" ];
              };
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
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkPolicyUniqueness — direct duplicate (from, to) =====

  testCheckPolicyUniquenessDirectDuplicate = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
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
          }
        )
      ).errors;
    expected = [
      {
        name = "policyConflict";
        value = "duplicate policy for (lan → wan): allow, deny";
      }
    ];
  };

  # ===== checkPolicyUniqueness — wildcard expansion produces conflict =====

  testCheckPolicyUniquenessWildcardConflict = {
    # `broad` fans out to a cell per in-scope source zone for `to = wan`;
    # `specific` produces only the (lan, wan) cell. The two collide on
    # (lan → wan).
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
          checkPolicyUniqueness
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
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
          }
        )
      ).errors;
    expected = [
      {
        name = "policyConflict";
        value = "duplicate policy for (lan → wan): broad, specific";
      }
    ];
  };

  # ===== expandWildcardZones — pass-through (no wildcard) =====

  testExpandWildcardsPassThrough = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "wan" ];
            };
          }
        )
      ).expandedGroups.filters.f;
    expected = {
      from = [ "lan" ];
      to = [ "wan" ];
    };
  };

  # ===== expandWildcardZones — wildcard expanded with dedup =====

  testExpandWildcardsExpand = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.f = {
              from = [
                "lan"
                "all"
              ];
              to = [ "wan" ];
            };
          }
        )
      ).expandedGroups.filters.f;
    # Scope = { lan, wan } ++ [ "local" ] (default localZone).
    expected = {
      from = [
        "lan"
        "wan"
        "local"
      ];
      to = [ "wan" ];
    };
  };

  # ===== expandWildcardZones — single-direction groups =====

  testExpandWildcardsSingleDir = {
    expr =
      let
        out =
          runPipeline
            [
              convertNodesToZones
              collectAllZoneNames
              expandWildcardZones
            ]
            (
              emptyTable
              // {
                zones = {
                  x = { };
                  y = { };
                };
                settings = {
                  wildcardZone = "all";
                  localZone = "ignored";
                };
                dnats.d = {
                  from = [ "all" ];
                };
                sroutes.s = {
                  from = [ "all" ];
                };
                droutes.dr = {
                  to = [ "all" ];
                };
              }
            );
      in
      {
        dnatsFrom = out.expandedGroups.dnats.d.from;
        sroutesFrom = out.expandedGroups.sroutes.s.from;
        droutesTo = out.expandedGroups.droutes.dr.to;
      };
    expected = {
      dnatsFrom = [
        "x"
        "y"
        "ignored"
      ];
      sroutesFrom = [
        "x"
        "y"
        "ignored"
      ];
      droutesTo = [
        "x"
        "y"
        "ignored"
      ];
    };
  };

  # ===== expandWildcardZones — table left untouched =====

  testExpandWildcardsTableUntouched = {
    expr =
      let
        input = emptyTable // {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "all" ];
            to = [ "lan" ];
          };
        };
        result =
          pkgs.lib.pipe
            {
              table = input;
              ctx = emptyCtx;
            }
            [
              convertNodesToZones
              collectAllZoneNames
              expandWildcardZones
            ];
      in
      result.table == input;
    expected = true;
  };

  # ===== resolvePriorities — empty groups =====

  testResolvePrioritiesEmpty = {
    expr = (runPhase resolvePriorities emptyTable).resolvedPriorities;
    expected = {
      filters = { };
      snats = { };
      dnats = { };
      sroutes = { };
      droutes = { };
    };
  };

  # ===== resolvePriorities — every symbol resolves to its int =====

  testResolvePrioritiesAllSymbols = {
    expr =
      (runPhase resolvePriorities (
        emptyTable
        // {
          filters = {
            f-first = {
              priority = "first";
            };
            f-pre = {
              priority = "preDispatch";
            };
            f-post = {
              priority = "postDispatch";
            };
            f-default = {
              priority = "default";
            };
            f-last = {
              priority = "last";
            };
          };
        }
      )).resolvedPriorities.filters;
    expected = {
      f-first = 1;
      f-pre = 50;
      f-post = 100;
      f-default = 500;
      f-last = 999;
    };
  };

  # ===== resolvePriorities — int values pass through =====

  testResolvePrioritiesInts = {
    expr =
      (runPhase resolvePriorities (
        emptyTable
        // {
          filters.f = {
            priority = 250;
          };
        }
      )).resolvedPriorities.filters.f;
    expected = 250;
  };

  # ===== resolvePriorities — covers all priority-bearing groups =====

  testResolvePrioritiesAllGroups = {
    expr =
      let
        out =
          (runPhase resolvePriorities (
            emptyTable
            // {
              filters.f = {
                priority = "first";
              };
              snats.s = {
                priority = "default";
              };
              dnats.d = {
                priority = "last";
              };
              sroutes.sr = {
                priority = "preDispatch";
              };
              droutes.dr = {
                priority = "postDispatch";
              };
            }
          )).resolvedPriorities;
      in
      {
        filters = out.filters.f;
        snats = out.snats.s;
        dnats = out.dnats.d;
        sroutes = out.sroutes.sr;
        droutes = out.droutes.dr;
      };
    expected = {
      filters = 1;
      snats = 500;
      dnats = 999;
      sroutes = 50;
      droutes = 100;
    };
  };

  # ===== collectZoneRefs — empty table =====

  testCollectRefsEmpty = {
    expr = (runPhase collectZoneRefs emptyTable).zoneRefs;
    expected = [ ];
  };

  # ===== collectZoneRefs — filter with multi-element from + to =====

  testCollectRefsFilter = {
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          filters.web-out = {
            from = [
              "lan"
              "guest"
            ];
            to = [ "wan" ];
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "lan";
        direction = "from";
        path = "filters.web-out.from[0]";
      }
      {
        zone = "guest";
        direction = "from";
        path = "filters.web-out.from[1]";
      }
      {
        zone = "wan";
        direction = "to";
        path = "filters.web-out.to[0]";
      }
    ];
  };

  # ===== collectZoneRefs — single-direction groups =====

  testCollectRefsSingleDir = {
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          dnats.d = {
            from = [ "wan" ];
          };
          sroutes.s = {
            from = [ "guest" ];
          };
          droutes.dr = {
            to = [ "vpn" ];
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "wan";
        direction = "from";
        path = "dnats.d.from[0]";
      }
      {
        zone = "guest";
        direction = "from";
        path = "sroutes.s.from[0]";
      }
      {
        zone = "vpn";
        direction = "to";
        path = "droutes.dr.to[0]";
      }
    ];
  };

  # ===== collectZoneRefs — node parent references =====

  testCollectRefsNodes = {
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          nodes = {
            api = {
              zone = "dmz";
              address.ipv4 = "1.1.1.1";
            };
            web = {
              zone = "dmz";
              address.ipv4 = "2.2.2.2";
            };
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "dmz";
        path = "nodes.api.zone";
      }
      {
        zone = "dmz";
        path = "nodes.web.zone";
      }
    ];
  };

  # ===== collectZoneRefs — group ordering =====

  testCollectRefsGroupOrder = {
    expr =
      map (r: r.path)
        (runPhase collectZoneRefs (
          emptyTable
          // {
            filters.f = {
              from = [ "z" ];
              to = [ "z" ];
            };
            policies.p = {
              from = [ "z" ];
              to = [ "z" ];
            };
            snats.sn = {
              from = [ "z" ];
              to = [ "z" ];
            };
            dnats.d = {
              from = [ "z" ];
            };
            sroutes.sr = {
              from = [ "z" ];
            };
            droutes.dr = {
              to = [ "z" ];
            };
            nodes.n = {
              zone = "z";
              address.ipv4 = "1.1.1.1";
            };
          }
        )).zoneRefs;
    expected = [
      "filters.f.from[0]"
      "filters.f.to[0]"
      "policies.p.from[0]"
      "policies.p.to[0]"
      "snats.sn.from[0]"
      "snats.sn.to[0]"
      "dnats.d.from[0]"
      "sroutes.sr.from[0]"
      "droutes.dr.to[0]"
      "nodes.n.zone"
    ];
  };

  # ===== collectZoneRefs — wildcard placeholders skipped =====

  testCollectRefsSkipsWildcard = {
    # The wildcard ("all") should not appear in zoneRefs — it's
    # not a reference, it's a directive. Slot indices preserve the
    # user's input positions.
    expr =
      (runPhase collectZoneRefs (
        emptyTable
        // {
          filters.f = {
            from = [
              "lan"
              "all"
              "wan"
            ];
            to = [ "all" ];
          };
        }
      )).zoneRefs;
    expected = [
      {
        zone = "lan";
        direction = "from";
        path = "filters.f.from[0]";
      }
      {
        zone = "wan";
        direction = "from";
        path = "filters.f.from[2]";
      }
    ];
  };

  # ===== checkZoneRefs — all references valid =====

  testCheckZoneRefsAllValid = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
          collectZoneRefs
          checkZoneRefs
        ]
        (
          emptyTable
          // {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "wan" ];
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneRefs — unknown reference produces error =====

  testCheckZoneRefsUnknown = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
          collectZoneRefs
          checkZoneRefs
        ]
        (
          emptyTable
          // {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "missing" ];
            };
          }
        )
      ).errors;
    expected = [
      {
        name = "invalidZoneRef";
        value = "filters.f.to[0] references unknown zone 'missing' (known: lan, local)";
      }
    ];
  };

  # ===== checkZoneMatchable — interfaces alone make a zone matchable =====

  testCheckZoneMatchableInterfacesOnly = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — cidrs alone make a zone matchable =====

  testCheckZoneMatchableCidrsOnly = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones = {
            lan = {
              cidrs = [ "10.0.0.0/24" ];
            };
            wan = {
              cidrs = [ "0.0.0.0/0" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — matchOverride on both sides is matchable =====

  testCheckZoneMatchableOverrideBoth = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.custom = {
            matchOverride = {
              ingress = [ [ ] ];
              egress = [ [ ] ];
            };
          };
          filters.f = {
            from = [ "custom" ];
            to = [ "custom" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — empty zone used as `from` flags ingress =====

  testCheckZoneMatchableEmptyAsFrom = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones = {
            empty = { };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          filters.f = {
            from = [ "empty" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "zoneNotMatchable";
        value =
          "filters.f.from[0] references zone 'empty' which has no ingress match"
          + " (no interfaces, no ingress CIDRs, no matchOverride.ingress)";
      }
    ];
  };

  # ===== checkZoneMatchable — empty zone used as `to` flags egress =====

  testCheckZoneMatchableEmptyAsTo = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            empty = { };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "empty" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "zoneNotMatchable";
        value =
          "filters.f.to[0] references zone 'empty' which has no egress match"
          + " (no interfaces, no egress CIDRs, no matchOverride.egress)";
      }
    ];
  };

  # ===== checkZoneMatchable — asymmetric override flags only the missing side =====

  testCheckZoneMatchableAsymmetricOverride = {
    # Zone has only `ingress` populated. Used as `from` (ingress) → no
    # error. Used as `to` (egress) → flagged.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.partial = {
            matchOverride.ingress = [ [ ] ];
          };
          filters.fromOk = {
            from = [ "partial" ];
            to = [ "partial" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "zoneNotMatchable";
        value =
          "filters.fromOk.to[0] references zone 'partial' which has no egress match"
          + " (no interfaces, no egress CIDRs, no matchOverride.egress)";
      }
    ];
  };

  # ===== checkZoneMatchable — localZone references are skipped =====

  testCheckZoneMatchableSkipsLocalZone = {
    # `local` is the default localZone sentinel — never declared as a
    # zone, never has a `mergedZones` entry. Phase 4 skips that
    # side's match emission, so this validator must skip it too.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.wan = {
            interfaces = [ "wan0" ];
          };
          filters.in-rule = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
          };
          filters.out-rule = {
            from = [ "local" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — unknown zones are left to checkZoneRefs =====

  testCheckZoneMatchableSkipsUnknownZone = {
    # An unknown zone name is checkZoneRefs's problem; this validator
    # should not double-report.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "missing" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkZoneMatchable — node parent refs are not direction-bound =====

  testCheckZoneMatchableSkipsParentRefs = {
    # `nodes.<x>.zone` is a parent reference — names a zone for
    # inheritance, doesn't match traffic. No `direction` field on the
    # ref; checkZoneMatchable filters it out.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.empty = { };
          nodes.api = {
            zone = "empty";
            address.ipv4 = "10.0.0.5";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — default placement (no override) =====

  testCheckChainOverridePlacementNoOverride = {
    # No `chain` field set → validator skips the entry.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — override at default placement =====

  testCheckChainOverridePlacementValidOverride = {
    # User sets `chain = { hook = "forward"; priority = "filter"; }`
    # explicitly. Both directions reachable at hook=forward, no error.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
            chain = {
              hook = "forward";
              priority = "filter";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — addr-matchable at restrictive hook =====

  testCheckChainOverridePlacementAddrReachable = {
    # `wan` has CIDRs → `daddr` works at any hook, including
    # prerouting where `oifname` is unavailable. No error.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              cidrs = [ "203.0.113.0/24" ];
            };
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — interface-only zone unreachable at restrictive hook =====

  testCheckChainOverridePlacementUnreachable = {
    # `host` is interface-only; at hook=prerouting, `oifname` is
    # unavailable → `to = host` cannot be matched. Flag.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            wan = {
              interfaces = [ "wan0" ];
            };
            host = {
              interfaces = [ "lo" ];
            };
          };
          filters.early-drop = {
            from = [ "wan" ];
            to = [ "host" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [
      {
        name = "chainOverrideUnreachable";
        value =
          "filters.early-drop.to references zone 'host' which has no egress match expressible at chain"
          + " (hook=prerouting, priority=raw)"
          + " — zone has no daddr CIDRs / matchOverride.egress"
          + " and oifname is unavailable in prerouting";
      }
    ];
  };

  # ===== checkChainOverridePlacement — localZone is always reachable =====

  testCheckChainOverridePlacementSkipsLocalZone = {
    # `to = local` would naively look unreachable (sentinel has no
    # mergedZones entry), but it's a wildcard. No error.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones.wan = {
            interfaces = [ "wan0" ];
          };
          filters.f = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — matchOverride trusted as-is =====

  testCheckChainOverridePlacementMatchOverrideTrusted = {
    # `host` has `matchOverride.egress` non-null → trusted; the
    # validator doesn't introspect what's inside. No error even
    # at restrictive hook.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            wan = {
              interfaces = [ "wan0" ];
            };
            host = {
              interfaces = [ "lo" ];
              matchOverride.egress = [ [ ] ];
            };
          };
          filters.f = {
            from = [ "wan" ];
            to = [ "host" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainOverridePlacement — wildcard expansion checks each resolved zone =====

  testCheckChainOverridePlacementWildcardExpansion = {
    # `to = [ "all" ]` expands to declared zones + localZone.
    # `host` (iif-only) fails at prerouting; `wan` (with CIDRs)
    # passes; `local` (sentinel) skipped. Expect ONE error for host.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          collectAllZoneNames
          expandWildcardZones
          checkChainOverridePlacement
        ]
        {
          name = "fw";
          zones = {
            wan = {
              interfaces = [ "wan0" ];
              cidrs = [ "203.0.113.0/24" ];
            };
            host = {
              interfaces = [ "lo" ];
            };
          };
          filters.f = {
            from = [ "wan" ];
            to = [ "all" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          };
        }
      ).errors;
    expected = [
      {
        name = "chainOverrideUnreachable";
        value =
          "filters.f.to references zone 'host' which has no egress match expressible at chain"
          + " (hook=prerouting, priority=raw)"
          + " — zone has no daddr CIDRs / matchOverride.egress"
          + " and oifname is unavailable in prerouting";
      }
    ];
  };

  # ===== normalizeTable — empty table =====

  testNormalizeEmpty = {
    expr =
      (normalizeTable (evalTable {
        name = "fw";
      })).ctx.mergedZones;
    expected = { };
  };

  # ===== normalizeTable — nodes lowered into mergedZones =====

  testNormalizeLowersNodes = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones.dmz = {
            interfaces = [ "eth1" ];
          };
          nodes.web = {
            zone = "dmz";
            address.ipv4 = "10.0.0.5";
          };
        });
        web = out.ctx.mergedZones.web;
      in
      {
        zoneNames = pkgs.lib.sort (a: b: a < b) (builtins.attrNames out.ctx.mergedZones);
        webFields = {
          inherit (web)
            name
            parent
            interfaces
            cidrs
            ;
        };
      };
    expected = {
      zoneNames = [
        "dmz"
        "web"
      ];
      webFields = {
        name = "web";
        parent = "dmz";
        interfaces = [ ];
        cidrs = [ "10.0.0.5/32" ];
      };
    };
  };

  # ===== normalizeTable — wildcard resolved across declared + lowered + local =====

  testNormalizeResolvesWildcards = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "10.0.0.5";
          };
          filters.f = {
            from = [ "all" ];
            to = [ "wan" ];
            rule = [ ];
          };
        });
      in
      pkgs.lib.sort (a: b: a < b) out.ctx.expandedGroups.filters.f.from;
    expected = [
      "lan"
      "local"
      "wan"
      "web"
    ];
  };

  # ===== normalizeTable — custom localZone joins the wildcard scope =====

  testNormalizeCustomLocalZone = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          settings.localZone = "host";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "all" ];
            to = [ "host" ];
            rule = [ ];
          };
        });
      in
      pkgs.lib.sort (a: b: a < b) out.ctx.expandedGroups.filters.f.from;
    expected = [
      "host"
      "lan"
    ];
  };

  # ===== normalizeTable — table stays untouched =====

  testNormalizeTableUntouched = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          nodes.web = {
            zone = "lan";
            address.ipv4 = "10.0.0.5";
          };
          filters.f = {
            from = [ "all" ];
            to = [ "lan" ];
            rule = [ ];
          };
        });
      in
      {
        filtersFrom = out.table.filters.f.from;
        nodeNames = builtins.attrNames out.table.nodes;
      };
    expected = {
      filtersFrom = [ "all" ];
      nodeNames = [ "web" ];
    };
  };

  # ===== normalizeTable — name collision throws =====

  testNormalizeCollisionThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.web = { };
            nodes.web = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — unknown zone reference throws =====

  testNormalizeUnknownRefThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "missing" ];
              rule = [ ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — unknown node-parent reference throws =====

  testNormalizeUnknownNodeParentThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            nodes.web = {
              zone = "missing";
              address.ipv4 = "1.1.1.1";
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — settings conflict throws =====

  testNormalizeSettingsConflictThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.all = { };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== computeZoneSets — empty mergedZones produces empty zoneSets =====

  testComputeZoneSetsEmpty = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
        ]
        { name = "fw"; }
      ).zoneSets;
    expected = { };
  };

  # ===== computeZoneSets — multi-zone fold produces all expected keys =====

  testComputeZoneSetsMultipleZones = {
    # Three zones with different field combinations exercise
    # all three suffixes; the fold merges per-zone genSets
    # outputs into one flat attrset.
    expr = pkgs.lib.sort (a: b: a < b) (
      builtins.attrNames (
        (runEvalPipeline
          [
            convertNodesToZones
            computeZoneSets
          ]
          {
            name = "fw";
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                cidrs = [ "0.0.0.0/0" ];
              };
              vpn = {
                interfaces = [ "wg0" ];
                cidrs = [ "fd00::/8" ];
              };
            };
          }
        ).zoneSets
      )
    );
    expected = [
      "lan_iifs"
      "vpn_iifs"
      "vpn_v6"
      "wan_v4"
    ];
  };

  # ===== checkSetNameCollisions — no collision produces no errors =====

  testCheckSetNameCollisionsClean = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkSetNameCollisions
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            cidrs = [ "10.0.0.0/24" ];
          };
          objects.sets.user-blocklist = {
            type = "ipv4_addr";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkSetNameCollisions — colliding name flagged =====

  testCheckSetNameCollisionsConflict = {
    # Zone `lan` has v4 CIDRs → synthesizes `lan_v4`. User
    # declares `objects.sets.lan_v4` → collision.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneSets
              checkSetNameCollisions
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
                cidrs = [ "10.0.0.0/24" ];
              };
              objects.sets.lan_v4 = {
                type = "ipv4_addr";
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        name = (builtins.head errors).name;
        nm = pkgs.lib.hasInfix "lan_v4" (builtins.head errors).value;
        zone = pkgs.lib.hasInfix "zone 'lan'" (builtins.head errors).value;
        suffix = pkgs.lib.hasInfix "suffix 'v4'" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      name = "setNameCollision";
      nm = true;
      zone = true;
      suffix = true;
    };
  };

  # ===== checkSetNameCollisions — underscore-named zone resolves correctly =====

  testCheckSetNameCollisionsUnderscoreZone = {
    # Zone `web_app` with v4 CIDRs synthesizes `web_app_v4`. User
    # declares `objects.sets.web_app_v4` → collision. The error
    # must name `web_app` (not `web` + suffix `app_v4`).
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneSets
              checkSetNameCollisions
            ]
            {
              name = "fw";
              zones.web_app = {
                interfaces = [ "wa0" ];
                cidrs = [ "10.1.0.0/24" ];
              };
              objects.sets.web_app_v4 = {
                type = "ipv4_addr";
              };
            }
          ).errors;
      in
      {
        zone = pkgs.lib.hasInfix "zone 'web_app'" (builtins.head errors).value;
        suffix = pkgs.lib.hasInfix "suffix 'v4'" (builtins.head errors).value;
      };
    expected = {
      zone = true;
      suffix = true;
    };
  };

  # ===== checkSetNameCollisions — non-zone-derived name accepted =====

  testCheckSetNameCollisionsUnrelatedName = {
    # `objects.sets.lan_other` doesn't match the
    # `<zone>_{iifs,v4,v6}` pattern → no collision.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkSetNameCollisions
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            cidrs = [ "10.0.0.0/24" ];
          };
          objects.sets.lan_other = {
            type = "ipv4_addr";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — empty rule bodies produce no errors =====

  testCheckObjectRefsEmpty = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          filters.f = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — declared counter resolves =====

  testCheckObjectRefsCounterResolves = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          objects.counters.drops = { };
          filters.f = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [
              (dsl.counter.ref "drops")
              dsl.drop
            ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — undeclared counter flagged =====

  testCheckObjectRefsCounterUnknown = {
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
              };
              filters.f = {
                from = [ "lan" ];
                to = [ "lan" ];
                rule = [ (dsl.counter.ref "missing-counter") ];
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        name = (builtins.head errors).name;
        path = pkgs.lib.hasInfix "filters.f.rule" (builtins.head errors).value;
        kind = pkgs.lib.hasInfix "counters" (builtins.head errors).value;
        nm = pkgs.lib.hasInfix "missing-counter" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      name = "objectRefUnknown";
      path = true;
      kind = true;
      nm = true;
    };
  };

  # ===== checkObjectRefs — multiple kinds across multiple groups =====

  testCheckObjectRefsMultipleKindsAcrossGroups = {
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones = {
                lan = {
                  interfaces = [ "lan0" ];
                };
                wan = {
                  interfaces = [ "wan0" ];
                };
              };
              filters.bad-counter = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ (dsl.counter.ref "ghost") ];
              };
              dnats.bad-set = {
                from = [ "wan" ];
                rule = {
                  match = [
                    (dsl.inSet
                      nftypes.dsl.fields.ip.saddr
                      (dsl.expr.set "ghost-set"))
                  ];
                  action.dnat = {
                    addr = "10.0.0.5";
                    port = 80;
                  };
                };
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        kinds = pkgs.lib.sort (a: b: a < b) (
          map (e: builtins.head (pkgs.lib.match ".* unknown ([a-zA-Z]+) object .*" e.value)) errors
        );
      };
    expected = {
      count = 2;
      kinds = [
        "counters"
        "sets"
      ];
    };
  };

  # ===== checkObjectRefs — zone-derived auto-set names accepted (option a) =====

  testCheckObjectRefsZoneSetAccepted = {
    # Per open question 6 (decision (a)): users can reference
    # zone-derived sets like `lan_v4` directly in match clauses;
    # they're synthesized at Phase 4 but the validator must
    # treat them as known.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            cidrs = [ "10.0.0.0/24" ];
          };
          filters.use-zone-set = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [
              (dsl.inSet
                nftypes.dsl.fields.ip.saddr
                (dsl.expr.set "lan_v4"))
              dsl.accept
            ];
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — zone-derived names limited to existing zones =====

  testCheckObjectRefsUnknownZoneSetFlagged = {
    # `wan_v6` would only exist if zone `wan` had v6 CIDRs; it
    # doesn't, so the ref is unresolved.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.wan = {
                interfaces = [ "wan0" ];
              };
              filters.f = {
                from = [ "wan" ];
                to = [ "wan" ];
                rule = [
                  (dsl.inSet
                    nftypes.dsl.fields.ip6.saddr
                    (dsl.expr.set "wan_v6"))
                  dsl.accept
                ];
              };
            }
          ).errors;
      in
      builtins.length errors;
    expected = 1;
  };

  # ===== checkObjectRefs — matchOverride content is walked =====

  testCheckObjectRefsMatchOverrideUnknown = {
    # A user-supplied matchOverride is also a vector for
    # named-ref typos — checkObjectRefs must walk it just like
    # entry.rule bodies.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
                matchOverride.ingress = [
                  [
                    (dsl.inSet
                      nftypes.dsl.fields.ip.saddr
                      (dsl.expr.set "ghost-set"))
                  ]
                ];
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        path = pkgs.lib.hasInfix "zones.lan.matchOverride.ingress" (builtins.head errors).value;
        kind = pkgs.lib.hasInfix "sets" (builtins.head errors).value;
        nm = pkgs.lib.hasInfix "ghost-set" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      path = true;
      kind = true;
      nm = true;
    };
  };

  # ===== checkObjectRefs — object bodies with no refs produce no errors =====

  testCheckObjectRefsObjectBodiesNoFalsePositives = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          objects = {
            counters.drops = { };
            limits.burst-1 = {
              rate = 100;
              per = "second";
            };
            sets.blocklist = {
              type = "ipv4_addr";
              elem = [ "1.2.3.4" "5.6.7.8" ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — element-attached stmt ref flagged when unknown =====

  testCheckObjectRefsElementStmtUnknown = {
    # Per-element stateful statements (`add element ip filter
    # tracker { 1.2.3.4 counter "tracker-hits" }`) carry refs
    # that must resolve against `objects.<kind>` keys.
    expr =
      let
        errors =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneSets
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
              };
              objects.sets.tracker = {
                type = "ipv4_addr";
                elem = [
                  (dsl.expr.elem {
                    val = "1.2.3.4";
                    stmt = [ (dsl.counter.ref "ghost-counter") ];
                  })
                ];
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        path = pkgs.lib.hasInfix "objects.sets.tracker" (builtins.head errors).value;
        kind = pkgs.lib.hasInfix "counters" (builtins.head errors).value;
        nm = pkgs.lib.hasInfix "ghost-counter" (builtins.head errors).value;
      };
    expected = {
      count = 1;
      path = true;
      kind = true;
      nm = true;
    };
  };

  # ===== checkObjectRefs — element-attached stmt ref accepted when known =====

  testCheckObjectRefsElementStmtResolves = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
          objects = {
            counters.tracker-hits = { };
            sets.tracker = {
              type = "ipv4_addr";
              elem = [
                (dsl.expr.elem {
                  val = "1.2.3.4";
                  stmt = [ (dsl.counter.ref "tracker-hits") ];
                })
              ];
            };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkObjectRefs — matchOverride resolved refs accepted =====

  testCheckObjectRefsMatchOverrideResolves = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneSets
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            matchOverride.egress = [
              [
                (dsl.inSet
                  nftypes.dsl.fields.ip.daddr
                  (dsl.expr.set "blocklist"))
              ]
            ];
          };
          objects.sets.blocklist = {
            type = "ipv4_addr";
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== normalizeTable — unknown object ref throws =====

  testNormalizeUnknownObjectRefThrows = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "lan" ];
              to = [ "lan" ];
              rule = [ (dsl.counter.ref "ghost") ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== normalizeTable — declared zones survive intact in mergedZones =====

  testNormalizeZonesPassThrough = {
    expr =
      let
        out = normalizeTable (evalTable {
          name = "fw";
          zones.lan = {
            interfaces = [ "eth1" ];
            cidrs = [ "10.0.0.0/24" ];
          };
        });
      in
      {
        interfaces = out.ctx.mergedZones.lan.interfaces;
        cidrs = out.ctx.mergedZones.lan.cidrs;
      };
    expected = {
      interfaces = [ "eth1" ];
      cidrs = [ "10.0.0.0/24" ];
    };
  };
}
