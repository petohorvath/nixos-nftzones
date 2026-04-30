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
    checkNameCollisions
    checkSettings
    collectAllZoneNames
    expandWildcardZones
    resolvePriorities
    collectZoneRefs
    checkZoneRefs
    normalizeTable
    ;

  /*
    Build a realistic `nftzones.types.table` value via evalModules.
    The table type fills in submodule defaults for `settings`, rule
    groups, and `objects`; each test only specifies the fields it
    cares about.
  */
  evalTable =
    body:
    let
      cfg = pkgs.lib.evalModules {
        modules = [
          {
            options.fw = pkgs.lib.mkOption {
              type = nftzones.types.table;
            };
          }
          { config.fw = body; }
        ];
      };
    in
    cfg.config.fw;

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
          zones.lan = { };
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
            zones.lan = { };
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
              lan = { };
              wan = { };
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
              lan = { };
              wan = { };
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
          zones.lan = { };
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
        path = "filters.web-out.from[0]";
      }
      {
        zone = "guest";
        path = "filters.web-out.from[1]";
      }
      {
        zone = "wan";
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
        path = "dnats.d.from[0]";
      }
      {
        zone = "guest";
        path = "sroutes.s.from[0]";
      }
      {
        zone = "vpn";
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
        path = "filters.f.from[0]";
      }
      {
        zone = "wan";
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
              lan = { };
              wan = { };
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
            zones.lan = { };
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
            lan = { };
            wan = { };
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
          zones.lan = { };
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
          zones.lan = { };
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
            zones.lan = { };
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
