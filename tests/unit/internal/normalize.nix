/*
  Unit tests for `lib/internal/normalize.nix` (exposed as
  `nftzones.internal.normalize`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.normalize)
    checkChainOverridePlacement
    checkChainOverrideSemantics
    checkChainPlacement
    checkExtraSectionFields
    checkNameCollisions
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
    ;

  inherit (nftypes) dsl;
  inherit (pkgs) lib;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;

  # Minimal table fixture for direct (non-`evalTable`) phase tests.
  # Carries every field the phases destructure; tests overlay what
  # they need.
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
    warnings = [ ];
  };

  /*
    Run a phase against the supplied (or `emptyTable`) table with a
    fresh `emptyCtx`, returning just the resulting `ctx` attrset —
    what every phase test wants to inspect.
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
    (lib.pipe {
      inherit table;
      ctx = emptyCtx;
    } phases).ctx;

  /*
    Same as `runPipeline` but accepts a `body` and runs it through
    the table submodule first (via `evalTable`). Use when phases
    rely on submodule-evaluated defaults (e.g. `matchOverride`'s
    nullable fields filled in from defaults).
  */
  runEvalPipeline = phases: body: runPipeline phases (evalTable body);
in
{
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
        message = "name collision: 'web' is also declared as zones.web";
        path = [
          "nodes"
          "web"
        ];
        tag = "zoneNameCollision";
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
        message = "name collision: 'a' is also declared as zones.a";
        path = [
          "nodes"
          "a"
        ];
        tag = "zoneNameCollision";
      }
      {
        message = "name collision: 'c' is also declared as zones.c";
        path = [
          "nodes"
          "c"
        ];
        tag = "zoneNameCollision";
      }
    ];
  };

  # ===== checkChainPlacement — inet defaults are accepted =====

  testCheckChainPlacementInetDefaults = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "inet";
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.allow = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
          snats.masq = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
          };
        }
      ).errors;
    expected = [ ];
  };

  # ===== checkChainPlacement — bridge family + snat is rejected =====

  testCheckChainPlacementBridgeRejectsSnat = {
    # Bridge family doesn't support `nat` chains
    # (`familiesByChainType.nat = [ip ip6 inet]`); the default
    # snat placement at postrouting+srcnat must be flagged.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "bridge";
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          snats.masq = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
          };
        }
      ).errors;
    expected = [
      {
        message = "would emit a base chain at (family=bridge, hook=postrouting, priority=srcnat) — kernel rejects chain type 'nat' on hook 'postrouting' for family 'bridge'";
        path = [
          "snats"
          "masq"
        ];
        tag = "invalidChainPlacement";
      }
    ];
  };

  # ===== checkChainPlacement — bridge sroute has a null chainType =====

  testCheckChainPlacementBridgeSrouteUnknownPriority = {
    # Bridge has no `mangle` priority, so `chainTypeFor` returns
    # null — the validator surfaces it as a clear error rather
    # than letting emit throw.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "bridge";
          zones.lan.interfaces = [ "lan0" ];
          sroutes.mark = {
            from = [ "lan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        message = "would emit a base chain at (family=bridge, hook=prerouting, priority=mangle) — priority symbol 'mangle' has no value in family 'bridge'";
        path = [
          "sroutes"
          "mark"
        ];
        tag = "invalidChainPlacement";
      }
    ];
  };

  # ===== checkChainPlacement — bridge filter+policy is fine =====

  testCheckChainPlacementBridgeFilter = {
    # Bridge supports filter chains; with no nat/route groups
    # declared the placement check passes.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          expandWildcardZones
          checkChainPlacement
        ]
        {
          family = "bridge";
          zones.lan.interfaces = [ "lan0" ];
          filters.allow = {
            from = [ "lan" ];
            to = [ "lan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [ ];
  };

  testCheckChainPlacementAggregatesOverridesAndDefaults = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          expandWildcardZones
          (
            { table, ctx }:
            {
              inherit table;
              ctx = ctx // {
                errors = [
                  {
                    name = "earlierError";
                    value = "kept";
                  }
                ];
              };
            }
          )
          checkChainPlacement
        ]
        {
          family = "bridge";
          settings.localZone = "host";
          zones.lan.interfaces = [ "br0" ];
          filters.early = {
            from = [ "lan" ];
            to = [ "host" ];
            rule = [ ];
            chain = {
              hook = "prerouting";
              priority = "mangle";
            };
          };
          snats.masq = {
            from = [ "lan" ];
            to = [ "host" ];
            rule.masquerade = { };
          };
          droutes.mark = {
            to = [ "lan" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        name = "earlierError";
        value = "kept";
      }
      {
        message = "would emit a base chain at (family=bridge, hook=output, priority=mangle) — priority symbol 'mangle' has no value in family 'bridge'";
        path = [
          "droutes"
          "mark"
        ];
        tag = "invalidChainPlacement";
      }
      {
        message = "would emit a base chain at (family=bridge, hook=prerouting, priority=mangle) — priority symbol 'mangle' has no value in family 'bridge'";
        path = [
          "filters"
          "early"
        ];
        tag = "invalidChainPlacement";
      }
      {
        message = "would emit a base chain at (family=bridge, hook=postrouting, priority=srcnat) — kernel rejects chain type 'nat' on hook 'postrouting' for family 'bridge'";
        path = [
          "snats"
          "masq"
        ];
        tag = "invalidChainPlacement";
      }
    ];
  };

  # ===== checkRpfilterOverride — rpfilter on, no override → silent =====

  testCheckRpfilterOverrideNoOverride = {
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        settings.rpfilter = true;
        zones.lan.interfaces = [ "lan0" ];
      }).warnings;
    expected = [ ];
  };

  # ===== checkRpfilterOverride — override but rpfilter off → silent =====

  testCheckRpfilterOverrideRpfilterOff = {
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        zones.wan.interfaces = [ "wan0" ];
        filters.early-drop = {
          from = [ "wan" ];
          to = [ "wan" ];
          rule = [ ];
          chain = {
            hook = "prerouting";
            priority = "raw";
          };
        };
      }).warnings;
    expected = [ ];
  };

  # ===== checkRpfilterOverride — both set → warning fires =====

  testCheckRpfilterOverrideConflict = {
    # User chain at (prerouting, raw) suppresses the synthesized
    # rpfilter chain in Phase 4. Validator surfaces a warning so
    # the suppression isn't silent.
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        settings.rpfilter = true;
        zones.wan.interfaces = [ "wan0" ];
        filters.early-drop = {
          from = [ "wan" ];
          to = [ "wan" ];
          rule = [ ];
          chain = {
            hook = "prerouting";
            priority = "raw";
          };
        };
      }).warnings;
    expected = [
      {
        message = "is enabled but a user chain override already claims (prerouting, raw); the synthesized rpfilter chain is suppressed and the user-authored chain is used as-is. Add `fib saddr . iif oif eq 0 drop` to the override manually if you want rpfilter behavior in that chain.";
        path = [
          "settings"
          "rpfilter"
        ];
        tag = "rpfilterChainSuppressed";
      }
    ];
  };

  # ===== checkRpfilterOverride — int form override is detected too =====

  testCheckRpfilterOverrideIntPriority = {
    # `priority = -300` is the int form of `"raw"`; canonicalized
    # via priorityNameOf so the check matches both forms.
    expr =
      (runEvalPipeline [ checkRpfilterOverride ] {
        settings.rpfilter = true;
        zones.wan.interfaces = [ "wan0" ];
        filters.early-drop = {
          from = [ "wan" ];
          to = [ "wan" ];
          rule = [ ];
          chain = {
            hook = "prerouting";
            priority = -300;
          };
        };
      }).warnings;
    expected = [
      {
        message = "is enabled but a user chain override already claims (prerouting, raw); the synthesized rpfilter chain is suppressed and the user-authored chain is used as-is. Add `fib saddr . iif oif eq 0 drop` to the override manually if you want rpfilter behavior in that chain.";
        path = [
          "settings"
          "rpfilter"
        ];
        tag = "rpfilterChainSuppressed";
      }
    ];
  };

  # ===== checkNodeAddresses — node with ipv4 passes =====

  testCheckNodeAddressesV4Only = {
    expr =
      (runEvalPipeline [ checkNodeAddresses ] {
        zones.dmz.interfaces = [ "dmz0" ];
        nodes.web = {
          zone = "dmz";
          address.ipv4 = "10.0.0.5";
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNodeAddresses — node with ipv6 passes =====

  testCheckNodeAddressesV6Only = {
    expr =
      (runEvalPipeline [ checkNodeAddresses ] {
        zones.dmz.interfaces = [ "dmz0" ];
        nodes.web = {
          zone = "dmz";
          address.ipv6 = "fe80::1";
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNodeAddresses — both-null rejected =====

  testCheckNodeAddressesBothNull = {
    expr =
      (runEvalPipeline [ checkNodeAddresses ] {
        zones.dmz.interfaces = [ "dmz0" ];
        nodes.web = {
          zone = "dmz";
          address = { };
        };
      }).errors;
    expected = [
      {
        message = "address must set at least one of `ipv4` / `ipv6` — a node with no address contributes no CIDR to its lowered zone.";
        path = [
          "nodes"
          "web"
        ];
        tag = "nodeAddressMissing";
      }
    ];
  };

  # ===== checkNodeAddresses — aggregates across multiple nodes =====

  testCheckNodeAddressesAggregates = {
    expr =
      builtins.length
        (runEvalPipeline [ checkNodeAddresses ] {
          zones.dmz.interfaces = [ "dmz0" ];
          nodes.a = {
            zone = "dmz";
            address = { };
          };
          nodes.b = {
            zone = "dmz";
            address = { };
          };
          nodes.c = {
            zone = "dmz";
            address.ipv4 = "10.0.0.5";
          };
        }).errors;
    expected = 2;
  };

  # ===== checkNatBodies — well-formed snat passes =====

  testCheckNatBodiesValidSnat = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        snats.outbound = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule.snat.addr = "203.0.113.5";
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — masquerade has no addr requirement =====

  testCheckNatBodiesValidMasquerade = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        snats.outbound = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule.masquerade = { };
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — empty snat body rejected =====

  testCheckNatBodiesEmptySnat = {
    # `rule.snat = { }` selects the `snat` tag with an all-null
    # body. Type accepts it (every natBody field is nullable);
    # nft rejects `snat to;` with no target at activation. This
    # validator catches it earlier with a clear error.
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        snats.outbound = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule.snat = { };
        };
      }).errors;
    expected = [
      {
        message = "rule.snat.addr is null — `snat` requires a target address. Use `rule.masquerade = { }` for auto-target via the outgoing interface, or set `rule.snat.addr` explicitly.";
        path = [
          "snats"
          "outbound"
        ];
        tag = "natBodyMissingAddr";
      }
    ];
  };

  # ===== checkNatBodies — well-formed dnat passes =====

  testCheckNatBodiesValidDnat = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.wan.interfaces = [ "wan0" ];
        dnats.web-fwd = {
          from = [ "wan" ];
          rule = {
            match = [ ];
            action.dnat = {
              addr = "10.0.0.5";
              port = 443;
            };
          };
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — redirect has no addr requirement =====

  testCheckNatBodiesValidRedirect = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.wan.interfaces = [ "wan0" ];
        dnats.ssh-redirect = {
          from = [ "wan" ];
          rule = {
            match = [ ];
            action.redirect.port = 22;
          };
        };
      }).errors;
    expected = [ ];
  };

  # ===== checkNatBodies — empty dnat action body rejected =====

  testCheckNatBodiesEmptyDnat = {
    expr =
      (runEvalPipeline [ checkNatBodies ] {
        zones.wan.interfaces = [ "wan0" ];
        dnats.bad-fwd = {
          from = [ "wan" ];
          rule = {
            match = [ ];
            action.dnat = { };
          };
        };
      }).errors;
    expected = [
      {
        message = "rule.action.dnat.addr is null — `dnat` requires a target address. Use `rule.action.redirect = { port = N; }` for redirect-to-localhost, or set `rule.action.dnat.addr` explicitly.";
        path = [
          "dnats"
          "bad-fwd"
        ];
        tag = "natBodyMissingAddr";
      }
    ];
  };

  # ===== checkNatBodies — errors aggregate across both groups =====

  testCheckNatBodiesAggregates = {
    expr =
      builtins.length
        (runEvalPipeline [ checkNatBodies ] {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          snats.bad-s = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.snat = { };
          };
          dnats.bad-d = {
            from = [ "wan" ];
            rule = {
              match = [ ];
              action.dnat = { };
            };
          };
        }).errors;
    expected = 2;
  };

  # ===== checkSettings — defaults are conflict-free =====

  testCheckSettingsNoConflict = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
          computeZoneMembership
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
        message = "'any' equals settings.wildcardZone — they must differ";
        path = [
          "settings"
          "localZone"
        ];
        tag = "settingsConflict";
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
          computeZoneMembership
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
        message = "'all' collides with a declared zone or node";
        path = [
          "settings"
          "wildcardZone"
        ];
        tag = "settingsConflict";
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
          computeZoneMembership
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
        message = "'local' collides with a declared zone or node";
        path = [
          "settings"
          "localZone"
        ];
        tag = "settingsConflict";
      }
    ];
  };

  # ===== checkPolicyUniqueness — no policies =====

  testCheckPolicyUniquenessNoPolicies = {
    expr =
      (runPipeline [
        convertNodesToZones
        computeZoneMembership
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
          computeZoneMembership
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
          computeZoneMembership
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
          computeZoneMembership
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
        message = "duplicate policy for (lan → wan), also declared by policies.deny";
        path = [
          "policies"
          "allow"
        ];
        tag = "policyConflict";
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
          computeZoneMembership
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
        message = "duplicate policy for (lan → wan), also declared by policies.specific";
        path = [
          "policies"
          "broad"
        ];
        tag = "policyConflict";
      }
    ];
  };

  # ===== checkZoneRefs — all references valid =====

  testCheckZoneRefsAllValid = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
          computeZoneMembership
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
        message = "references unknown zone 'missing' (known: lan, local)";
        path = [
          "filters"
          "f"
          "to"
          "0"
        ];
        tag = "invalidZoneRef";
      }
    ];
  };

  # ===== checkZoneMatchable — interfaces alone make a zone matchable =====

  testCheckZoneMatchableInterfacesOnly = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
          computeZoneMembership
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
    # An `extra` section with a `meta mark` clause makes the zone
    # matchable on both sides without any interfaces / cidrs.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.custom = {
            matchOverride = {
              ingress.extra = [ (dsl.eq dsl.fields.meta.mark 256) ];
              egress.extra = [ (dsl.eq dsl.fields.meta.mark 256) ];
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
          computeZoneMembership
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
        message = "references zone 'empty' which has no ingress match (no interfaces, no CIDRs, and no matchOverride sections set on the ingress side)";
        path = [
          "filters"
          "f"
          "from"
          "0"
        ];
        tag = "zoneNotMatchable";
      }
    ];
  };

  # ===== checkZoneMatchable — empty zone used as `to` flags egress =====

  testCheckZoneMatchableEmptyAsTo = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
        message = "references zone 'empty' which has no egress match (no interfaces, no CIDRs, and no matchOverride sections set on the egress side)";
        path = [
          "filters"
          "f"
          "to"
          "0"
        ];
        tag = "zoneNotMatchable";
      }
    ];
  };

  # ===== checkZoneMatchable — asymmetric override flags the missing side =====

  testCheckZoneMatchableAsymmetricOverride = {
    # Zone has only `ingress` populated (via the `extra` section). Used as
    # `from` (ingress) → no error. Used as `to` (egress) → flagged.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.partial = {
            matchOverride.ingress.extra = [ (dsl.eq dsl.fields.meta.mark 256) ];
          };
          filters.from-ok = {
            from = [ "partial" ];
            to = [ "partial" ];
            rule = [ ];
          };
        }
      ).errors;
    expected = [
      {
        message = "references zone 'partial' which has no egress match (no interfaces, no CIDRs, and no matchOverride sections set on the egress side)";
        path = [
          "filters"
          "from-ok"
          "to"
          "0"
        ];
        tag = "zoneNotMatchable";
      }
    ];
  };

  # ===== checkZoneMatchable — empty list section contributes nothing =====

  testCheckZoneMatchableEmptySectionDoesntCount = {
    # `matchOverride.egress.extra = [ ]` (empty list) is treated
    # the same as `null` — both mean "no constraint contributed".
    # Zone has no interfaces / cidrs / other sections → unmatchable
    # on egress.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          collectZoneRefs
          checkZoneMatchable
        ]
        {
          name = "fw";
          zones.empty-section = {
            matchOverride.egress.extra = [ ];
          };
          filters.f = {
            from = [ "empty-section" ];
            to = [ "empty-section" ];
            rule = [ ];
          };
        }
      ).errors;
    # Both directions are unmatchable (empty-section has nothing). Two
    # errors: ingress (mapped from `from`) and egress (mapped from `to`).
    expected = [
      {
        message = "references zone 'empty-section' which has no ingress match (no interfaces, no CIDRs, and no matchOverride sections set on the ingress side)";
        path = [
          "filters"
          "f"
          "from"
          "0"
        ];
        tag = "zoneNotMatchable";
      }
      {
        message = "references zone 'empty-section' which has no egress match (no interfaces, no CIDRs, and no matchOverride sections set on the egress side)";
        path = [
          "filters"
          "f"
          "to"
          "0"
        ];
        tag = "zoneNotMatchable";
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
          computeZoneMembership
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
          computeZoneMembership
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
          computeZoneMembership
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
          computeZoneMembership
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
          computeZoneMembership
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
          computeZoneMembership
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

  # ===== checkChainOverridePlacement — interface-only zone unreachable =====

  testCheckChainOverridePlacementUnreachable = {
    # `host` is interface-only; at hook=prerouting, `oifname` is
    # unavailable → `to = host` cannot be matched. Flag.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
        message = "references zone 'host' which has no egress match expressible at chain (hook=prerouting, priority=raw) — zone has no daddr CIDRs and no hook-agnostic matchOverride.egress sections (ipv4 / ipv6 / extra) set, and oifname is unavailable in prerouting";
        path = [
          "filters"
          "early-drop"
          "to"
        ];
        tag = "chainOverrideUnreachable";
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
          computeZoneMembership
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

  # ===== checkChainOverridePlacement — hook-agnostic override reachable =====

  testCheckChainOverridePlacementMatchOverrideTrusted = {
    # `host` has a hook-agnostic `matchOverride.egress.extra`
    # section → reachable at any hook. No error even at restrictive
    # `prerouting` (where `oifname` is unavailable).
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
              matchOverride.egress.extra = [ (dsl.eq dsl.fields.meta.mark 256) ];
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

  # ===== checkChainOverridePlacement — wildcard checks each resolved zone =====

  testCheckChainOverridePlacementWildcardExpansion = {
    # `to = [ "all" ]` expands to declared zones + localZone.
    # `host` (iif-only) fails at prerouting; `wan` (with CIDRs)
    # passes; `local` (sentinel) skipped. Expect ONE error for host.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
        message = "references zone 'host' which has no egress match expressible at chain (hook=prerouting, priority=raw) — zone has no daddr CIDRs and no hook-agnostic matchOverride.egress sections (ipv4 / ipv6 / extra) set, and oifname is unavailable in prerouting";
        path = [
          "filters"
          "f"
          "to"
        ];
        tag = "chainOverrideUnreachable";
      }
    ];
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

  # ===== checkSetNameCollisions — no collision produces no errors =====

  testCheckSetNameCollisionsClean = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
              computeZoneMembership
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
        tag = (builtins.head errors).tag;
        path =
          (builtins.head errors).path == [
            "objects"
            "sets"
            "lan_v4"
          ];
        zone = lib.hasInfix "zone 'lan'" (builtins.head errors).message;
        suffix = lib.hasInfix "suffix 'v4'" (builtins.head errors).message;
      };
    expected = {
      count = 1;
      tag = "setNameCollision";
      path = true;
      zone = true;
      suffix = true;
    };
  };

  # ===== checkSetNameCollisions — underscore-named zone resolves =====

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
              computeZoneMembership
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
        zone = lib.hasInfix "zone 'web_app'" (builtins.head errors).message;
        suffix = lib.hasInfix "suffix 'v4'" (builtins.head errors).message;
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
          computeZoneMembership
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
          computeZoneMembership
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
          computeZoneMembership
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
              computeZoneMembership
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
        tag = (builtins.head errors).tag;
        path =
          (builtins.head errors).path == [
            "filters"
            "f"
            "rule"
          ];
        kind = lib.hasInfix "counters" (builtins.head errors).message;
        mentionsName = lib.hasInfix "missing-counter" (builtins.head errors).message;
      };
    expected = {
      count = 1;
      tag = "objectRefUnknown";
      path = true;
      kind = true;
      mentionsName = true;
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
              computeZoneMembership
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
                    (dsl.inSet dsl.fields.ip.saddr (dsl.expr.setRef "ghost-set"))
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
        kinds = lib.sort (a: b: a < b) (
          map (e: builtins.head (lib.match ".* unknown ([a-zA-Z]+) object .*" e.message)) errors
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

  # ===== checkObjectRefs — zone-derived auto-set names accepted =====

  testCheckObjectRefsZoneSetAccepted = {
    # Per open question 6 (decision (a)): users can reference
    # zone-derived sets like `lan_v4` directly in match clauses;
    # they're synthesized at Phase 4 but the validator must
    # treat them as known.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
              (dsl.inSet dsl.fields.ip.saddr (dsl.expr.setRef "lan_v4"))
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
              computeZoneMembership
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
                  (dsl.inSet dsl.fields.ip6.saddr (dsl.expr.setRef "wan_v6"))
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
              computeZoneMembership
              checkObjectRefs
            ]
            {
              name = "fw";
              zones.lan = {
                interfaces = [ "lan0" ];
                matchOverride.ingress.ipv4 = [
                  (dsl.inSet dsl.fields.ip.saddr (dsl.expr.setRef "ghost-set"))
                ];
              };
            }
          ).errors;
      in
      {
        count = builtins.length errors;
        path =
          (builtins.head errors).path == [
            "zones"
            "lan"
            "matchOverride"
            "ingress"
            "ipv4"
          ];
        kind = lib.hasInfix "sets" (builtins.head errors).message;
        mentionsName = lib.hasInfix "ghost-set" (builtins.head errors).message;
      };
    expected = {
      count = 1;
      path = true;
      kind = true;
      mentionsName = true;
    };
  };

  # ===== checkObjectRefs — object bodies with no refs produce no errors =====

  testCheckObjectRefsObjectBodiesNoFalsePositives = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
              elem = [
                "1.2.3.4"
                "5.6.7.8"
              ];
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
              computeZoneMembership
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
        path =
          (builtins.head errors).path == [
            "objects"
            "sets"
            "tracker"
          ];
        kind = lib.hasInfix "counters" (builtins.head errors).message;
        mentionsName = lib.hasInfix "ghost-counter" (builtins.head errors).message;
      };
    expected = {
      count = 1;
      path = true;
      kind = true;
      mentionsName = true;
    };
  };

  # ===== checkObjectRefs — element-attached stmt ref accepted when known =====

  testCheckObjectRefsElementStmtResolves = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
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
          computeZoneMembership
          checkObjectRefs
        ]
        {
          name = "fw";
          zones.lan = {
            interfaces = [ "lan0" ];
            matchOverride.egress.ipv4 = [
              (dsl.inSet dsl.fields.ip.daddr (dsl.expr.setRef "blocklist"))
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

  # ===== normalizeTable — failing validators aggregate into one throw =====
  # Phase 1 is fail-aggregating: when multiple validators detect
  # problems, normalizeTable throws ONCE with all messages, not
  # validator-by-validator. The throw must mention every failing
  # category so the user sees the full picture in one shot.

  testNormalizeMultipleErrorsAggregated = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            # Triggers checkNameCollisions: zone+node share "web"
            zones.web = { };
            nodes.web = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
            # Triggers checkZoneRefs: "missing" is unknown
            filters.f = {
              from = [ "missing" ];
              to = [ "web" ];
              rule = [ ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== checkParentRefs — null parent passes =====

  testCheckParentRefsNullPasses = {
    expr =
      (runPipeline [
        convertNodesToZones
        computeZoneMembership
        checkParentRefs
      ] emptyTable).errors;
    expected = [ ];
  };

  # ===== checkParentRefs — known parent passes =====

  testCheckParentRefsKnownPasses = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentRefs
        ]
        (
          emptyTable
          // {
            zones = {
              dmz = {
                interfaces = [ "dmz0" ];
              };
              web = {
                parent = "dmz";
                cidrs = [ "10.0.0.5/32" ];
              };
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkParentRefs — unknown parent flagged =====

  testCheckParentRefsUnknown = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentRefs
        ]
        (
          emptyTable
          // {
            zones.web = {
              parent = "ghost";
              cidrs = [ "10.0.0.5/32" ];
            };
          }
        )
      ).errors;
    expected = [
      {
        message = "references unknown zone 'ghost'";
        path = [
          "zones"
          "web"
          "parent"
        ];
        tag = "zoneParentUnknown";
      }
    ];
  };

  # ===== checkParentRefs — localZone as parent flagged =====

  testCheckParentRefsLocalZone = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentRefs
        ]
        (
          emptyTable
          // {
            zones.web = {
              parent = "local";
              cidrs = [ "10.0.0.5/32" ];
            };
          }
        )
      ).errors;
    expected = [
      {
        message = "is 'local' (the localZone sentinel) — localZone cannot be a parent";
        path = [
          "zones"
          "web"
          "parent"
        ];
        tag = "zoneParentLocalZone";
      }
    ];
  };

  # ===== checkParentRefs — node lowering propagates parent for validation =====

  testCheckParentRefsNodeLowered = {
    # A node lowers to a zone with `parent = node.zone`. If
    # node.zone is unknown, validator flags it.
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentRefs
        ]
        (
          emptyTable
          // {
            nodes.web = {
              name = "web";
              zone = "ghost";
              address = {
                ipv4 = "10.0.0.5";
                ipv6 = null;
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        message = "references unknown zone 'ghost'";
        path = [
          "zones"
          "web"
          "parent"
        ];
        tag = "zoneParentUnknown";
      }
    ];
  };

  # ===== checkParentCycles — no cycle =====

  testCheckParentCyclesNone = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = { };
              b = {
                parent = "a";
              };
              c = {
                parent = "b";
              };
            };
          }
        )
      ).errors;
    expected = [ ];
  };

  # ===== checkParentCycles — simple cycle flagged exactly once =====

  testCheckParentCyclesSimple = {
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = {
                parent = "b";
              };
              b = {
                parent = "a";
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        message = "closes a zone parent cycle: a → b → a";
        path = [
          "zones"
          "a"
          "parent"
        ];
        tag = "zoneParentCycle";
      }
    ];
  };

  # ===== checkParentCycles — 3-cycle dedups across all rotations =====

  testCheckParentCyclesThreeNodeDedup = {
    # Cycle `a → c → b → a` (following parent pointers).
    # Walks starting from a, b, c each discover the same cycle
    # from different positions. Canonicalization (rotate to
    # lex-smallest) collapses them into one error.
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = {
                parent = "c";
              };
              b = {
                parent = "a";
              };
              c = {
                parent = "b";
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        message = "closes a zone parent cycle: a → c → b → a";
        path = [
          "zones"
          "a"
          "parent"
        ];
        tag = "zoneParentCycle";
      }
    ];
  };

  # ===== checkParentCycles — tail leading into cycle is stripped =====

  testCheckParentCyclesTailStripped = {
    # `d → a → b → c → a`: walk from d hits the cycle but `d`
    # itself isn't part of it. Output should be just the cycle
    # members, canonicalized.
    expr =
      (runPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkParentCycles
        ]
        (
          emptyTable
          // {
            zones = {
              a = {
                parent = "b";
              };
              b = {
                parent = "c";
              };
              c = {
                parent = "a";
              };
              d = {
                parent = "a";
              };
            };
          }
        )
      ).errors;
    expected = [
      {
        message = "closes a zone parent cycle: a → b → c → a";
        path = [
          "zones"
          "a"
          "parent"
        ];
        tag = "zoneParentCycle";
      }
    ];
  };

  # ===== checkChainOverrideSemantics — no overrides, no warnings =====

  testCheckChainOverrideSemanticsDefaults = {
    expr =
      (runPhase checkChainOverrideSemantics (
        emptyTable
        // {
          family = "inet";
          filters.allow-ssh = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
            chain = null;
            priority = "default";
          };
          snats.masq = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
            chain = null;
            priority = "default";
          };
          dnats.fwd = {
            from = [ "wan" ];
            rule = {
              match = [ ];
              action.dnat = {
                addr = "10.0.0.5";
                port = 443;
              };
            };
            chain = null;
            priority = "default";
          };
        }
      )).warnings;
    expected = [ ];
  };

  # ===== checkChainOverrideSemantics — filter at postrouting warns =====

  testCheckChainOverrideSemanticsFilterPostrouting = {
    expr =
      let
        warnings =
          (runPhase checkChainOverrideSemantics (
            emptyTable
            // {
              family = "inet";
              filters.late = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
                chain = {
                  hook = "postrouting";
                  priority = "srcnat";
                };
                priority = "default";
              };
            }
          )).warnings;
      in
      {
        count = lib.length warnings;
        mentionsHook = lib.any (w: lib.hasInfix "hook=postrouting" w.message) warnings;
        mentionsEntry = lib.any (
          w:
          w.path == [
            "filters"
            "late"
            "chain"
          ]
        ) warnings;
      };
    expected = {
      count = 1;
      mentionsHook = true;
      mentionsEntry = true;
    };
  };

  # ===== checkChainOverrideSemantics — dnat at output warns =====

  testCheckChainOverrideSemanticsDnatOutput = {
    expr =
      let
        warnings =
          (runPhase checkChainOverrideSemantics (
            emptyTable
            // {
              family = "inet";
              dnats.local-rewrite = {
                from = [ "local" ];
                rule = {
                  match = [ ];
                  action.dnat = {
                    addr = "10.0.0.5";
                    port = 443;
                  };
                };
                chain = {
                  hook = "output";
                  priority = "dstnat";
                };
                priority = "default";
              };
            }
          )).warnings;
      in
      {
        count = lib.length warnings;
        mentionsHook = lib.any (w: lib.hasInfix "hook=output" w.message) warnings;
      };
    expected = {
      count = 1;
      mentionsHook = true;
    };
  };

  # ===== checkChainOverrideSemantics — snat at non-srcnat priority warns =====

  testCheckChainOverrideSemanticsSnatNonSrcnat = {
    expr =
      let
        warnings =
          (runPhase checkChainOverrideSemantics (
            emptyTable
            // {
              family = "inet";
              snats.early = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule.masquerade = { };
                chain = {
                  hook = "postrouting";
                  priority = "mangle";
                };
                priority = "default";
              };
            }
          )).warnings;
      in
      {
        count = lib.length warnings;
        mentionsPriority = lib.any (
          w: lib.hasInfix "mangle" w.message && lib.hasInfix "srcnat" w.message
        ) warnings;
      };
    expected = {
      count = 1;
      mentionsPriority = true;
    };
  };

  # ===== checkChainOverrideSemantics — snat at explicit srcnat passes =====

  testCheckChainOverrideSemanticsSnatExplicitSrcnat = {
    # Explicit override at the *correct* priority is fine. Same
    # for the int form (100 = srcnat).
    expr =
      (runPhase checkChainOverrideSemantics (
        emptyTable
        // {
          family = "inet";
          snats.s1 = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
            chain = {
              hook = "postrouting";
              priority = "srcnat";
            };
            priority = "default";
          };
          snats.s2 = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
            chain = {
              hook = "postrouting";
              priority = 100;
            };
            priority = "default";
          };
        }
      )).warnings;
    expected = [ ];
  };

  # ===== checkChainOverrideSemantics — multiple sub-cases aggregate =====

  testCheckChainOverrideSemanticsMultiple = {
    expr =
      lib.length
        (runPhase checkChainOverrideSemantics (
          emptyTable
          // {
            family = "inet";
            filters.f = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
              chain = {
                hook = "postrouting";
                priority = "srcnat";
              };
              priority = "default";
            };
            dnats.d = {
              from = [ "local" ];
              rule = {
                match = [ ];
                action.dnat = {
                  addr = "10.0.0.5";
                  port = 443;
                };
              };
              chain = {
                hook = "output";
                priority = "dstnat";
              };
              priority = "default";
            };
            snats.s = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule.masquerade = { };
              chain = {
                hook = "postrouting";
                priority = "filter";
              };
              priority = "default";
            };
          }
        )).warnings;
    expected = 3;
  };

  # ===== checkExtraSectionFields — extra without iif/oif is clean =====

  testCheckExtraSectionFieldsClean = {
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkExtraSectionFields
        ]
        {
          zones.lan = {
            interfaces = [ "lan0" ];
            matchOverride.ingress.extra = [
              (dsl.eq dsl.fields.meta.mark 256)
              (dsl.eq dsl.fields.meta.cgroup 100)
            ];
          };
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkExtraSectionFields — iif in extra fires =====

  testCheckExtraSectionFieldsIifWarns = {
    expr =
      let
        warnings =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneMembership
              checkExtraSectionFields
            ]
            {
              zones.lan.matchOverride.ingress.extra = [ (dsl.eq dsl.fields.meta.iif "lo") ];
            }
          ).warnings;
      in
      {
        count = lib.length warnings;
        path = lib.any (
          w:
          w.path == [
            "zones"
            "lan"
            "matchOverride"
            "ingress"
            "extra"
            "0"
          ]
        ) warnings;
        field = lib.any (w: lib.hasInfix "meta.iif" w.message) warnings;
        recommendsInterfaces = lib.any (
          w: lib.hasInfix "matchOverride.ingress.interfaces" w.message
        ) warnings;
      };
    expected = {
      count = 1;
      path = true;
      field = true;
      recommendsInterfaces = true;
    };
  };

  # ===== checkExtraSectionFields — oifname in extra fires =====

  testCheckExtraSectionFieldsOifWarns = {
    expr =
      let
        warnings =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneMembership
              checkExtraSectionFields
            ]
            {
              zones.wan.matchOverride.egress.extra = [ (dsl.eq dsl.fields.meta.oifname "wan0") ];
            }
          ).warnings;
      in
      {
        count = lib.length warnings;
        field = lib.any (w: lib.hasInfix "meta.oifname" w.message) warnings;
      };
    expected = {
      count = 1;
      field = true;
    };
  };

  # ===== checkExtraSectionFields — both sides aggregate =====

  testCheckExtraSectionFieldsBothSidesAggregate = {
    expr =
      lib.length
        (runEvalPipeline
          [
            convertNodesToZones
            computeZoneMembership
            checkExtraSectionFields
          ]
          {
            zones.lan = {
              matchOverride.ingress.extra = [ (dsl.eq dsl.fields.meta.iif "lan0") ];
              matchOverride.egress.extra = [ (dsl.eq dsl.fields.meta.oif "lan0") ];
            };
          }
        ).warnings;
    expected = 2;
  };

  # ===== checkExtraSectionFields — warnings aggregate across zones =====

  testCheckExtraSectionFieldsMultipleZones = {
    expr =
      let
        warnings =
          (runEvalPipeline
            [
              convertNodesToZones
              computeZoneMembership
              checkExtraSectionFields
            ]
            {
              zones = {
                lan.matchOverride.ingress.extra = [
                  (dsl.eq dsl.fields.meta.iifname "lan0")
                ];
                wan.matchOverride.egress.extra = [
                  (dsl.eq dsl.fields.meta.oifname "wan0")
                ];
              };
            }
          ).warnings;
      in
      {
        count = lib.length warnings;
        lan = lib.any (
          w:
          lib.take 5 w.path == [
            "zones"
            "lan"
            "matchOverride"
            "ingress"
            "extra"
          ]
        ) warnings;
        wan = lib.any (
          w:
          lib.take 5 w.path == [
            "zones"
            "wan"
            "matchOverride"
            "egress"
            "extra"
          ]
        ) warnings;
      };
    expected = {
      count = 2;
      lan = true;
      wan = true;
    };
  };

  # ===== checkExtraSectionFields — iif in interfaces section not flagged =====

  testCheckExtraSectionFieldsInterfacesSectionNotFlagged = {
    # The whole point: the `interfaces` section is the *right*
    # place for iif/oif clauses. Hook-gating happens there, so
    # this validator should ignore them.
    expr =
      (runEvalPipeline
        [
          convertNodesToZones
          computeZoneMembership
          checkExtraSectionFields
        ]
        {
          zones.lan.matchOverride.ingress.interfaces = [
            (dsl.eq dsl.fields.meta.iifname "lan0")
          ];
        }
      ).warnings;
    expected = [ ];
  };

  # ===== checkWildcardZoneMix — wildcard-only direction is fine =====

  testCheckWildcardZoneMixCleanWildcard = {
    expr =
      (runEvalPipeline [ checkWildcardZoneMix ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        policies.deny-all = {
          from = [ "all" ];
          to = [ "wan" ];
          verdict = "drop";
        };
      }).warnings;
    expected = [ ];
  };

  # ===== checkWildcardZoneMix — wildcard + explicit zone fires =====

  testCheckWildcardZoneMixFires = {
    expr =
      let
        warnings =
          (runEvalPipeline [ checkWildcardZoneMix ] {
            zones.lan.interfaces = [ "lan0" ];
            zones.wan.interfaces = [ "wan0" ];
            policies.confused = {
              from = [
                "all"
                "wan"
              ];
              to = [ "lan" ];
              verdict = "drop";
            };
          }).warnings;
      in
      {
        count = lib.length warnings;
        mentionsPath = lib.any (
          w:
          w.path == [
            "policies"
            "confused"
            "from"
          ]
        ) warnings;
        mentionsWildcard = lib.any (w: lib.hasInfix "'all'" w.message) warnings;
        mentionsExplicit = lib.any (w: lib.hasInfix "'wan'" w.message) warnings;
      };
    expected = {
      count = 1;
      mentionsPath = true;
      mentionsWildcard = true;
      mentionsExplicit = true;
    };
  };

  # ===== checkWildcardZoneMix — fires across multiple groups + directions =====

  testCheckWildcardZoneMixMultiple = {
    expr =
      lib.length
        (runEvalPipeline [ checkWildcardZoneMix ] {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.f = {
            from = [
              "all"
              "lan"
            ];
            to = [
              "all"
              "wan"
            ];
            rule = [ ];
          };
          dnats.d = {
            from = [
              "all"
              "wan"
            ];
            rule = {
              match = [ ];
              action.dnat = {
                addr = "10.0.0.5";
                port = 443;
              };
            };
          };
        }).warnings;
    # filters.f.from + filters.f.to + dnats.d.from = 3 warnings.
    expected = 3;
  };

  # ===== checkWildcardZoneMix — pure explicit list (no wildcard) is fine =====

  testCheckWildcardZoneMixExplicitOnly = {
    expr =
      (runEvalPipeline [ checkWildcardZoneMix ] {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        policies.allow = {
          from = [
            "lan"
            "wan"
          ];
          to = [ "wan" ];
          verdict = "accept";
        };
      }).warnings;
    expected = [ ];
  };
}
