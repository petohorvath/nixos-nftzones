/*
  Unit tests for `lib/internal/compile.nix` (exposed as
  `nftzones.internal.compile`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  helpers,
  lib,
  nftypes,
  nftzones,
  ...
}:
let
  inherit (nftzones.internal.compile)
    compile
    mkRuleset
    mkTable
    ;

  inherit (helpers) evalTable;

  inherit (nftypes.dsl) accept eq;
  inherit (nftypes.dsl.fields) tcp;

  /*
    The jump rules of one chain of a compiled `inet fw` table with
    `lan` and `wan` interface zones, as nftables text without the
    `add rule inet fw <chain>` prefix. The regression in #54 was a
    jump with no match in front of it.
  */
  chainJumps =
    chain: body:
    let
      prefix = "add rule inet fw ${chain} ";
      lines = lib.splitString "\n" (
        nftypes.toText (
          mkRuleset (
            evalTable (
              {
                zones = {
                  lan.interfaces = [ "lan0" ];
                  wan.interfaces = [ "wan0" ];
                };
              }
              // body
            )
          )
        )
      );
    in
    map (lib.removePrefix prefix) (
      builtins.filter (line: lib.hasPrefix prefix line && lib.hasInfix " jump " line) lines
    );

  # The chain names of the same compiled table, sorted.
  chainNames =
    body:
    lib.sort (a: b: a < b) (
      builtins.attrNames
        (mkTable (
          evalTable (
            {
              zones = {
                lan.interfaces = [ "lan0" ];
                wan.interfaces = [ "wan0" ];
              };
            }
            // body
          )
        )).chains
    );
in
{
  # ===== compile — runs all four phases, ctx carries every artifact =====

  testCompileFullCtx = {
    # The exact key set and the type of each value: a regression that
    # dropped a key, leaked a scratch key, or set, e.g., `cells` to a
    # list fails here. Content is exercised by the per-phase tests in
    # `tests/unit/internal/<phase>.nix`.
    expr =
      builtins.mapAttrs (_: builtins.typeOf)
        (compile (evalTable {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        })).ctx;
    expected = {
      # Phase 1 artifacts
      expandedGroups = "set";
      resolvedPriorities = "set";
      zoneMembership = "set";
      # Phase 2 artifact
      cells = "set";
      # Phase 3 artifacts
      groupedByChain = "set";
      dispatchTrees = "set";
      # Phase 4 artifacts
      baseChains = "set";
      subChains = "set";
      userObjects = "set";
      output = "set";
    };
  };

  # ===== compile — Phase 1 errors propagate as a thrown message =====

  testCompileThrowsOnPhase1Error = {
    # `from = [ "missing" ]` references an unknown zone — Phase 1
    # reports `zoneRefUnknown`; `normalizeTable` aggregates errors
    # and throws.
    expr =
      let
        attempt = builtins.tryEval (
          compile (evalTable {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            filters.f = {
              from = [ "missing" ];
              to = [ "lan" ];
              rule = [ accept ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };

  # ===== mkTable — extracts ctx.output =====

  testMkTableExtractsOutput = {
    # The output is a `nftypes.dsl.table` value, which carries a
    # marker attribute. Family + name must propagate from the
    # input table.
    expr =
      let
        table = mkTable (evalTable {
          family = "ip";
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        });
      in
      {
        inherit (table) family name;
        hasMarker = table._type or null == "nix-nftypes.tableTree";
      };
    expected = {
      family = "ip";
      name = "fw";
      hasMarker = true;
    };
  };

  # ===== mkRuleset — wraps mkTable's output in a ruleset envelope =====

  testMkRulesetWrapsTable = {
    # `nftypes.dsl.ruleset` produces the canonical
    # `{ nftables = [ <commands>... ]; }` shape. The first command
    # in our case is the `add table` for our compiled table.
    expr =
      let
        ruleset = mkRuleset (evalTable {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        });
        firstCommand = builtins.head ruleset.nftables;
      in
      {
        hasNftables = ruleset ? nftables;
        nftablesIsList = builtins.isList ruleset.nftables;
        firstIsAddTable = firstCommand ? add && firstCommand.add ? table;
      };
    expected = {
      hasNftables = true;
      nftablesIsList = true;
      firstIsAddTable = true;
    };
  };

  # ===== mkRuleset — JSON output contains a table command =====

  testMkRulesetJSONShape = {
    # End-to-end: the produced ruleset, when rendered, must yield
    # the canonical `{ nftables = [ ... ] }` shape with at least
    # one `add table` command.
    expr =
      let
        json = builtins.fromJSON (
          nftypes.toJson (
            mkRuleset (evalTable {
              zones.lan = {
                interfaces = [ "lan0" ];
              };
            })
          )
        );
        firstCommand = builtins.head json.nftables;
      in
      {
        hasNftables = json ? nftables;
        firstIsAddTable = firstCommand ? add && firstCommand.add ? table;
        firstTableName = firstCommand.add.table.name;
        firstTableFamily = firstCommand.add.table.family;
      };
    expected = {
      hasNftables = true;
      firstIsAddTable = true;
      firstTableName = "fw";
      firstTableFamily = "inet";
    };
  };

  # ===== Public API — nftzones.mkTable name body =====

  testPublicMkTableAcceptsRawBody = {
    # The lib/default.nix wrapper does `evalModules` internally so
    # users can pass an unevaluated body straight in. Name is a
    # separate positional arg (mirrors `nftypes.dsl.table`).
    expr =
      let
        table = nftzones.mkTable "fw" {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        };
      in
      {
        inherit (table) family name;
      };
    expected = {
      family = "inet";
      name = "fw";
    };
  };

  # ===== Public API — name argument flows through to output =====

  testPublicMkTableUsesArgName = {
    # The user's `name` arg is the authoritative on-wire table name:
    # it becomes the evalModules option key (so the table's
    # `default = name` derives it) and the boundary then overrides any
    # `name` the body carried with it, so the emitted table name
    # always equals the arg.
    expr = (nftzones.mkTable "production-fw" { }).name;
    expected = "production-fw";
  };

  # ===== Public API — nftzones.mkRuleset name body =====

  testPublicMkRulesetAcceptsRawBody = {
    expr =
      let
        ruleset = nftzones.mkRuleset "fw" {
          zones.lan = {
            interfaces = [ "lan0" ];
          };
        };
      in
      {
        hasNftables = ruleset ? nftables;
        commandCount = builtins.length ruleset.nftables;
      };
    # 2 commands: 1 table declaration + 1 set declaration for lan_iifs.
    expected = {
      hasNftables = true;
      commandCount = 2;
    };
  };

  # ===== Multi-table composition — two mkTable values in one ruleset =====
  # The README documents `dsl.ruleset [ tableA tableB ]` as the
  # multi-table path. Verify both tables appear in the rendered
  # output with their declared families intact.

  testMkTableMultiTableComposition = {
    expr =
      let
        v4 = nftzones.mkTable "fw-v4" {
          family = "ip";
          zones.lan.interfaces = [ "lan0" ];
        };
        v6 = nftzones.mkTable "fw-v6" {
          family = "ip6";
          zones.lan.interfaces = [ "lan0" ];
        };
        ruleset = nftypes.dsl.ruleset [
          v4
          v6
        ];
        json = builtins.fromJSON (nftypes.toJson ruleset);
        tableCommands = builtins.filter (command: command ? add && command.add ? table) json.nftables;
        tableTuples = map (command: {
          inherit (command.add.table) family name;
        }) tableCommands;
      in
      lib.sort (a: b: a.name < b.name) tableTuples;
    expected = [
      {
        name = "fw-v4";
        family = "ip";
      }
      {
        name = "fw-v6";
        family = "ip6";
      }
    ];
  };

  # ===== mkRuleset — chain commands appear when there are filter rules =====
  # The "2 commands" counted in `testPublicMkRulesetAcceptsRawBody`
  # is the empty case. With actual rules, the ruleset must also emit
  # add-chain commands per base + sub-chain. This catches a regression
  # where chain wiring drops out of the ruleset.

  testMkRulesetEmitsChainCommands = {
    expr =
      let
        json = builtins.fromJSON (
          nftypes.toJson (
            nftzones.mkRuleset "fw" {
              zones = {
                lan.interfaces = [ "lan0" ];
                wan.interfaces = [ "wan0" ];
              };
              filters.f = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ nftypes.dsl.accept ];
              };
            }
          )
        );
      in
      lib.sort (a: b: a < b) (
        map (command: command.add.chain.name) (
          builtins.filter (command: command ? add && command.add ? chain) json.nftables
        )
      );
    expected = [
      "forward-at-filter"
      "forward-at-filter__lan-TO-wan"
    ];
  };

  # ===== local zone — host-only matches (#54, ADR-0013) =====

  # Prerouting never sees the host's own packets, so `all` leaves the
  # local zone out instead of jumping on every packet.
  testLocalZoneWildcardSkipsLocalAtPrerouting = {
    expr =
      let
        body = {
          dnats.fwd = {
            from = [ "all" ];
            rule = {
              match = [ (eq tcp.dport 8443) ];
              action.dnat = {
                addr = "10.0.0.5";
                port = 443;
              };
            };
          };
        };
      in
      {
        jumps = chainJumps "prerouting-at-dstnat" body;
        chains = chainNames body;
      };
    expected = {
      jumps = [
        "meta iifname == @lan_iifs jump prerouting-at-dstnat__lan"
        "meta iifname == @wan_iifs jump prerouting-at-dstnat__wan"
      ];
      chains = [
        "prerouting-at-dstnat"
        "prerouting-at-dstnat__lan"
        "prerouting-at-dstnat__wan"
      ];
    };
  };

  # The issue's first reproduction: a rule for the host talking to
  # itself opened the port on every interface at input. The cell
  # stays at input but matches only loopback traffic.
  testLocalZoneLocalToLocalMatchesLoopback = {
    expr =
      let
        body = {
          # With the loopback rule on, Phase 1 warns that this
          # entry's only cell never fires (`localToLocalShadowed`).
          settings.loopback = false;
          filters.selfonly = {
            from = [ "local" ];
            to = [ "local" ];
            rule = [
              (eq tcp.dport 8080)
              accept
            ];
          };
        };
      in
      {
        input = chainJumps "input-at-filter" body;
        output = chainJumps "output-at-filter" body;
      };
    expected = {
      input = [ "meta iif == lo jump input-at-filter__local-TO-local" ];
      output = [ ];
    };
  };

  # Traffic on an interface outside every zone no longer reaches a
  # wildcard source at input, and the local cell creates no output
  # chain.
  testLocalZoneWildcardSourceToLocal = {
    expr =
      let
        body = {
          policies.inbound = {
            from = [ "all" ];
            to = [ "local" ];
            verdict = "accept";
          };
        };
      in
      {
        input = chainJumps "input-at-filter" body;
        output = chainJumps "output-at-filter" body;
      };
    expected = {
      input = [
        "meta iifname == @lan_iifs jump input-at-filter__lan-TO-local"
        "meta iif == lo jump input-at-filter__local-TO-local"
        "meta iifname == @wan_iifs jump input-at-filter__wan-TO-local"
      ];
      output = [ ];
    };
  };

  # A local source at postrouting masquerades only the host's own
  # packets, not forwarded ones.
  testLocalZoneSourceAtPostrouting = {
    expr = chainJumps "postrouting-at-srcnat" {
      snats.host-out = {
        from = [ "local" ];
        to = [ "wan" ];
        rule.action.masquerade = { };
      };
    };
    expected = [
      "meta iif == 0 meta oifname == @wan_iifs jump postrouting-at-srcnat__local-TO-wan"
    ];
  };

  # A local destination at output marks only the host's traffic to
  # itself.
  testLocalZoneDestinationAtOutput = {
    expr = chainJumps "output-at-mangle" {
      droutes.self = {
        to = [ "local" ];
        rule = [ (nftypes.dsl.mangle nftypes.dsl.fields.meta.mark 100) ];
      };
    };
    expected = [
      "fib daddr type == local jump output-at-mangle__local"
    ];
  };

  # A wildcard in a bridge table drops the local-to-local cell, whose
  # source cannot match at input there, instead of emitting it.
  testLocalZoneWildcardInBridge = {
    expr = chainNames {
      family = "bridge";
      filters.anywhere = {
        from = [ "all" ];
        to = [ "local" ];
        rule = [ accept ];
      };
    };
    expected = [
      "input-at-filter"
      "input-at-filter__lan-TO-local"
      "input-at-filter__wan-TO-local"
    ];
  };

  # The remaining rows of ADR-0013's table: a local source at output
  # needs no match, and a local destination outside input matches
  # the host's addresses — at prerouting through a `chain` override,
  # and at postrouting through a wildcard snat's local cell.
  testLocalZoneSourceAtOutputNeedsNoMatch = {
    expr = chainJumps "output-at-filter" {
      filters.out = {
        from = [ "local" ];
        to = [ "wan" ];
        rule = [ accept ];
      };
    };
    expected = [ "meta oifname == @wan_iifs jump output-at-filter__local-TO-wan" ];
  };

  testLocalZoneDestinationAtPrerouting = {
    expr = chainJumps "prerouting-at-raw" {
      filters.early = {
        from = [ "wan" ];
        to = [ "local" ];
        chain = {
          hook = "prerouting";
          priority = "raw";
        };
        rule = [ accept ];
      };
    };
    expected = [
      "meta iifname == @wan_iifs fib daddr type == local jump prerouting-at-raw__wan-TO-local"
    ];
  };

  testLocalZoneWildcardDestinationAtPostrouting = {
    expr = chainJumps "postrouting-at-srcnat" {
      snats.masq = {
        from = [ "lan" ];
        to = [ "all" ];
        rule.action.masquerade = { };
      };
    };
    expected = [
      "meta iifname == @lan_iifs meta oifname == @lan_iifs jump postrouting-at-srcnat__lan-TO-lan"
      "meta iifname == @lan_iifs fib daddr type == local jump postrouting-at-srcnat__lan-TO-local"
      "meta iifname == @lan_iifs meta oifname == @wan_iifs jump postrouting-at-srcnat__lan-TO-wan"
    ];
  };
}
