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
    # reports `invalidZoneRef`; `normalizeTable` aggregates errors
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
              rule = [ ];
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
        hasMarker = table ? __nftTable;
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
                rule = [ ];
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
}
