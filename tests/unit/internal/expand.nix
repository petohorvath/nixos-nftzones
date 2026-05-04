/*
  Unit tests for `lib/internal/expand.nix` (exposed as
  `nftzones.internal.expand`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.normalize) normalizeTable;
  inherit (nftzones.internal.expand) expandTable;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;

  runExpand = body: (expandTable (normalizeTable (evalTable body))).ctx;
in
{
  # ===== expandTable — empty groups =====

  testExpandEmpty = {
    expr = (runExpand { name = "fw"; }).cells;
    expected = {
      filters = [ ];
      policies = [ ];
      snats = [ ];
      dnats = [ ];
      sroutes = [ ];
      droutes = [ ];
    };
  };

  # ===== expandTable — bidirectional cartesian product =====

  testExpandBidirectional = {
    # `from = [ "lan" "guest" ]` × `to = [ "wan" "vpn" ]` → 4 cells.
    expr = map (c: { inherit (c) from to name; }) (
      (runExpand {
        name = "fw";
        zones = {
          lan = {
            interfaces = [ "lan0" ];
          };
          guest = {
            interfaces = [ "guest0" ];
          };
          wan = {
            interfaces = [ "wan0" ];
          };
          vpn = {
            interfaces = [ "vpn0" ];
          };
        };
        filters.web-out = {
          from = [
            "lan"
            "guest"
          ];
          to = [
            "wan"
            "vpn"
          ];
          rule = [ ];
        };
      }).cells.filters
    );
    expected = [
      {
        from = "lan";
        to = "wan";
        name = "web-out";
      }
      {
        from = "lan";
        to = "vpn";
        name = "web-out";
      }
      {
        from = "guest";
        to = "wan";
        name = "web-out";
      }
      {
        from = "guest";
        to = "vpn";
        name = "web-out";
      }
    ];
  };

  # ===== expandTable — wildcard expansion flows through =====

  testExpandWildcard = {
    # `from = [ "all" ]` resolves to declared zones + localZone, so
    # 3 from-values × 1 to-value = 3 cells.
    expr = pkgs.lib.sort (a: b: a < b) (
      map (c: c.from) (
        (runExpand {
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
            from = [ "all" ];
            to = [ "wan" ];
            rule = [ ];
          };
        }).cells.filters
      )
    );
    expected = [
      "lan"
      "local"
      "wan"
    ];
  };

  # ===== expandTable — single-direction kinds =====

  testExpandSingleDirection = {
    expr =
      let
        out = runExpand {
          name = "fw";
          zones = {
            wan = {
              interfaces = [ "wan0" ];
            };
            lan = {
              interfaces = [ "lan0" ];
            };
          };
          dnats.fwd = {
            from = [
              "wan"
              "lan"
            ];
            rule = {
              match = [ ];
              action.dnat = {
                addr = "10.0.0.5";
                port = 80;
              };
            };
          };
          droutes.mark = {
            to = [
              "wan"
              "lan"
            ];
            rule = [ ];
          };
        };
      in
      {
        # dnats: cells have `from` only, no `to`
        dnatHasFrom = builtins.all (c: c ? from && !(c ? to)) out.cells.dnats;
        dnatFroms = pkgs.lib.sort (a: b: a < b) (map (c: c.from) out.cells.dnats);
        # droutes: cells have `to` only, no `from`
        drouteHasTo = builtins.all (c: c ? to && !(c ? from)) out.cells.droutes;
        drouteTos = pkgs.lib.sort (a: b: a < b) (map (c: c.to) out.cells.droutes);
      };
    expected = {
      dnatHasFrom = true;
      dnatFroms = [
        "lan"
        "wan"
      ];
      drouteHasTo = true;
      drouteTos = [
        "lan"
        "wan"
      ];
    };
  };

  # ===== expandTable — body fields preserved on cells =====

  testExpandBodyPreserved = {
    expr =
      let
        cell =
          builtins.head
            (runExpand {
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
                comment = "preserved";
                priority = "first";
              };
            }).cells.filters;
      in
      {
        inherit (cell) name comment priority;
        ruleIsList = builtins.isList cell.rule;
      };
    expected = {
      name = "f";
      comment = "preserved";
      priority = 1; # "first" symbol resolved via Phase 1's resolvePriorities
      ruleIsList = true;
    };
  };

  # ===== expandTable — policy cells lack priority =====

  testExpandPoliciesNoPriority = {
    expr =
      let
        cell =
          builtins.head
            (runExpand {
              name = "fw";
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
                verdict = "accept";
              };
            }).cells.policies;
      in
      {
        hasPriority = cell ? priority;
        verdict = cell.verdict;
      };
    expected = {
      hasPriority = false;
      verdict = "accept";
    };
  };

  # ===== expandTable — original table left untouched =====

  testExpandTableUntouched = {
    expr =
      let
        out = expandTable (
          normalizeTable (evalTable {
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
              from = [ "all" ];
              to = [ "wan" ];
              rule = [ ];
            };
          })
        );
      in
      {
        # Original from is the wildcard "all", not the expanded list
        originalFrom = out.table.filters.f.from;
        # Expanded cells use concrete zone names
        cellFroms = pkgs.lib.sort (a: b: a < b) (map (c: c.from) out.ctx.cells.filters);
      };
    expected = {
      originalFrom = [ "all" ];
      cellFroms = [
        "lan"
        "local"
        "wan"
      ];
    };
  };
}
