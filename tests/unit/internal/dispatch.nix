/*
  Unit tests for `lib/internal/dispatch.nix` (exposed as
  `nftzones.internal.dispatch`). Same `testFoo = { expr; expected; }`
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
  inherit (nftzones.internal.dispatch) dispatchAndSort;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;

  /*
    Run Phase 1 + Phase 2 + Phase 3 against an evalModules-produced
    table and return the final `ctx`. Tests inspect
    `ctx.chainBuckets`.
  */
  runDispatch =
    body:
    (pkgs.lib.pipe (evalTable body) [
      normalizeTable
      expandTable
      dispatchAndSort
    ]).ctx;

  inherit (pkgs) lib;

  # Helpers for inspecting the new sub-chain shape.
  cellNames = cells: map (c: c.name) cells;
  allCellNames = sub: cellNames sub.preChildCells ++ cellNames sub.postChildCells;
in
{
  # ===== dispatchAndSort — empty cells =====

  testDispatchEmpty = {
    expr = (runDispatch { name = "fw"; }).chainBuckets;
    expected = { };
  };

  # ===== dispatchAndSort — filter to localZone → input chain =====

  testDispatchFilterToLocal = {
    expr =
      let
        bucket =
          (runDispatch {
            name = "fw";
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.allow-ssh = {
              from = [ "wan" ];
              to = [ "local" ];
              rule = [ ];
            };
          }).chainBuckets."input-at-filter";
      in
      {
        inherit (bucket) hook priority;
        subChainKeys = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "input";
      priority = "filter";
      subChainKeys = [ "wan-to-local" ];
    };
  };

  # ===== dispatchAndSort — filter from localZone → output chain =====

  testDispatchFilterFromLocal = {
    expr =
      let
        bucket =
          (runDispatch {
            name = "fw";
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.outbound = {
              from = [ "local" ];
              to = [ "wan" ];
              rule = [ ];
            };
          }).chainBuckets."output-at-filter";
      in
      {
        inherit (bucket) hook priority;
        subChainKeys = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "output";
      priority = "filter";
      subChainKeys = [ "local-to-wan" ];
    };
  };

  # ===== dispatchAndSort — filter neither side localZone → forward chain =====

  testDispatchFilterForward = {
    expr =
      let
        bucket =
          (runDispatch {
            name = "fw";
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.web-out = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
            };
          }).chainBuckets."forward-at-filter";
      in
      {
        inherit (bucket) hook priority;
        subChainKeys = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "forward";
      priority = "filter";
      subChainKeys = [ "lan-to-wan" ];
    };
  };

  # ===== dispatchAndSort — snat → postrouting@srcnat =====

  testDispatchSnat = {
    expr =
      let
        bucket =
          (runDispatch {
            name = "fw";
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            snats.lan-out = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule.masquerade = { };
            };
          }).chainBuckets."postrouting-at-srcnat";
      in
      {
        inherit (bucket) hook priority;
        subChainKeys = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "postrouting";
      priority = "srcnat";
      subChainKeys = [ "lan-to-wan" ];
    };
  };

  # ===== dispatchAndSort — dnat (single-direction `from`) =====

  testDispatchDnat = {
    expr =
      let
        bucket =
          (runDispatch {
            name = "fw";
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            dnats.web-fwd = {
              from = [ "wan" ];
              rule = {
                match = [ ];
                action.dnat = {
                  addr = "10.0.0.5";
                  port = 80;
                };
              };
            };
          }).chainBuckets."prerouting-at-dstnat";
        sub = bucket.subChains.wan;
      in
      {
        inherit (bucket) hook priority;
        subChainKeys = lib.attrNames bucket.subChains;
        subFields = {
          inherit (sub) from;
          hasTo = sub ? to;
          # Default priority (500) → postChildCells.
          preChildCount = builtins.length sub.preChildCells;
          postChildCount = builtins.length sub.postChildCells;
        };
      };
    expected = {
      hook = "prerouting";
      priority = "dstnat";
      subChainKeys = [ "wan" ];
      subFields = {
        from = "wan";
        hasTo = false;
        preChildCount = 0;
        postChildCount = 1;
      };
    };
  };

  # ===== dispatchAndSort — droute (single-direction `to`) =====

  testDispatchDroute = {
    expr =
      let
        bucket =
          (runDispatch {
            name = "fw";
            zones.vpn = {
              interfaces = [ "vpn0" ];
            };
            droutes.mark-vpn = {
              to = [ "vpn" ];
              rule = [ ];
            };
          }).chainBuckets."output-at-mangle";
        sub = bucket.subChains.vpn;
      in
      {
        inherit (bucket) hook priority;
        subFields = {
          inherit (sub) to;
          hasFrom = sub ? from;
        };
      };
    expected = {
      hook = "output";
      priority = "mangle";
      subFields = {
        to = "vpn";
        hasFrom = false;
      };
    };
  };

  # ===== dispatchAndSort — chain override → synthesized chain key =====

  testDispatchChainOverride = {
    expr =
      let
        bucket =
          (runDispatch {
            name = "fw";
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.rpfilter = {
              from = [ "wan" ];
              to = [ "local" ];
              rule = [ ];
              chain = {
                hook = "prerouting";
                priority = "raw";
              };
            };
          }).chainBuckets."prerouting-at-raw";
      in
      {
        inherit (bucket) hook priority;
        subChainKeys = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "prerouting";
      priority = "raw";
      subChainKeys = [ "wan-to-local" ];
    };
  };

  # ===== dispatchAndSort — pre-child priority (< 100) → preChildCells =====

  testDispatchPreChildSlot = {
    # priority `"first"` resolves to 1 < 100 → preChildCells.
    expr =
      let
        sub =
          (runDispatch {
            name = "fw";
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.early = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
              priority = "first";
            };
          }).chainBuckets."forward-at-filter".subChains."lan-to-wan";
      in
      {
        preChildNames = cellNames sub.preChildCells;
        postChildNames = cellNames sub.postChildCells;
      };
    expected = {
      preChildNames = [ "early" ];
      postChildNames = [ ];
    };
  };

  # ===== dispatchAndSort — post-child priority (>= 100) → postChildCells =====

  testDispatchPostChildSlot = {
    # priority `"last"` resolves to 999 >= 100 → postChildCells.
    expr =
      let
        sub =
          (runDispatch {
            name = "fw";
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.late = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
              priority = "last";
            };
          }).chainBuckets."forward-at-filter".subChains."lan-to-wan";
      in
      {
        preChildNames = cellNames sub.preChildCells;
        postChildNames = cellNames sub.postChildCells;
      };
    expected = {
      preChildNames = [ ];
      postChildNames = [ "late" ];
    };
  };

  # ===== dispatchAndSort — default priority (500) → postChildCells =====

  testDispatchDefaultSlot = {
    # Default priority (500) lands in postChildCells — the natural
    # parent-fallback slot.
    expr =
      let
        sub =
          (runDispatch {
            name = "fw";
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.regular = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
            };
          }).chainBuckets."forward-at-filter".subChains."lan-to-wan";
      in
      {
        preChildNames = cellNames sub.preChildCells;
        postChildNames = cellNames sub.postChildCells;
      };
    expected = {
      preChildNames = [ ];
      postChildNames = [ "regular" ];
    };
  };

  # ===== dispatchAndSort — sort by (priority, name) within postChildCells =====

  testDispatchSortOrder = {
    expr = cellNames (
      (runDispatch {
        name = "fw";
        zones = {
          lan = {
            interfaces = [ "lan0" ];
          };
          wan = {
            interfaces = [ "wan0" ];
          };
        };
        filters = {
          # All same (from, to) → same sub-chain. Different
          # priorities and names test the sort order.
          zebra = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
            priority = 500;
          };
          alpha = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
            priority = 500;
          };
          high = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
            priority = 200;
          };
        };
      }).chainBuckets."forward-at-filter".subChains."lan-to-wan".postChildCells
    );
    # Sorted by priority asc, name asc within priority.
    expected = [
      "high"
      "alpha"
      "zebra"
    ];
  };

  # ===== dispatchAndSort — filter + policy: policies sort to end of postChildCells =====

  testDispatchPolicyAtEnd = {
    expr = cellNames (
      (runDispatch {
        name = "fw";
        zones = {
          lan = {
            interfaces = [ "lan0" ];
          };
          wan = {
            interfaces = [ "wan0" ];
          };
        };
        filters.allow-https = {
          from = [ "lan" ];
          to = [ "wan" ];
          rule = [ ];
        };
        policies.lan-to-wan = {
          from = [ "lan" ];
          to = [ "wan" ];
          verdict = "drop";
        };
      }).chainBuckets."forward-at-filter".subChains."lan-to-wan".postChildCells
    );
    # Filter first (has priority); policy last (tail rule).
    expected = [
      "allow-https"
      "lan-to-wan"
    ];
  };

  # ===== dispatchAndSort — same (from, to) different groups land in different chains =====

  testDispatchGroupSeparation = {
    # snat lan→wan and filter lan→wan share a sub-chain key but
    # belong to different chains; they must not merge.
    expr =
      let
        out = runDispatch {
          name = "fw";
          zones = {
            lan = {
              interfaces = [ "lan0" ];
            };
            wan = {
              interfaces = [ "wan0" ];
            };
          };
          filters.web = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule = [ ];
          };
          snats.lan-out = {
            from = [ "lan" ];
            to = [ "wan" ];
            rule.masquerade = { };
          };
        };
      in
      {
        filterChainSubs = lib.attrNames out.chainBuckets."forward-at-filter".subChains;
        snatChainSubs = lib.attrNames out.chainBuckets."postrouting-at-srcnat".subChains;
        filterCellName =
          (builtins.head out.chainBuckets."forward-at-filter".subChains."lan-to-wan".postChildCells).name;
        snatCellName =
          (builtins.head out.chainBuckets."postrouting-at-srcnat".subChains."lan-to-wan".postChildCells).name;
      };
    expected = {
      filterChainSubs = [ "lan-to-wan" ];
      snatChainSubs = [ "lan-to-wan" ];
      filterCellName = "web";
      snatCellName = "lan-out";
    };
  };

  # ===== dispatchAndSort — chain override + default land in same bucket =====
  # An explicit chain override like `{ hook = "forward"; priority =
  # "filter"; }` must merge into the existing default-chain bucket
  # rather than creating a duplicate. Documented in dispatch.nix.

  testDispatchOverrideMergesWithDefault = {
    expr =
      let
        sub =
          (runDispatch {
            name = "fw";
            zones = {
              lan.interfaces = [ "lan0" ];
              wan.interfaces = [ "wan0" ];
            };
            filters = {
              # Default for lan→wan: forward@filter.
              regular = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
              };
              # Explicit override for the same chain coordinates.
              override = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
                chain = {
                  hook = "forward";
                  priority = "filter";
                };
              };
            };
          }).chainBuckets."forward-at-filter".subChains."lan-to-wan";
      in
      lib.sort (a: b: a < b) (cellNames sub.postChildCells);
    expected = [
      "override"
      "regular"
    ];
  };

  # ===== dispatchAndSort — pre + post sub-slots populate independently =====
  # One sub-chain receives one cell per sub-slot. Verifies the cells
  # split correctly inside `subChainOf`.

  testDispatchPreAndPostChildSplit = {
    expr =
      let
        sub =
          (runDispatch {
            name = "fw";
            zones = {
              lan.interfaces = [ "lan0" ];
              wan.interfaces = [ "wan0" ];
            };
            filters = {
              early = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
                priority = "preDispatch";
              };
              regular = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
              };
              late = {
                from = [ "lan" ];
                to = [ "wan" ];
                rule = [ ];
                priority = "last";
              };
            };
          }).chainBuckets."forward-at-filter".subChains."lan-to-wan";
      in
      {
        preChildNames = cellNames sub.preChildCells;
        postChildNames = cellNames sub.postChildCells;
      };
    expected = {
      # priority preDispatch (50) < 100 → preChildCells.
      preChildNames = [ "early" ];
      # priority default (500) and last (999) >= 100 → postChildCells,
      # sorted ascending: regular (500), late (999).
      postChildNames = [
        "regular"
        "late"
      ];
    };
  };

  # ===== dispatchAndSort — policy fan-out spans multiple sub-chains =====
  # One policy with `from = [ "lan" "guest" ]; to = [ "wan" ]` must
  # land in two distinct sub-chains, both as tail rules.

  testDispatchPolicyFanOut = {
    expr =
      let
        subChains =
          (runDispatch {
            name = "fw";
            zones = {
              lan.interfaces = [ "lan0" ];
              guest.interfaces = [ "guest0" ];
              wan.interfaces = [ "wan0" ];
            };
            policies.deny-out = {
              from = [
                "lan"
                "guest"
              ];
              to = [ "wan" ];
              verdict = "drop";
            };
          }).chainBuckets."forward-at-filter".subChains;
      in
      {
        keys = lib.sort (a: b: a < b) (lib.attrNames subChains);
        guestCellName = (builtins.head subChains."guest-to-wan".postChildCells).name;
        lanCellName = (builtins.head subChains."lan-to-wan".postChildCells).name;
      };
    expected = {
      keys = [
        "guest-to-wan"
        "lan-to-wan"
      ];
      guestCellName = "deny-out";
      lanCellName = "deny-out";
    };
  };

  # ===== dispatchAndSort — bucket carries hook + priority as fields =====

  testDispatchBucketFields = {
    # Verify Phase 4 doesn't have to parse the chain key — the
    # bucket exposes hook and priority directly.
    expr =
      let
        bucket =
          (runDispatch {
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
          }).chainBuckets."forward-at-filter";
      in
      {
        inherit (bucket) hook priority;
        hasSubChains = bucket ? subChains;
        # Base chain no longer carries pre/post slots — every cell
        # lives in a sub-chain now.
        hasPreDispatch = bucket ? preDispatch;
        hasPostDispatch = bucket ? postDispatch;
      };
    expected = {
      hook = "forward";
      priority = "filter";
      hasSubChains = true;
      hasPreDispatch = false;
      hasPostDispatch = false;
    };
  };
}
