/*
  Unit tests for `lib/internal/dispatch.nix` (exposed as
  `nftzones.internal.dispatch`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (pkgs) lib;

  inherit (nftzones.internal.dispatch) dispatchAndSort;
  inherit (nftzones.internal.expand) expandTable;
  inherit (nftzones.internal.normalize) normalizeTable;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;

  /*
    Run Phase 1 + Phase 2 + Phase 3 against an evalModules-produced
    table and return the final `ctx`. Tests inspect
    `ctx.dispatchTrees`.
  */
  runDispatch =
    body:
    (lib.pipe (evalTable body) [
      normalizeTable
      expandTable
      dispatchAndSort
    ]).ctx;

  cellNames = map (cell: cell.name);
in
{
  # ===== dispatchAndSort — empty cells =====

  testDispatchEmpty = {
    expr = (runDispatch { name = "fw"; }).dispatchTrees;
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
          }).dispatchTrees."input-at-filter";
      in
      {
        inherit (bucket) hook priority;
        subChainNames = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "input";
      priority = "filter";
      subChainNames = [ "input-at-filter__wan-TO-local" ];
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
          }).dispatchTrees."output-at-filter";
      in
      {
        inherit (bucket) hook priority;
        subChainNames = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "output";
      priority = "filter";
      subChainNames = [ "output-at-filter__local-TO-wan" ];
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
          }).dispatchTrees."forward-at-filter";
      in
      {
        inherit (bucket) hook priority;
        subChainNames = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "forward";
      priority = "filter";
      subChainNames = [ "forward-at-filter__lan-TO-wan" ];
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
          }).dispatchTrees."postrouting-at-srcnat";
      in
      {
        inherit (bucket) hook priority;
        subChainNames = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "postrouting";
      priority = "srcnat";
      subChainNames = [ "postrouting-at-srcnat__lan-TO-wan" ];
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
          }).dispatchTrees."prerouting-at-dstnat";
        subChain = bucket.subChains."prerouting-at-dstnat__wan";
      in
      {
        inherit (bucket) hook priority;
        subChainNames = lib.attrNames bucket.subChains;
        subFields = {
          inherit (subChain) from;
          hasTo = subChain ? to;
          # Default priority (500) → postChildCells.
          preChildCount = builtins.length subChain.preChildCells;
          postChildCount = builtins.length subChain.postChildCells;
        };
      };
    expected = {
      hook = "prerouting";
      priority = "dstnat";
      subChainNames = [ "prerouting-at-dstnat__wan" ];
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
          }).dispatchTrees."output-at-mangle";
        subChain = bucket.subChains."output-at-mangle__vpn";
      in
      {
        inherit (bucket) hook priority;
        subFields = {
          inherit (subChain) to;
          hasFrom = subChain ? from;
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
          }).dispatchTrees."prerouting-at-raw";
      in
      {
        inherit (bucket) hook priority;
        subChainNames = lib.attrNames bucket.subChains;
      };
    expected = {
      hook = "prerouting";
      priority = "raw";
      subChainNames = [ "prerouting-at-raw__wan-TO-local" ];
    };
  };

  # ===== dispatchAndSort — int priority on chain override collapses
  # into the same bucket as the symbol-form default =====

  testDispatchIntPriorityCanonicalizes = {
    # `chain.priority = 0` is the int form of `"filter"`; the
    # default filter dispatch uses the symbol. Both must land in
    # `"input-at-filter"` — otherwise nftables would see two
    # base chains at the same `(hook, priority)` slot under
    # different names.
    expr =
      let
        buckets =
          (runDispatch {
            name = "fw";
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters = {
              default-form = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
              };
              int-override = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
                chain = {
                  hook = "input";
                  priority = 0;
                };
              };
            };
          }).dispatchTrees;
      in
      {
        bucketKeys = lib.attrNames buckets;
        subNames = lib.attrNames buckets."input-at-filter".subChains;
      };
    expected = {
      bucketKeys = [ "input-at-filter" ];
      subNames = [ "input-at-filter__wan-TO-local" ];
    };
  };

  # ===== dispatchAndSort — pre-child priority (< 100) → preChildCells =====

  testDispatchPreChildSlot = {
    # priority `"first"` resolves to 1 < 100 → preChildCells.
    expr =
      let
        subChain =
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
          }).dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan";
      in
      {
        preChildNames = cellNames subChain.preChildCells;
        postChildNames = cellNames subChain.postChildCells;
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
        subChain =
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
          }).dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan";
      in
      {
        preChildNames = cellNames subChain.preChildCells;
        postChildNames = cellNames subChain.postChildCells;
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
        subChain =
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
          }).dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan";
      in
      {
        preChildNames = cellNames subChain.preChildCells;
        postChildNames = cellNames subChain.postChildCells;
      };
    expected = {
      preChildNames = [ ];
      postChildNames = [ "regular" ];
    };
  };

  # ===== dispatchAndSort — sort by (priority, name) within postChildCells =====

  testDispatchSortOrder = {
    expr =
      cellNames
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
        }).dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan".postChildCells;
    # Sorted by priority asc, name asc within priority.
    expected = [
      "high"
      "alpha"
      "zebra"
    ];
  };

  # ===== dispatchAndSort — filter + policy: the policy sorts last =====

  testDispatchPolicyAtEnd = {
    expr =
      cellNames
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
        }).dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan".postChildCells;
    # Filter first (has priority); policy last (tail rule).
    expected = [
      "allow-https"
      "lan-to-wan"
    ];
  };

  # ===== dispatchAndSort — same (from, to) in two groups → two chains =====

  testDispatchGroupSeparation = {
    # snat lan→wan and filter lan→wan share their zones but belong
    # to different chains; they must not merge.
    expr =
      let
        ctx = runDispatch {
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
        filterChainSubs = lib.attrNames ctx.dispatchTrees."forward-at-filter".subChains;
        snatChainSubs = lib.attrNames ctx.dispatchTrees."postrouting-at-srcnat".subChains;
        filterCellName =
          (builtins.head
            ctx.dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan".postChildCells
          ).name;
        snatCellName =
          (builtins.head
            ctx.dispatchTrees."postrouting-at-srcnat".subChains."postrouting-at-srcnat__lan-TO-wan".postChildCells
          ).name;
      };
    expected = {
      filterChainSubs = [ "forward-at-filter__lan-TO-wan" ];
      snatChainSubs = [ "postrouting-at-srcnat__lan-TO-wan" ];
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
        subChain =
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
          }).dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan";
      in
      lib.sort (a: b: a < b) (cellNames subChain.postChildCells);
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
        subChain =
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
          }).dispatchTrees."forward-at-filter".subChains."forward-at-filter__lan-TO-wan";
      in
      {
        preChildNames = cellNames subChain.preChildCells;
        postChildNames = cellNames subChain.postChildCells;
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
          }).dispatchTrees."forward-at-filter".subChains;
      in
      {
        keys = lib.sort (a: b: a < b) (lib.attrNames subChains);
        guestCellName = (builtins.head subChains."forward-at-filter__guest-TO-wan".postChildCells).name;
        lanCellName = (builtins.head subChains."forward-at-filter__lan-TO-wan".postChildCells).name;
      };
    expected = {
      keys = [
        "forward-at-filter__guest-TO-wan"
        "forward-at-filter__lan-TO-wan"
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
          }).dispatchTrees."forward-at-filter";
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

  # ===== dispatchAndSort — transparent dispatcher for a cell-less parent =====

  testDispatchTransparentDispatcher = {
    # web-server (node under dmz) has a cell; dmz has none. The
    # tree still holds a dmz sub-chain with empty slots, because
    # the base chain only jumps to root zones.
    expr =
      let
        tree =
          (runDispatch {
            name = "fw";
            zones.dmz.interfaces = [ "dmz0" ];
            nodes.web-server = {
              zone = "dmz";
              address.ipv4 = "10.0.0.5";
            };
            filters.allow-http = {
              from = [ "web-server" ];
              to = [ "local" ];
              rule = [ ];
            };
          }).dispatchTrees."input-at-filter";
        dispatcher = tree.subChains."input-at-filter__dmz-TO-local";
      in
      {
        subChainNames = lib.attrNames tree.subChains;
        inherit (dispatcher) from to;
        preChildCells = cellNames dispatcher.preChildCells;
        postChildCells = cellNames dispatcher.postChildCells;
      };
    expected = {
      subChainNames = [
        "input-at-filter__dmz-TO-local"
        "input-at-filter__web-server-TO-local"
      ];
      from = "dmz";
      to = "local";
      preChildCells = [ ];
      postChildCells = [ ];
    };
  };

  # ===== dispatchAndSort — roots: root from-zones, from-less sub-chains =====

  testDispatchRoots = {
    # dmz is a root; web-server (node under dmz) is reached only
    # through dmz's child-dispatch jump. A droute has no `from`,
    # so its sub-chain dispatches straight from the base chain.
    expr =
      let
        trees =
          (runDispatch {
            name = "fw";
            zones.dmz.interfaces = [ "dmz0" ];
            zones.wan.interfaces = [ "wan0" ];
            zones.vpn.cidrs = [ "10.8.0.0/24" ];
            nodes.web-server = {
              zone = "dmz";
              address.ipv4 = "10.0.0.5";
            };
            filters.dmz-out = {
              from = [ "dmz" ];
              to = [ "wan" ];
              rule = [ ];
            };
            filters.web-out = {
              from = [ "web-server" ];
              to = [ "wan" ];
              rule = [ ];
            };
            droutes.to-vpn = {
              to = [ "vpn" ];
              rule = [ ];
            };
          }).dispatchTrees;
      in
      {
        forward = trees."forward-at-filter".roots;
        droute = trees."output-at-mangle".roots;
      };
    expected = {
      forward = [ "forward-at-filter__dmz-TO-wan" ];
      droute = [ "output-at-mangle__vpn" ];
    };
  };

  # ===== dispatchAndSort — children are child sub-chains with content =====

  testDispatchChildren = {
    # dmz keeps its own cell and lists the children whose sub-chain
    # exists for the same to-zone, in lexical order. mail has no
    # cells, so dmz doesn't dispatch to it.
    expr =
      let
        tree =
          (runDispatch {
            name = "fw";
            zones.dmz.interfaces = [ "dmz0" ];
            nodes.db = {
              zone = "dmz";
              address.ipv4 = "10.0.0.6";
            };
            nodes.mail = {
              zone = "dmz";
              address.ipv4 = "10.0.0.7";
            };
            nodes.web-server = {
              zone = "dmz";
              address.ipv4 = "10.0.0.5";
            };
            filters.dmz-ssh = {
              from = [ "dmz" ];
              to = [ "local" ];
              rule = [ ];
            };
            filters.db-backup = {
              from = [ "db" ];
              to = [ "local" ];
              rule = [ ];
            };
            filters.web-http = {
              from = [ "web-server" ];
              to = [ "local" ];
              rule = [ ];
            };
          }).dispatchTrees."input-at-filter";
        dmz = tree.subChains."input-at-filter__dmz-TO-local";
      in
      {
        dmzChildren = dmz.children;
        dmzCells = cellNames dmz.postChildCells;
        webServerChildren = tree.subChains."input-at-filter__web-server-TO-local".children;
      };
    expected = {
      dmzChildren = [
        "input-at-filter__db-TO-local"
        "input-at-filter__web-server-TO-local"
      ];
      dmzCells = [ "dmz-ssh" ];
      webServerChildren = [ ];
    };
  };
}
