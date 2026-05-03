# Unit tests for `lib/internal/dispatch.nix` (exposed as
# `nftzones.internal.dispatch`). Same `testFoo = { expr; expected; }`
# shape as every other unit test; aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
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
              rule = {
                match = [ ];
                action.masquerade = null;
              };
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
          cellCount = builtins.length sub.cells;
        };
      };
    expected = {
      hook = "prerouting";
      priority = "dstnat";
      subChainKeys = [ "wan" ];
      subFields = {
        from = "wan";
        hasTo = false;
        cellCount = 1;
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

  # ===== dispatchAndSort — pre-dispatch priority → preDispatch slot =====

  testDispatchPreDispatchSlot = {
    # priority `"first"` resolves to 1 → preDispatch.
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
            filters.early = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
              priority = "first";
            };
          }).chainBuckets."forward-at-filter";
      in
      {
        preDispatchCount = builtins.length bucket.preDispatch;
        subChainsCount = builtins.length (lib.attrNames bucket.subChains);
        postDispatchCount = builtins.length bucket.postDispatch;
        firstName = (builtins.head bucket.preDispatch).name;
      };
    expected = {
      preDispatchCount = 1;
      subChainsCount = 0;
      postDispatchCount = 0;
      firstName = "early";
    };
  };

  # ===== dispatchAndSort — post-dispatch priority → postDispatch slot =====

  testDispatchPostDispatchSlot = {
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
            filters.late = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
              priority = "last";
            };
          }).chainBuckets."forward-at-filter";
      in
      {
        preDispatchCount = builtins.length bucket.preDispatch;
        subChainsCount = builtins.length (lib.attrNames bucket.subChains);
        postDispatchCount = builtins.length bucket.postDispatch;
        lastName = (builtins.head bucket.postDispatch).name;
      };
    expected = {
      preDispatchCount = 0;
      subChainsCount = 0;
      postDispatchCount = 1;
      lastName = "late";
    };
  };

  # ===== dispatchAndSort — default priority → subChains slot =====

  testDispatchDefaultSlot = {
    # No explicit priority → default ("default" = 500) → subChains.
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
            filters.regular = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ ];
            };
          }).chainBuckets."forward-at-filter";
      in
      {
        preDispatchCount = builtins.length bucket.preDispatch;
        subChainsCount = builtins.length (lib.attrNames bucket.subChains);
        postDispatchCount = builtins.length bucket.postDispatch;
      };
    expected = {
      preDispatchCount = 0;
      subChainsCount = 1;
      postDispatchCount = 0;
    };
  };

  # ===== dispatchAndSort — sort by (priority, name) =====

  testDispatchSortOrder = {
    expr = map (c: c.name) (
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
      }).chainBuckets."forward-at-filter".subChains."lan-to-wan".cells
    );
    # Sorted by priority asc, name asc within priority.
    expected = [
      "high"
      "alpha"
      "zebra"
    ];
  };

  # ===== dispatchAndSort — filter + policy: policies sort to end =====

  testDispatchPolicyAtEnd = {
    expr = map (c: c.name) (
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
      }).chainBuckets."forward-at-filter".subChains."lan-to-wan".cells
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
            rule = {
              match = [ ];
              action.masquerade = null;
            };
          };
        };
      in
      {
        filterChainSubs = lib.attrNames out.chainBuckets."forward-at-filter".subChains;
        snatChainSubs = lib.attrNames out.chainBuckets."postrouting-at-srcnat".subChains;
        filterCellName =
          (builtins.head out.chainBuckets."forward-at-filter".subChains."lan-to-wan".cells).name;
        snatCellName =
          (builtins.head out.chainBuckets."postrouting-at-srcnat".subChains."lan-to-wan".cells).name;
      };
    expected = {
      filterChainSubs = [ "lan-to-wan" ];
      snatChainSubs = [ "lan-to-wan" ];
      filterCellName = "web";
      snatCellName = "lan-out";
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
        hasPreDispatch = bucket ? preDispatch;
        hasSubChains = bucket ? subChains;
        hasPostDispatch = bucket ? postDispatch;
      };
    expected = {
      hook = "forward";
      priority = "filter";
      hasPreDispatch = true;
      hasSubChains = true;
      hasPostDispatch = true;
    };
  };
}
