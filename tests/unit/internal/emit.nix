# Unit tests for `lib/internal/emit.nix` (exposed as
# `nftzones.internal.emit`). Same `testFoo = { expr; expected; }`
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
  inherit (nftzones.internal.emit)
    mkPerZoneSets
    chainTypeOf
    mkBaseChain
    mkBaseChains
    mkRuleBody
    mkSubChain
    mkSubChains
    mkDirectionVariants
    mkJumpRules
    mkUserObjects
    assembleTable
    emitTable
    ;
  inherit (nftypes.dsl) expr;

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
    Run Phase 1 → Phase 4 against an evalModules-produced table
    and return the final `ctx`. Tests inspect `ctx.output` (the
    `nftypes.dsl.table` value).
  */
  runEmit =
    body:
    (pkgs.lib.pipe (evalTable body) [
      normalizeTable
      expandTable
      dispatchAndSort
      emitTable
    ]).ctx;

  /*
    Test fixture: minimal `settings` attrset carrying just the
    fields `mkBaseChain` reads. Tests overlay what they care
    about.
  */
  defaultSettings = {
    stateful = true;
    loopback = true;
    rpfilter = false;
    chainPolicy = "drop";
  };

  /*
    Convenience wrapper: pin family to `"inet"` and default
    settings, with neutral defaults for the jump-related args
    (no sub-chains by default, so `baseChainName` / `zoneSets` are
    inert). Tests pass a `bucket` and optionally override the
    rest.
  */
  mkChain =
    {
      settings ? defaultSettings,
      bucket,
      baseChainName ? "test-chain",
      zoneSets ? { },
    }:
    mkBaseChain {
      family = "inet";
      inherit
        settings
        bucket
        baseChainName
        zoneSets
        ;
    };
in
{
  # ===== mkPerZoneSets — empty input =====

  testMkPerZoneSetsEmpty = {
    expr = mkPerZoneSets { };
    expected = { };
  };

  # ===== mkPerZoneSets — interfaces only =====

  testMkPerZoneSetsInterfacesOnly = {
    expr = mkPerZoneSets {
      lan = {
        interfaces = [
          "lan0"
          "lan1"
        ];
        cidrs = [ ];
      };
    };
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = [
          "lan0"
          "lan1"
        ];
      };
    };
  };

  # ===== mkPerZoneSets — v4 cidrs only =====

  testMkPerZoneSetsV4Only = {
    expr = mkPerZoneSets {
      lan = {
        interfaces = [ ];
        cidrs = [
          "10.0.0.0/24"
          "192.168.1.0/24"
        ];
      };
    };
    expected = {
      lan_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [
          (expr.prefix "10.0.0.0" 24)
          (expr.prefix "192.168.1.0" 24)
        ];
      };
    };
  };

  # ===== mkPerZoneSets — v6 cidrs only =====

  testMkPerZoneSetsV6Only = {
    expr = mkPerZoneSets {
      lan = {
        interfaces = [ ];
        cidrs = [ "2001:db8::/32" ];
      };
    };
    expected = {
      lan_v6 = {
        type = "ipv6_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "2001:db8::" 32) ];
      };
    };
  };

  # ===== mkPerZoneSets — interfaces + v4 + v6 (all three) =====

  testMkPerZoneSetsMixed = {
    expr = pkgs.lib.attrNames (mkPerZoneSets {
      lan = {
        interfaces = [ "eth0" ];
        cidrs = [
          "10.0.0.0/24"
          "fe80::/64"
        ];
      };
    });
    expected = [
      "lan_iifs"
      "lan_v4"
      "lan_v6"
    ];
  };

  # ===== mkPerZoneSets — multiple zones produce distinct keys =====

  testMkPerZoneSetsMultipleZones = {
    expr = pkgs.lib.attrNames (mkPerZoneSets {
      lan = {
        interfaces = [ "lan0" ];
        cidrs = [ ];
      };
      wan = {
        interfaces = [ ];
        cidrs = [ "0.0.0.0/0" ];
      };
      vpn = {
        interfaces = [ "wg0" ];
        cidrs = [ "fd00::/8" ];
      };
    });
    expected = [
      "lan_iifs"
      "vpn_iifs"
      "vpn_v6"
      "wan_v4"
    ];
  };

  # ===== emitTable — empty table assembles a table marker =====

  testEmitTableEmpty = {
    # No zones → output is a `nftypes.dsl.table` value with name +
    # family but no body. Marker presence proves dsl.table was used.
    expr =
      let
        out = (runEmit { }).output;
      in
      {
        inherit (out) family name;
        hasSets = out ? sets;
      };
    expected = {
      family = "inet";
      name = "fw";
      hasSets = false;
    };
  };

  # ===== emitTable — zones flow through to body.sets =====

  testEmitTableSetsFromZones = {
    expr =
      let
        out =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "eth1" ];
                cidrs = [ "10.0.0.0/24" ];
              };
              wan = {
                interfaces = [ "eth0" ];
              };
            };
          }).output;
      in
      pkgs.lib.attrNames out.sets;
    expected = [
      "lan_iifs"
      "lan_v4"
      "wan_iifs"
    ];
  };

  # ===== emitTable — lowered nodes contribute v4/v6 sets via cidrs =====

  testEmitTableNodeAddressBecomesSet = {
    # A node lowers to a zone with `cidrs = [ "<ipv4>/32" "<ipv6>/128" ]`.
    # Phase 4 should produce v4 and v6 sets containing those /32 and /128
    # prefixes.
    expr =
      let
        out =
          (runEmit {
            nodes.api = {
              zone = "dmz";
              address = {
                ipv4 = "10.0.0.5";
                ipv6 = "fe80::1";
              };
            };
            zones.dmz = {
              interfaces = [ "dmz0" ];
            };
          }).output;
        apiV4 = out.sets.api_v4;
        apiV6 = out.sets.api_v6;
      in
      {
        v4Type = apiV4.type;
        v4Elements = apiV4.elements;
        v6Type = apiV6.type;
        v6Elements = apiV6.elements;
      };
    expected = {
      v4Type = "ipv4_addr";
      v4Elements = [ (expr.prefix "10.0.0.5" 32) ];
      v6Type = "ipv6_addr";
      v6Elements = [ (expr.prefix "fe80::1" 128) ];
    };
  };

  # ===== emitTable — table.family propagates to output =====

  testEmitTableFamilyPropagates = {
    expr =
      ((runEmit {
        family = "ip";
      }).output
      ).family;
    expected = "ip";
  };

  # ===== assembleTable — thin wrapper around nftypes.dsl.table =====

  testAssembleTableShape = {
    # Pin the contract: `assembleTable { family; name; body; }`
    # equals `nftypes.dsl.table family name body`. Marker presence
    # + the four pass-through fields proves the wrapper isn't
    # reshaping anything.
    expr =
      let
        body = {
          sets = {
            x = {
              type = "ifname";
              elements = [ "lo" ];
            };
          };
        };
        out = assembleTable {
          family = "inet";
          name = "fw";
          inherit body;
        };
      in
      {
        inherit (out) family name;
        hasSets = out ? sets;
        sameAsDirect = out == nftypes.dsl.table "inet" "fw" body;
      };
    expected = {
      family = "inet";
      name = "fw";
      hasSets = true;
      sameAsDirect = true;
    };
  };

  # ===== chainTypeOf — filter (filter priority) =====

  testChainTypeOfFilter = {
    expr = chainTypeOf {
      hook = "forward";
      priority = "filter";
    };
    expected = "filter";
  };

  # ===== chainTypeOf — nat (srcnat / dstnat priorities) =====

  testChainTypeOfSrcnat = {
    expr = chainTypeOf {
      hook = "postrouting";
      priority = "srcnat";
    };
    expected = "nat";
  };

  testChainTypeOfDstnat = {
    expr = chainTypeOf {
      hook = "prerouting";
      priority = "dstnat";
    };
    expected = "nat";
  };

  # ===== chainTypeOf — route (mangle on prerouting / output) =====

  testChainTypeOfRouteOnPrerouting = {
    expr = chainTypeOf {
      hook = "prerouting";
      priority = "mangle";
    };
    expected = "route";
  };

  testChainTypeOfRouteOnOutput = {
    expr = chainTypeOf {
      hook = "output";
      priority = "mangle";
    };
    expected = "route";
  };

  # ===== chainTypeOf — mangle on non-route hook → filter =====

  testChainTypeOfMangleOnInput = {
    # Non-canonical placement; classify as filter (caller's
    # problem if they want type=route at input).
    expr = chainTypeOf {
      hook = "input";
      priority = "mangle";
    };
    expected = "filter";
  };

  # ===== chainTypeOf — chain override at raw priority → filter =====

  testChainTypeOfRpfilterOverride = {
    expr = chainTypeOf {
      hook = "prerouting";
      priority = "raw";
    };
    expected = "filter";
  };

  # ===== chainTypeOf — int priority resolves correctly =====

  testChainTypeOfIntSrcnat = {
    # priorityIntsDefault.srcnat == 100
    expr = chainTypeOf {
      hook = "postrouting";
      priority = 100;
    };
    expected = "nat";
  };

  # ===== mkBaseChain — filter input gets stateful + loopback =====

  testMkBaseChainFilterInput = {
    expr =
      let
        c = mkChain {
          bucket = {
            hook = "input";
            priority = "filter";
            preDispatch = [ ];
            subChains = { };
            postDispatch = [ ];
          };
        };
      in
      {
        inherit (c)
          type
          hook
          prio
          policy
          ;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "filter";
      hook = "input";
      prio = 0;
      policy = "drop";
      ruleCount = 3; # 2 stateful + 1 loopback
    };
  };

  # ===== mkBaseChain — filter forward: stateful only, no loopback =====

  testMkBaseChainFilterForward = {
    expr =
      let
        c = mkChain {
          bucket = {
            hook = "forward";
            priority = "filter";
            preDispatch = [ ];
            subChains = { };
            postDispatch = [ ];
          };
        };
      in
      {
        inherit (c) type hook;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "filter";
      hook = "forward";
      ruleCount = 2; # stateful only
    };
  };

  # ===== mkBaseChain — boilerplate disabled by settings =====

  testMkBaseChainBoilerplateDisabled = {
    expr =
      let
        c = mkChain {
          settings = defaultSettings // {
            stateful = false;
            loopback = false;
          };
          bucket = {
            hook = "input";
            priority = "filter";
            preDispatch = [ ];
            subChains = { };
            postDispatch = [ ];
          };
        };
      in
      builtins.length c.rules;
    expected = 0;
  };

  # ===== mkBaseChain — snat (type nat, no policy field) =====

  testMkBaseChainSnat = {
    expr =
      let
        c = mkChain {
          bucket = {
            hook = "postrouting";
            priority = "srcnat";
            preDispatch = [ ];
            subChains = { };
            postDispatch = [ ];
          };
        };
      in
      {
        inherit (c) type hook prio;
        hasPolicy = c ? policy;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "nat";
      hook = "postrouting";
      prio = 100;
      hasPolicy = false;
      ruleCount = 0;
    };
  };

  # ===== mkBaseChain — droute (type route) =====

  testMkBaseChainDroute = {
    expr =
      let
        c = mkChain {
          bucket = {
            hook = "output";
            priority = "mangle";
            preDispatch = [ ];
            subChains = { };
            postDispatch = [ ];
          };
        };
      in
      {
        inherit (c) type hook prio;
        hasPolicy = c ? policy;
      };
    expected = {
      type = "route";
      hook = "output";
      prio = -150;
      hasPolicy = false;
    };
  };

  # ===== mkBaseChain — rpfilter chain gets the fib drop rule =====

  testMkBaseChainRpfilter = {
    expr =
      let
        c = mkChain {
          settings = defaultSettings // {
            rpfilter = true;
          };
          bucket = {
            hook = "prerouting";
            priority = "raw";
            preDispatch = [ ];
            subChains = { };
            postDispatch = [ ];
          };
        };
      in
      {
        inherit (c) type hook prio;
        ruleCount = builtins.length c.rules;
      };
    expected = {
      type = "filter";
      hook = "prerouting";
      prio = -300;
      ruleCount = 1; # rpfilter rule only
    };
  };

  # ===== mkBaseChains — rpfilter synthesizes chain when absent =====

  testMkBaseChainsRpfilterSynthesized = {
    expr = builtins.attrNames (mkBaseChains {
      family = "inet";
      settings = defaultSettings // {
        rpfilter = true;
      };
      chainBuckets = { };
      zoneSets = { };
    });
    expected = [ "prerouting-at-raw" ];
  };

  # ===== mkBaseChains — rpfilter false produces no chains from empty =====

  testMkBaseChainsEmpty = {
    expr = mkBaseChains {
      family = "inet";
      settings = defaultSettings;
      chainBuckets = { };
      zoneSets = { };
    };
    expected = { };
  };

  # ===== emitTable — base chain + per-pair sub-chain land in output.chains =====

  testEmitTableHasChains = {
    expr = builtins.attrNames (
      (runEmit {
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
      }).output.chains
    );
    expected = [
      "forward-at-filter"
      "forward-at-filter__lan-to-wan"
    ];
  };

  # ===== emitTable — chain header carries type/hook/prio/policy =====

  testEmitTableChainHeader = {
    expr =
      let
        chain =
          (runEmit {
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
          }).output.chains.forward-at-filter;
      in
      {
        inherit (chain)
          type
          hook
          prio
          policy
          ;
      };
    expected = {
      type = "filter";
      hook = "forward";
      prio = 0;
      policy = "drop";
    };
  };

  # ===== emitTable — chain override flows to the right base chain =====

  testEmitTableChainOverride = {
    # A filter rule with `chain = { hook = "prerouting"; priority = "raw"; }`
    # should produce a `prerouting-at-raw` base chain at type=filter,
    # WITHOUT the `policy` field (raw is not the canonical filter
    # priority that gets the chain-level fallback).
    expr =
      let
        chains =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.rpfilter-rule = {
              from = [ "wan" ];
              to = [ "local" ];
              rule = [ ];
              chain = {
                hook = "prerouting";
                priority = "raw";
              };
            };
          }).output.chains;
        chain = chains.prerouting-at-raw;
      in
      {
        keys = builtins.attrNames chains;
        inherit (chain) type hook prio;
        hasPolicy = chain ? policy;
      };
    expected = {
      keys = [
        "prerouting-at-raw"
        "prerouting-at-raw__wan-to-local"
      ];
      type = "filter";
      hook = "prerouting";
      prio = -300;
      hasPolicy = false;
    };
  };

  # ===== emitTable — settings.rpfilter adds the rpfilter chain =====

  testEmitTableRpfilterEnabled = {
    expr =
      let
        chains =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            settings.rpfilter = true;
            filters.f = {
              from = [ "lan" ];
              to = [ "local" ];
              rule = [ ];
            };
          }).output.chains;
      in
      {
        keys = pkgs.lib.sort (a: b: a < b) (builtins.attrNames chains);
        rpfilterRuleCount = builtins.length chains.prerouting-at-raw.rules;
      };
    expected = {
      keys = [
        "input-at-filter"
        "input-at-filter__lan-to-local"
        "prerouting-at-raw"
      ];
      rpfilterRuleCount = 1;
    };
  };

  # ===== mkRuleBody — filter cell (rule already a list) =====

  testMkRuleBodyFilter = {
    expr = mkRuleBody {
      rule = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
        nftypes.dsl.accept
      ];
    };
    expected = [
      (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
      nftypes.dsl.accept
    ];
  };

  # ===== mkRuleBody — snat with address translation =====

  testMkRuleBodySnatAddr = {
    expr = mkRuleBody {
      rule.snat = {
        addr = "203.0.113.5";
        port = 8080;
      };
    };
    expected = [
      (nftypes.dsl.snat {
        addr = "203.0.113.5";
        port = 8080;
      })
    ];
  };

  # ===== mkRuleBody — snat masquerade =====

  testMkRuleBodySnatMasquerade = {
    expr = mkRuleBody {
      rule.masquerade = { };
    };
    expected = [ (nftypes.dsl.masquerade { }) ];
  };

  # ===== mkRuleBody — dnat (match clauses + dnat action) =====

  testMkRuleBodyDnat = {
    expr = mkRuleBody {
      rule = {
        match = [ (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 443) ];
        action.dnat = {
          addr = "10.0.0.5";
          port = 443;
        };
      };
    };
    expected = [
      (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 443)
      (nftypes.dsl.dnat {
        addr = "10.0.0.5";
        port = 443;
      })
    ];
  };

  # ===== mkRuleBody — dnat with redirect action =====

  testMkRuleBodyDnatRedirect = {
    expr = mkRuleBody {
      rule = {
        match = [ ];
        action.redirect = {
          port = 22;
        };
      };
    };
    expected = [ (nftypes.dsl.redirect { port = 22; }) ];
  };

  # ===== mkRuleBody — sroute / droute (rule is a list of mangle stmts) =====

  testMkRuleBodySroute = {
    # sroute and droute look identical to filter at this layer.
    expr = mkRuleBody {
      rule = [
        (nftypes.dsl.mangle nftypes.dsl.fields.meta.mark 100)
      ];
    };
    expected = [
      (nftypes.dsl.mangle nftypes.dsl.fields.meta.mark 100)
    ];
  };

  # ===== mkRuleBody — policy accept =====

  testMkRuleBodyPolicyAccept = {
    expr = mkRuleBody { verdict = "accept"; };
    expected = [ nftypes.dsl.accept ];
  };

  # ===== mkRuleBody — policy drop =====

  testMkRuleBodyPolicyDrop = {
    expr = mkRuleBody { verdict = "drop"; };
    expected = [ nftypes.dsl.drop ];
  };

  # ===== mkSubChain — produces a chain body with rules =====

  testMkSubChainSingleCell = {
    expr = mkSubChain [
      {
        rule = [ nftypes.dsl.accept ];
      }
    ];
    expected = {
      rules = [
        [ nftypes.dsl.accept ]
      ];
    };
  };

  # ===== mkSubChains — empty input =====

  testMkSubChainsEmpty = {
    expr = mkSubChains { };
    expected = { };
  };

  # ===== mkSubChains — bidirectional sub-chain naming =====

  testMkSubChainsBidirectional = {
    # Naming convention: <baseChainName>__<subChainKey>
    expr = builtins.attrNames (mkSubChains {
      "forward-at-filter" = {
        hook = "forward";
        priority = "filter";
        preDispatch = [ ];
        postDispatch = [ ];
        subChains = {
          "lan-to-wan" = {
            from = "lan";
            to = "wan";
            cells = [ { rule = [ nftypes.dsl.accept ]; } ];
          };
        };
      };
    });
    expected = [ "forward-at-filter__lan-to-wan" ];
  };

  # ===== mkSubChains — single-direction sub-chain (dnat-style) =====

  testMkSubChainsSingleDirection = {
    expr = builtins.attrNames (mkSubChains {
      "prerouting-at-dstnat" = {
        hook = "prerouting";
        priority = "dstnat";
        preDispatch = [ ];
        postDispatch = [ ];
        subChains = {
          "wan" = {
            from = "wan";
            cells = [ ];
          };
        };
      };
    });
    expected = [ "prerouting-at-dstnat__wan" ];
  };

  # ===== emitTable — sub-chain body contains the cell rule =====

  testEmitTableSubChainHasRule = {
    expr =
      let
        sub =
          (runEmit {
            zones = {
              lan = {
                interfaces = [ "lan0" ];
              };
              wan = {
                interfaces = [ "wan0" ];
              };
            };
            filters.allow = {
              from = [ "lan" ];
              to = [ "wan" ];
              rule = [ nftypes.dsl.accept ];
            };
          }).output.chains."forward-at-filter__lan-to-wan";
      in
      sub.rules;
    expected = [
      [ nftypes.dsl.accept ]
    ];
  };

  # ===== emitTable — preDispatch cells land in base chain, NOT sub-chain =====

  testEmitTablePreDispatchInBaseChain = {
    expr =
      let
        out =
          (runEmit {
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
              rule = [ nftypes.dsl.accept ];
              priority = "first";
            };
          }).output;
        baseChain = out.chains."forward-at-filter";
      in
      {
        # Expect the rule in base chain (after stateful prelude).
        baseRuleCount = builtins.length baseChain.rules;
        # Expect NO sub-chain (cell didn't go to subChains slot).
        hasSubChain = out.chains ? "forward-at-filter__lan-to-wan";
      };
    expected = {
      baseRuleCount = 3; # 2 stateful + 1 early (preDispatch slot)
      hasSubChain = false;
    };
  };

  # ===== emitTable — filter + policy in same pair: policy is tail rule =====

  testEmitTableFilterAndPolicyInSubChain = {
    # Phase 3 sorts cells with priority first, then policies (no
    # priority) appended as tail rules. Sub-chain body should
    # reflect that order.
    expr =
      let
        sub =
          (runEmit {
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
              rule = [ nftypes.dsl.accept ];
            };
            policies.lan-to-wan = {
              from = [ "lan" ];
              to = [ "wan" ];
              verdict = "drop";
            };
          }).output.chains."forward-at-filter__lan-to-wan";
      in
      {
        ruleCount = builtins.length sub.rules;
        # Last rule should be the policy verdict (drop).
        lastRuleStmt = builtins.head (builtins.elemAt sub.rules 1);
      };
    expected = {
      ruleCount = 2;
      lastRuleStmt = nftypes.dsl.drop;
    };
  };

  # ===== emitTable — snat masquerade lands in postrouting sub-chain =====

  testEmitTableSnatSubChain = {
    expr =
      let
        sub =
          (runEmit {
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
          }).output.chains."postrouting-at-srcnat__lan-to-wan";
      in
      sub.rules;
    expected = [
      [ (nftypes.dsl.masquerade { }) ]
    ];
  };

  # ===== mkDirectionVariants — localZone sentinel =====

  testMkDirectionVariantsLocalZone = {
    expr = mkDirectionVariants {
      hook = "input";
      direction = "to";
      zoneName = "local";
      zoneSets = { };
      localZone = "local";
    };
    expected = [ [ ] ];
  };

  # ===== mkDirectionVariants — null direction (single-direction sub-chain) =====

  testMkDirectionVariantsNullDirection = {
    expr = mkDirectionVariants {
      hook = "prerouting";
      direction = "to";
      zoneName = null;
      zoneSets = { };
      localZone = "local";
    };
    expected = [ [ ] ];
  };

  # ===== mkDirectionVariants — interface-only zone at hook with iif valid =====

  testMkDirectionVariantsInterfaceOnly = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "lan_iifs")) ]
    ];
  };

  # ===== mkDirectionVariants — iif unavailable + no addrs → empty =====

  testMkDirectionVariantsUnreachable = {
    # `output` hook makes `iifname` unavailable for `from` matching;
    # zone has no addr sets → no variants. Phase 1 should normally
    # catch this; defensive empty result causes the cartesian
    # product to drop the entire jump.
    expr = mkDirectionVariants {
      hook = "output";
      direction = "from";
      zoneName = "wan";
      zoneSets = {
        wan_iifs = {
          type = "ifname";
          elements = [ "wan0" ];
        };
      };
      localZone = "local";
    };
    expected = [ ];
  };

  # ===== mkDirectionVariants — v4 only =====

  testMkDirectionVariantsV4Only = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      zoneSets = {
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.set "lan_v4")) ]
    ];
  };

  # ===== mkDirectionVariants — v4 + v6 (one variant per family) =====

  testMkDirectionVariantsV4AndV6 = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      zoneSets = {
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
        lan_v6 = {
          type = "ipv6_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.set "lan_v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.set "lan_v6")) ]
    ];
  };

  # ===== mkDirectionVariants — iif + v4 + v6 (each variant carries iif prefix) =====

  testMkDirectionVariantsIfPlusV4V6 = {
    expr = mkDirectionVariants {
      hook = "forward";
      direction = "from";
      zoneName = "lan";
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
        lan_v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
        lan_v6 = {
          type = "ipv6_addr";
          flags = [ "interval" ];
          elements = [ ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.set "lan_v4"))
      ]
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.set "lan_v6"))
      ]
    ];
  };

  # ===== mkJumpRules — empty subChains =====

  testMkJumpRulesEmpty = {
    expr = mkJumpRules {
      hook = "forward";
      baseChainName = "forward-at-filter";
      subChains = { };
      zoneSets = { };
      localZone = "local";
    };
    expected = [ ];
  };

  # ===== mkJumpRules — bidirectional sub-chain produces one jump =====

  testMkJumpRulesBidirectional = {
    expr = mkJumpRules {
      hook = "forward";
      baseChainName = "forward-at-filter";
      subChains = {
        "lan-to-wan" = {
          from = "lan";
          to = "wan";
          cells = [ ];
        };
      };
      zoneSets = {
        lan_iifs = {
          type = "ifname";
          elements = [ "lan0" ];
        };
        wan_iifs = {
          type = "ifname";
          elements = [ "wan0" ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.oifname (nftypes.dsl.expr.set "wan_iifs"))
        (nftypes.dsl.jump "forward-at-filter__lan-to-wan")
      ]
    ];
  };

  # ===== mkJumpRules — single-direction sub-chain (dnat from-only) =====

  testMkJumpRulesSingleDirection = {
    expr = mkJumpRules {
      hook = "prerouting";
      baseChainName = "prerouting-at-dstnat";
      subChains = {
        "wan" = {
          from = "wan";
          cells = [ ];
        };
      };
      zoneSets = {
        wan_iifs = {
          type = "ifname";
          elements = [ "wan0" ];
        };
      };
      localZone = "local";
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "wan_iifs"))
        (nftypes.dsl.jump "prerouting-at-dstnat__wan")
      ]
    ];
  };

  # ===== mkJumpRules — cartesian product of multi-variant directions =====

  testMkJumpRulesCartesian = {
    # `lan` has v4 + v6, `wan` has v4 + v6 → 4 jump rules
    # (incl. 2 family-mismatched ones; harmless, see docstring).
    expr = builtins.length (mkJumpRules {
      hook = "forward";
      baseChainName = "forward-at-filter";
      subChains = {
        "lan-to-wan" = {
          from = "lan";
          to = "wan";
          cells = [ ];
        };
      };
      zoneSets = {
        lan_v4 = { };
        lan_v6 = { };
        wan_v4 = { };
        wan_v6 = { };
      };
      localZone = "local";
    });
    expected = 4;
  };

  # ===== emitTable — jump rule lands in base chain =====

  testEmitTableJumpRule = {
    expr =
      let
        out =
          (runEmit {
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
          }).output;
        baseRules = out.chains."forward-at-filter".rules;
        # Last rule should be the jump (after stateful boilerplate).
        jumpRule = builtins.elemAt baseRules 2;
      in
      jumpRule;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "lan_iifs"))
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.oifname (nftypes.dsl.expr.set "wan_iifs"))
      (nftypes.dsl.jump "forward-at-filter__lan-to-wan")
    ];
  };

  # ===== emitTable — dnat: from-side-only jump =====

  testEmitTableDnatJump = {
    expr =
      let
        out =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            dnats.fwd = {
              from = [ "wan" ];
              rule = {
                match = [ ];
                action.dnat = {
                  addr = "10.0.0.5";
                  port = 80;
                };
              };
            };
          }).output;
        baseRules = out.chains."prerouting-at-dstnat".rules;
      in
      builtins.head baseRules;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "wan_iifs"))
      (nftypes.dsl.jump "prerouting-at-dstnat__wan")
    ];
  };

  # ===== emitTable — filter to localZone: from-side-only jump =====

  testEmitTableJumpToLocalZone = {
    expr =
      let
        out =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.allow-ssh = {
              from = [ "wan" ];
              to = [ "local" ];
              rule = [ ];
            };
          }).output;
        # input chain: stateful (2) + loopback (1) + jump (1) = 4 rules
        baseRules = out.chains."input-at-filter".rules;
        jumpRule = builtins.elemAt baseRules 3;
      in
      jumpRule;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.set "wan_iifs"))
      (nftypes.dsl.jump "input-at-filter__wan-to-local")
    ];
  };

  # ===== emitTable — full base-chain rule order =====

  testEmitTableBaseChainRuleOrder = {
    # Rule order: stateful → loopback → preDispatch → jumps → postDispatch.
    # input chain with default + first + last priority cells:
    #   stateful (2) + loopback (1) + preDispatch (1) + jump (1) + postDispatch (1) = 6
    expr =
      let
        out =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters = {
              early = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
                priority = "first";
              };
              normal = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
                # default priority → subChains slot
              };
              late = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ ];
                priority = "last";
              };
            };
          }).output;
        baseRules = out.chains."input-at-filter".rules;
      in
      builtins.length baseRules;
    expected = 6;
  };

  # ===== mkUserObjects — identity passthrough =====

  testMkUserObjectsIdentity = {
    expr = mkUserObjects {
      counters.web = { };
      quotas = { };
    };
    expected = {
      counters.web = { };
      quotas = { };
    };
  };

  # ===== emitTable — empty table.objects → no extra body kinds =====

  testEmitTableEmptyObjects = {
    expr =
      let
        out =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
          }).output;
      in
      pkgs.lib.attrNames out;
    # `family` and `name` are always present; `sets` for the zone;
    # `__nftTable` is the marker added by `nftypes.dsl.table`. No
    # other body kinds because all 12 `table.objects.<kind>`
    # default to `{}` and are filtered out.
    expected = [
      "__nftTable"
      "family"
      "name"
      "sets"
    ];
  };

  # ===== emitTable — counter passes through to body.counters =====

  testEmitTableCounterPassthrough = {
    expr =
      let
        out =
          (runEmit {
            objects.counters.web-hits = { };
          }).output;
      in
      pkgs.lib.attrNames out.counters;
    # Counter body fields (`bytes` / `comment` / `packets`) come
    # from the type defaults; we only assert the entry shows up
    # under the right name.
    expected = [ "web-hits" ];
  };

  # ===== emitTable — multiple kinds flow through =====

  testEmitTableMultipleKinds = {
    expr =
      let
        out =
          (runEmit {
            objects = {
              counters.hits = { };
              quotas.bw = {
                bytes = 1000000;
              };
              ctHelpers.ftp = {
                type = "ftp";
                protocol = "tcp";
              };
            };
          }).output;
      in
      pkgs.lib.sort (a: b: a < b) (
        builtins.filter (
          k:
          builtins.elem k [
            "counters"
            "quotas"
            "ctHelpers"
          ]
        ) (pkgs.lib.attrNames out)
      );
    expected = [
      "counters"
      "ctHelpers"
      "quotas"
    ];
  };

  # ===== emitTable — user-defined set merges with zone sets =====

  testEmitTableUserSetMergesWithZoneSets = {
    expr =
      let
        out =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            objects.sets.blocklist_v4 = {
              type = "ipv4_addr";
              flags = [ "interval" ];
            };
          }).output;
      in
      pkgs.lib.sort (a: b: a < b) (pkgs.lib.attrNames out.sets);
    # Both zone-generated and user-defined sets share `body.sets`.
    expected = [
      "blocklist_v4"
      "lan_iifs"
    ];
  };

  # ===== emitTable — empty user-object kinds are skipped =====

  testEmitTableEmptyKindsSkipped = {
    # `objects.counters = {}` (default) shouldn't add a `counters`
    # field to the output body.
    expr =
      let
        out =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            # all 12 kinds default to {}
          }).output;
      in
      builtins.any (k: builtins.elem k (pkgs.lib.attrNames out)) [
        "counters"
        "quotas"
        "limits"
        "ctHelpers"
        "ctTimeouts"
        "ctExpectations"
        "secmarks"
        "synproxies"
        "tunnels"
        "maps"
        "flowtables"
      ];
    expected = false;
  };
}
