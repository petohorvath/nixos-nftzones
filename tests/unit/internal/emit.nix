/*
  Unit tests for `lib/internal/emit.nix` (exposed as
  `nftzones.internal.emit`). Same `testFoo = { expr; expected; }`
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

  inherit (nftypes.dsl) accept expr mangle;
  inherit (nftypes.dsl.fields) meta;
  inherit (nftzones.internal.dispatch) dispatchAndSort;
  inherit (nftzones.internal.emit)
    assembleTable
    emitTable
    mkBaseChain
    mkBaseChains
    mkRootJumpRules
    mkRuleBody
    mkSubChain
    mkSubChains
    ;
  inherit (nftzones.internal.expand) expandTable;
  inherit (nftzones.internal.normalize) normalizeTable;

  inherit (helpers) evalTable membershipFor;

  /*
    Run Phase 1 → Phase 4 against an evalModules-produced table
    and return the final `ctx`. Tests inspect `ctx.output` (the
    `nftypes.dsl.table` value).
  */
  runEmit =
    body:
    (lib.pipe (evalTable body) [
      normalizeTable
      expandTable
      dispatchAndSort
      emitTable
    ]).ctx;

  # Minimal `settings` carrying just the fields `mkBaseChain` reads.
  # Tests overlay what they care about.
  defaultSettings = {
    stateful = true;
    loopback = true;
    rpfilter = false;
    chainPolicy = "drop";
    localZone = "local";
  };

  # Convenience wrapper: pin family to `"inet"` and default settings.
  # With no sub-chains in the tree, `zoneMembership` is inert. Tests
  # pass a `tree` and optionally override the rest.
  mkChain =
    {
      settings ? defaultSettings,
      tree,
      zoneMembership ? membershipFor { },
    }:
    mkBaseChain {
      family = "inet";
      inherit
        settings
        tree
        zoneMembership
        ;
    };

  emptyTree = hook: priority: {
    inherit hook priority;
    roots = [ ];
    subChains = { };
  };
in
{
  # ===== emitTable — empty table assembles a table marker =====

  testEmitTableEmpty = {
    expr =
      let
        output = (runEmit { }).output;
      in
      {
        inherit (output) family name;
        hasSets = output ? sets;
        hasFlags = output ? flags;
        hasComment = output ? comment;
      };
    expected = {
      family = "inet";
      name = "fw";
      hasSets = false;
      hasFlags = false;
      hasComment = false;
    };
  };

  # ===== emitTable — non-empty table.flags surfaces on the output =====

  testEmitTableFlagsHonored = {
    expr = (runEmit { flags = [ "dormant" ]; }).output.flags;
    expected = [ "dormant" ];
  };

  # ===== emitTable — non-null table.comment surfaces on the output =====

  testEmitTableCommentHonored = {
    expr = (runEmit { comment = "main firewall"; }).output.comment;
    expected = "main firewall";
  };

  # ===== emitTable — zones flow through to body.sets =====

  testEmitTableSetsFromZones = {
    expr =
      let
        output =
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
      lib.attrNames output.sets;
    expected = [
      "lan_iifs"
      "lan_v4"
      "wan_iifs"
    ];
  };

  # ===== emitTable — lowered nodes contribute v4/v6 sets via cidrs =====

  testEmitTableNodeAddressBecomesSet = {
    expr =
      let
        output =
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
        apiV4 = output.sets.api_v4;
        apiV6 = output.sets.api_v6;
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
      (runEmit {
        family = "ip";
      }).output.family;
    expected = "ip";
  };

  # ===== assembleTable — thin wrapper around nftypes.dsl.table =====

  testAssembleTableShape = {
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
        table = assembleTable {
          family = "inet";
          name = "fw";
          inherit body;
        };
      in
      {
        inherit (table) family name;
        hasSets = table ? sets;
        sameAsDirect = table == nftypes.dsl.table "inet" "fw" body;
      };
    expected = {
      family = "inet";
      name = "fw";
      hasSets = true;
      sameAsDirect = true;
    };
  };

  # Chain type derivation belongs to
  # `nftypes.compatibility.chainTypeFor`; tests for it live with
  # the upstream helper. End-to-end coverage of the consumer path
  # comes from the scenario tests.

  # ===== mkBaseChain — filter input gets stateful + loopback =====

  testMkBaseChainFilterInput = {
    expr =
      let
        chain = mkChain { tree = emptyTree "input" "filter"; };
      in
      {
        inherit (chain)
          hook
          policy
          prio
          type
          ;
        ruleCount = builtins.length chain.rules;
      };
    expected = {
      type = "filter";
      hook = "input";
      prio = 0;
      policy = "drop";
      ruleCount = 3; # 2 stateful + 1 loopback
    };
  };

  testMkBaseChainFilterForward = {
    expr =
      let
        chain = mkChain { tree = emptyTree "forward" "filter"; };
      in
      {
        inherit (chain) hook type;
        ruleCount = builtins.length chain.rules;
      };
    expected = {
      type = "filter";
      hook = "forward";
      ruleCount = 2; # stateful only
    };
  };

  testMkBaseChainBoilerplateDisabled = {
    expr =
      let
        chain = mkChain {
          settings = defaultSettings // {
            stateful = false;
            loopback = false;
          };
          tree = emptyTree "input" "filter";
        };
      in
      builtins.length chain.rules;
    expected = 0;
  };

  testMkBaseChainSnat = {
    expr =
      let
        chain = mkChain { tree = emptyTree "postrouting" "srcnat"; };
      in
      {
        inherit (chain) hook prio type;
        hasPolicy = chain ? policy;
        ruleCount = builtins.length chain.rules;
      };
    expected = {
      type = "nat";
      hook = "postrouting";
      prio = 100;
      hasPolicy = false;
      ruleCount = 0;
    };
  };

  testMkBaseChainSymbolOutsideHookResolvesToInt = {
    # nftzones names priorities per family; nftypes accepts `srcnat`
    # only at input and postrouting. Emitting the int keeps an
    # output-hook srcnat chain loadable.
    expr =
      let
        chain = mkChain { tree = emptyTree "output" "srcnat"; };
      in
      {
        inherit (chain) hook prio type;
      };
    expected = {
      type = "nat";
      hook = "output";
      prio = 100;
    };
  };

  testMkBaseChainSroute = {
    # `type route` is output-only per nftypes' hooksByChainType;
    # sroute (prerouting + mangle) compiles as a regular filter
    # chain that does mangle ops. The mark-set still happens; the
    # routing-table re-evaluation that `type route` would trigger
    # is meaningless at prerouting (no routing decision yet).
    expr =
      let
        chain = mkChain { tree = emptyTree "prerouting" "mangle"; };
      in
      {
        inherit (chain) hook prio type;
        hasPolicy = chain ? policy;
      };
    expected = {
      type = "filter";
      hook = "prerouting";
      prio = -150;
      hasPolicy = false;
    };
  };

  testMkBaseChainDnat = {
    expr =
      let
        chain = mkChain { tree = emptyTree "prerouting" "dstnat"; };
      in
      {
        inherit (chain) hook prio type;
        hasPolicy = chain ? policy;
      };
    expected = {
      type = "nat";
      hook = "prerouting";
      prio = -100;
      hasPolicy = false;
    };
  };

  testMkBaseChainDroute = {
    expr =
      let
        chain = mkChain { tree = emptyTree "output" "mangle"; };
      in
      {
        inherit (chain) hook prio type;
        hasPolicy = chain ? policy;
      };
    expected = {
      type = "route";
      hook = "output";
      prio = -150;
      hasPolicy = false;
    };
  };

  # `mkBaseChain` does not attach the rpfilter rule itself —
  # the synthesized chain in `mkBaseChains` carries it instead.
  # A user override at (prerouting, raw) gets only the standard
  # boilerplate + jump rules, never the rpfilter `fib` drop.
  testMkBaseChainNoRpfilterPrelude = {
    expr =
      let
        chain = mkChain {
          settings = defaultSettings // {
            rpfilter = true;
          };
          tree = emptyTree "prerouting" "raw";
        };
      in
      {
        inherit (chain) hook prio type;
        ruleCount = builtins.length chain.rules;
      };
    expected = {
      type = "filter";
      hook = "prerouting";
      prio = -300;
      ruleCount = 0;
    };
  };

  # ===== mkBaseChains — rpfilter synthesizes a dedicated chain =====

  testMkBaseChainsRpfilterSynthesized = {
    expr =
      let
        chains = mkBaseChains {
          family = "inet";
          settings = defaultSettings // {
            rpfilter = true;
          };
          dispatchTrees = { };
          zoneMembership = membershipFor { };
        };
        chain = chains."prerouting-at-raw";
      in
      {
        keys = builtins.attrNames chains;
        inherit (chain) hook prio type;
        ruleCount = builtins.length chain.rules;
      };
    expected = {
      keys = [ "prerouting-at-raw" ];
      type = "filter";
      hook = "prerouting";
      prio = -300;
      ruleCount = 1;
    };
  };

  # ===== mkBaseChains — override at (prerouting, raw) skips synthesis =====

  testMkBaseChainsRpfilterUserOverrideWins = {
    expr =
      let
        chains = mkBaseChains {
          family = "inet";
          settings = defaultSettings // {
            rpfilter = true;
          };
          dispatchTrees = {
            "prerouting-at-raw" = emptyTree "prerouting" "raw";
          };
          zoneMembership = membershipFor { };
        };
      in
      builtins.length chains."prerouting-at-raw".rules;
    # User chain runs through `mkBaseChain` only; with no
    # boilerplate-eligible settings + no zone jumps, the chain
    # is empty. Crucially, the rpfilter fib-drop is NOT injected.
    expected = 0;
  };

  testMkBaseChainsEmpty = {
    expr = mkBaseChains {
      family = "inet";
      settings = defaultSettings;
      dispatchTrees = { };
      zoneMembership = membershipFor { };
    };
    expected = { };
  };

  testMkBaseChainsPerTree = {
    expr = lib.sort (a: b: a < b) (
      builtins.attrNames (mkBaseChains {
        family = "inet";
        settings = defaultSettings;
        dispatchTrees = {
          "input-at-filter" = emptyTree "input" "filter";
          "forward-at-filter" = emptyTree "forward" "filter";
          "postrouting-at-srcnat" = emptyTree "postrouting" "srcnat";
        };
        zoneMembership = membershipFor { };
      })
    );
    expected = [
      "forward-at-filter"
      "input-at-filter"
      "postrouting-at-srcnat"
    ];
  };

  # ===== emitTable — base chain + pair sub-chain land in output.chains =====

  testEmitTableHasChains = {
    expr =
      builtins.attrNames
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
            rule = [ accept ];
          };
        }).output.chains;
    expected = [
      "forward-at-filter"
      "forward-at-filter__lan-TO-wan"
    ];
  };

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
              rule = [ accept ];
            };
          }).output.chains.forward-at-filter;
      in
      {
        inherit (chain)
          hook
          policy
          prio
          type
          ;
      };
    expected = {
      type = "filter";
      hook = "forward";
      prio = 0;
      policy = "drop";
    };
  };

  testEmitTableChainOverride = {
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
              rule = [ accept ];
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
        inherit (chain) hook prio type;
        hasPolicy = chain ? policy;
      };
    expected = {
      keys = [
        "prerouting-at-raw"
        "prerouting-at-raw__wan-TO-local"
      ];
      type = "filter";
      hook = "prerouting";
      prio = -300;
      hasPolicy = false;
    };
  };

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
              rule = [ accept ];
            };
          }).output.chains;
      in
      {
        keys = lib.sort (a: b: a < b) (builtins.attrNames chains);
        rpfilterRuleCount = builtins.length chains.prerouting-at-raw.rules;
      };
    expected = {
      keys = [
        "input-at-filter"
        "input-at-filter__lan-TO-local"
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
      comment = null;
    };
    expected = [
      (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
      nftypes.dsl.accept
    ];
  };

  testMkRuleBodySnatAddr = {
    expr = mkRuleBody {
      rule.snat = {
        addr = "203.0.113.5";
        port = 8080;
      };
      comment = null;
    };
    expected = [
      (nftypes.dsl.snat {
        addr = "203.0.113.5";
        port = 8080;
      })
    ];
  };

  testMkRuleBodySnatMasquerade = {
    expr = mkRuleBody {
      rule.masquerade = { };
      comment = null;
    };
    expected = [ (nftypes.dsl.masquerade { }) ];
  };

  testMkRuleBodyDnat = {
    expr = mkRuleBody {
      rule = {
        match = [ (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 443) ];
        action.dnat = {
          addr = "10.0.0.5";
          port = 443;
        };
      };
      comment = null;
    };
    expected = [
      (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 443)
      (nftypes.dsl.dnat {
        addr = "10.0.0.5";
        port = 443;
      })
    ];
  };

  testMkRuleBodyDnatRedirect = {
    expr = mkRuleBody {
      rule = {
        match = [ ];
        action.redirect = {
          port = 22;
        };
      };
      comment = null;
    };
    expected = [ (nftypes.dsl.redirect { port = 22; }) ];
  };

  testMkRuleBodySroute = {
    expr = mkRuleBody {
      rule = [
        (nftypes.dsl.mangle nftypes.dsl.fields.meta.mark 100)
      ];
      comment = null;
    };
    expected = [
      (nftypes.dsl.mangle nftypes.dsl.fields.meta.mark 100)
    ];
  };

  testMkRuleBodyPolicyAccept = {
    expr = mkRuleBody {
      verdict = "accept";
      comment = null;
    };
    expected = [ nftypes.dsl.accept ];
  };

  testMkRuleBodyPolicyDrop = {
    expr = mkRuleBody {
      verdict = "drop";
      comment = null;
    };
    expected = [ nftypes.dsl.drop ];
  };

  # ===== mkRuleBody — non-null comment wraps the statement list =====

  testMkRuleBodyFilterWithComment = {
    expr = mkRuleBody {
      rule = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
        nftypes.dsl.accept
      ];
      comment = "ssh from anywhere";
    };
    expected = {
      statements = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
        nftypes.dsl.accept
      ];
      comment = "ssh from anywhere";
    };
  };

  testMkRuleBodyPolicyWithComment = {
    expr = mkRuleBody {
      verdict = "accept";
      comment = "lan->wan default-allow";
    };
    expected = {
      statements = [ nftypes.dsl.accept ];
      comment = "lan->wan default-allow";
    };
  };

  testMkRuleBodySnatMasqueradeWithComment = {
    expr = mkRuleBody {
      rule.masquerade = { };
      comment = "nat lan to wan";
    };
    expected = {
      statements = [ (nftypes.dsl.masquerade { }) ];
      comment = "nat lan to wan";
    };
  };

  testMkRuleBodyDnatWithComment = {
    expr = mkRuleBody {
      rule = {
        match = [ (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80) ];
        action.dnat = {
          addr = "10.0.0.5";
          port = 8080;
        };
      };
      comment = "web port forward";
    };
    expected = {
      statements = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80)
        (nftypes.dsl.dnat {
          addr = "10.0.0.5";
          port = 8080;
        })
      ];
      comment = "web port forward";
    };
  };

  # ===== mkSubChain — single cell, no children =====

  testMkSubChainSingleCell = {
    expr = mkSubChain {
      hook = "forward";
      subChain = {
        from = "lan";
        to = "wan";
        preChildCells = [ ];
        postChildCells = [
          {
            rule = [ nftypes.dsl.accept ];
            comment = null;
          }
        ];
        children = [ ];
      };
      subChains = { };
      zoneMembership = membershipFor {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
      };
    };
    expected = {
      rules = [
        [ nftypes.dsl.accept ]
      ];
    };
  };

  # ===== mkSubChain — pre-child cells, child jumps, post-child cells =====

  testMkSubChainOrder = {
    # The child-dispatch jump re-checks only the child's from-side
    # match and sits between the parent's pre- and post-child cells.
    expr = mkSubChain {
      hook = "input";
      subChain = {
        from = "dmz";
        to = "local";
        preChildCells = [
          {
            rule = [ nftypes.dsl.accept ];
            comment = null;
          }
        ];
        postChildCells = [
          {
            rule = [ nftypes.dsl.drop ];
            comment = null;
          }
        ];
        children = [ "input-at-filter__web-server-TO-local" ];
      };
      subChains."input-at-filter__web-server-TO-local" = {
        from = "web-server";
        to = "local";
        preChildCells = [ ];
        postChildCells = [ ];
        children = [ ];
      };
      zoneMembership = membershipFor {
        zones.dmz.interfaces = [ "dmz0" ];
        nodes.web-server = {
          zone = "dmz";
          address.ipv4 = "10.0.0.5";
        };
      };
    };
    expected = {
      rules = [
        [ nftypes.dsl.accept ]
        [
          (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "web-server_v4"))
          (nftypes.dsl.jump "input-at-filter__web-server-TO-local")
        ]
        [ nftypes.dsl.drop ]
      ];
    };
  };

  # ===== mkSubChains — empty input =====

  testMkSubChainsEmpty = {
    expr = mkSubChains {
      dispatchTrees = { };
      zoneMembership = membershipFor { };
    };
    expected = { };
  };

  # ===== emitTable — sub-chain body contains the cell rule =====

  testEmitTableSubChainHasRule = {
    expr =
      let
        subChain =
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
          }).output.chains."forward-at-filter__lan-TO-wan";
      in
      subChain.rules;
    expected = [
      [ nftypes.dsl.accept ]
    ];
  };

  # ===== emitTable — preDispatch cells land in the sub-chain pre slot =====

  testEmitTablePreDispatchInSubChain = {
    # priority="first" (1 < 100) lands in the sub-chain's
    # preChildCells — NOT in the base chain pre slot. The base chain
    # only carries boilerplate + jumps.
    expr =
      let
        output =
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
        baseChain = output.chains."forward-at-filter";
        subChain = output.chains."forward-at-filter__lan-TO-wan";
      in
      {
        # Base chain: stateful (2) + jump (1).
        baseRuleCount = builtins.length baseChain.rules;
        # Sub-chain: the early rule (priority < 100 → pre slot).
        subRuleCount = builtins.length subChain.rules;
      };
    expected = {
      baseRuleCount = 3;
      subRuleCount = 1;
    };
  };

  # ===== emitTable — filter + policy in same pair: policy is tail rule =====

  testEmitTableFilterAndPolicyInSubChain = {
    expr =
      let
        subChain =
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
          }).output.chains."forward-at-filter__lan-TO-wan";
      in
      {
        ruleCount = builtins.length subChain.rules;
        lastRuleStmt = builtins.head (builtins.elemAt subChain.rules 1);
      };
    expected = {
      ruleCount = 2;
      lastRuleStmt = nftypes.dsl.drop;
    };
  };

  testEmitTableSnatSubChain = {
    expr =
      let
        subChain =
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
          }).output.chains."postrouting-at-srcnat__lan-TO-wan";
      in
      subChain.rules;
    expected = [
      [ (nftypes.dsl.masquerade { }) ]
    ];
  };

  # ===== mkRootJumpRules — empty =====

  testMkRootJumpRulesEmpty = {
    expr = mkRootJumpRules {
      tree = emptyTree "forward" "filter";
      zoneMembership = membershipFor { };
    };
    expected = [ ];
  };

  testMkRootJumpRulesBidirectional = {
    # One jump per root, gated on both sides' direction variants.
    expr = mkRootJumpRules {
      tree = emptyTree "forward" "filter" // {
        roots = [ "forward-at-filter__lan-TO-wan" ];
        subChains."forward-at-filter__lan-TO-wan" = {
          from = "lan";
          to = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
          children = [ ];
        };
      };
      zoneMembership = membershipFor {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
      };
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.oifname (nftypes.dsl.expr.setRef "wan_iifs"))
        (nftypes.dsl.jump "forward-at-filter__lan-TO-wan")
      ]
    ];
  };

  testMkRootJumpRulesSingleDirection = {
    expr = mkRootJumpRules {
      tree = emptyTree "prerouting" "dstnat" // {
        roots = [ "prerouting-at-dstnat__wan" ];
        subChains."prerouting-at-dstnat__wan" = {
          from = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
          children = [ ];
        };
      };
      zoneMembership = membershipFor { zones.wan.interfaces = [ "wan0" ]; };
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "wan_iifs"))
        (nftypes.dsl.jump "prerouting-at-dstnat__wan")
      ]
    ];
  };

  # ===== mkRootJumpRules — cartesian product drops cross-family pairs =====

  testMkRootJumpRulesCartesian = {
    # With both lan and wan exposing v4 *and* v6 sets, the
    # cartesian product is 4 (lan_v4×wan_v4, lan_v4×wan_v6,
    # lan_v6×wan_v4, lan_v6×wan_v6). nft rejects mixed-family
    # match in `inet`, so emit drops the 2 cross-family pairs
    # and keeps the 2 matching-family pairs. Assert on the
    # actual jump bodies, not just the count — a regression
    # that kept the cross-family pairs (and dropped the matching
    # ones) would still produce length 2 and pass a count-only
    # assertion.
    expr = mkRootJumpRules {
      tree = emptyTree "forward" "filter" // {
        roots = [ "forward-at-filter__lan-TO-wan" ];
        subChains."forward-at-filter__lan-TO-wan" = {
          from = "lan";
          to = "wan";
          preChildCells = [ ];
          postChildCells = [ ];
          children = [ ];
        };
      };
      zoneMembership = membershipFor {
        zones.lan.cidrs = [
          "10.0.0.0/24"
          "fd00::/64"
        ];
        zones.wan.cidrs = [
          "192.0.2.0/24"
          "2001:db8::/32"
        ];
      };
    };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.daddr (nftypes.dsl.expr.setRef "wan_v4"))
        (nftypes.dsl.jump "forward-at-filter__lan-TO-wan")
      ]
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.daddr (nftypes.dsl.expr.setRef "wan_v6"))
        (nftypes.dsl.jump "forward-at-filter__lan-TO-wan")
      ]
    ];
  };

  # ===== emitTable — jump rule lands in base chain =====

  testEmitTableJumpRule = {
    expr =
      let
        output =
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
              rule = [ accept ];
            };
          }).output;
        baseRules = output.chains."forward-at-filter".rules;
      in
      # After stateful (2 rules), the jump.
      builtins.elemAt baseRules 2;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.oifname (nftypes.dsl.expr.setRef "wan_iifs"))
      (nftypes.dsl.jump "forward-at-filter__lan-TO-wan")
    ];
  };

  testEmitTableDnatJump = {
    expr =
      let
        output =
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
        baseRules = output.chains."prerouting-at-dstnat".rules;
      in
      builtins.head baseRules;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "wan_iifs"))
      (nftypes.dsl.jump "prerouting-at-dstnat__wan")
    ];
  };

  testEmitTableJumpToLocalZone = {
    expr =
      let
        output =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters.allow-ssh = {
              from = [ "wan" ];
              to = [ "local" ];
              rule = [ accept ];
            };
          }).output;
        # input chain: stateful (2) + loopback (1) + jump (1) = 4 rules
        baseRules = output.chains."input-at-filter".rules;
      in
      builtins.elemAt baseRules 3;
    expected = [
      (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "wan_iifs"))
      (nftypes.dsl.jump "input-at-filter__wan-TO-local")
    ];
  };

  # ===== emitTable — base chain rule order =====

  testEmitTableBaseChainRuleOrder = {
    # The base chain has only:
    #   stateful (2) + loopback (1) + jump (1) = 4 rules.
    # The early/normal/late cells all live inside the sub-chain.
    expr =
      let
        output =
          (runEmit {
            zones.wan = {
              interfaces = [ "wan0" ];
            };
            filters = {
              early = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ accept ];
                priority = "first";
              };
              normal = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ accept ];
              };
              late = {
                from = [ "wan" ];
                to = [ "local" ];
                rule = [ accept ];
                priority = "last";
              };
            };
          }).output;
        baseRules = output.chains."input-at-filter".rules;
        subRules = output.chains."input-at-filter__wan-TO-local".rules;
      in
      {
        baseRuleCount = builtins.length baseRules;
        subRuleCount = builtins.length subRules;
      };
    expected = {
      baseRuleCount = 4; # stateful (2) + loopback (1) + jump (1)
      subRuleCount = 3; # early, normal, late
    };
  };

  testEmitTableDrouteChain = {
    expr =
      let
        chains =
          (runEmit {
            zones.lan.interfaces = [ "lan0" ];
            droutes.mark-lan = {
              to = [ "lan" ];
              rule = [ (mangle meta.mark 1) ];
            };
          }).output.chains;
      in
      {
        keys = lib.sort (a: b: a < b) (builtins.attrNames chains);
        baseType = chains."output-at-mangle".type;
      };
    expected = {
      keys = [
        "output-at-mangle"
        "output-at-mangle__lan"
      ];
      baseType = "route";
    };
  };

  testEmitTableSrouteChain = {
    # sroute lands at prerouting+mangle as `type filter` (route
    # chains are output-only — see `testMkBaseChainSroute`).
    expr =
      let
        chains =
          (runEmit {
            zones.wan.interfaces = [ "wan0" ];
            sroutes.mark-wan = {
              from = [ "wan" ];
              rule = [ (mangle meta.mark 1) ];
            };
          }).output.chains;
      in
      {
        keys = lib.sort (a: b: a < b) (builtins.attrNames chains);
        baseType = chains."prerouting-at-mangle".type;
      };
    expected = {
      keys = [
        "prerouting-at-mangle"
        "prerouting-at-mangle__wan"
      ];
      baseType = "filter";
    };
  };

  testEmitTableEmptyObjects = {
    expr =
      let
        output =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
          }).output;
      in
      lib.attrNames output;
    expected = [
      "_type"
      "family"
      "name"
      "sets"
    ];
  };

  testEmitTableCounterPassthrough = {
    expr =
      let
        output =
          (runEmit {
            objects.counters.web-hits = { };
          }).output;
      in
      lib.attrNames output.counters;
    expected = [ "web-hits" ];
  };

  testEmitTableMultipleKinds = {
    expr =
      let
        output =
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
      lib.sort (a: b: a < b) (
        builtins.filter (
          kind:
          builtins.elem kind [
            "counters"
            "quotas"
            "ctHelpers"
          ]
        ) (lib.attrNames output)
      );
    expected = [
      "counters"
      "ctHelpers"
      "quotas"
    ];
  };

  testEmitTableUserSetMergesWithZoneSets = {
    expr =
      let
        output =
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
      lib.sort (a: b: a < b) (lib.attrNames output.sets);
    expected = [
      "blocklist_v4"
      "lan_iifs"
    ];
  };

  # ===== emitTable — user objects take nftypes' DSL field names =====

  testEmitTableUserObjectsUseDslFieldNames = {
    # The object options keep nft's JSON field names, which
    # `nftypes.dsl.table` rejects.
    expr =
      let
        output =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
            objects = {
              sets.blocklist_v4 = {
                type = "ipv4_addr";
                elem = [ "1.2.3.4" ];
              };
              maps.marks = {
                type = "ipv4_addr";
                map = "mark";
              };
              limits.slow = {
                rate = 10;
                per = "second";
                rate_unit = "kbytes";
              };
            };
          }).output;
      in
      lib.mapAttrs (_: lib.filterAttrs (_: value: value != null)) {
        set = output.sets.blocklist_v4;
        map = output.maps.marks;
        limit = output.limits.slow;
      };
    expected = {
      set = {
        type = "ipv4_addr";
        elements = [ "1.2.3.4" ];
      };
      map = {
        type = "ipv4_addr";
        dataType = "mark";
      };
      limit = {
        rate = 10;
        per = "second";
        rateUnit = "kbytes";
      };
    };
  };

  testEmitTableEmptyKindsSkipped = {
    expr =
      let
        output =
          (runEmit {
            zones.lan = {
              interfaces = [ "lan0" ];
            };
          }).output;
      in
      builtins.any (kind: builtins.elem kind (lib.attrNames output)) [
        "counters"
        "quotas"
        "limits"
        "ctHelpers"
        "ctTimeouts"
        "ctExpectations"
        "secmarks"
        "synproxies"
        "maps"
        "flowtables"
      ];
    expected = false;
  };

  # ===== emitTable — parent hierarchy: parent jumps to child sub-chain =====

  testEmitTableParentBasic = {
    # web-server (node, parent dmz) has its own rule. The dmz
    # sub-chain is synthesized as a transparent dispatcher; base
    # chain jumps only to dmz; dmz jumps to web-server.
    expr =
      let
        output =
          (runEmit {
            zones.dmz = {
              interfaces = [ "dmz0" ];
              cidrs = [ "10.0.0.0/24" ];
            };
            nodes.web-server = {
              zone = "dmz";
              address.ipv4 = "10.0.0.5";
            };
            filters.allow-http = {
              from = [ "web-server" ];
              to = [ "local" ];
              rule = [
                (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80)
                nftypes.dsl.accept
              ];
            };
          }).output;
        inherit (output) chains;
      in
      {
        chainKeys = lib.sort (a: b: a < b) (builtins.attrNames chains);
        # Base chain (input-at-filter): stateful (2) + loopback (1) +
        # one jump to dmz. The base chain only jumps to root
        # from-zones (dmz), not web-server.
        baseRulesCount = builtins.length chains."input-at-filter".rules;
        # dmz transparent dispatcher: only the child-dispatch jump
        # to web-server.
        dmzRules = chains."input-at-filter__dmz-TO-local".rules;
        # web-server sub-chain: the actual rule.
        webRules = chains."input-at-filter__web-server-TO-local".rules;
      };
    expected = {
      chainKeys = [
        "input-at-filter"
        "input-at-filter__dmz-TO-local"
        "input-at-filter__web-server-TO-local"
      ];
      # 2 stateful + 1 loopback + 1 dmz jump (iif AND v4 ANDed in
      # one variant; to-side is localZone → empty variant) = 4.
      baseRulesCount = 4;
      # One child-dispatch jump (web-server has only v4, not iifs).
      dmzRules = [
        [
          (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "web-server_v4"))
          (nftypes.dsl.jump "input-at-filter__web-server-TO-local")
        ]
      ];
      webRules = [
        [
          (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 80)
          nftypes.dsl.accept
        ]
      ];
    };
  };
}
