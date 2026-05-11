/*
  Unit tests for `lib/internal/placement.nix` (exposed as
  `nftzones.internal.placement`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by
  `tests/unit/default.nix`.
*/
{
  nftzones,
  ...
}:
let
  inherit (nftzones.internal.placement)
    defaultGroupChainAttrs
    filterChainHook
    filterChainPriority
    baseChainNameOf
    subChainKeyOf
    walkParents
    hooksWithIifname
    ;
in
{
  # ===== defaultGroupChainAttrs — non-filter group placements =====

  testDefaultGroupChainAttrsSnats = {
    expr = defaultGroupChainAttrs.snats;
    expected = {
      hook = "postrouting";
      priority = "srcnat";
    };
  };

  testDefaultGroupChainAttrsDnats = {
    expr = defaultGroupChainAttrs.dnats;
    expected = {
      hook = "prerouting";
      priority = "dstnat";
    };
  };

  testDefaultGroupChainAttrsSroutes = {
    expr = defaultGroupChainAttrs.sroutes;
    expected = {
      hook = "prerouting";
      priority = "mangle";
    };
  };

  testDefaultGroupChainAttrsDroutes = {
    expr = defaultGroupChainAttrs.droutes;
    expected = {
      hook = "output";
      priority = "mangle";
    };
  };

  # filter / policy aren't in the table — they dispatch by host
  # position via `filterChainHook` instead.
  testDefaultGroupChainAttrsNoFilters = {
    expr = defaultGroupChainAttrs ? filters || defaultGroupChainAttrs ? policies;
    expected = false;
  };

  # ===== filterChainHook — host-position dispatch =====

  testFilterChainHookToLocalIsInput = {
    expr = filterChainHook "local" {
      from = "wan";
      to = "local";
    };
    expected = "input";
  };

  testFilterChainHookFromLocalIsOutput = {
    expr = filterChainHook "local" {
      from = "local";
      to = "wan";
    };
    expected = "output";
  };

  testFilterChainHookNeitherIsForward = {
    expr = filterChainHook "local" {
      from = "lan";
      to = "wan";
    };
    expected = "forward";
  };

  # `localZone` is configurable; the helper consults it dynamically.
  testFilterChainHookCustomLocalZone = {
    expr = filterChainHook "host" {
      from = "wan";
      to = "host";
    };
    expected = "input";
  };

  # ===== filterChainPriority — canonical symbol =====

  testFilterChainPriority = {
    expr = filterChainPriority;
    expected = "filter";
  };

  # ===== baseChainNameOf — bucket-key / chain-name format =====

  testBaseChainNameOfSymbol = {
    expr = baseChainNameOf "inet" {
      hook = "input";
      priority = "filter";
    };
    expected = "input-at-filter";
  };

  # Int form of a canonical symbol must collapse to the same key
  # (so user-overrides written as int don't bypass collision
  # checks that consult the key).
  testBaseChainNameOfIntCanonicalizes = {
    expr = baseChainNameOf "inet" {
      hook = "prerouting";
      priority = -300;
    };
    expected = "prerouting-at-raw";
  };

  # Family-aware: bridge's `filter = -200` canonicalizes through
  # `priorityIntsBridge`, not `priorityIntsDefault`.
  testBaseChainNameOfBridgeFamily = {
    expr = baseChainNameOf "bridge" {
      hook = "input";
      priority = -200;
    };
    expected = "input-at-filter";
  };

  # Non-canonical ints (no symbol matches) pass through unchanged.
  testBaseChainNameOfUnknownInt = {
    expr = baseChainNameOf "inet" {
      hook = "input";
      priority = 42;
    };
    expected = "input-at-42";
  };

  # ===== subChainKeyOf — bucket-local sub-chain key =====

  testSubChainKeyOfBidirectional = {
    expr = subChainKeyOf {
      from = "lan";
      to = "wan";
    };
    expected = "lan-to-wan";
  };

  testSubChainKeyOfFromOnly = {
    expr = subChainKeyOf { from = "lan"; };
    expected = "lan";
  };

  testSubChainKeyOfToOnly = {
    expr = subChainKeyOf { to = "wan"; };
    expected = "wan";
  };

  # Extra fields (rule, priority, etc.) are ignored — works on
  # cell-shaped inputs directly.
  testSubChainKeyOfIgnoresExtraFields = {
    expr = subChainKeyOf {
      from = "lan";
      to = "wan";
      rule = [ ];
      priority = "default";
    };
    expected = "lan-to-wan";
  };

  # ===== walkParents — strict ancestor walk =====

  testWalkParentsRoot = {
    expr = walkParents {
      a.parent = null;
    } "a";
    expected = [ ];
  };

  testWalkParentsChain = {
    # c → b → a (root). Result is ancestors of c in root-toward
    # order: immediate parent first, root last.
    expr = walkParents {
      a.parent = null;
      b.parent = "a";
      c.parent = "b";
    } "c";
    expected = [
      "b"
      "a"
    ];
  };

  # Unresolved parent stops the walk gracefully (returns the
  # ancestors gathered so far, doesn't throw).
  testWalkParentsUnresolved = {
    expr = walkParents {
      a.parent = "missing";
    } "a";
    expected = [ ];
  };

  # Cycle-safe: defensive even if `checkParentCycles` were bypassed.
  testWalkParentsCycle = {
    expr = walkParents {
      a.parent = "b";
      b.parent = "a";
    } "a";
    expected = [ "b" ];
  };

  # Null input (e.g. a single-direction cell with no `from`) is
  # safe — walker returns empty rather than throwing.
  testWalkParentsNullName = {
    expr = walkParents { } null;
    expected = [ ];
  };

  # ===== hooksWithIifname — constant =====

  testHooksWithIifname = {
    expr = hooksWithIifname;
    expected = [
      "prerouting"
      "input"
      "forward"
      "postrouting"
    ];
  };
}
