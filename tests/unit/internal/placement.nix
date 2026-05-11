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
}
