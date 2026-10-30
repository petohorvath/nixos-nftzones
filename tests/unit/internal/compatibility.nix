/*
  Unit tests for `lib/internal/compatibility.nix` (exposed as
  `nftzones.internal.compatibility`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{ nftzones, ... }:
let
  inherit (nftzones.internal.compatibility)
    chainTypeFor
    hooksWithOifname
    priorityInts
    priorityNameOf
    resolvePriority
    ;
in
{
  # ===== priorityInts — every symbol the family accepts at any hook =====

  testPriorityIntsInet = {
    expr = priorityInts "inet";
    expected = {
      raw = -300;
      mangle = -150;
      dstnat = -100;
      filter = 0;
      security = 50;
      srcnat = 100;
    };
  };

  testPriorityIntsBridge = {
    expr = priorityInts "bridge";
    expected = {
      dstnat = -300;
      filter = -200;
      out = 100;
      srcnat = 300;
    };
  };

  # ===== resolvePriority — family-wide, not per hook =====

  testResolvePrioritySymbol = {
    expr = resolvePriority "ip" "srcnat";
    expected = 100;
  };

  testResolvePriorityBridgeSymbol = {
    expr = resolvePriority "bridge" "filter";
    expected = -200;
  };

  testResolvePriorityIntPassesThrough = {
    expr = resolvePriority "inet" 42;
    expected = 42;
  };

  testResolvePriorityUnknownSymbolThrows = {
    expr = resolvePriority "bridge" "mangle";
    expectedError.type = "ThrownError";
  };

  # ===== priorityNameOf — int → symbol, else unchanged =====

  testPriorityNameOfInt = {
    expr = priorityNameOf "inet" (-300);
    expected = "raw";
  };

  testPriorityNameOfBridgeInt = {
    expr = priorityNameOf "bridge" (-200);
    expected = "filter";
  };

  testPriorityNameOfUnnamedInt = {
    expr = priorityNameOf "inet" 10;
    expected = 10;
  };

  testPriorityNameOfSymbolPassesThrough = {
    expr = priorityNameOf "inet" "dstnat";
    expected = "dstnat";
  };

  # ===== chainTypeFor — classify, then fall back to filter =====

  testChainTypeForNat = {
    expr = chainTypeFor "inet" "postrouting" "srcnat";
    expected = "nat";
  };

  testChainTypeForNatInt = {
    expr = chainTypeFor "ip" "prerouting" (-100);
    expected = "nat";
  };

  testChainTypeForRouteAtOutput = {
    expr = chainTypeFor "inet" "output" "mangle";
    expected = "route";
  };

  testChainTypeForRouteIntAtOutput = {
    expr = chainTypeFor "inet" "output" (-150);
    expected = "route";
  };

  testChainTypeForUnnamedInt = {
    expr = chainTypeFor "inet" "input" 10;
    expected = "filter";
  };

  testChainTypeForRouteFallsBackAtPrerouting = {
    expr = chainTypeFor "inet" "prerouting" "mangle";
    expected = "filter";
  };

  testChainTypeForNatFallsBackAtForward = {
    expr = chainTypeFor "inet" "forward" "dstnat";
    expected = "filter";
  };

  testChainTypeForBridgeHasNoNat = {
    expr = chainTypeFor "bridge" "postrouting" "srcnat";
    expected = "filter";
  };

  testChainTypeForUnknownSymbol = {
    expr = chainTypeFor "bridge" "prerouting" "mangle";
    expected = null;
  };

  # ===== hooksWithOifname — hooks that know the output interface =====

  testHooksWithOifname = {
    expr = hooksWithOifname;
    expected = [
      "forward"
      "output"
      "postrouting"
    ];
  };
}
