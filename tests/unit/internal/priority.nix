/*
  Unit tests for `lib/internal/priority.nix` (exposed as
  `nftzones.internal.priority`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.priority) resolvePriority entryPriorities;
in
{
  # ===== resolvePriority — every symbol resolves to its int =====

  testResolveFirst = {
    expr = resolvePriority "first";
    expected = 1;
  };

  testResolvePreDispatch = {
    expr = resolvePriority "preDispatch";
    expected = 50;
  };

  testResolvePostDispatch = {
    expr = resolvePriority "postDispatch";
    expected = 100;
  };

  testResolveDefault = {
    expr = resolvePriority "default";
    expected = 500;
  };

  testResolveLast = {
    expr = resolvePriority "last";
    expected = 999;
  };

  # ===== resolvePriority — int values pass through =====

  testResolveIntPassThrough = {
    expr = resolvePriority 250;
    expected = 250;
  };

  testResolveIntZero = {
    expr = resolvePriority 0;
    expected = 0;
  };

  testResolveIntNegative = {
    # nftables priorities legitimately accept negatives
    # (e.g. raw-prerouting at -300). Pass-through must not coerce.
    expr = resolvePriority (-300);
    expected = -300;
  };

  # ===== entryPriorities — canonical symbol → int table consumed by Phase 3 =====

  testEntryPrioritiesShape = {
    # Phase 3's `bucketOf` reads `entryPriorities.postDispatch` as
    # the cutoff between sub-chain and post-dispatch slots. A
    # silent rename here would break dispatch in subtle ways; pin
    # the full canonical table.
    expr = entryPriorities;
    expected = {
      first = 1;
      preDispatch = 50;
      postDispatch = 100;
      default = 500;
      last = 999;
    };
  };

  # ===== pre-dispatch cutoff — symbols below 100 emit before per-zone jumps =====

  testFirstIsPreDispatch = {
    expr = resolvePriority "first" < 100;
    expected = true;
  };

  testPreDispatchIsPreDispatch = {
    expr = resolvePriority "preDispatch" < 100;
    expected = true;
  };

  # ===== post-dispatch cutoff — symbols >= 100 emit after per-zone jumps =====

  testPostDispatchIsPostDispatch = {
    expr = resolvePriority "postDispatch" >= 100;
    expected = true;
  };

  testDefaultIsPostDispatch = {
    expr = resolvePriority "default" >= 100;
    expected = true;
  };

  testLastIsPostDispatch = {
    expr = resolvePriority "last" >= 100;
    expected = true;
  };

  # ===== ordering invariant — symbols sort in declaration order =====

  testSymbolsAreOrdered = {
    expr =
      resolvePriority "first" < resolvePriority "preDispatch"
      && resolvePriority "preDispatch" < resolvePriority "postDispatch"
      && resolvePriority "postDispatch" < resolvePriority "default"
      && resolvePriority "default" < resolvePriority "last";
    expected = true;
  };
}
