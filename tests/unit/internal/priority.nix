# Unit tests for `lib/internal/priority.nix` (exposed as
# `nftzones.internal.priority`). Same `testFoo = { expr; expected; }`
# shape as every other unit test; aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftzones.internal.priority) resolvePrioritySymbol;
in
{
  # ===== resolvePrioritySymbol — every symbol resolves to its int =====

  testResolveFirst = {
    expr = resolvePrioritySymbol "first";
    expected = 1;
  };

  testResolvePreDispatch = {
    expr = resolvePrioritySymbol "preDispatch";
    expected = 50;
  };

  testResolvePostDispatch = {
    expr = resolvePrioritySymbol "postDispatch";
    expected = 100;
  };

  testResolveDefault = {
    expr = resolvePrioritySymbol "default";
    expected = 500;
  };

  testResolveLast = {
    expr = resolvePrioritySymbol "last";
    expected = 999;
  };

  # ===== resolvePrioritySymbol — int values pass through =====

  testResolveIntPassThrough = {
    expr = resolvePrioritySymbol 250;
    expected = 250;
  };

  testResolveIntZero = {
    expr = resolvePrioritySymbol 0;
    expected = 0;
  };

  # ===== pre-dispatch cutoff — symbols below 100 emit before per-zone jumps =====

  testFirstIsPreDispatch = {
    expr = resolvePrioritySymbol "first" < 100;
    expected = true;
  };

  testPreDispatchIsPreDispatch = {
    expr = resolvePrioritySymbol "preDispatch" < 100;
    expected = true;
  };

  # ===== post-dispatch cutoff — symbols >= 100 emit after per-zone jumps =====

  testPostDispatchIsPostDispatch = {
    expr = resolvePrioritySymbol "postDispatch" >= 100;
    expected = true;
  };

  testDefaultIsPostDispatch = {
    expr = resolvePrioritySymbol "default" >= 100;
    expected = true;
  };

  testLastIsPostDispatch = {
    expr = resolvePrioritySymbol "last" >= 100;
    expected = true;
  };

  # ===== ordering invariant — symbols sort in declaration order =====

  testSymbolsAreOrdered = {
    expr =
      resolvePrioritySymbol "first" < resolvePrioritySymbol "preDispatch"
      && resolvePrioritySymbol "preDispatch" < resolvePrioritySymbol "postDispatch"
      && resolvePrioritySymbol "postDispatch" < resolvePrioritySymbol "default"
      && resolvePrioritySymbol "default" < resolvePrioritySymbol "last";
    expected = true;
  };
}
