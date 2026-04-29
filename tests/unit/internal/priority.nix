# Unit tests for `lib/internal/priority.nix` (exposed as
# `nftzones.internal.priority`). Same `testFoo = { expr; expected; }`
# shape as every other unit test; aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftzones.internal.priority) rulePrioritySymbols;
in
{
  # ===== rulePrioritySymbols — full mapping =====

  testRulePrioritySymbolMapping = {
    expr = rulePrioritySymbols;
    expected = {
      first = 1;
      preDispatch = 50;
      postDispatch = 100;
      default = 500;
      last = 999;
    };
  };

  # ===== rulePrioritySymbols — keys =====

  testRulePrioritySymbolKeys = {
    expr = builtins.attrNames rulePrioritySymbols;
    expected = [
      "default"
      "first"
      "last"
      "postDispatch"
      "preDispatch"
    ];
  };

  # ===== pre-dispatch cutoff — symbols below 100 emit before per-zone jumps =====

  testFirstIsPreDispatch = {
    expr = rulePrioritySymbols.first < 100;
    expected = true;
  };

  testPreDispatchIsPreDispatch = {
    expr = rulePrioritySymbols.preDispatch < 100;
    expected = true;
  };

  # ===== post-dispatch cutoff — symbols >= 100 emit after per-zone jumps =====

  testPostDispatchIsPostDispatch = {
    expr = rulePrioritySymbols.postDispatch >= 100;
    expected = true;
  };

  testDefaultIsPostDispatch = {
    expr = rulePrioritySymbols.default >= 100;
    expected = true;
  };

  testLastIsPostDispatch = {
    expr = rulePrioritySymbols.last >= 100;
    expected = true;
  };

  # ===== ordering invariant — symbols sort in declaration order =====

  testSymbolsAreOrdered = {
    expr =
      rulePrioritySymbols.first < rulePrioritySymbols.preDispatch
      && rulePrioritySymbols.preDispatch < rulePrioritySymbols.postDispatch
      && rulePrioritySymbols.postDispatch < rulePrioritySymbols.default
      && rulePrioritySymbols.default < rulePrioritySymbols.last;
    expected = true;
  };
}
