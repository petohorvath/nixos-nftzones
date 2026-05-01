# Unit tests for `lib/internal/filter.nix` (exposed as
# `nftzones.internal.filter.groupCellsByChain`). Same
# `testFoo = { expr; expected; }` shape as every other unit test;
# aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftzones.internal.filter) groupCellsByChain;

  bareCellOf = from: to: { inherit from to; };

  emptyChains = {
    input = [ ];
    output = [ ];
    forward = [ ];
  };
in
{
  # ===== groupCellsByChain — empty input =====

  testChainsEmpty = {
    expr = groupCellsByChain {
      localZone = "host";
      cells = [ ];
    };
    expected = emptyChains;
  };

  # ===== groupCellsByChain — to == localZone → input =====

  testChainsInputDispatch = {
    expr = groupCellsByChain {
      localZone = "host";
      cells = [ (bareCellOf "wan" "host") ];
    };
    expected = emptyChains // {
      input = [ (bareCellOf "wan" "host") ];
    };
  };

  # ===== groupCellsByChain — from == localZone → output =====

  testChainsOutputDispatch = {
    expr = groupCellsByChain {
      localZone = "host";
      cells = [ (bareCellOf "host" "wan") ];
    };
    expected = emptyChains // {
      output = [ (bareCellOf "host" "wan") ];
    };
  };

  # ===== groupCellsByChain — neither side is localZone → forward =====

  testChainsForwardDispatch = {
    expr = groupCellsByChain {
      localZone = "host";
      cells = [ (bareCellOf "lan" "wan") ];
    };
    expected = emptyChains // {
      forward = [ (bareCellOf "lan" "wan") ];
    };
  };

  # ===== groupCellsByChain — both endpoints localZone → input (to-side wins) =====

  testChainsHostToHostInput = {
    expr = groupCellsByChain {
      localZone = "host";
      cells = [ (bareCellOf "host" "host") ];
    };
    expected = emptyChains // {
      input = [ (bareCellOf "host" "host") ];
    };
  };

  # ===== groupCellsByChain — localZone parameter is honoured =====

  testChainsCustomLocalZone = {
    # `host` is just a string here; `self` is the actual local zone
    expr = groupCellsByChain {
      localZone = "self";
      cells = [
        (bareCellOf "wan" "self")
        (bareCellOf "lan" "host")
      ];
    };
    expected = emptyChains // {
      input = [ (bareCellOf "wan" "self") ];
      forward = [ (bareCellOf "lan" "host") ];
    };
  };

  # ===== groupCellsByChain — mixed dispatch, preserves order within bucket =====

  testChainsMixedBuckets = {
    expr = groupCellsByChain {
      localZone = "host";
      cells = [
        (bareCellOf "wan" "host")
        (bareCellOf "lan" "wan")
        (bareCellOf "host" "wan")
        (bareCellOf "lan" "host")
      ];
    };
    expected = {
      input = [
        (bareCellOf "wan" "host")
        (bareCellOf "lan" "host")
      ];
      output = [ (bareCellOf "host" "wan") ];
      forward = [ (bareCellOf "lan" "wan") ];
    };
  };
}
