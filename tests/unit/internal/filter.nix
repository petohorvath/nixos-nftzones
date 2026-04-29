# Unit tests for `lib/internal/filter.nix` (exposed as
# `nftzones.internal.filter.groupExpansionsByChain`). Same
# `testFoo = { expr; expected; }` shape as every other unit test;
# aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftzones.internal.filter) groupExpansionsByChain;

  bareExpansionOf = from: to: { inherit from to; };

  emptyChains = {
    input = [ ];
    output = [ ];
    forward = [ ];
  };
in
{
  # ===== groupExpansionsByChain — empty input =====

  testChainsEmpty = {
    expr = groupExpansionsByChain {
      localZone = "host";
      expansions = [ ];
    };
    expected = emptyChains;
  };

  # ===== groupExpansionsByChain — to == localZone → input =====

  testChainsInputDispatch = {
    expr = groupExpansionsByChain {
      localZone = "host";
      expansions = [ (bareExpansionOf "wan" "host") ];
    };
    expected = emptyChains // {
      input = [ (bareExpansionOf "wan" "host") ];
    };
  };

  # ===== groupExpansionsByChain — from == localZone → output =====

  testChainsOutputDispatch = {
    expr = groupExpansionsByChain {
      localZone = "host";
      expansions = [ (bareExpansionOf "host" "wan") ];
    };
    expected = emptyChains // {
      output = [ (bareExpansionOf "host" "wan") ];
    };
  };

  # ===== groupExpansionsByChain — neither side is localZone → forward =====

  testChainsForwardDispatch = {
    expr = groupExpansionsByChain {
      localZone = "host";
      expansions = [ (bareExpansionOf "lan" "wan") ];
    };
    expected = emptyChains // {
      forward = [ (bareExpansionOf "lan" "wan") ];
    };
  };

  # ===== groupExpansionsByChain — both endpoints localZone → input (to-side wins) =====

  testChainsHostToHostInput = {
    expr = groupExpansionsByChain {
      localZone = "host";
      expansions = [ (bareExpansionOf "host" "host") ];
    };
    expected = emptyChains // {
      input = [ (bareExpansionOf "host" "host") ];
    };
  };

  # ===== groupExpansionsByChain — localZone parameter is honoured =====

  testChainsCustomLocalZone = {
    # `host` is just a string here; `self` is the actual local zone
    expr = groupExpansionsByChain {
      localZone = "self";
      expansions = [
        (bareExpansionOf "wan" "self")
        (bareExpansionOf "lan" "host")
      ];
    };
    expected = emptyChains // {
      input = [ (bareExpansionOf "wan" "self") ];
      forward = [ (bareExpansionOf "lan" "host") ];
    };
  };

  # ===== groupExpansionsByChain — mixed dispatch, preserves order within bucket =====

  testChainsMixedBuckets = {
    expr = groupExpansionsByChain {
      localZone = "host";
      expansions = [
        (bareExpansionOf "wan" "host")
        (bareExpansionOf "lan" "wan")
        (bareExpansionOf "host" "wan")
        (bareExpansionOf "lan" "host")
      ];
    };
    expected = {
      input = [
        (bareExpansionOf "wan" "host")
        (bareExpansionOf "lan" "host")
      ];
      output = [ (bareExpansionOf "host" "wan") ];
      forward = [ (bareExpansionOf "lan" "wan") ];
    };
  };
}
