# Unit tests for `lib/internal/wildcard.nix` (exposed as
# `nftzones.internal.wildcard.expandWildcard`). Same
# `testFoo = { expr; expected; }` shape as every other unit test;
# aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftzones.internal.wildcard) expandWildcard;
in
{
  # ===== expandWildcard — pass-through (no wildcard in list) =====

  testPassThroughNoWildcard = {
    expr = expandWildcard "all" [ "lan" "wan" "local" ] [ "lan" "wan" ];
    expected = [
      "lan"
      "wan"
    ];
  };

  # ===== expandWildcard — sole wildcard expands to full scope =====

  testWildcardOnly = {
    expr = expandWildcard "all" [ "lan" "wan" "local" ] [ "all" ];
    expected = [
      "lan"
      "wan"
      "local"
    ];
  };

  # ===== expandWildcard — dedup after expansion =====

  testWildcardDedupAfterExpansion = {
    # `lan` already in list, then `all` expands and re-introduces
    # it; first-occurrence order preserved.
    expr = expandWildcard "all" [ "lan" "wan" "local" ] [ "lan" "all" ];
    expected = [
      "lan"
      "wan"
      "local"
    ];
  };

  # ===== expandWildcard — empty input =====

  testEmptyList = {
    expr = expandWildcard "all" [ "lan" "wan" ] [ ];
    expected = [ ];
  };

  # ===== expandWildcard — wildcard name is configurable =====

  testCustomWildcard = {
    expr = expandWildcard "everywhere" [ "x" "y" "z" ] [ "everywhere" ];
    expected = [
      "x"
      "y"
      "z"
    ];
  };

  # ===== expandWildcard — wildcard repeated in list =====

  testWildcardRepeated = {
    expr = expandWildcard "all" [ "lan" "wan" ] [ "all" "all" ];
    expected = [
      "lan"
      "wan"
    ];
  };

  # ===== expandWildcard — empty allZones =====
  # Edge case: wildcard expands to nothing → result drops it.

  testEmptyScope = {
    expr = expandWildcard "all" [ ] [ "all" "lan" ];
    expected = [ "lan" ];
  };

  # ===== expandWildcard — order preservation =====

  testOrderPreservation = {
    # Concrete entries before and after the wildcard appear in
    # writing order; expanded entries slot in where the wildcard
    # was, before the trailing concretes.
    expr = expandWildcard "all" [ "wan" "vpn" ] [ "lan" "all" "guest" ];
    expected = [
      "lan"
      "wan"
      "vpn"
      "guest"
    ];
  };
}
