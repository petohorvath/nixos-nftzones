/*
  Unit tests for `lib/internal/normalize.nix` (exposed as
  `nftzones.internal.normalize`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (nftzones.internal.normalize) normalizeTable;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable;
in
{
  # ===== normalizeTable — failing validators aggregate into one throw =====
  # Phase 1 is fail-aggregating: when multiple validators detect
  # problems, normalizeTable throws ONCE with all messages, not
  # validator-by-validator. The throw must mention every failing
  # category so the user sees the full picture in one shot.

  testNormalizeMultipleErrorsAggregated = {
    expr =
      let
        attempt = builtins.tryEval (
          normalizeTable (evalTable {
            name = "fw";
            # Triggers checkNameCollisions: zone+node share "web"
            zones.web = { };
            nodes.web = {
              zone = "lan";
              address.ipv4 = "1.1.1.1";
            };
            # Triggers checkZoneRefs: "missing" is unknown
            filters.f = {
              from = [ "missing" ];
              to = [ "web" ];
              rule = [ ];
            };
          })
        );
      in
      attempt.success;
    expected = false;
  };
}
