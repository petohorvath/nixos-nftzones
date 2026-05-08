/*
  Unit tests for `lib/types/droute.nix` (exposed as
  `nftzones.types.{droute,drouteName,drouteZones,drouteRule,
  droutePriority,drouteComment}`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable evalFails;

  basicBody = {
    to = [ "lan-remote" ];
  };

  drouteIn =
    body:
    (evalTable {
      droutes.lan-via-vpn = body;
    }).droutes.lan-via-vpn;
in
{
  # ===== droute.name — derives from attrset key =====

  testDrouteNameDerivedFromKey = {
    expr = (drouteIn basicBody).name;
    expected = "lan-via-vpn";
  };

  # ===== droute has `to` only (no `from`) =====

  testDrouteToAccepted = {
    expr = (drouteIn basicBody).to;
    expected = [ "lan-remote" ];
  };

  testDrouteToEmptyRejected = {
    expr = evalFails (drouteIn (basicBody // { to = [ ]; })).to;
    expected = true;
  };

  testDrouteHasNoFromField = {
    expr = evalFails (drouteIn (basicBody // { from = [ "local" ]; })).from;
    expected = true;
  };

  # ===== droute.rule — defaults to [ ] =====

  testDrouteRuleDefault = {
    expr = (drouteIn basicBody).rule;
    expected = [ ];
  };

  # ===== droute.priority — default "default" =====

  testDroutePriorityDefault = {
    expr = (drouteIn basicBody).priority;
    expected = "default";
  };

  # ===== droute.comment — optional, null default =====

  testDrouteCommentDefault = {
    expr = (drouteIn basicBody).comment;
    expected = null;
  };
}
