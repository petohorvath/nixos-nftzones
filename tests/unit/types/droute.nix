/*
  Unit tests for `lib/types/droute.nix` (exposed as
  `nftzones.types.{droute,drouteName,drouteRule,
  droutePriority,drouteComment}`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{ helpers, nftypes, ... }:
let
  inherit (helpers) evalFails evalTable;

  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;

  basicBody = {
    to = [ "lan-remote" ];
    rule = [ (mangle meta.mark 200) ];
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

  # ===== droute.rule — required, non-empty =====

  testDrouteRuleAccepted = {
    expr = (drouteIn basicBody).rule;
    expected = [ (mangle meta.mark 200) ];
  };

  testDrouteRuleRequired = {
    expr = evalFails (drouteIn (removeAttrs basicBody [ "rule" ])).rule;
    expected = true;
  };

  testDrouteRuleEmptyRejected = {
    expr = evalFails (drouteIn (basicBody // { rule = [ ]; })).rule;
    expected = true;
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
