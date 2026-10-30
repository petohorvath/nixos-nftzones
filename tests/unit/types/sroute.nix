/*
  Unit tests for `lib/types/sroute.nix` (exposed as
  `nftzones.types.{sroute,srouteName,srouteRule,
  sroutePriority,srouteComment}`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{ helpers, nftypes, ... }:
let
  inherit (helpers) evalFails evalTable;

  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;

  basicBody = {
    from = [ "guest" ];
    rule = [ (mangle meta.mark 100) ];
  };

  srouteIn =
    body:
    (evalTable {
      sroutes.guest-via-vpn = body;
    }).sroutes.guest-via-vpn;
in
{
  # ===== sroute.name — derives from attrset key =====

  testSrouteNameDerivedFromKey = {
    expr = (srouteIn basicBody).name;
    expected = "guest-via-vpn";
  };

  # ===== sroute has `from` only (no `to`) =====

  testSrouteFromAccepted = {
    expr = (srouteIn basicBody).from;
    expected = [ "guest" ];
  };

  testSrouteFromEmptyRejected = {
    expr = evalFails (srouteIn (basicBody // { from = [ ]; })).from;
    expected = true;
  };

  testSrouteHasNoToField = {
    expr = evalFails (srouteIn (basicBody // { to = [ "vpn" ]; })).to;
    expected = true;
  };

  # ===== sroute.rule — required, non-empty =====

  testSrouteRuleAccepted = {
    expr = (srouteIn basicBody).rule;
    expected = [ (mangle meta.mark 100) ];
  };

  testSrouteRuleRequired = {
    expr = evalFails (srouteIn (removeAttrs basicBody [ "rule" ])).rule;
    expected = true;
  };

  testSrouteRuleEmptyRejected = {
    expr = evalFails (srouteIn (basicBody // { rule = [ ]; })).rule;
    expected = true;
  };

  testSrouteRuleRejectsBogusStatement = {
    expr = evalFails (srouteIn (basicBody // { rule = [ "not-a-statement" ]; })).rule;
    expected = true;
  };

  # ===== sroute.priority — default "default" =====

  testSroutePriorityDefault = {
    expr = (srouteIn basicBody).priority;
    expected = "default";
  };

  testSroutePriorityRejectsUnknown = {
    expr = evalFails (srouteIn (basicBody // { priority = "asap"; })).priority;
    expected = true;
  };

  # ===== sroute.comment — optional, null default =====

  testSrouteCommentDefault = {
    expr = (srouteIn basicBody).comment;
    expected = null;
  };
}
