/*
  Unit tests for `lib/types/sroute.nix` (exposed as
  `nftzones.types.{sroute,srouteName,srouteZones,srouteRule,
  sroutePriority,srouteComment}`). Same
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
    from = [ "guest" ];
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

  # ===== sroute.rule — defaults to [ ] =====

  testSrouteRuleDefault = {
    expr = (srouteIn basicBody).rule;
    expected = [ ];
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
