/*
  Unit tests for `lib/types/policy.nix` (exposed as
  `nftzones.types.{policy,policyName,policyVerdict,
  policyComment}`). Same `testFoo = { expr; expected; }` shape as
  every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable evalFails;

  basicBody = {
    from = [ "lan" ];
    to = [ "wan" ];
    verdict = "accept";
  };

  policyIn =
    body:
    (evalTable {
      policies.lan-to-wan = body;
    }).policies.lan-to-wan;
in
{
  # ===== policy.name — derives from attrset key =====

  testPolicyNameDerivedFromKey = {
    expr = (policyIn basicBody).name;
    expected = "lan-to-wan";
  };

  # ===== from / to — required, non-empty =====

  testPolicyFromEmptyRejected = {
    expr = evalFails (policyIn (basicBody // { from = [ ]; })).from;
    expected = true;
  };

  testPolicyToEmptyRejected = {
    expr = evalFails (policyIn (basicBody // { to = [ ]; })).to;
    expected = true;
  };

  # ===== policy.verdict — required, enum [ accept drop ] =====

  testPolicyVerdictAccept = {
    expr = (policyIn basicBody).verdict;
    expected = "accept";
  };

  testPolicyVerdictDrop = {
    expr = (policyIn (basicBody // { verdict = "drop"; })).verdict;
    expected = "drop";
  };

  testPolicyVerdictRejectsReject = {
    # nftables permits `reject` as a chain-level policy in some
    # versions, but the per-pair compile pipeline only handles
    # `accept` / `drop`. Reject anything else at the type layer.
    expr = evalFails (policyIn (basicBody // { verdict = "reject"; })).verdict;
    expected = true;
  };

  testPolicyVerdictRejectsArbitrary = {
    expr = evalFails (policyIn (basicBody // { verdict = "log"; })).verdict;
    expected = true;
  };

  # ===== absent fields — policy has no rule / priority / chain =====

  testPolicyHasNoRuleField = {
    # Setting `rule` should fail — policies are verdict-only.
    expr = evalFails (policyIn (basicBody // { rule = [ ]; })).rule;
    expected = true;
  };

  testPolicyHasNoPriorityField = {
    expr = evalFails (policyIn (basicBody // { priority = "first"; })).priority;
    expected = true;
  };

  testPolicyHasNoChainField = {
    expr =
      evalFails
        (policyIn (
          basicBody
          // {
            chain = {
              hook = "prerouting";
              priority = "raw";
            };
          }
        )).chain;
    expected = true;
  };

  # ===== policy.comment — optional, null default =====

  testPolicyCommentDefault = {
    expr = (policyIn basicBody).comment;
    expected = null;
  };

  testPolicyCommentAccepted = {
    expr = (policyIn (basicBody // { comment = "lan reaches wan"; })).comment;
    expected = "lan reaches wan";
  };
}
