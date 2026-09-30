/*
  Unit tests for `lib/types/snat.nix` (exposed as
  `nftzones.types.{snat,snatName,snatRule,snatPriority,
  snatComment}`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by
  `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalFails evalTable;

  masqueradeBody = {
    from = [ "lan" ];
    to = [ "wan" ];
    rule.masquerade = { };
  };

  snatIn =
    body:
    (evalTable {
      snats.outbound = body;
    }).snats.outbound;
in
{
  # ===== snat.name — derives from attrset key =====

  testSnatNameDerivedFromKey = {
    expr = (snatIn masqueradeBody).name;
    expected = "outbound";
  };

  # ===== from / to — required, non-empty =====

  testSnatFromEmptyRejected = {
    expr = evalFails (snatIn (masqueradeBody // { from = [ ]; })).from;
    expected = true;
  };

  testSnatToEmptyRejected = {
    expr = evalFails (snatIn (masqueradeBody // { to = [ ]; })).to;
    expected = true;
  };

  # ===== snat.rule — attrTag {snat, masquerade} =====

  testSnatRuleMasqueradeEmpty = {
    # nftypes' masqueradeBody fills its optional fields with
    # null defaults at submodule-eval time.
    expr = (snatIn masqueradeBody).rule;
    expected = {
      masquerade = {
        flags = null;
        port = null;
      };
    };
  };

  testSnatRuleSnatBody = {
    # Same — natBody adds `family`/`flags`/`type_flags` null
    # defaults alongside the user-supplied `addr`/`port`.
    expr =
      (snatIn (
        masqueradeBody
        // {
          rule.snat = {
            addr = "203.0.113.5";
            port = 8080;
          };
        }
      )).rule;
    expected = {
      snat = {
        addr = "203.0.113.5";
        family = null;
        flags = null;
        port = 8080;
        type_flags = null;
      };
    };
  };

  testSnatRuleRejectsBothVariants = {
    # attrTag enforces "exactly one of {snat, masquerade}".
    expr =
      evalFails
        (snatIn (
          masqueradeBody
          // {
            rule = {
              snat.addr = "203.0.113.5";
              masquerade = { };
            };
          }
        )).rule;
    expected = true;
  };

  testSnatRuleRejectsUnknownTag = {
    expr = evalFails (snatIn (masqueradeBody // { rule.redirect = { }; })).rule;
    expected = true;
  };

  # ===== snat.priority — entryPriority, default "default" =====

  testSnatPriorityDefault = {
    expr = (snatIn masqueradeBody).priority;
    expected = "default";
  };

  testSnatPriorityRejectsUnknown = {
    expr = evalFails (snatIn (masqueradeBody // { priority = "wat"; })).priority;
    expected = true;
  };

  # ===== snat.chain — null default =====

  testSnatChainDefaultNull = {
    expr = (snatIn masqueradeBody).chain;
    expected = null;
  };

  testSnatChainAccepted = {
    expr =
      (snatIn (
        masqueradeBody
        // {
          chain = {
            hook = "output";
            priority = "srcnat";
          };
        }
      )).chain;
    expected = {
      hook = "output";
      priority = "srcnat";
    };
  };

  # ===== snat.comment — optional =====

  testSnatCommentDefault = {
    expr = (snatIn masqueradeBody).comment;
    expected = null;
  };
}
