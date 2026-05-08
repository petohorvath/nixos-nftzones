/*
  Unit tests for `lib/types/dnat.nix` (exposed as
  `nftzones.types.{dnat,dnatName,dnatZones,dnatRule,dnatPriority,
  dnatChain,dnatComment}`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by
  `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) evalTable evalFails;

  inherit (nftypes.dsl) eq;
  inherit (nftypes.dsl.fields) tcp;

  basicBody = {
    from = [ "wan" ];
    rule = {
      match = [ (eq tcp.dport 443) ];
      action.dnat = {
        addr = "10.0.0.5";
        port = 443;
      };
    };
  };

  dnatIn =
    body:
    (evalTable {
      dnats.web-fwd = body;
    }).dnats.web-fwd;
in
{
  # ===== dnat.name — derives from attrset key =====

  testDnatNameDerivedFromKey = {
    expr = (dnatIn basicBody).name;
    expected = "web-fwd";
  };

  # ===== dnat has `from` only (no `to`) =====

  testDnatFromAccepted = {
    expr = (dnatIn basicBody).from;
    expected = [ "wan" ];
  };

  testDnatFromEmptyRejected = {
    expr = evalFails (dnatIn (basicBody // { from = [ ]; })).from;
    expected = true;
  };

  testDnatHasNoToField = {
    expr = evalFails (dnatIn (basicBody // { to = [ "lan" ]; })).to;
    expected = true;
  };

  # ===== dnat.rule.match — defaults to [ ] =====

  testDnatRuleMatchDefault = {
    expr =
      (dnatIn {
        from = [ "wan" ];
        rule.action.dnat = {
          addr = "10.0.0.5";
          port = 443;
        };
      }).rule.match;
    expected = [ ];
  };

  testDnatRuleMatchAccepted = {
    expr = (dnatIn basicBody).rule.match;
    expected = [ (eq tcp.dport 443) ];
  };

  # ===== dnat.rule.action — attrTag {dnat, redirect} =====

  testDnatRuleActionDnat = {
    # natBody fills `family`/`flags`/`type_flags` with null
    # defaults at submodule-eval time alongside user-supplied fields.
    expr = (dnatIn basicBody).rule.action;
    expected = {
      dnat = {
        addr = "10.0.0.5";
        family = null;
        flags = null;
        port = 443;
        type_flags = null;
      };
    };
  };

  testDnatRuleActionRedirect = {
    expr =
      (dnatIn {
        from = [ "wan" ];
        rule.action.redirect = {
          port = 22;
        };
      }).rule.action;
    expected = {
      redirect = {
        flags = null;
        port = 22;
      };
    };
  };

  testDnatRuleActionRejectsBothVariants = {
    expr =
      evalFails
        (dnatIn {
          from = [ "wan" ];
          rule.action = {
            dnat.addr = "10.0.0.5";
            redirect = { };
          };
        }).rule.action;
    expected = true;
  };

  testDnatRuleActionRejectsUnknownTag = {
    expr =
      evalFails
        (dnatIn {
          from = [ "wan" ];
          rule.action.snat = { };
        }).rule.action;
    expected = true;
  };

  # ===== dnat.priority — default "default" =====

  testDnatPriorityDefault = {
    expr = (dnatIn basicBody).priority;
    expected = "default";
  };

  # ===== dnat.chain — null default =====

  testDnatChainDefaultNull = {
    expr = (dnatIn basicBody).chain;
    expected = null;
  };
}
