/*
  Policy scenario — filter rule plus default policy (drop). The
  policy must land as the tail rule of the same sub-chain, after
  the filter rule. Exercises the policy-as-tail-rule sort
  contract.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept drop;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    filters.allow-https = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [
        (eq tcp.dport 443)
        accept
      ];
    };

    policies.lan-to-wan = {
      from = [ "lan" ];
      to = [ "wan" ];
      verdict = "drop";
    };
  };

  assertions = compiled: [
    {
      description = "filter and policy share the same lan-to-wan sub-chain (2 rules total)";
      expr = builtins.length compiled.tables.policy-default.chains."forward-at-filter__lan-to-wan".rules;
      expected = 2;
    }
    {
      description = "filter rule is first (preDispatch-priority precedes policy)";
      expr =
        builtins.elemAt compiled.tables.policy-default.chains."forward-at-filter__lan-to-wan".rules
          0;
      expected = [
        (eq tcp.dport 443)
        accept
      ];
    }
    {
      description = "policy is the tail rule (last entry — sort contract)";
      expr =
        builtins.elemAt compiled.tables.policy-default.chains."forward-at-filter__lan-to-wan".rules
          1;
      expected = [ drop ];
    }
  ];
}
