/*
  Filter scenario — one bidirectional filter rule. Exercises the
  complete forward chain wiring: zone-derived sets, base chain
  with stateful preamble, sub-chain with the user rule, jump rule
  in the base chain. Assertions pin the sub-chain name and rule
  body.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept;
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
  };

  assertions = compiled: [
    {
      description = "filter rule lands in forward-at-filter__lan-to-wan sub-chain";
      expr = compiled.tables.filter-basic.chains ? "forward-at-filter__lan-to-wan";
      expected = true;
    }
    {
      description = "sub-chain carries the user rule (1 entry)";
      expr = builtins.length compiled.tables.filter-basic.chains."forward-at-filter__lan-to-wan".rules;
      expected = 1;
    }
    {
      description = "rule body is the bare statement list (no comment wrap)";
      expr = builtins.elemAt compiled.tables.filter-basic.chains."forward-at-filter__lan-to-wan".rules 0;
      expected = [
        (eq tcp.dport 443)
        accept
      ];
    }
  ];
}
