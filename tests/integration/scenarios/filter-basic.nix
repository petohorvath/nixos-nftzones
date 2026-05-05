/*
  Filter scenario — one bidirectional filter rule. Exercises the
  complete forward chain wiring: zone-derived sets, base chain
  with stateful preamble, sub-chain with the user rule, jump rule
  in the base chain.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
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
}
