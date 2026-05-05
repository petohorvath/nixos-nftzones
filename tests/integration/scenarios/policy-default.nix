/*
  Policy scenario — filter rule plus default policy (drop). The
  policy must land as the tail rule of the same sub-chain, after
  the filter rule. Exercises the policy-as-tail-rule sort
  contract.
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

  policies.lan-to-wan = {
    from = [ "lan" ];
    to = [ "wan" ];
    verdict = "drop";
  };
}
