/*
  SNAT scenario — masquerade only lan→wan TCP traffic to ports
  80 and 443. Exercises an snat body with a `match`: the pair's
  sub-chain rule is the match statements followed by the
  masquerade statement, so the rewrite applies only to packets
  that match.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq inSet masquerade;
  inherit (nftypes.dsl.fields) meta tcp;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    snats.lan-web-out = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = {
        match = [
          (eq meta.l4proto "tcp")
          (inSet tcp.dport [
            80
            443
          ])
        ];
        action.masquerade = { };
      };
    };
  };

  assertions = compiled: [
    {
      description = "rule body is the match statements followed by masquerade";
      expr = builtins.elemAt compiled.table.chains."postrouting-at-srcnat__lan-TO-wan".rules 0;
      expected = [
        (eq meta.l4proto "tcp")
        (inSet tcp.dport [
          80
          443
        ])
        (masquerade { })
      ];
    }
  ];
}
