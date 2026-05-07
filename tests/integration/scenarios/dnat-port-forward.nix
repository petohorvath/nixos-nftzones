/*
  DNAT scenario — forward inbound HTTPS to an internal host.
  Single-direction (`from` only) lands in prerouting@dstnat with
  type=nat. Exercises the action.dnat dispatch path and verifies
  rule-body emission for `{ match; action.dnat; }` shape.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq dnat;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    zones.wan.interfaces = [ "wan0" ];

    dnats.public-https = {
      from = [ "wan" ];
      rule = {
        match = [ (eq tcp.dport 443) ];
        # `family = "ip"` is required in `inet`-family tables — nft
        # otherwise can't disambiguate ip-vs-ip6 dnat targets.
        action.dnat = {
          family = "ip";
          addr = "10.0.0.5";
          port = 443;
        };
      };
    };
  };

  assertions = compiled: [
    {
      description = "dnat rule lands at prerouting-at-dstnat (nat-family base chain)";
      expr = compiled.tables.dnat-port-forward.chains ? "prerouting-at-dstnat__wan";
      expected = true;
    }
    {
      description = "base chain type is nat";
      expr = compiled.tables.dnat-port-forward.chains."prerouting-at-dstnat".type;
      expected = "nat";
    }
    {
      description = "rule body is match clauses followed by the dnat statement";
      expr = builtins.elemAt compiled.tables.dnat-port-forward.chains."prerouting-at-dstnat__wan".rules 0;
      expected = [
        (eq tcp.dport 443)
        (dnat {
          family = "ip";
          addr = "10.0.0.5";
          port = 443;
        })
      ];
    }
  ];
}
