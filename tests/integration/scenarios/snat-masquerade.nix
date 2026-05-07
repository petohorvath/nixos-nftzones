/*
  SNAT scenario — masquerade lan-out traffic. Lands in the
  postrouting@srcnat base chain with type=nat. Exercises the
  snat-via-rule.masquerade dispatch path.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) masquerade;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    snats.lan-out = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule.masquerade = { };
    };
  };

  assertions = compiled: [
    {
      description = "snat rule lands at postrouting-at-srcnat (nat-family base chain)";
      expr = compiled.tables.snat-masquerade.chains ? "postrouting-at-srcnat__lan-to-wan";
      expected = true;
    }
    {
      description = "base chain type is nat";
      expr = compiled.tables.snat-masquerade.chains."postrouting-at-srcnat".type;
      expected = "nat";
    }
    {
      description = "rule body is the bare masquerade statement";
      expr =
        builtins.elemAt compiled.tables.snat-masquerade.chains."postrouting-at-srcnat__lan-to-wan".rules
          0;
      expected = [ (masquerade { }) ];
    }
  ];
}
