/*
  SNAT scenario — explicit address rewrite (non-masquerade)
  with multi-zone fanout. Two `from` zones share one rule,
  producing two sub-chains under `postrouting-at-srcnat`.
  Exercises the `rule.snat = { ... }` path (full address
  translation) that `snat-masquerade.nix` doesn't cover, plus
  the from-side cartesian for SNATs.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) snat;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      guest.interfaces = [ "guest0" ];
      wan.interfaces = [ "wan0" ];
    };

    snats.uplink = {
      from = [
        "lan"
        "guest"
      ];
      to = [ "wan" ];
      # `family = "ip"` is required in `inet`-family tables —
      # nft otherwise can't disambiguate ip-vs-ip6 snat targets.
      rule.snat = {
        family = "ip";
        addr = "203.0.113.5";
      };
    };
  };

  assertions = compiled: [
    {
      description = "lan→wan sub-chain present";
      expr = compiled.tables.snat-explicit-rewrite.chains ? "postrouting-at-srcnat__lan-to-wan";
      expected = true;
    }
    {
      description = "guest→wan sub-chain present";
      expr = compiled.tables.snat-explicit-rewrite.chains ? "postrouting-at-srcnat__guest-to-wan";
      expected = true;
    }
    {
      description = "base chain type is nat";
      expr = compiled.tables.snat-explicit-rewrite.chains."postrouting-at-srcnat".type;
      expected = "nat";
    }
    {
      description = "lan→wan rule body is the snat statement";
      expr =
        builtins.elemAt
          compiled.tables.snat-explicit-rewrite.chains."postrouting-at-srcnat__lan-to-wan".rules
          0;
      expected = [
        (snat {
          family = "ip";
          addr = "203.0.113.5";
        })
      ];
    }
    {
      description = "guest→wan rule body matches lan→wan (shared rule)";
      expr =
        builtins.elemAt
          compiled.tables.snat-explicit-rewrite.chains."postrouting-at-srcnat__guest-to-wan".rules
          0;
      expected = [
        (snat {
          family = "ip";
          addr = "203.0.113.5";
        })
      ];
    }
  ];
}
