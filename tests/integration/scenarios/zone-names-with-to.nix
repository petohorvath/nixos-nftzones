/*
  Regression scenario for issue #18 — zone names may contain `-to-`.
  The pairs `a-to → b` and `a → to-b` would both build
  `…__a-to-to-b` with a lowercase separator and share one sub-chain
  behind one jump. The uppercase `-TO-` separator, which no zone
  name can contain, gives each pair its own sub-chain and its own
  base-chain jump.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl)
    accept
    expr
    inSet
    jump
    ;
  inherit (nftypes.dsl.fields) meta;
in
{
  body = {
    # Stateful boilerplate off so the base chain carries only the
    # dispatch jumps.
    settings.stateful = false;

    zones = {
      a.interfaces = [ "eth-a" ];
      a-to.interfaces = [ "eth-ato" ];
      b.interfaces = [ "eth-b" ];
      to-b.interfaces = [ "eth-tob" ];
    };

    filters = {
      x = {
        from = [ "a-to" ];
        to = [ "b" ];
        rule = [ accept ];
        comment = "x";
      };
      y = {
        from = [ "a" ];
        to = [ "to-b" ];
        rule = [ accept ];
        comment = "y";
      };
    };
  };

  assertions = compiled: [
    {
      description = "each pair gets its own sub-chain";
      expr = builtins.attrNames compiled.table.chains;
      expected = [
        "forward-at-filter"
        "forward-at-filter__a-TO-to-b"
        "forward-at-filter__a-to-TO-b"
      ];
    }
    {
      description = "each pair's jump is gated on its own zones";
      expr = compiled.table.chains."forward-at-filter".rules;
      expected = [
        [
          (inSet meta.iifname (expr.setRef "a_iifs"))
          (inSet meta.oifname (expr.setRef "to-b_iifs"))
          (jump "forward-at-filter__a-TO-to-b")
        ]
        [
          (inSet meta.iifname (expr.setRef "a-to_iifs"))
          (inSet meta.oifname (expr.setRef "b_iifs"))
          (jump "forward-at-filter__a-to-TO-b")
        ]
      ];
    }
    {
      description = "each sub-chain holds only its own filter";
      expr = {
        "a → to-b" = compiled.table.chains."forward-at-filter__a-TO-to-b".rules;
        "a-to → b" = compiled.table.chains."forward-at-filter__a-to-TO-b".rules;
      };
      expected = {
        "a → to-b" = [
          {
            expr = [ accept ];
            comment = "y";
          }
        ];
        "a-to → b" = [
          {
            expr = [ accept ];
            comment = "x";
          }
        ];
      };
    }
  ];
}
