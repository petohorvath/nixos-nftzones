/*
  matchOverride scenario — a zone matched by a `meta mark` clause
  in the `extra` section, with no interfaces or CIDRs of its own.
  Exercises the `extra`-only direction-variant path (single
  prefix-only variant produced).
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) meta;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];

      # Marked zone: no interfaces / cidrs, matchable purely via mark.
      marked = {
        matchOverride = {
          ingress.extra = [ (eq meta.mark 256) ];
          egress.extra = [ (eq meta.mark 256) ];
        };
      };
    };

    filters.lan-to-marked = {
      from = [ "lan" ];
      to = [ "marked" ];
      rule = [ accept ];
    };
  };

  assertions = compiled: [
    {
      description = "extra-only zone produces no auto sets (no iifs/v4/v6)";
      expr = {
        iifs = compiled.tables.match-override.sets ? marked_iifs;
        v4 = compiled.tables.match-override.sets ? marked_v4;
        v6 = compiled.tables.match-override.sets ? marked_v6;
      };
      expected = {
        iifs = false;
        v4 = false;
        v6 = false;
      };
    }
    {
      description = "filter sub-chain to the override zone is emitted";
      expr = compiled.tables.match-override.chains ? "forward-at-filter__lan-to-marked";
      expected = true;
    }
  ];
}
