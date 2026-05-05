/*
  matchOverride scenario — a zone matched by a `meta mark` clause
  in the `extra` section, with no interfaces or CIDRs of its own.
  Exercises Phase 4's `mkDirectionVariants` `extra`-only path
  (single prefix-only variant produced).
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) meta;
in
{
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
}
