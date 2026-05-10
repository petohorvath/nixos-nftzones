/*
  Named-objects scenario — rule body references a counter and a
  set declared in `objects`. Exercises object-ref validation and
  user-object pass-through into the rendered table.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl)
    inSet
    counter
    accept
    expr
    ;
  inherit (nftypes.dsl.fields) ip;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    objects = {
      counters.lan-out-hits = { };
      sets.trusted-v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        # Structured prefix avoids nft's NSS path on bare-string CIDRs.
        elem = [ (expr.prefix "10.0.0.0" 24) ];
      };
    };

    filters.allow-trusted = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [
        (inSet ip.saddr (expr.setRef "trusted-v4"))
        (counter.ref "lan-out-hits")
        accept
      ];
    };
  };

  assertions = compiled: [
    {
      description = "user counter passes through to the rendered table";
      expr =
        compiled.tables.named-objects ? counters && compiled.tables.named-objects.counters ? lan-out-hits;
      expected = true;
    }
    {
      description = "user set merges with auto zone-derived sets under one body.sets";
      expr = compiled.tables.named-objects.sets ? "trusted-v4";
      expected = true;
    }
  ];
}
