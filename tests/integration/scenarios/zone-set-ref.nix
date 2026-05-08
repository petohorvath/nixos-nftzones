/*
  Zone-set-ref scenario — a user rule body references a
  zone-derived auto-set (`@<zone>_v4`) directly via a raw match
  clause. Pins the option-(a) namespace resolution decided in
  `docs/compile-pipeline.md` §Open questions item 6:
  `checkObjectRefs` resolves names against the union of
  `table.objects.sets.<name>` keys and the predictable
  `<zone>_{iifs,v4,v6}` names — a user can use an auto-set as an
  escape hatch for raw `match`-against-zone-membership without
  declaring a parallel user set.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) inSet accept expr;
  inherit (nftypes.dsl.fields) ip;
in
{
  body = {
    zones = {
      lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      wan.interfaces = [ "wan0" ];
    };

    filters.lan-v4-out = {
      from = [ "lan" ];
      to = [ "wan" ];
      # Raw `@lan_v4` match — referencing the auto-emitted
      # zone-derived v4 set rather than re-declaring the CIDR
      # under `objects.sets`. Compiles only because
      # checkObjectRefs accepts zone-derived names.
      rule = [
        (inSet ip.saddr (expr.setRef "lan_v4"))
        accept
      ];
    };
  };

  assertions = compiled: [
    {
      description = "auto-emitted lan_v4 set is present in the rendered table";
      expr = compiled.tables.zone-set-ref.sets ? "lan_v4";
      expected = true;
    }
  ];
}
