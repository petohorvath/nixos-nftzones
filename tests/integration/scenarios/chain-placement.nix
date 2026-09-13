/*
  Shared placement through the full compiler: custom local and
  wildcard names, filter/policy hooks, override precedence, and
  family-aware coalescing of integer and symbol priorities.
*/
{ nftypes, ... }:
let
  mkBody = family: filterPriority: {
    inherit family;
    settings = {
      localZone = "host";
      wildcardZone = "any";
    };
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };
    filters = {
      all-directions = {
        from = [ "any" ];
        to = [ "any" ];
        rule = [ nftypes.dsl.accept ];
      };
      integer-override = {
        from = [ "wan" ];
        to = [ "host" ];
        rule = [ nftypes.dsl.drop ];
        chain = {
          hook = "input";
          priority = filterPriority;
        };
      };
      early-override = {
        from = [ "wan" ];
        to = [ "host" ];
        rule = [ nftypes.dsl.drop ];
        chain = {
          hook = "prerouting";
          priority = -450;
        };
      };
    };
    policies.outbound = {
      from = [ "host" ];
      to = [ "wan" ];
      verdict = "drop";
    };
  };
in
{
  body = [
    {
      name = "inet-placement";
      body = mkBody "inet" 0;
    }
    {
      name = "bridge-placement";
      body = mkBody "bridge" (-200);
    }
  ];

  assertions =
    compiled:
    builtins.concatLists (
      map
        (
          name:
          let
            chains = compiled.tables.${name}.chains;
          in
          [
            {
              description = "${name}: wildcard directions use all three local-zone hooks; override gets its own chain";
              expr = builtins.attrNames chains;
              expected = [
                "forward-at-filter"
                "forward-at-filter__lan-to-lan"
                "forward-at-filter__lan-to-wan"
                "forward-at-filter__wan-to-lan"
                "forward-at-filter__wan-to-wan"
                "input-at-filter"
                "input-at-filter__host-to-host"
                "input-at-filter__lan-to-host"
                "input-at-filter__wan-to-host"
                "output-at-filter"
                "output-at-filter__host-to-lan"
                "output-at-filter__host-to-wan"
                "prerouting-at--450"
                "prerouting-at--450__wan-to-host"
              ];
            }
            {
              description = "${name}: emitted base-chain hooks follow placement";
              expr = map (key: chains.${key}.hook) [
                "forward-at-filter"
                "input-at-filter"
                "output-at-filter"
                "prerouting-at--450"
              ];
              expected = [
                "forward"
                "input"
                "output"
                "prerouting"
              ];
            }
            {
              description = "${name}: integer and symbol priorities share the input sub-chain";
              expr = chains."input-at-filter__wan-to-host".rules;
              expected = [
                [ nftypes.dsl.accept ]
                [ nftypes.dsl.drop ]
              ];
            }
            {
              description = "${name}: policy follows the filter in the output sub-chain";
              expr = chains."output-at-filter__host-to-wan".rules;
              expected = [
                [ nftypes.dsl.accept ]
                [ nftypes.dsl.drop ]
              ];
            }
            {
              description = "${name}: overridden rule appears at its explicit placement";
              expr = chains."prerouting-at--450__wan-to-host".rules;
              expected = [ [ nftypes.dsl.drop ] ];
            }
          ]
        )
        [
          "inet-placement"
          "bridge-placement"
        ]
    );
}
