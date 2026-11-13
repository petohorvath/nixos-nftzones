/*
  Shared placement through the full compiler: custom local and
  wildcard names, filter/policy hooks, override precedence, and
  family-aware coalescing of integer and symbol priorities.

  A bridge table has no host-only match for the local zone outside
  the hooks that imply it (ADR-0013). Its copy therefore has no
  prerouting override, which would name `host` as a destination at
  prerouting, and emits no `host` to `host` cell, whose source would
  sit at input.
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
    }
    // (
      if family == "bridge" then
        { }
      else
        {
          early-override = {
            from = [ "wan" ];
            to = [ "host" ];
            rule = [ nftypes.dsl.drop ];
            chain = {
              hook = "prerouting";
              priority = -450;
            };
          };
        }
    );
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
            isBridge = name == "bridge-placement";
            # Chains only the inet copy emits; see the header.
            inetOnly = [
              "input-at-filter__host-TO-host"
              "prerouting-at--450"
              "prerouting-at--450__wan-TO-host"
            ];
            forFamily = builtins.filter (chain: !(isBridge && builtins.elem chain inetOnly));
          in
          [
            {
              description = "${name}: wildcard directions use all three local-zone hooks; override gets its own chain";
              expr = builtins.attrNames chains;
              expected = forFamily [
                "forward-at-filter"
                "forward-at-filter__lan-TO-lan"
                "forward-at-filter__lan-TO-wan"
                "forward-at-filter__wan-TO-lan"
                "forward-at-filter__wan-TO-wan"
                "input-at-filter"
                "input-at-filter__host-TO-host"
                "input-at-filter__lan-TO-host"
                "input-at-filter__wan-TO-host"
                "output-at-filter"
                "output-at-filter__host-TO-lan"
                "output-at-filter__host-TO-wan"
                "prerouting-at--450"
                "prerouting-at--450__wan-TO-host"
              ];
            }
            {
              description = "${name}: emitted base-chain hooks follow placement";
              expr = map (key: chains.${key}.hook) (forFamily [
                "forward-at-filter"
                "input-at-filter"
                "output-at-filter"
                "prerouting-at--450"
              ]);
              expected = [
                "forward"
                "input"
                "output"
              ]
              ++ (if isBridge then [ ] else [ "prerouting" ]);
            }
            {
              description = "${name}: integer and symbol priorities share the input sub-chain";
              expr = chains."input-at-filter__wan-TO-host".rules;
              expected = [
                [ nftypes.dsl.accept ]
                [ nftypes.dsl.drop ]
              ];
            }
            {
              description = "${name}: policy follows the filter in the output sub-chain";
              expr = chains."output-at-filter__host-TO-wan".rules;
              expected = [
                [ nftypes.dsl.accept ]
                [ nftypes.dsl.drop ]
              ];
            }
          ]
          ++ (
            if isBridge then
              [ ]
            else
              [
                {
                  description = "${name}: overridden rule appears at its explicit placement";
                  expr = chains."prerouting-at--450__wan-TO-host".rules;
                  expected = [ [ nftypes.dsl.drop ] ];
                }
              ]
          )
        )
        [
          "inet-placement"
          "bridge-placement"
        ]
    );
}
