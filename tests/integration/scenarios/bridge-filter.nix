/*
  Bridge family scenario — minimal L2 filter on a bridged-port
  zone. Exercises family-aware priority canonicalization
  (`priorityNameOf "bridge" (-200) == "filter"` so the chain
  name lands in `"forward-at-filter"`, not `"forward-at-(-200)"`)
  and chain-type derivation (`chainTypeFor "bridge" "forward"
  "filter" == "filter"`). Bridge `nat` and `route` chain types
  are rejected upstream by `checkChainPlacement`, so this
  scenario stays L2-pure.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  body = {
    family = "bridge";

    zones.bridged = {
      interfaces = [ "br0" ];
    };

    filters.allow-bridged = {
      from = [ "bridged" ];
      to = [ "bridged" ];
      rule = [ accept ];
    };
  };

  assertions = compiled: [
    {
      description = "table family is bridge";
      expr = compiled.tables.bridge-filter.family;
      expected = "bridge";
    }
    {
      description = "base chain name uses canonical priority 'filter', not raw -200";
      expr = compiled.tables.bridge-filter.chains ? "forward-at-filter";
      expected = true;
    }
    {
      description = "base chain type is filter (canonicalized via chainTypeFor)";
      expr = compiled.tables.bridge-filter.chains."forward-at-filter".type;
      expected = "filter";
    }
    {
      description = "base chain prio is bridge-family -200 (numeric form on the wire)";
      expr = compiled.tables.bridge-filter.chains."forward-at-filter".prio;
      expected = -200;
    }
  ];
}
