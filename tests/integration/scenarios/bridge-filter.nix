/*
  Bridge family scenario — minimal L2 filter on a bridged-port
  zone. Exercises family-aware priority canonicalization
  (`priorityNameOf "bridge" (-200) == "filter"` so the chain
  name lands in `"input-at-filter"`, not `"input-at-(-200)"`)
  and chain-type derivation (`chainTypeFor "bridge" "input"
  "filter" == "filter"`). Bridge `nat` and `route` chain types
  are rejected upstream by `checkChainPlacement`, so this
  scenario stays L2-pure.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  family = "bridge";

  zones.bridged = {
    interfaces = [ "br0" ];
  };

  filters.allow-bridged = {
    from = [ "bridged" ];
    to = [ "bridged" ];
    rule = [ accept ];
  };
}
