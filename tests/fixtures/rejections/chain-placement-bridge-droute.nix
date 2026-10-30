/*
  Rejection scenario for `invalidChainPlacement` — bridge family
  with a droute rule. Symmetric to chain-placement-bridge-sroute:
  bridge has no `mangle` priority symbol, so destination-route
  mangling is unsupported at the kernel level. Pins that
  placement is checked for the droute group too, not just sroute.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;
in
{
  description = "invalidChainPlacement: bridge family + droute (no mangle priority)";

  errors = [
    {
      tag = "invalidChainPlacement";
      path = [
        "droutes"
        "mark-it"
      ];
    }
  ];

  body = {
    family = "bridge";

    zones.lan.interfaces = [ "br0" ];

    droutes.mark-it = {
      to = [ "lan" ];
      rule = [ (mangle meta.mark 1) ];
    };
  };
}
