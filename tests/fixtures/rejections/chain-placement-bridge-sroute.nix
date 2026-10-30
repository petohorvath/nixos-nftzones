/*
  Rejection scenario for `chainPlacementInvalid` — bridge family
  with an sroute rule. Bridge has no `mangle` priority symbol,
  so source-route mangling is unsupported at the kernel level.
  The complementary case (bridge + snat, which exercises the
  invalid chain-type branch) is covered by chain-placement.nix;
  this one pins the null-priority-symbol branch via the route
  path.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;
in
{
  description = "chainPlacementInvalid: bridge family + sroute (no mangle priority)";

  errors = [
    {
      tag = "chainPlacementInvalid";
      path = [
        "sroutes"
        "mark-it"
      ];
    }
  ];

  body = {
    family = "bridge";

    zones.lan.interfaces = [ "br0" ];

    sroutes.mark-it = {
      from = [ "lan" ];
      rule = [ (mangle meta.mark 1) ];
    };
  };
}
