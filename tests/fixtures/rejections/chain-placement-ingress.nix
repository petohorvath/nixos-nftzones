/*
  Rejection scenario for `chainPlacementInvalid` — a filter pinned
  to the inet `ingress` hook. An ingress base chain sees traffic only
  on the devices it is bound to, and the chain model has no device
  binding, so the emitted chain would bind to no device and never see
  a packet. nft accepts it, so without rejection the entry's drop
  would load and silently do nothing.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) drop;
in
{
  description = "chainPlacementInvalid: filter at the inet ingress hook (no device binding)";

  errors = [
    {
      tag = "chainPlacementInvalid";
      path = [
        "filters"
        "early-drop"
      ];
    }
  ];

  body = {
    zones = {
      bogons.cidrs = [ "240.0.0.0/4" ];
      lan.cidrs = [ "192.168.1.0/24" ];
    };

    filters.early-drop = {
      from = [ "bogons" ];
      to = [ "lan" ];
      chain = {
        hook = "ingress";
        priority = "filter";
      };
      rule = [ drop ];
    };
  };
}
