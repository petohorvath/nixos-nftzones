/*
  DNAT scenario — forward inbound HTTPS to an internal host.
  Single-direction (`from` only) lands in prerouting@dstnat with
  type=nat. Exercises the action.dnat dispatch path and verifies
  rule-body emission for `{ match; action.dnat; }` shape.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq;
  inherit (nftypes.dsl.fields) tcp;
in
{
  zones.wan.interfaces = [ "wan0" ];

  dnats.public-https = {
    from = [ "wan" ];
    rule = {
      match = [ (eq tcp.dport 443) ];
      # `family = "ip"` is required in `inet`-family tables — nft
      # otherwise can't disambiguate ip-vs-ip6 dnat targets.
      action.dnat = {
        family = "ip";
        addr = "10.0.0.5";
        port = 443;
      };
    };
  };
}
