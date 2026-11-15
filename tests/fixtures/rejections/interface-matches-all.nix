/*
  Rejection scenario for `interfaceMatchesAll` — `lan` lists `*`.
  nft reads the bare `*` set element as a catch-all, so `lan`
  would match `wan`'s `eth0` and every unzoned interface, and
  the lan->local accept would admit wan traffic.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  description = "interfaceMatchesAll: zone lists `*` as an interface";

  errors = [
    {
      tag = "interfaceMatchesAll";
      path = [
        "zones"
        "lan"
        "interfaces"
      ];
    }
  ];

  body = {
    zones = {
      lan.interfaces = [ "*" ];
      wan.interfaces = [ "eth0" ];
    };
    filters.lan-ssh = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = [ accept ];
    };
  };
}
