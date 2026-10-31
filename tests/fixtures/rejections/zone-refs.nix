/*
  Rejection scenario for `zoneRefUnknown` — a filter references a
  `from` zone that is neither declared nor lowered from a node. Without
  rejection, downstream emit would either crash on missing zone
  data or silently emit a chain referencing a non-existent set.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  description = "zoneRefUnknown: filter.from points to undeclared zone";

  errors = [
    {
      tag = "zoneRefUnknown";
      path = [
        "filters"
        "f"
        "from"
        "0"
      ];
    }
  ];

  body = {
    zones.lan.interfaces = [ "eth1" ];

    filters.f = {
      from = [ "ghost" ];
      to = [ "lan" ];
      rule = [ accept ];
    };
  };
}
