/*
  Rejection scenario for `checkZoneRefs` — a filter references a
  `from` zone that doesn't exist in `mergedZones`. Without
  rejection, downstream emit would either crash on missing zone
  data or silently emit a chain referencing a non-existent set.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  description = "checkZoneRefs: filter.from points to undeclared zone";

  body = {
    zones.lan.interfaces = [ "eth1" ];

    filters.f = {
      from = [ "ghost" ];
      to = [ "lan" ];
      rule = [ accept ];
    };
  };
}
