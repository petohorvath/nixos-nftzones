/*
  Rejection scenario for `checkZoneMatchable` — a filter
  references a zone that has no matchable content (no
  interfaces, no CIDRs, no matchOverride). The dispatcher would
  emit an empty match set, producing rules that match nothing.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  description = "checkZoneMatchable: filter.from points to zone with no match content";

  body = {
    zones = {
      lan.interfaces = [ "eth1" ];
      empty = { };
    };

    filters.f = {
      from = [ "empty" ];
      to = [ "lan" ];
      rule = [ accept ];
    };
  };
}
