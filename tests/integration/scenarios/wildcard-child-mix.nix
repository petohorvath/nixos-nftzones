/*
  Wildcard-child-mix scenario — `from = [ "all" "iot" ]`, where
  `iot` is a child zone. The wildcard expands to root zones plus
  `localZone` only, so the explicit child adds its own sub-chain.

  The `wildcardZoneMixed` warning still calls the explicit name
  redundant, which this ruleset disproves. The expected warning
  pins today's misleading behaviour; fixing the warning shows up
  as a change to `warnings` here.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) accept eq;
  inherit (nftypes.dsl.fields) udp;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      iot = {
        cidrs = [ "10.0.1.0/24" ];
        parent = "lan";
      };
      wan.interfaces = [ "wan0" ];
    };

    filters.allow-dns = {
      from = [
        "all"
        "iot"
      ];
      to = [ "local" ];
      rule = [
        (eq udp.dport 53)
        accept
      ];
    };
  };

  warnings = [
    {
      tag = "wildcardZoneMixed";
      path = [
        "filters"
        "allow-dns"
        "from"
      ];
    }
  ];

  assertions = compiled: [
    {
      description = "the explicit child zone gets a sub-chain the wildcard alone would not";
      expr = compiled.table.chains ? "input-at-filter__iot-TO-local";
      expected = true;
    }
  ];
}
