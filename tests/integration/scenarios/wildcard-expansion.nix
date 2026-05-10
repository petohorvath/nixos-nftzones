/*
  Wildcard-expansion scenario — `from = [ "all" ]` fans out across
  every declared zone plus `localZone`. Validates the expanded
  cell stream renders to a multi-jump base chain that parses.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      guest.interfaces = [ "guest0" ];
      wan.interfaces = [ "wan0" ];
    };

    # `all` resolves to lan, guest, wan, local — four cells against `to = local`.
    filters.allow-ssh = {
      from = [ "all" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
    };
  };

  assertions = compiled: [
    {
      description = "wildcard 'all' expands to one sub-chain per zone (lan, guest, wan, local)";
      expr = builtins.attrNames compiled.tables.wildcard-expansion.chains;
      expected = [
        "input-at-filter"
        "input-at-filter__guest-to-local"
        "input-at-filter__lan-to-local"
        "input-at-filter__local-to-local"
        "input-at-filter__wan-to-local"
      ];
    }
  ];
}
