/*
  Chain-override scenario — filter rule routed to prerouting@raw
  (an early-drop slot) instead of the default forward@filter.
  Exercises chain-override dispatch and base-chain wiring at
  non-default coordinates. Assertions pin the override
  destination chain.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq drop expr;
  inherit (nftypes.dsl.fields) ip;
in
{
  body = {
    zones = {
      wan = {
        interfaces = [ "wan0" ];
        cidrs = [ "203.0.113.0/24" ];
      };
    };

    filters.early-drop-loopback = {
      from = [ "wan" ];
      to = [ "wan" ];
      # Bogon source from loopback range — explicit prefix avoids
      # nft's DNS-resolution path on bare-string operands.
      rule = [
        (eq ip.saddr (expr.prefix "127.0.0.0" 8))
        drop
      ];
      chain = {
        hook = "prerouting";
        priority = "raw";
      };
    };
  };

  assertions = compiled: [
    {
      description = "rule lands at the override coordinates, not the default forward@filter";
      expr = builtins.attrNames compiled.tables.chain-override.chains;
      expected = [
        "prerouting-at-raw"
        "prerouting-at-raw__wan-to-wan"
      ];
    }
    {
      description = "override base chain hook is prerouting";
      expr = compiled.tables.chain-override.chains."prerouting-at-raw".hook;
      expected = "prerouting";
    }
  ];
}
