/*
  Chain-override scenario — filter rule routed to prerouting@raw
  (an early-drop slot) instead of the default forward@filter.
  Exercises chain-override dispatch and base-chain wiring at
  non-default coordinates.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq drop expr;
  inherit (nftypes.dsl.fields) ip;
in
{
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
}
