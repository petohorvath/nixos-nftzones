/*
  Parent-deep-nesting scenario — three-level hierarchy:
  `corp` (root) → `dmz` → `web-server` (node). Validates that
  intermediate parents synthesize transparent dispatchers, and
  base-chain jumps emit only for the root (corp).
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  zones.corp = {
    interfaces = [ "corp0" ];
    cidrs = [ "10.0.0.0/16" ];
  };

  zones.dmz = {
    parent = "corp";
    interfaces = [ "dmz0" ];
    cidrs = [ "10.0.0.0/24" ];
  };

  nodes.web-server = {
    zone = "dmz";
    address.ipv4 = "10.0.0.5";
  };

  filters.web-server-http = {
    from = [ "web-server" ];
    to = [ "local" ];
    rule = [
      (eq tcp.dport 80)
      accept
    ];
  };
}
