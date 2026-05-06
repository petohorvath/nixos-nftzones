/*
  Parent-basic scenario — one zone with one child node. Validates
  that the lowered child gets a sub-chain reachable via the
  parent's transparent dispatcher, and the parent's own rule lands
  in `postChildCells` as fallback.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  zones.dmz = {
    interfaces = [ "dmz0" ];
    cidrs = [ "10.0.0.0/24" ];
  };

  nodes.web-server = {
    zone = "dmz";
    address.ipv4 = "10.0.0.5";
  };

  filters.dmz-rate-limit = {
    from = [ "dmz" ];
    to = [ "local" ];
    rule = [
      (eq tcp.dport 22)
      accept
    ];
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
