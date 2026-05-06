/*
  Parent-empty-intermediate scenario — parent zone has no rules
  of its own; only the child does. The intermediate parent
  sub-chain should be synthesized as a transparent dispatcher
  (just the child-dispatch jump, no own rules).
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

  # Only the child has a rule. dmz must still get a sub-chain
  # (the dispatcher) so traffic can reach web-server.
  filters.web-server-http = {
    from = [ "web-server" ];
    to = [ "local" ];
    rule = [
      (eq tcp.dport 80)
      accept
    ];
  };
}
