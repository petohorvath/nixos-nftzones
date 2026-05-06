/*
  Parent-priorities scenario — pre-child vs post-child slot
  semantics around the child-dispatch jump. The `early` rule
  (priority < 100) lands in dmz's preChildCells (fires before
  child dispatch); `late` (priority >= 100) lands in
  postChildCells (fires after child returns).
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept drop;
  inherit (nftypes.dsl.fields) tcp ip;
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

  filters = {
    early-block = {
      from = [ "dmz" ];
      to = [ "local" ];
      priority = "preDispatch";
      rule = [
        (eq ip.saddr "10.0.0.99")
        drop
      ];
    };

    late-rate-limit = {
      from = [ "dmz" ];
      to = [ "local" ];
      priority = "last";
      rule = [
        (eq tcp.dport 22)
        accept
      ];
    };

    web-server-http = {
      from = [ "web-server" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 80)
        accept
      ];
    };
  };
}
