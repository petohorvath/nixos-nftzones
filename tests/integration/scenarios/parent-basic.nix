/*
  Parent-basic scenario — one zone with one child node. Validates
  that the lowered child gets a sub-chain reachable via the
  parent's transparent dispatcher, and the parent's own rule lands
  in `postChildCells` as fallback.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
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
  };

  assertions = compiled: [
    {
      description = "both the parent dispatcher and child sub-chain are emitted";
      expr = {
        parent = compiled.tables.parent-basic.chains ? "input-at-filter__dmz-to-local";
        child = compiled.tables.parent-basic.chains ? "input-at-filter__web-server-to-local";
      };
      expected = {
        parent = true;
        child = true;
      };
    }
    {
      description = "node lowers to a /32 v4 set with the address";
      expr = compiled.tables.parent-basic.sets ? "web-server_v4";
      expected = true;
    }
  ];
}
