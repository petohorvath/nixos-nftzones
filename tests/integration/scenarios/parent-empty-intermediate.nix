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
  body = {
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
  };

  assertions = compiled: [
    {
      description = "parent dmz dispatcher is synthesized even with no own rules";
      expr = compiled.tables.parent-empty-intermediate.chains ? "input-at-filter__dmz-to-local";
      expected = true;
    }
    {
      description = "intermediate dispatcher carries exactly one rule (child-dispatch jump)";
      expr =
        builtins.length
          compiled.tables.parent-empty-intermediate.chains."input-at-filter__dmz-to-local".rules;
      expected = 1;
    }
    {
      description = "child sub-chain carries the user rule";
      expr = compiled.tables.parent-empty-intermediate.chains ? "input-at-filter__web-server-to-local";
      expected = true;
    }
  ];
}
