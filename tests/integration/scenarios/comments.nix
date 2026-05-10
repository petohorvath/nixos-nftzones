/*
  Comment-propagation scenario — sets `comment` on the table and
  filter entry. The runner's parse-check catches malformed JSON;
  the structured assertions below pin the comment text actually
  surfacing on the compiled output, since `nft -j --check` is
  lenient about unknown fields and would silently accept a
  regression that dropped the comment during emit.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    comment = "main firewall";

    zones.wan = {
      interfaces = [ "wan0" ];
    };

    filters.allow-ssh = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
      comment = "ssh from anywhere";
    };
  };

  assertions = compiled: [
    {
      description = "table-level comment surfaces on compiled output";
      expr = compiled.tables.comments.comment;
      expected = "main firewall";
    }
    {
      description = "filter rule comment wraps the rule body";
      expr =
        (builtins.elemAt compiled.tables.comments.chains."input-at-filter__wan-to-local".rules 0).comment;
      expected = "ssh from anywhere";
    }
  ];
}
