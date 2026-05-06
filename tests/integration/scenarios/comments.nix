/*
  Comment-propagation scenario — sets `comment` on the table and
  filter entry. Verifies the type system accepts the field and
  that the rendered ruleset passes `nft -j --check` with comments
  attached.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
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
}
