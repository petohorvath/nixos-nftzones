/*
  Wildcard-expansion scenario — `from = [ "all" ]` fans out across
  every declared zone plus `localZone`. Validates the expanded
  cell stream renders to a multi-jump base chain that parses.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  zones = {
    lan.interfaces = [ "lan0" ];
    guest.interfaces = [ "guest0" ];
    wan.interfaces = [ "wan0" ];
  };

  # `all` resolves to lan, guest, wan, local — five cells against `to = local`.
  filters.allow-ssh = {
    from = [ "all" ];
    to = [ "local" ];
    rule = [
      (eq tcp.dport 22)
      accept
    ];
  };
}
