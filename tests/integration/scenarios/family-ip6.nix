/*
  IPv6-only family scenario — `family = "ip6"` forces the table
  into the v6-only kernel netfilter codepath. The dual-stack
  scenario covers `inet` with both families; this one pins the
  v6-only path on its own.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  family = "ip6";

  zones = {
    lan = {
      interfaces = [ "lan0" ];
      cidrs = [ "fd00:abcd::/64" ];
    };
    wan.interfaces = [ "wan0" ];
  };

  filters.allow-ssh-from-lan = {
    from = [ "lan" ];
    to = [ "local" ];
    rule = [
      (eq tcp.dport 22)
      accept
    ];
  };
}
