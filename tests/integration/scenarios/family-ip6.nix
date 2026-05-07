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
  body = {
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
  };

  assertions = compiled: [
    {
      description = "table family is ip6";
      expr = compiled.tables.family-ip6.family;
      expected = "ip6";
    }
    {
      description = "lan zone has v6 set but no v4 set (v6-only family)";
      expr = {
        v4 = compiled.tables.family-ip6.sets ? lan_v4;
        v6 = compiled.tables.family-ip6.sets ? lan_v6;
      };
      expected = {
        v4 = false;
        v6 = true;
      };
    }
  ];
}
