/*
  IPv4-only family scenario — `family = "ip"` forces the table
  into the v4-only kernel netfilter codepath. Exercises the
  `priorityNameOf "ip"` and `chainTypeFor "ip" ...` lookups
  separately from the inet/bridge paths already covered.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    family = "ip";

    zones = {
      lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
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
      description = "table family is ip";
      expr = compiled.tables.family-ip.family;
      expected = "ip";
    }
    {
      description = "lan zone has v4 set but no v6 set (v4-only family)";
      expr = {
        v4 = compiled.tables.family-ip.sets ? lan_v4;
        v6 = compiled.tables.family-ip.sets ? lan_v6;
      };
      expected = {
        v4 = true;
        v6 = false;
      };
    }
  ];
}
