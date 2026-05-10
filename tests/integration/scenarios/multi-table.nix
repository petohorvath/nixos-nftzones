/*
  Multi-table scenario — separate `ip` and `ip6` family tables
  composed into one ruleset. Exercises the multi-table render path
  and verifies both family-pinned outputs validate together.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;

  mkBody = family: lanCidr: wanCidr: {
    inherit family;
    zones = {
      lan = {
        interfaces = [ "lan0" ];
        cidrs = [ lanCidr ];
      };
      wan = {
        interfaces = [ "wan0" ];
        cidrs = [ wanCidr ];
      };
    };
    filters.allow-https = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [
        (eq tcp.dport 443)
        accept
      ];
    };
  };
in
{
  body = [
    {
      name = "fw-v4";
      body = mkBody "ip" "10.0.0.0/24" "203.0.113.0/24";
    }
    {
      name = "fw-v6";
      body = mkBody "ip6" "fd00::/8" "2000::/3";
    }
  ];

  assertions = compiled: [
    {
      description = "ruleset contains both tables keyed by name";
      expr = builtins.attrNames compiled.tables;
      expected = [
        "fw-v4"
        "fw-v6"
      ];
    }
    {
      description = "each table carries its declared family";
      expr = {
        v4 = compiled.tables."fw-v4".family;
        v6 = compiled.tables."fw-v6".family;
      };
      expected = {
        v4 = "ip";
        v6 = "ip6";
      };
    }
  ];
}
