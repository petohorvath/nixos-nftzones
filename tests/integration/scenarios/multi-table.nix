/*
  Multi-table scenario — separate `ip` and `ip6` family tables
  composed into one ruleset. Exercises the multi-table render path
  and verifies both family-pinned outputs validate together.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
[
  {
    name = "fw-v4";
    body = {
      family = "ip";
      zones = {
        lan = {
          interfaces = [ "lan0" ];
          cidrs = [ "10.0.0.0/24" ];
        };
        wan = {
          interfaces = [ "wan0" ];
          cidrs = [ "203.0.113.0/24" ];
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
  }
  {
    name = "fw-v6";
    body = {
      family = "ip6";
      zones = {
        lan = {
          interfaces = [ "lan0" ];
          cidrs = [ "fd00::/8" ];
        };
        wan = {
          interfaces = [ "wan0" ];
          cidrs = [ "2000::/3" ];
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
  }
]
