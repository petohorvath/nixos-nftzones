/*
  matchOverride per-section scenario — user supplies explicit
  `ipv4` and `ipv6` match expressions that replace the auto-
  derived `@<zone>_v4` / `@<zone>_v6` set lookups. The existing
  match-override scenario covers `extra`-only zones; this one
  covers the family-segregated section overrides that
  `mkDirectionVariants` flows separately.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept expr;
  inherit (nftypes.dsl.fields) ip ip6;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      custom = {
        # zone declared with no auto path — overrides supply both
        # ingress and egress on both families directly.
        matchOverride = {
          ingress.ipv4 = [ (eq ip.saddr (expr.prefix "10.99.0.0" 16)) ];
          ingress.ipv6 = [ (eq ip6.saddr (expr.prefix "fd00:99::" 32)) ];
          egress.ipv4 = [ (eq ip.daddr (expr.prefix "10.99.0.0" 16)) ];
          egress.ipv6 = [ (eq ip6.daddr (expr.prefix "fd00:99::" 32)) ];
        };
      };
    };

    filters.lan-to-custom = {
      from = [ "lan" ];
      to = [ "custom" ];
      rule = [ accept ];
    };
  };

  assertions = compiled: [
    {
      description = "override zone produces no auto sets — overrides take over both families";
      expr = {
        v4 = compiled.tables.match-override-sections.sets ? custom_v4;
        v6 = compiled.tables.match-override-sections.sets ? custom_v6;
      };
      expected = {
        v4 = false;
        v6 = false;
      };
    }
    {
      description = "lan-to-custom sub-chain emits with the user rule";
      expr = compiled.tables.match-override-sections.chains ? "forward-at-filter__lan-to-custom";
      expected = true;
    }
  ];
}
