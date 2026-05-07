/*
  Rejection scenario for `checkPolicyUniqueness` — one
  explicit policy and one wildcard-from policy collide on the
  same `(from, to)` cell after wildcard expansion. The
  complementary case (two explicit policies on the same pair)
  is covered by policy-uniqueness.nix; this one pins that the
  validator runs *after* `expandWildcardZones` in the live
  pipeline.
*/
_: {
  description = "checkPolicyUniqueness: explicit + wildcard collide on (lan → wan)";

  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    policies = {
      broad = {
        # `from = [ "all" ]` expands to every root zone plus
        # localZone, including `lan`.
        from = [ "all" ];
        to = [ "wan" ];
        verdict = "accept";
      };
      specific = {
        from = [ "lan" ];
        to = [ "wan" ];
        verdict = "drop";
      };
    };
  };
}
