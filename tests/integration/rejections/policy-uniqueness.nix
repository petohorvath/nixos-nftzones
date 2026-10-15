/*
  Rejection scenario for `policyConflict` — two policy
  entries claim the same `(from, to)` pair. The compile would
  emit two tail rules in the same sub-chain with conflicting
  verdicts; Phase 1 must reject the ambiguity.
*/
_: {
  description = "policyConflict: two policies for same (from, to)";

  errors = [
    {
      tag = "policyConflict";
      path = [
        "policies"
        "a"
      ];
    }
  ];

  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    policies = {
      a = {
        from = [ "lan" ];
        to = [ "wan" ];
        verdict = "accept";
      };
      b = {
        from = [ "lan" ];
        to = [ "wan" ];
        verdict = "drop";
      };
    };
  };
}
