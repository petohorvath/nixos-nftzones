/*
  Rejection scenario for `checkPolicyUniqueness` — two policy
  entries claim the same `(from, to)` pair. The compile would
  emit two tail rules in the same sub-chain with conflicting
  verdicts; the validator must reject the ambiguity.
*/
_: {
  description = "checkPolicyUniqueness: two policies for same (from, to)";

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
