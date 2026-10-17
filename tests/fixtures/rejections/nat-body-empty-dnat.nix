/*
  Rejection scenario for `natBodyMissingAddr` — `rule.action.dnat = { }`
  selects the `dnat` tag with an all-null body. Type accepts it
  (every nftypes `natBody` field is nullable); nft rejects the
  resulting `dnat to;` statement at activation. Phase 1
  catches it early with a clear error.
*/
_: {
  description = "natBodyMissingAddr: rule.action.dnat with null addr";

  errors = [
    {
      tag = "natBodyMissingAddr";
      path = [
        "dnats"
        "bad-fwd"
      ];
    }
  ];

  body = {
    zones.wan.interfaces = [ "wan0" ];

    dnats.bad-fwd = {
      from = [ "wan" ];
      rule = {
        match = [ ];
        action.dnat = { };
      };
    };
  };
}
