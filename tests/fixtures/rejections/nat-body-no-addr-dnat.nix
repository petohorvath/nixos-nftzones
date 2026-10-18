/*
  Rejection scenario for `natBodyMissingAddr` — `rule.action.dnat` with a
  port and no `addr`. nftypes' `natBody` type accepts it (it needs
  an `addr` or a `port`), but nftzones requires a target address,
  pointing to `redirect` as the no-address alternative. Phase 1
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
        action.dnat.port = 8080;
      };
    };
  };
}
