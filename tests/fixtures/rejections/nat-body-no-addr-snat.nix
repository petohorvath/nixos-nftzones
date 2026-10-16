/*
  Rejection scenario for `natBodyMissingAddr` — `rule.snat` with a
  port and no `addr`. nftypes' `natBody` type accepts it (it needs
  an `addr` or a `port`), but nftzones requires a target address,
  pointing to `masquerade` as the no-address alternative. Phase 1
  catches it early with a clear error.
*/
_: {
  description = "natBodyMissingAddr: rule.snat with null addr";

  errors = [
    {
      tag = "natBodyMissingAddr";
      path = [
        "snats"
        "outbound"
      ];
    }
  ];

  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    snats.outbound = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule.snat.port = 8080;
    };
  };
}
