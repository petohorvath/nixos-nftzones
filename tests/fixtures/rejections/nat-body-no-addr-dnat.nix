/*
  Rejection scenario for `natAddrMissing` — `rule.action.dnat` with a
  port and no `addr`. nftypes' `natBody` type accepts it (it needs
  an `addr` or a `port`), but nftzones requires a target address,
  pointing to `redirect` as the no-address alternative. Phase 1
  catches it early with a clear error.
*/
_: {
  description = "natAddrMissing: rule.action.dnat with null addr";

  errors = [
    {
      tag = "natAddrMissing";
      path = [
        "dnats"
        "bad-fwd"
        "rule"
        "action"
        "dnat"
        "addr"
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
