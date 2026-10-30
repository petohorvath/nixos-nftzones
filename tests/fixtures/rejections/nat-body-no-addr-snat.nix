/*
  Rejection scenario for `natAddrMissing` — `rule.action.snat`
  with a port and no `addr`. nftypes' `natBody` type accepts it (it
  needs an `addr` or a `port`), but nftzones requires a target
  address, pointing to `rule.action.masquerade` as the no-address
  alternative. Phase 1 catches it early with a clear error.
*/
_: {
  description = "natAddrMissing: rule.action.snat with null addr";

  errors = [
    {
      tag = "natAddrMissing";
      path = [
        "snats"
        "outbound"
        "rule"
        "action"
        "snat"
        "addr"
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
      rule.action.snat.port = 8080;
    };
  };
}
