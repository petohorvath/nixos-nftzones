/*
  Rejection scenario for `checkNatBodies` — `rule.snat = { }`
  selects the `snat` tag with an all-null body. Type accepts it
  (every nftypes `natBody` field is nullable); nft rejects the
  resulting `snat to;` statement at activation. The validator
  catches it early with a clear error.
*/
_: {
  description = "checkNatBodies: rule.snat with null addr";

  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    snats.outbound = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule.snat = { };
    };
  };
}
