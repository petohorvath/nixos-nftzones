/*
  Rejection scenario for `checkNatBodies` — `rule.action.dnat = { }`
  selects the `dnat` tag with an all-null body. Type accepts it
  (every nftypes `natBody` field is nullable); nft rejects the
  resulting `dnat to;` statement at activation. The validator
  catches it early with a clear error.
*/
_: {
  description = "checkNatBodies: rule.action.dnat with null addr";

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
