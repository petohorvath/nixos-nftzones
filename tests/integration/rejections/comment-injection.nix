/*
  Rejection scenario for the `primitives.comment` restriction. nft
  has no string-escape grammar — a comment containing `"` terminates
  the quoted token early and the trailing content parses as further
  nft constructs. At table scope that includes nested `chain` blocks,
  which is a real firewall bypass (the verified PoC injects a chain
  with `policy accept` at priority -10).

  The type rejects `"`, `\`, control chars, and >128-byte comments
  at eval time; this scenario pins that the rejection is wired into
  the live `mkRuleset` pipeline.
*/
_: {
  description = "primitives.comment: rejects table comments containing characters unsafe for nft's quoted-string syntax";

  body = {
    comment = ''X"; chain bypass { type filter hook input priority -10; policy accept; }; #'';
    zones.lan.interfaces = [ "lan0" ];
  };
}
