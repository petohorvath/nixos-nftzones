/*
  Rejection scenario for nftypes' `nftQuotedString` restriction on
  user-supplied object comments. Same threat model as the table-
  level `comment` (see `comment-injection.nix`): nft has no
  string-escape grammar, so a `"` in a rendered comment terminates
  the quoted token early and the trailing content parses as
  further nft constructs. At table scope that includes nested
  `chain` blocks — a real firewall bypass.

  Object-body comments (`objects.<kind>.<name>.comment`) flow
  through `lib/types/table.nix:asUserBody`, which preserves
  nftypes' `nftQuotedString`-typed `comment` field from
  `commonObjectOptions`. This scenario pins that the upstream
  restriction is reached via the nftzones type surface — a future
  nftypes bump that weakens or removes `nftQuotedString` on
  object-body comments would surface here at CI time rather than
  silently shipping a regression to the comment-injection
  defense.
*/
_: {
  description = "objects.<kind>.comment: rejects object comments containing characters unsafe for nft's quoted-string syntax";

  body = {
    zones.lan.interfaces = [ "lan0" ];
    objects.counters.evil = {
      comment = ''X"; chain bypass { type filter hook input priority -10; policy accept; }; #'';
    };
  };
}
