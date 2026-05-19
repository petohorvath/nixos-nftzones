/*
  Rejection scenario for nftypes' `nftQuotedString` restriction on
  set-element comments. Same threat model as object-body comments
  (see `object-comment-injection.nix`): a `"` in a rendered
  comment terminates the quoted token early and the trailing
  content parses as further nft constructs. At table scope that
  includes nested `chain` blocks.

  Set elements declared via `dsl.expr.elem { val; comment; }` go
  through nftypes' `elementBody` / `setElem` shape, whose
  `comment` field is typed by `nftQuotedString`. The element-level
  path is structurally distinct from the object-body path — a
  separate `mkOption` site — so a future nftypes bump could
  regress one without the other. This scenario pins the element-
  level wiring.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) expr;
in
{
  description = "objects.sets.<name>.elem.comment: rejects set-element comments containing characters unsafe for nft's quoted-string syntax";

  body = {
    zones.lan.interfaces = [ "lan0" ];
    objects.sets.evil = {
      type = "ipv4_addr";
      flags = [ "interval" ];
      elem = [
        (expr.elem {
          val = expr.prefix "10.0.0.0" 24;
          comment = ''X"; chain bypass { type filter hook input priority -10; policy accept; }; #'';
        })
      ];
    };
  };
}
