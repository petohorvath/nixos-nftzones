/*
  internal/zone-pair — exposes zone-pair helpers under
  `nftzones.internal.zonePair`.

  Exported functions:
    - `genExpansions` — expands an attrset's `from × to` fan-out
                        into a flat list of single-pair attrsets.

  Used by the filter, snat, dnat, and policy compile pipelines —
  every group that's keyed by a `(from, to)` zone pair. The function
  is purely structural: it doesn't interpret any field beyond `from`
  and `to`, so it doesn't need to know which group's rule it's
  expanding.

  Wired into the surface from `lib/default.nix`.

  ===== genExpansions =====

  Inputs:
    Any attrset with `from` and `to` list-shaped fields. Other
    attributes pass through unchanged onto every emitted expansion
    — the function does not interpret them.

  Output:
    A list of expansions, one per `(from, to)` combination. Each
    expansion is the input attrset with `from` and `to` replaced by
    single zone names (not lists). Iteration is `from`-major,
    `to`-minor: expansions appear in the order a reader would
    expand the input by hand.

  Example:
    genExpansions {
      name = "web-out";
      from = [ "lan" "guest" ];
      to = [ "wan" "vpn" ];
      rule = [ (eq tcp.dport 443) accept ];
    }
    => [
      { name = "web-out"; from = "lan";   to = "wan";   ... }
      { name = "web-out"; from = "lan";   to = "vpn";   ... }
      { name = "web-out"; from = "guest"; to = "wan";   ... }
      { name = "web-out"; from = "guest"; to = "vpn";   ... }
    ]
*/
{ inputs }:
let
  inherit (inputs) lib;

  /*
    `lib.mapCartesianProduct` walks `attrNames` alphabetically, so
    `from` (the outer dimension) sits before `to` and the result
    comes out `from`-major. Renaming either field could flip the
    order — adjust here if that ever happens.
  */
  genExpansions =
    {
      from,
      to,
      ...
    }@input:
    lib.mapCartesianProduct (lib.mergeAttrs input) { inherit from to; };
in
{
  inherit genExpansions;
}
