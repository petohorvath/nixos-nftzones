/*
  internal/entry — exposes entry-related helpers under
  `nftzones.internal.entry`.

  Exported functions:
    - `toCells` — fan one entry out into a flat list of cells via
                  cartesian product over whichever directions
                  (`from` / `to`) the entry carries.

  Used by Phase 2 (expand) of the compile pipeline to turn an
  entry like `{ from = [ "lan" "guest" ]; to = [ "wan" "vpn" ];
  rule = …; }` into one cell per `(from, to)` combination,
  preserving every other field. Single-direction entries
  (`dnat` / `sroute` / `droute` shapes that carry only `from` or
  only `to`) auto-resolve to a 1-D product.

  Wired into the surface from `lib/internal/default.nix`.
*/
{ inputs }:
let
  inherit (inputs) lib;

  /*
    `null` defaults distinguish "direction absent on the entry"
    (skip producting on it) from "direction present but empty"
    (mapCartesianProduct produces no cells, the desired behavior).
  */
  toCells =
    {
      from ? null,
      to ? null,
      ...
    }@entry:
    let
      productInput = lib.filterAttrs (_: v: v != null) { inherit from to; };
    in
    lib.mapCartesianProduct (lib.mergeAttrs entry) productInput;
in
{
  inherit toCells;
}
