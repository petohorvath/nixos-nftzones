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

  ===== toCells =====

  Input:
    entry — attrset with `from` and / or `to` as list-shaped
            fields. Other fields (`rule`, `priority`, `comment`,
            `chain`, …) pass through unchanged onto every emitted
            cell. Directions present on the entry are auto-
            detected; missing ones are simply not producted on.

  Output:
    A flat list of cells. Each cell is the entry with its
    direction fields replaced by single zone names (one per
    combination). Iteration is alphabetical-major:
    `lib.mapCartesianProduct` walks the product attrset's keys in
    `attrNames` order, so for an entry with both `from` and `to`
    the outer loop is `from`, the inner loop is `to`.

  Example (bidirectional):
    toCells {
      name = "web-out";
      from = [ "lan" "guest" ];
      to = [ "wan" "vpn" ];
      rule = [ (eq tcp.dport 443) accept ];
    }
    => [
      { name = "web-out"; from = "lan";   to = "wan"; rule = …; }
      { name = "web-out"; from = "lan";   to = "vpn"; rule = …; }
      { name = "web-out"; from = "guest"; to = "wan"; rule = …; }
      { name = "web-out"; from = "guest"; to = "vpn"; rule = …; }
    ]

  Example (single-direction):
    toCells {
      name = "web-fwd";
      from = [ "wan" ];
      rule = { … };
    }
    => [ { name = "web-fwd"; from = "wan"; rule = { … }; } ]
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
