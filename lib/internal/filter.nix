/*
  internal/filter — exposes filter-specific helpers under
  `nftzones.internal.filter`.

  Exported functions:
    - `groupCellsByChain` — buckets a list of cells by the base
                            chain each one belongs in.

  Filter-specific because the dispatch (input / output / forward)
  depends on whether `host` is on either side of the `(from, to)`
  pair — semantics that don't apply to snat / dnat / policy. The
  generic `from × to` expansion lives in `internal.entry.toCells`.

  Wired into the surface from `lib/default.nix`.

  ===== groupCellsByChain =====

  Inputs:
    localZone — name that means "the firewall machine itself" on
                whichever side of the cell it appears (e.g.
                `"host"`).
    cells     — list of cells from `internal.entry.toCells`. Each
                cell must have concrete singular `from` and `to`
                (wildcards `any` / `all` are expected to be
                resolved upstream).

  Output:
    {
      input   = [ <cells where to == localZone> ];
      output  = [ <cells where from == localZone, to != localZone> ];
      forward = [ <cells where neither endpoint is localZone> ];
    }

    All three keys are always present (empty list when no cell
    matches), so consumers can iterate uniformly.

  Dispatch (`chainOf`, private):
    if cell.to   == localZone → "input"
    else if cell.from == localZone → "output"
    else                       → "forward"

    The `to`-side check runs first, so a cell with `from == to ==
    localZone` (firewall talking to itself) lands in `input`.

  Example:
    groupCellsByChain {
      localZone = "host";
      cells = [
        { from = "wan"; to = "host"; rule = ...; }
        { from = "lan"; to = "wan";  rule = ...; }
      ];
    }
    => {
      input   = [ { from = "wan"; to = "host"; rule = ...; } ];
      output  = [ ];
      forward = [ { from = "lan"; to = "wan"; rule = ...; } ];
    }
*/
{ inputs }:
let
  inherit (inputs) lib;

  groupCellsByChain =
    {
      localZone,
      cells,
    }:
    let
      chainOf =
        cell:
        if cell.to == localZone then
          "input"
        else if cell.from == localZone then
          "output"
        else
          "forward";

      grouped = lib.groupBy chainOf cells;
    in
    {
      input = grouped.input or [ ];
      output = grouped.output or [ ];
      forward = grouped.forward or [ ];
    };
in
{
  inherit groupCellsByChain;
}
