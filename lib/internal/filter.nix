/*
  internal/filter — exposes filter-specific helpers under
  `nftzones.internal.filter`.

  Exported functions:
    - `groupExpansionsByChain` — buckets a list of expansions by the
                                 base chain each one belongs in.

  Filter-specific because the dispatch (input / output / forward)
  depends on whether `host` is on either side of the `(from, to)`
  pair — semantics that don't apply to snat / dnat / policy. The
  generic `from × to` expansion lives in `internal.zonePair`.

  Wired into the surface from `lib/default.nix`.

  ===== groupExpansionsByChain =====

  Inputs:
    localZone   — name that means "the firewall machine itself" on
                  whichever side of the expansion it appears (e.g.
                  `"host"`).
    expansions  — list of expansions from
                  `internal.zonePair.genExpansions`. Each one must
                  have concrete singular `from` and `to` (wildcards
                  `any` / `all` are expected to be resolved
                  upstream).

  Output:
    {
      input   = [ <expansions where to == localZone> ];
      output  = [ <expansions where from == localZone, to != localZone> ];
      forward = [ <expansions where neither endpoint is localZone> ];
    }

    All three keys are always present (empty list when no expansion
    matches), so consumers can iterate uniformly.

  Dispatch (`chainOf`, private):
    if expansion.to    == localZone → "input"
    else if expansion.from == localZone → "output"
    else                            → "forward"

    The `to`-side check runs first, so an expansion with `from ==
    to == localZone` (firewall talking to itself) lands in `input`.

  Example:
    groupExpansionsByChain {
      localZone = "host";
      expansions = [
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

  groupExpansionsByChain =
    {
      localZone,
      expansions,
    }:
    let
      chainOf =
        expansion:
        if expansion.to == localZone then
          "input"
        else if expansion.from == localZone then
          "output"
        else
          "forward";

      grouped = lib.groupBy chainOf expansions;
    in
    {
      input = grouped.input or [ ];
      output = grouped.output or [ ];
      forward = grouped.forward or [ ];
    };
in
{
  inherit groupExpansionsByChain;
}
