/*
  lib/types — composes the per-concept type modules into one
  aggregate value consumed by `lib/default.nix`.

  Each `<concept>.nix` file in this directory defines one or more
  NixOS option types built on top of `primitives.nix` and (where
  needed) on `zone.nix`. Per-file dependencies are threaded in
  explicitly here so the graph stays inspectable at this level:

    primitives.nix      no deps — atoms (identifier, comment,
                        rule, entryPriority, chainPriority,
                        chainOverride, mkNameOption)
    zone.nix            primitives — zone-related types
                        (`zoneName`, `zoneNames`, `zoneParent`,
                        `zoneInterfaces`, `zoneCidrs`,
                        `zoneMatchOverride`, `zone`)
    node.nix            primitives + zone — `node`
    filter / snat /     primitives + zone — per-group entry types
      dnat / sroute /
      droute / policy
    table.nix           all of the above — the top-level `table`
                        submodule plus `tableSettings`, `tableObjects`,
                        etc.

  `primitives` itself is NOT exposed via `nftzones.types` —
  consumers should reach for the named types built on top of it
  (`zoneName`, `filterName`, …). This is enforced structurally
  by omitting `primitives` from the `inherit` at the bottom of
  this file; the merge in `lib/default.nix` flattens the
  per-module exports into one `nftzones.types` namespace, and
  per-module submodule keys here are just for internal wiring.
*/
{ inputs }:
let
  primitives = import ./primitives.nix { inherit inputs; };
  zone = import ./zone.nix { inherit inputs primitives; };
  node = import ./node.nix { inherit inputs primitives zone; };
  filter = import ./filter.nix { inherit inputs primitives zone; };
  snat = import ./snat.nix { inherit inputs primitives zone; };
  dnat = import ./dnat.nix { inherit inputs primitives zone; };
  sroute = import ./sroute.nix { inherit inputs primitives zone; };
  droute = import ./droute.nix { inherit inputs primitives zone; };
  policy = import ./policy.nix { inherit inputs primitives zone; };
  table = import ./table.nix {
    inherit
      inputs
      primitives
      zone
      node
      filter
      snat
      dnat
      sroute
      droute
      policy
      ;
  };
in
{
  inherit
    zone
    node
    filter
    snat
    dnat
    sroute
    droute
    policy
    table
    ;
}
