# Assemble the `build-<test>` and `vm-<scenario>` entries of the
# `checks` output. nix-unit's flake-parts module adds the `nix-unit`
# entry.
{ inputs, pkgs }:
let
  inherit (pkgs) lib;
  testArgs = { inherit inputs pkgs; };
  prefixNames = prefix: lib.mapAttrs' (name: lib.nameValuePair "${prefix}-${name}");
in
lib.attrsets.unionOfDisjoint (prefixNames "build" (import ./build testArgs)) (
  prefixNames "vm" (import ./vm testArgs)
)
