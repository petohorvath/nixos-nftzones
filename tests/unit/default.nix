/*
  Unit-test definitions for nix-unit. Each test file returns an attrset
  of `testFoo = { expr; expected; }` cases; the result nests them by
  file, for example `internal.compile.testFoo` or `module.testFoo`.
  `tests/unit-check.nix` runs each file as one nix-unit group.

  Discovery is automatic: every `*.nix` file under this directory
  (top-level + `internal/` + `types/`) is imported, except the
  aggregator (`default.nix`) and the shared `helpers.nix`. Adding a
  new unit-test file means dropping `tests/unit/<group>/<name>.nix`;
  no edit here is required.
*/
args@{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (pkgs) lib;

  excludedFiles = [
    "default.nix"
    "helpers.nix"
  ];

  importTestFiles =
    dir:
    lib.pipe (builtins.readDir dir) [
      (lib.filterAttrs (
        name: type: type == "regular" && lib.hasSuffix ".nix" name && !(builtins.elem name excludedFiles)
      ))
      (lib.mapAttrs' (
        name: _: lib.nameValuePair (lib.removeSuffix ".nix" name) (import (dir + "/${name}") args)
      ))
    ];
in
importTestFiles ./.
// {
  internal = importTestFiles ./internal;
  types = importTestFiles ./types;
  version.testVersion = {
    expr = nftzones.version;
    expected = "0.1.0";
  };
}
