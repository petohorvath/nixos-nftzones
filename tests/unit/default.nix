/*
  Unit-test definitions. Each test file's attrset
  (`testFoo = { expr; expected; }`) is merged into one big
  `runTests`-shaped value consumed by `tests/unit/runner.nix`.

  Discovery is automatic: every `*.nix` file under this directory
  (top-level + `internal/` + `types/`) is imported and merged,
  except the runner-internal files (`default.nix`, `runner.nix`,
  `helpers.nix`). Adding a new unit-test file means dropping
  `tests/unit/<group>/<name>.nix` — no edit here required.
*/
args@{
  pkgs,
  nftzones,
  ...
}:
let
  inherit (pkgs) lib;

  excluded = [
    "default.nix"
    "runner.nix"
    "helpers.nix"
  ];

  listTestFiles =
    dir:
    lib.pipe (builtins.readDir dir) [
      (lib.filterAttrs (n: t: t == "regular" && lib.hasSuffix ".nix" n && !(builtins.elem n excluded)))
      builtins.attrNames
    ];

  importsFromDir = dir: map (n: import (dir + "/${n}") args) (listTestFiles dir);
in
{
  testVersion = {
    expr = nftzones.version;
    expected = "0.1.0";
  };
}
// lib.mergeAttrsList (importsFromDir ./. ++ importsFromDir ./internal ++ importsFromDir ./types)
