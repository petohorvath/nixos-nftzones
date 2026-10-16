# Assemble the test entries of the `checks` output: `unit` and
# `integration` run the nix-unit suites, `build-<test>` the build tests,
# and `vm-<scenario>` the VM tests.
{ inputs, pkgs }:
let
  inherit (pkgs) lib;
  repo = "nftzones";

  # The files the nix-unit suites read, so other edits do not rebuild
  # their entries.
  srcDir = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../examples
      ../lib
      ../nixos
      ./fixtures
      ./helpers
      ./integration
      ./test-context.nix
      ./unit
    ];
  };

  runNixUnit = import ./runners/nix-unit.nix {
    inherit
      inputs
      pkgs
      repo
      srcDir
      ;
  };
  runBuild = import ./runners/build.nix { inherit pkgs repo; };
  runVm = import ./runners/vm.nix { inherit pkgs repo; };
in
lib.foldl' lib.attrsets.unionOfDisjoint { } [
  {
    unit = runNixUnit { kind = "unit"; };
    integration = runNixUnit { kind = "integration"; };
  }
  (runBuild (import ./build { inherit inputs pkgs; }))
  (runVm (import ./vm { inherit inputs pkgs; }))
]
