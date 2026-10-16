# The unit suites for nix-unit, listed by hand. Each suite's attribute
# path matches the path of the source file it tests.
# Example: nix-unit tests/unit --attr internal.compile
let
  rootInputs = (builtins.getFlake (toString ../..)).inputs;
  rebuild = import ../helpers/evaluation-inputs.nix;

  # libnet and nftypes follow nixpkgs, and flake-parts through
  # nixpkgs-lib, so rebuild them against the selected one.
  rebuildAgainst =
    nixpkgs: inputName:
    rebuild {
      path = rootInputs.${inputName}.outPath;
      inputs = {
        inherit nixpkgs;
        flake-parts = rebuild {
          path = rootInputs.flake-parts.outPath;
          inputs.nixpkgs-lib = nixpkgs;
        };
      };
    };
in
{
  nixpkgs ? rootInputs.nixpkgs,
  libnet ? rebuildAgainst nixpkgs "libnet",
  nftypes ? rebuildAgainst nixpkgs "nftypes",
  system ? builtins.currentSystem,
}:
let
  testContext = import ../test-context.nix {
    inherit
      libnet
      nftypes
      nixpkgs
      system
      ;
  };
in
{
  examples = import ./examples.nix testContext;
  internal = {
    compile = import ./internal/compile.nix testContext;
    dispatch = import ./internal/dispatch.nix testContext;
    emit = import ./internal/emit.nix testContext;
    entry = import ./internal/entry.nix testContext;
    expand = import ./internal/expand.nix testContext;
    node = import ./internal/node.nix testContext;
    normalize = {
      diagnose = import ./internal/normalize/diagnose.nix testContext;
      diagnose-hierarchy = import ./internal/normalize/diagnose-hierarchy.nix testContext;
      diagnose-overlap = import ./internal/normalize/diagnose-overlap.nix testContext;
      diagnose-placement = import ./internal/normalize/diagnose-placement.nix testContext;
      normalize-output = import ./internal/normalize/normalize-output.nix testContext;
    };
    placement = import ./internal/placement.nix testContext;
    priority = import ./internal/priority.nix testContext;
    refs = import ./internal/refs.nix testContext;
    zone = import ./internal/zone.nix testContext;
  };
  lib = import ./lib.nix testContext;
  name-key = import ./name-key.nix testContext;
  nixos = {
    module = import ./nixos/module.nix testContext;
  };
  rejections = import ./rejections.nix testContext;
  scenarios = import ./scenarios.nix testContext;
  snippets = {
    snippets = import ./snippets/snippets.nix testContext;
  };
  types = {
    dnat = import ./types/dnat.nix testContext;
    droute = import ./types/droute.nix testContext;
    filter = import ./types/filter.nix testContext;
    node = import ./types/node.nix testContext;
    policy = import ./types/policy.nix testContext;
    snat = import ./types/snat.nix testContext;
    sroute = import ./types/sroute.nix testContext;
    table = import ./types/table.nix testContext;
    zone = import ./types/zone.nix testContext;
  };
}
