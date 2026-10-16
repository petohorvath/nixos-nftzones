# The integration suites for nix-unit, listed by hand. Each suite
# evaluates nftzones inside a host, such as nixpkgs' NixOS modules.
# Example: nix-unit tests/integration --attr nixos-module
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
  nixos-module = import ./nixos-module.nix testContext;
}
