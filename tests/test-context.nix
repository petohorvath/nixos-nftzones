/*
  Build `testContext`, the single argument every nix-unit suite
  receives.

  Takes the `nixpkgs`, `nix-libnet`, and `nix-nftypes` flakes, and, for the
  integration suites, `self`, the flake itself, and the `system` whose
  package set evaluates NixOS. Imports nftzones and its NixOS module
  from source, with the dependencies `flake.nix` passes them, so suites
  need no flake-parts evaluation.
*/
{
  nix-libnet,
  nix-nftypes,
  nixpkgs,
  self ? null,
  system ? null,
}:
let
  inherit (nixpkgs) lib;
  pkgs = if system == null then null else nixpkgs.legacyPackages.${system};

  nftzones = import ../lib {
    inputs = {
      inherit lib;
      libnet = nix-libnet.lib.withLib lib;
      nftypes = nix-nftypes.lib;
    };
  };

  # What `flake-parts.lib.importApply` does in `flake.nix`.
  nixosModule = lib.setDefaultModuleLocation ../nixos/module.nix (
    import ../nixos/module.nix {
      libnet = nix-libnet.lib;
      nftypes = nix-nftypes.lib;
    }
  );
in
{
  inherit lib nftzones self;
  libnet = nix-libnet.lib.withLib lib;
  nftypes = nix-nftypes.lib;
  fixtures = import ./fixtures {
    inherit nftzones;
    nftypes = nix-nftypes.lib;
  };
  helpers =
    import ./helpers/evaluation.nix {
      inherit
        lib
        nftzones
        nixosModule
        pkgs
        ;
    }
    // import ./helpers/scenarios.nix {
      inherit lib nftzones;
      nftypes = nix-nftypes.lib;
    };
}
