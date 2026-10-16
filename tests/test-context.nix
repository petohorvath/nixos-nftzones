/*
  Build `testContext`, the single argument every nix-unit suite
  receives.

  Takes the `nixpkgs`, `libnet`, and `nftypes` flakes and the `system`
  to test. Imports nftzones and its NixOS module from source, with the
  dependencies `flake.nix` passes them, so suites need no flake-parts
  evaluation.
*/
{
  libnet,
  nftypes,
  nixpkgs,
  system,
}:
let
  inherit (nixpkgs) lib;
  pkgs = nixpkgs.legacyPackages.${system};

  nftzones = import ../lib {
    inputs = {
      inherit lib;
      libnet = libnet.lib.withLib lib;
      nftypes = nftypes.lib;
    };
  };

  # What `flake-parts.lib.importApply` does in `flake.nix`.
  nixosModule = lib.setDefaultModuleLocation ../nixos/module.nix (
    import ../nixos/module.nix {
      libnet = libnet.lib;
      nftypes = nftypes.lib;
    }
  );
in
{
  inherit lib nftzones;
  libnet = libnet.lib.withLib lib;
  nftypes = nftypes.lib;
  fixtures = import ./fixtures {
    inherit nftzones;
    nftypes = nftypes.lib;
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
      nftypes = nftypes.lib;
    };
}
