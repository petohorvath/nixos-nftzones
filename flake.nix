{
  description = "nixos-nftzones — library for zone-based nftables firewall configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    nix-libnet = {
      url = "github:petohorvath/nix-libnet/v0.2.0";
      inputs = {
        flake-parts.follows = "flake-parts";
        nixpkgs.follows = "nixpkgs";
        nix-unit.follows = "nix-unit";
        treefmt-nix.follows = "treefmt-nix";
      };
    };
    nix-unit = {
      url = "github:nix-community/nix-unit";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        treefmt-nix.follows = "";
        nix-github-actions.follows = "";
      };
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Downstream flakes follow `nftzones/nix-nftypes`, so keep this input
    # name.
    nix-nftypes = {
      url = "github:petohorvath/nix-nftypes/v0.2.0";
      inputs = {
        flake-parts.follows = "flake-parts";
        nixpkgs.follows = "nixpkgs";
        nix-unit.follows = "nix-unit";
        treefmt-nix.follows = "treefmt-nix";
      };
    };
  };

  outputs =
    inputs@{
      flake-parts,
      nix-libnet,
      nix-nftypes,
      nixpkgs,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      imports = [ flake-parts.flakeModules.partitions ];

      partitions.dev.module = ./dev;

      partitionedAttrs = {
        checks = "dev";
        devShells = "dev";
        formatter = "dev";
        tests = "dev";
      };

      flake = {
        lib = import ./lib {
          inputs = {
            inherit (nixpkgs) lib;
            libnet = nix-libnet.lib.withLib nixpkgs.lib;
            nftypes = nix-nftypes.lib;
          };
        };
        nixosModules.default = flake-parts.lib.importApply ./nixos/module.nix {
          libnet = nix-libnet.lib;
          nftypes = nix-nftypes.lib;
        };
      };
    };
}
