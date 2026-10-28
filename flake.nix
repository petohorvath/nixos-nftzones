{
  description = "nixos-nftzones — library for zone-based nftables firewall configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    nix-libnet = {
      url = "github:petohorvath/nix-libnet/v0.1.0";
      inputs = {
        flake-parts.follows = "flake-parts";
        nixpkgs.follows = "nixpkgs";
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
    # name. Temporary pin to a `main` commit past v0.1.0; repin to the next
    # release tag once nftypes cuts one.
    nix-nftypes = {
      url = "github:petohorvath/nix-nftypes/d805ffa5e87b887702a16926cc73869896a911fa";
      inputs = {
        flake-parts.follows = "flake-parts";
        nixpkgs.follows = "nixpkgs";
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
