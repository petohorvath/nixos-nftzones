{
  description = "nixos-nftzones — library for zone-based nftables firewall configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    libnet = {
      url = "github:petohorvath/nix-libnet/v0.1.0";
      inputs = {
        flake-parts.follows = "flake-parts";
        nixpkgs.follows = "nixpkgs";
      };
    };
    # Downstream flakes read `inputs.nftypes`, so keep this input name.
    nftypes = {
      url = "github:petohorvath/nix-nftypes/v0.1.0";
      inputs = {
        flake-parts.follows = "flake-parts";
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs =
    inputs@{
      flake-parts,
      libnet,
      nftypes,
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
      };

      flake = {
        lib = import ./lib {
          inputs = {
            inherit (nixpkgs) lib;
            libnet = libnet.lib.withLib nixpkgs.lib;
            nftypes = nftypes.lib;
          };
        };
        nixosModules.default = flake-parts.lib.importApply ./nixos/module.nix {
          libnet = libnet.lib;
          nftypes = nftypes.lib;
        };
      };
    };
}
