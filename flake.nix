{
  description = "nixos-nftzones — library for zone-based nftables firewall configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    # Sibling libraries are pinned by commit until they publish release tags.
    libnet = {
      url = "github:petohorvath/nix-libnet?rev=2e544133d906e7c631d08ce1b57770edca8e3349";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.git-hooks.inputs.nixpkgs.follows = "nixpkgs";
    };
    # Downstream flakes read `inputs.nftypes`, so keep this input name.
    nftypes = {
      url = "github:petohorvath/nix-nftypes?rev=aab9d4bc4f7b1dafb1d2d3297c8e010713745d3a";
      inputs.nixpkgs.follows = "nixpkgs";
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
        legacyPackages = "dev";
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
