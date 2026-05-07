{
  description = "nix-nftzones — library for zone-based nftables firewall configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    libnet.url = "github:petohorvath/nix-libnet";
    libnet.inputs.nixpkgs.follows = "nixpkgs";

    nftypes.url = "github:petohorvath/nix-nftypes";
    nftypes.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      libnet,
      nftypes,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkLib =
        pkgs:
        import ./lib {
          inputs = {
            inherit (pkgs) lib;
            libnet = libnet.lib.withLib pkgs.lib;
            nftypes = nftypes.lib;
          };
        };

      nftzonesModule =
        { pkgs, ... }:
        {
          imports = [ ./modules/nftzones.nix ];
          _module.args = {
            nftzones = mkLib pkgs;
            nftypes = nftypes.lib;
          };
        };

      mkChecks =
        pkgs:
        let
          testArgs = {
            inherit pkgs nftzonesModule;
            nftzones = mkLib pkgs;
            nftypes = nftypes.lib;
          };
          runner = import ./tests/unit/runner.nix { inherit pkgs; };
          unitTests = import ./tests/unit/default.nix testArgs;
          vmTestsLinux = nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            vm = import ./tests/vm/default.nix testArgs;
          };
        in
        {
          unit = runner.runTests unitTests;
          integration = import ./tests/integration/default.nix testArgs;
        }
        // vmTestsLinux;
    in
    {
      lib = forAllSystems mkLib;
      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
      checks = forAllSystems mkChecks;
      nixosModules.default = nftzonesModule;
    };
}
