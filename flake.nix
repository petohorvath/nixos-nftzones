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

      # Compute the per-system library once. `mkLib`'s `import
      # ./lib` is already memoized by file path, but threading
      # one canonical `libBySystem` through downstream consumers
      # keeps the wiring explicit and removes the temptation to
      # call `mkLib pkgs` ad-hoc in new code paths.
      libBySystem = forAllSystems mkLib;

      nftzonesModule =
        { pkgs, ... }:
        {
          imports = [ ./modules/nftzones.nix ];
          # The module needs only `nftzones`; it pulls `nftypes`
          # out of `nftzones.nftypes` rather than taking a second
          # injection.
          _module.args = {
            nftzones = libBySystem.${pkgs.stdenv.hostPlatform.system};
          };
        };

      mkChecks =
        pkgs:
        let
          nftzones = libBySystem.${pkgs.stdenv.hostPlatform.system};
          testArgs = {
            inherit pkgs nftzonesModule nftzones;
            nftypes = nftypes.lib;
            libnet = libnet.lib.withLib pkgs.lib;
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
      lib = libBySystem;
      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
      checks = forAllSystems mkChecks;
      nixosModules.default = nftzonesModule;

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShellNoCC {
          # Tools a contributor reaches for when working on this
          # repo: nixfmt-tree for formatting (matches `nix fmt`),
          # nftables for hand-running `nft --check` against
          # rendered scenarios, and nix-output-monitor for the
          # `nix build` UX.
          packages = [
            pkgs.nixfmt-tree
            pkgs.nftables
            pkgs.nix-output-monitor
          ];
        };
      });
    };
}
