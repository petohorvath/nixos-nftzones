{ inputs, ... }:
{
  imports = [
    inputs.nix-unit.modules.flake.default
    inputs.treefmt-nix.flakeModule
  ];

  perSystem =
    {
      config,
      pkgs,
      system,
      ...
    }:
    {
      treefmt.imports = [ ./treefmt.nix ];
      devShells.default = pkgs.callPackage ./shell.nix {
        treefmtShell = config.treefmt.build.devShell;
      };
      checks = import ./checks.nix { inherit inputs pkgs; };
      nix-unit = {
        package = pkgs.nix-unit;
        inputs = removeAttrs inputs [ "self" ];
        enableSystemAgnostic = false;
        tests = {
          unit = import ../tests/unit { inherit (inputs) nix-libnet nix-nftypes nixpkgs; };
          integration = import ../tests/integration {
            inherit (inputs)
              nix-libnet
              nix-nftypes
              nixpkgs
              self
              ;
            inherit system;
          };
        };
      };
    };
}
