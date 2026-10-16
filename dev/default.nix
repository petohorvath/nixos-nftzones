{ inputs, ... }:
{
  imports = [ inputs.nix-unit.modules.flake.default ];

  perSystem =
    {
      config,
      pkgs,
      system,
      ...
    }:
    {
      formatter = pkgs.callPackage ./formatter.nix { };
      devShells.default = pkgs.callPackage ./shell.nix {
        inherit (config) formatter;
      };
      checks = import ./checks.nix {
        inherit inputs pkgs;
        inherit (config) formatter;
      };
      nix-unit = {
        package = pkgs.nix-unit;
        inputs = removeAttrs inputs [ "self" ];
        tests = {
          unit = import ../tests/unit {
            inherit (inputs) libnet nftypes nixpkgs;
            inherit system;
          };
          integration = import ../tests/integration {
            inherit (inputs)
              libnet
              nftypes
              nixpkgs
              self
              ;
            inherit system;
          };
        };
      };
    };
}
