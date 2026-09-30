{ inputs, ... }:
{
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
        inherit inputs pkgs system;
        inherit (config) formatter;
      };
      # The shared policy builds `vmTests` in a KVM-enabled job, apart
      # from `checks`.
      legacyPackages.vmTests = import ../tests/vm {
        inherit system;
        flake = inputs.self;
      };
    };
}
