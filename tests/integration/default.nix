# The integration suites, listed by hand. Each suite evaluates nftzones
# inside a host, such as nixpkgs' NixOS modules, or reads the flake
# itself as consumers see it.
# Example: nix-unit --flake .#tests.systems.x86_64-linux.integration
{
  nix-libnet,
  nix-nftypes,
  nixpkgs,
  self,
  system,
}:
let
  testContext = import ../test-context.nix {
    inherit
      nix-libnet
      nix-nftypes
      nixpkgs
      self
      system
      ;
  };
in
{
  flake-outputs = import ./flake-outputs.nix testContext;
  nixos-module = import ./nixos-module.nix testContext;
}
