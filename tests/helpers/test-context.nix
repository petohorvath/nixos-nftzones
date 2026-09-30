/*
  Build the arguments every test tier receives from one flake: the
  public `lib` and `nixosModules.default` exports plus the package set
  and sibling libraries they were built from.

  Takes the root `flake` (the live flake or an offline reconstruction)
  and the `system` to test. Returns `pkgs`, `nftzones`,
  `nftzonesModule`, `nftypes`, and `libnet`.
*/
{ flake, system }:
let
  inherit (flake.inputs) libnet nftypes nixpkgs;
  pkgs = nixpkgs.legacyPackages.${system};
in
{
  inherit pkgs;
  nftzones = flake.lib;
  nftzonesModule = flake.nixosModules.default;
  nftypes = nftypes.lib;
  libnet = libnet.lib.withLib pkgs.lib;
}
