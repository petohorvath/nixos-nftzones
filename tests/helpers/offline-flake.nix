/*
  Reconstruct the root flake from store paths, so nix-unit can
  evaluate the public exports inside the build sandbox without
  fetching inputs.

  Takes the source directories of the root flake and each input it
  loads. Returns the root flake's outputs with `inputs` and `outPath`
  attached, the same shape `builtins.getFlake` returns.
*/
{
  flakePartsDir,
  libnetDir,
  nftypesDir,
  nixpkgsDir,
  rootDir,
}:
let
  /*
    Call a flake's `outputs` with `self` and every input provided, as
    Nix does. `functionArgs` cannot see inputs reached only through
    `...`, so all provided inputs are passed, not only the named ones.
    Named inputs that the offline evaluation does not provide throw only
    when a test reaches them.
  */
  callFlake =
    dir: inputs:
    let
      inherit (import (dir + "/flake.nix")) outputs;
      inputsWithSelf = inputs // {
        self = flake;
      };
      missingInput = name: _: throw "offline-flake: input `${name}` of ${dir} is unavailable";
      flake =
        outputs (builtins.mapAttrs missingInput (builtins.functionArgs outputs) // inputsWithSelf)
        // {
          inherit inputs;
          outPath = dir;
        };
    in
    flake;

  nixpkgs = callFlake nixpkgsDir { };
  flake-parts = callFlake flakePartsDir { nixpkgs-lib = nixpkgs; };
  libnet = callFlake libnetDir { inherit flake-parts nixpkgs; };
  nftypes = callFlake nftypesDir { inherit flake-parts nixpkgs; };
in
callFlake rootDir {
  inherit
    flake-parts
    libnet
    nftypes
    nixpkgs
    ;
}
