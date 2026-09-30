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
    Call a flake's `outputs` with `self` and the inputs it names.
    `functionArgs` cannot see inputs reached only through `...`, so
    `self` is always passed. Inputs that the offline evaluation does not
    provide throw only when a test reaches them.
  */
  callFlake =
    dir: inputs:
    let
      inherit (import (dir + "/flake.nix")) outputs;
      inputsWithSelf = inputs // {
        self = flake;
      };
      selectInput =
        name: _:
        inputsWithSelf.${name} or (throw "offline-flake: input `${name}` of ${dir} is unavailable");
      flake =
        outputs (builtins.mapAttrs selectInput (builtins.functionArgs outputs // { self = false; }))
        // {
          inherit inputs;
          outPath = dir;
        };
    in
    flake;

  nixpkgs = callFlake nixpkgsDir { };
  flake-parts = callFlake flakePartsDir { nixpkgs-lib = nixpkgs; };
  libnet = callFlake libnetDir { inherit nixpkgs; };
  nftypes = callFlake nftypesDir { inherit nixpkgs; };
in
callFlake rootDir {
  inherit
    flake-parts
    libnet
    nftypes
    nixpkgs
    ;
}
