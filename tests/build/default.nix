# The build tests, listed by hand. Each runs a real program on the
# output of nftzones.
{ inputs, pkgs }:
let
  testArgs = { inherit inputs pkgs; };
in
{
  scenarios = import ./scenarios.nix testArgs;
}
