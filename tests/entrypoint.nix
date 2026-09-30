/*
  Load the unit-test definitions for nix-unit; nix-unit checks their
  expectations.
  Example: nix-unit tests/entrypoint.nix --attr internal.compile
*/
{
  # Direct runs load the live root flake. The `unit` check supplies an
  # offline reconstruction instead.
  flake ? builtins.getFlake (toString ../.),
  system ? builtins.currentSystem,
}:
import ./unit (import ./helpers/test-context.nix { inherit flake system; })
