/*
  VM tests — Tier B. Real-kernel multi-VM scenarios that boot
  three NixOS machines (client, router, server) and assert traffic
  behaviour from a live kernel. Slower than the parse-check and
  validator-rejection tiers, and they need KVM, so they are exposed
  as `legacyPackages.<system>.vmTests.<name>` rather than `checks`.
  Build one with `nix build .#vmTests.<name>`.
*/
{ flake, system }:
let
  testArgs = import ../helpers/test-context.nix { inherit flake system; };
in
{
  activation = import ./activation.nix testArgs;
  atomic-reload = import ./atomic-reload.nix testArgs;
  bridge = import ./bridge.nix testArgs;
  droutes = import ./droutes.nix testArgs;
  dualstack = import ./dualstack.nix testArgs;
  forward = import ./forward.nix testArgs;
  marks = import ./marks.nix testArgs;
  rpfilter = import ./rpfilter.nix testArgs;
  vlan = import ./vlan.nix testArgs;
}
