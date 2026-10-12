/*
  VM tests — Tier B. Real-kernel multi-VM scenarios that boot
  three NixOS machines (client, router, server) and assert traffic
  behaviour from a live kernel. Slower than the parse-check and
  validator-rejection tiers, and they need KVM. They are checks named
  `vm-<name>`; build one with
  `nix build .#checks.x86_64-linux.vm-<name>`.
*/
{ flake, system }:
let
  testContext = import ../helpers/test-context.nix { inherit flake system; };
in
{
  activation = import ./activation.nix testContext;
  atomic-reload = import ./atomic-reload.nix testContext;
  bridge = import ./bridge.nix testContext;
  droutes = import ./droutes.nix testContext;
  dualstack = import ./dualstack.nix testContext;
  forward = import ./forward.nix testContext;
  marks = import ./marks.nix testContext;
  rpfilter = import ./rpfilter.nix testContext;
  vlan = import ./vlan.nix testContext;
}
