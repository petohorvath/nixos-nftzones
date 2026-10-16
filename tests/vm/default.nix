/*
  The VM scenarios, listed by hand. Each boots NixOS machines, usually
  a client, a router, and a server, and checks traffic against a real
  kernel. They need KVM; build one with
  `nix build .#checks.<system>.vm-<scenario>`.
*/
{ inputs, pkgs }:
let
  testArgs = { inherit inputs pkgs; };
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
