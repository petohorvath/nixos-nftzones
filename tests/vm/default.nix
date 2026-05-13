/*
  VM tests — Tier B. Real-kernel multi-VM scenarios that boot
  three NixOS machines (client, router, server) and assert traffic
  behaviour from a live kernel. Slower than the parse-check and
  validator-rejection tiers; only built on Linux systems.

  Aggregator returns one umbrella `linkFarm` derivation that
  depends on every VM test. Per-test derivations are reachable as
  `passthru.entries.<name>` for targeted `nix build` invocations.
*/
{
  pkgs,
  nftypes,
  nftzones,
  nftzonesModule,
  ...
}:
let
  testArgs = {
    inherit
      pkgs
      nftypes
      nftzones
      nftzonesModule
      ;
  };

  tests = {
    droutes = import ./droutes.nix testArgs;
    dualstack = import ./dualstack.nix testArgs;
    forward = import ./forward.nix testArgs;
    marks = import ./marks.nix testArgs;
    rpfilter = import ./rpfilter.nix testArgs;
    vlan = import ./vlan.nix testArgs;
  };
in
pkgs.linkFarm "nftzones-vm" (
  pkgs.lib.mapAttrsToList (name: drv: {
    inherit name;
    path = drv;
  }) tests
)
