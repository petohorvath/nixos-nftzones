# Run `nft -j --check` on every scenario fixture, one linked case per
# scenario. The unit suite `scenarios` checks their warnings and
# assertions.
{ inputs, pkgs }:
let
  inherit (pkgs) lib;
  nftypes = inputs.nix-nftypes.lib;
  nftzones = inputs.self.lib;

  fixtures = import ../fixtures { inherit nftypes nftzones; };
  checkRuleset = import ../helpers/nft-check.nix { inherit pkgs; };
  inherit (import ../helpers/scenarios.nix { inherit lib nftypes nftzones; }) renderScenario;
in
pkgs.linkFarm "nftzones-scenarios" (
  lib.mapAttrs (
    name: scenario: checkRuleset "nftzones-scenario-${name}" (renderScenario name scenario)
  ) fixtures.scenarios
)
