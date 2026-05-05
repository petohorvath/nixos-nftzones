/*
  Integration tests — Tier A. For each scenario in `./scenarios`,
  compile via `nftzones.mkRuleset`, render to nftables block-form
  text, and pipe through `nft --check` (LKL+libredirect-shimmed
  so it works inside the Nix sandbox).

  Each scenario file evaluates to either:
    - an attrset (single-table body), or
    - a list of `{ name; body; }` records (multi-table ruleset).

  Scenarios are passed `{ inherit nftypes; }` so they can use the
  DSL directly.

  Aggregator returns one umbrella derivation depending on every
  per-scenario check; failure in any scenario fails `nix flake
  check`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (pkgs) lib;
  inherit (import ./runner.nix { inherit pkgs nftzones nftypes; }) mkScenarioCheck;

  scenarioArgs = { inherit nftypes; };

  scenarioDir = ./scenarios;

  scenarioNames = lib.pipe (builtins.readDir scenarioDir) [
    (lib.filterAttrs (n: t: t == "regular" && lib.hasSuffix ".nix" n))
    builtins.attrNames
    (map (lib.removeSuffix ".nix"))
  ];

  scenarios = lib.genAttrs scenarioNames (
    name: mkScenarioCheck name (import (scenarioDir + "/${name}.nix") scenarioArgs)
  );
in
# `linkFarm` produces a directory of symlinks — one per scenario
# — that depends on every scenario derivation. Forcing the result
# builds them all; the symlink farm doubles as a discoverable
# `nix build .#checks.<system>.integration` output.
(pkgs.linkFarm "nftzones-integration" (
  lib.mapAttrsToList (name: drv: { inherit name; path = drv; }) scenarios
)).overrideAttrs
  (old: { passthru = (old.passthru or { }) // { inherit scenarios; }; })
