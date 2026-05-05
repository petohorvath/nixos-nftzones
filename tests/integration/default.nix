/*
  Integration tests — Tier A. For each scenario in `./scenarios`,
  compile via `nftzones.mkRuleset`, render to libnftables-JSON,
  and pipe through `nft -j --check` (LKL+libredirect-shimmed so
  it works inside the Nix sandbox).

  Each scenario file evaluates to either:
    - an attrset (single-table body), or
    - a list of `{ name; body; }` records (multi-table ruleset).

  Scenarios are passed `{ inherit nftypes; }` so they can use the
  DSL directly.

  Aggregator returns one umbrella `linkFarm` derivation that
  depends on every per-scenario check; per-scenario derivations
  are reachable via `passthru.entries.<name>` for targeted
  `nix build` invocations.
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

  scenarioDir = ./scenarios;

  scenarioNames = lib.pipe (builtins.readDir scenarioDir) [
    (lib.filterAttrs (n: t: t == "regular" && lib.hasSuffix ".nix" n))
    builtins.attrNames
    (map (lib.removeSuffix ".nix"))
  ];

  scenarios = map (name: {
    inherit name;
    path = mkScenarioCheck name (import (scenarioDir + "/${name}.nix") { inherit nftypes; });
  }) scenarioNames;
in
pkgs.linkFarm "nftzones-integration" scenarios
