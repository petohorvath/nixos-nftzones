/*
  Integration tests — Tier A. Two flavors:

    `./scenarios/`   — positive: each file describes a valid
                        `nftzones`-shaped table; the runner compiles
                        via `nftzones.mkRuleset`, renders to
                        libnftables-JSON, and pipes through `nft -j
                        --check` (LKL+libredirect-shimmed for the
                        Nix sandbox). Optional structured assertions
                        verify specific properties of the compiled
                        output. See `runner.nix` for the three
                        scenario forms.

    `./rejections/`  — negative: each file describes a deliberate
                        misconfiguration; the build succeeds iff
                        `mkRuleset` *throws*. Pins that Phase 1
                        validators are wired into the live
                        pipeline. Unit tests in
                        `tests/unit/internal/normalize.nix` cover
                        each validator in isolation; only these
                        integration rejections prove the
                        orchestrator still calls them.

  Both flavors are passed `{ inherit nftypes; }` so they can use
  the DSL directly.

  Aggregator returns one umbrella `linkFarm` derivation that
  depends on every per-scenario / per-rejection check.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (pkgs) lib;
  inherit (import ./runner.nix { inherit pkgs nftzones nftypes; })
    mkScenarioCheck
    mkRejectionCheck
    ;

  /*
    List `*.nix` regular files in `dir`, returning the basenames
    (no `.nix` suffix). Stable alphabetical order from
    `builtins.attrNames`.
  */
  listNixFiles =
    dir:
    lib.pipe (builtins.readDir dir) [
      (lib.filterAttrs (n: t: t == "regular" && lib.hasSuffix ".nix" n))
      builtins.attrNames
      (map (lib.removeSuffix ".nix"))
    ];

  scenarioDir = ./scenarios;
  rejectionDir = ./rejections;

  scenarios = map (name: {
    inherit name;
    path = mkScenarioCheck name (import (scenarioDir + "/${name}.nix") { inherit nftypes; });
  }) (listNixFiles scenarioDir);

  rejections = map (name: {
    name = "rejections/${name}";
    path = mkRejectionCheck name (import (rejectionDir + "/${name}.nix") { inherit nftypes; });
  }) (listNixFiles rejectionDir);
in
pkgs.linkFarm "nftzones-integration" (scenarios ++ rejections)
