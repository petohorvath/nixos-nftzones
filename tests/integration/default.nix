/*
  Integration tests — Tier A. Two flavors:

    `./scenarios/`   — positive: each file describes a valid
                        `nftzones`-shaped table; the runner compiles
                        via `nftzones.mkRuleset`, renders to
                        libnftables-JSON, and pipes through `nft -j
                        --check` (LKL+libredirect-shimmed for the
                        Nix sandbox). Each asserts its exact
                        Phase 1 warnings (none by default);
                        optional structured assertions verify
                        specific properties of the compiled
                        output. See `runner.nix` for the three
                        scenario forms.

    `./rejections/`  — negative: each file describes a deliberate
                        misconfiguration; the build succeeds iff
                        `mkRuleset` *throws*. Pins that Phase 1
                        validators are wired into the live
                        pipeline. A scenario that Phase 1 rejects
                        also lists its exact errors; one that the
                        table type rejects only asserts the
                        throw.

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
    mkRejectionCheck
    mkScenarioCheck
    ;

  /*
    List `*.nix` regular files in `dir`, returning the basenames
    (no `.nix` suffix). Stable alphabetical order from
    `builtins.attrNames`.
  */
  listNixFiles =
    dir:
    lib.pipe (builtins.readDir dir) [
      (lib.filterAttrs (name: type: type == "regular" && lib.hasSuffix ".nix" name))
      builtins.attrNames
      (map (lib.removeSuffix ".nix"))
    ];

  scenarioDir = ./scenarios;
  rejectionDir = ./rejections;

  scenarios = map (name: {
    inherit name;
    path = mkScenarioCheck name (import (scenarioDir + "/${name}.nix") { inherit nftypes nftzones; });
  }) (listNixFiles scenarioDir);

  rejections = map (name: {
    name = "rejections/${name}";
    path = mkRejectionCheck name (import (rejectionDir + "/${name}.nix") { inherit nftypes; });
  }) (listNixFiles rejectionDir);
in
pkgs.linkFarm "nftzones-integration" (scenarios ++ rejections)
