/*
  Examples aggregator — a `nix flake check` tier whose only job
  is keeping `examples/*.nix` from bit-rotting.

  Each `examples/*.nix` is a `{ nftypes, nftzones, ... }: body`
  function returning a `nftzones.types.table` body — a complete,
  realistic configuration meant to be read and adapted, not a
  feature-isolating test scenario (that's `tests/integration/`).

  The check compiles each example through `nftzones.mkRuleset`
  and forces the result with `builtins.deepSeq`. That runs the
  full pipeline — Phase 1 validators, expand, dispatch, emit,
  render — so any example that drifts out of sync with the
  type surface or the compiler fails `nix flake check` rather
  than silently misleading a reader. The `nft -j --check`
  validation that `tests/integration/` adds on top is omitted
  here: the integration tier already proves the renderer emits
  valid nftables; examples only need to prove they're valid
  *inputs*.

  Aggregator returns one umbrella `linkFarm` derivation that
  depends on every per-example compile check.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (pkgs) lib;

  /*
    List `*.nix` regular files in this directory, minus
    `default.nix` itself. Stable alphabetical order from
    `builtins.attrNames`.
  */
  exampleNames = lib.pipe (builtins.readDir ./.) [
    (lib.filterAttrs (n: t: t == "regular" && lib.hasSuffix ".nix" n && n != "default.nix"))
    builtins.attrNames
    (map (lib.removeSuffix ".nix"))
  ];

  /*
    Compile one example into a ruleset and force the whole
    value. `deepSeq` makes evaluation strict: a throwing Phase
    1 validator, a broken emit, or a type mismatch aborts here
    and the derivation never builds. On success the trivial
    `runCommand` just touches `$out`.
  */
  compileExample =
    name:
    let
      body = import (./. + "/${name}.nix") { inherit nftypes nftzones; };
      ruleset = nftzones.mkRuleset name body;
    in
    builtins.deepSeq ruleset (pkgs.runCommand "nftzones-example-${name}" { } "touch $out");
in
pkgs.linkFarm "nftzones-examples" (
  map (name: {
    inherit name;
    path = compileExample name;
  }) exampleNames
)
