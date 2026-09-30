/*
  Run the unit tests with nix-unit inside the build sandbox. Each test
  file runs in a fresh evaluator to bound memory.
*/
{
  inputs,
  lib,
  nix-unit,
  runCommand,
  system,
}:
let
  sourceDir = lib.cleanSource ../.;
  entrypointPath = sourceDir + "/tests/entrypoint.nix";

  # A group is an attrset holding test cases; nix-unit discovers the
  # cases nested beneath each selected group.
  listGroups =
    prefix: tests:
    if lib.any (lib.hasPrefix "test") (builtins.attrNames tests) then
      [ (lib.showAttrPath prefix) ]
    else
      lib.concatLists (lib.mapAttrsToList (name: listGroups (prefix ++ [ name ])) tests);

  testGroups = listGroups [ ] (
    import entrypointPath {
      flake = inputs.self;
      inherit system;
    }
  );

  # Reconstruct the root flake from store paths so the sandbox needs no
  # flake fetching.
  offlineFlakePath = builtins.toFile "nftzones-offline-flake.nix" ''
    import ${sourceDir}/tests/helpers/offline-flake.nix {
      flakePartsDir = "${inputs.flake-parts}";
      libnetDir = "${inputs.libnet}";
      nftypesDir = "${inputs.nftypes}";
      nixpkgsDir = "${inputs.nixpkgs}";
      rootDir = "${sourceDir}";
    }
  '';
in
assert testGroups != [ ];
runCommand "nftzones-unit-tests" { nativeBuildInputs = [ nix-unit ]; } ''
  # The writable store lets NixOS evaluation create derivations inside
  # the build sandbox.
  for group in ${lib.escapeShellArgs testGroups}; do
    nix-unit --show-trace \
      --eval-store "$TMPDIR/eval-store" --gc-roots-dir "$TMPDIR/gc-roots" \
      ${entrypointPath} --attr "$group" \
      --arg flake 'import ${offlineFlakePath}' \
      --argstr system ${lib.escapeShellArg system}
  done

  touch "$out"
''
