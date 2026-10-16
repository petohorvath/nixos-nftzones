# test-standard v1: copied from the test-standard skill; do not edit here.
/*
  Turn a nix-unit entry point into a check, so its suites run under
  `nix flake check` and the project policy's `test`.

  Takes the flake `inputs`, the package set `pkgs`, the `repo` name, and
  `srcDir`, a source tree holding the files the suites read. Returns a
  function from the entry's settings to a derivation that builds when
  every suite passes.
*/
{
  inputs,
  pkgs,
  repo,
  srcDir,
}:
{
  kind,
  name ? kind,
  suites ? null,
  extraArgs ? { },
  requiredSystemFeatures ? [ ],
  postCheck ? "",
  jobs ? null,
}:
let
  inherit (pkgs) lib nix-unit;
  inherit (pkgs.stdenv.hostPlatform) system;

  entryPointPath = "${srcDir}/tests/${kind}";
  evaluationInputsPath = "${srcDir}/tests/helpers/evaluation-inputs.nix";
  entryPoint = import entryPointPath;

  # The flake inputs the entry point declares, except those that
  # `extraArgs` overrides.
  entryInputs = removeAttrs (builtins.intersectAttrs (builtins.functionArgs entryPoint) inputs) (
    builtins.attrNames extraArgs
  );

  # Walk an input and its transitive inputs into a tree of store paths,
  # the shape `helpers/evaluation-inputs.nix` rebuilds. Each path keeps
  # its string context, so the sandbox receives every source.
  inputTree =
    input:
    if input ? inputs then
      {
        path = input.outPath;
        inputs = builtins.mapAttrs (_: inputTree) input.inputs;
      }
    else
      {
        path = input.outPath;
        flake = false;
      };

  inputArgs = lib.mapAttrs (
    inputName: input:
    let
      treePath = builtins.toFile "${repo}-${name}-${inputName}.json" (builtins.toJSON (inputTree input));
    in
    "(import ${evaluationInputsPath}) (builtins.fromJSON (builtins.readFile ${treePath}))"
  ) entryInputs;

  # Groups are listed at evaluation time. An `extraArgs` value is a Nix
  # expression string; it is imported without its context, which holds
  # as long as listing the groups does not read the paths it names.
  importExpression =
    expression:
    import (builtins.toFile "${repo}-arg.nix" (builtins.unsafeDiscardStringContext expression));

  tests = entryPoint (
    entryInputs // builtins.mapAttrs (_: importExpression) extraArgs // { inherit system; }
  );

  selectedTests = if suites == null then tests else lib.getAttrs suites tests;

  # A group is an attrset that directly holds test cases.
  listGroups =
    prefix: value:
    if !builtins.isAttrs value then
      [ ]
    else if lib.any (lib.hasPrefix "test") (builtins.attrNames value) then
      [ (lib.showAttrPath prefix) ]
    else
      lib.concatLists (lib.mapAttrsToList (attrName: listGroups (prefix ++ [ attrName ])) value);

  groups = listGroups [ ] selectedTests;

  nixUnitArgs = [
    "--show-trace"
    "--argstr"
    "system"
    system
  ]
  ++ lib.concatLists (
    lib.mapAttrsToList (argName: expression: [
      "--arg"
      argName
      expression
    ]) (inputArgs // extraArgs)
  );

  # nix-unit 2.35 stopped needing a directory for its GC roots.
  gcRootsArgs = lib.optionalString (lib.versionOlder nix-unit.version "2.35") "--gc-roots-dir \"$TMPDIR/gc-roots\"";
in
if groups == [ ] then
  throw "${repo}-${name}: tests/${kind} has no nix-unit groups"
else
  pkgs.runCommand "${repo}-${name}"
    {
      nativeBuildInputs = [ nix-unit ];
      inherit requiredSystemFeatures;
    }
    ''
      maxJobs=${if jobs == null then ''"$NIX_BUILD_CORES"'' else toString jobs}
      if [ "$maxJobs" -lt 1 ]; then
        maxJobs=1
      fi

      # The writable eval store lets NixOS evaluation add derivations
      # inside the sandbox. Each group runs in its own nix-unit process
      # to bound its memory; a group's log prints when it finishes.
      runGroup() {
        log="$TMPDIR/logs/$1.log"
        status=0
        nix-unit ${lib.escapeShellArgs nixUnitArgs} \
          --eval-store "$TMPDIR/eval-store" ${gcRootsArgs} \
          ${entryPointPath} --attr "$1" >"$log" 2>&1 || status=$?
        echo "=== $1"
        cat "$log"
        return "$status"
      }
      export -f runGroup

      mkdir "$TMPDIR/logs"
      printf '%s\n' ${lib.escapeShellArgs groups} |
        xargs -d '\n' -P "$maxJobs" -I '{}' \
          bash -c 'runGroup "$1"' runGroup '{}'

      ${postCheck}
      touch "$out"
    ''
