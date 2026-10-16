# test-standard v1: copied from the test-standard skill; do not edit here.
/*
  Turn the build entry point's tests into checks named `build-<test>`.

  Takes the package set `pkgs` and the `repo` name, then the attrset of
  build tests. A test that returns a derivation becomes its check
  unchanged; a test that returns an attrset of derivations becomes a
  `linkFarm` with one link per case, named by its attribute path.
*/
{ pkgs, repo }:
tests:
let
  inherit (pkgs) lib;

  linkCases =
    testName: cases:
    let
      links = lib.collect (link: link ? path) (
        lib.mapAttrsRecursiveCond (value: !lib.isDerivation value) (path: case: {
          name = lib.concatStringsSep "/" path;
          path = case;
        }) cases
      );
      # The project policy reads the features of each check itself.
      requiredSystemFeatures = lib.unique (
        lib.concatMap (link: link.path.requiredSystemFeatures or [ ]) links
      );
    in
    if links == [ ] then
      throw "${repo}: build test `${testName}` has no cases"
    else
      (pkgs.linkFarm "${repo}-build-${testName}" links).overrideAttrs { inherit requiredSystemFeatures; };
in
lib.mapAttrs' (
  testName: test:
  lib.nameValuePair "build-${testName}" (
    if lib.isDerivation test then test else linkCases testName test
  )
) tests
