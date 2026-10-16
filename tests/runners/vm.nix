# test-standard v1: copied from the test-standard skill; do not edit here.
/*
  Turn the VM entry point's scenarios into checks named
  `vm-<scenario>`.

  Takes the package set `pkgs` and the `repo` name, then the attrset of
  NixOS test modules. Each check runs its module with
  `pkgs.testers.runNixOSTest` under the name `<repo>-<scenario>`.
*/
{ pkgs, repo }:
scenarios:
pkgs.lib.mapAttrs' (
  scenarioName: module:
  pkgs.lib.nameValuePair "vm-${scenarioName}" (
    pkgs.testers.runNixOSTest {
      imports = [ module ];
      name = "${repo}-${scenarioName}";
    }
  )
) scenarios
