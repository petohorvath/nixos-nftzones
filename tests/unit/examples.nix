/*
  Compile each `examples/*.nix` through `mkRuleset` and force the
  result, so the shipped examples stay in sync with the types and the
  compiler. The build test `scenarios` already proves that rendered
  rulesets are valid nftables, so the examples skip `nft --check`.
*/
{
  lib,
  nftypes,
  nftzones,
  ...
}:
let
  compiles =
    name:
    let
      body = import ../../examples/${name}.nix { inherit nftypes nftzones; };
    in
    builtins.deepSeq (nftzones.mkRuleset name body) true;
in
{
  testDmzHierarchyCompiles = {
    expr = compiles "dmz-hierarchy";
    expected = true;
  };

  testHomeRouterCompiles = {
    expr = compiles "home-router";
    expected = true;
  };

  testPolicyRoutedVpnCompiles = {
    expr = compiles "policy-routed-vpn";
    expected = true;
  };

  testVlanSegmentationCompiles = {
    expr = compiles "vlan-segmentation";
    expected = true;
  };

  # Fails when an example is added without a test above.
  testListsEveryExample = {
    expr = lib.pipe (builtins.readDir ../../examples) [
      builtins.attrNames
      (map (lib.removeSuffix ".nix"))
    ];
    expected = [
      "dmz-hierarchy"
      "home-router"
      "policy-routed-vpn"
      "vlan-segmentation"
    ];
  };
}
