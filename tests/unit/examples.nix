/*
  Compile each example in `fixtures.examples` through `mkRuleset` and
  force the result, so the shipped examples stay in sync with the types
  and the compiler. The build test `scenarios` already proves that
  rendered rulesets are valid nftables, so the examples skip
  `nft --check`. Every example also drops by default at input and
  forward, as its comments promise.
*/
{
  fixtures,
  lib,
  nftzones,
  ...
}:
let
  compiles = name: builtins.deepSeq (nftzones.mkRuleset name fixtures.examples.${name}) true;

  /*
    The policy of each filter base chain at input and forward in an
    example, as `{ <hook> = <policy>; }`. The compiler emits a base
    chain only at a hook where an entry lands, so a missing hook means
    nothing in the table filters that traffic.
  */
  chainPolicies =
    name:
    lib.pipe (nftzones.mkTable name fixtures.examples.${name}).chains [
      builtins.attrValues
      (builtins.filter (
        chain:
        chain.type or null == "filter"
        && builtins.elem (chain.hook or null) [
          "input"
          "forward"
        ]
      ))
      (map (chain: lib.nameValuePair chain.hook (chain.policy or null)))
      builtins.listToAttrs
    ];
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

  testEveryExampleDropsByDefault = {
    expr = lib.mapAttrs (name: _: chainPolicies name) fixtures.examples;
    expected = lib.mapAttrs (_: _: {
      forward = "drop";
      input = "drop";
    }) fixtures.examples;
  };

  # Fails when an example is added without a fixture.
  testListsEveryExample = {
    expr = lib.pipe (builtins.readDir ../../examples) [
      builtins.attrNames
      (map (lib.removeSuffix ".nix"))
    ];
    expected = builtins.attrNames fixtures.examples;
  };
}
