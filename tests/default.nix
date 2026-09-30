/*
  Assemble the project checks. The unit, integration, and examples
  tiers test the root flake's public exports; formatting and lint run
  against the cleaned source tree.
*/
{
  formatter,
  inputs,
  pkgs,
  system,
}:
let
  sourceDir = pkgs.lib.cleanSource ../.;
  testContext = import ./helpers/test-context.nix {
    flake = inputs.self;
    inherit system;
  };

  mkSourceCheck =
    {
      name,
      packages,
      script,
    }:
    pkgs.runCommand name { nativeBuildInputs = packages; } ''
      cp -R ${sourceDir} source
      chmod -R u+w source
      cd source
      ${script}
      touch "$out"
    '';
in
{
  unit = pkgs.callPackage ./unit-check.nix { inherit inputs system; };
  integration = import ./integration testContext;
  examples = import ./examples.nix testContext;
  formatting = mkSourceCheck {
    name = "nftzones-formatting";
    packages = [ formatter ];
    script = "nftzones-fmt --ci";
  };
  lint = mkSourceCheck {
    name = "nftzones-lint";
    packages = [
      pkgs.statix
      pkgs.deadnix
      pkgs.actionlint
    ];
    script = ''
      statix check .
      deadnix --fail .
      actionlint .github/workflows/*.yml
    '';
  };
}
