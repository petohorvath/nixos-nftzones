# Assemble the `checks` output: the test entries from `tests/`, plus
# `formatting` and `lint`, which run against the cleaned source tree.
{
  formatter,
  inputs,
  pkgs,
}:
let
  inherit (pkgs) lib;
  sourceDir = lib.cleanSource ../.;

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
lib.attrsets.unionOfDisjoint (import ../tests { inherit inputs pkgs; }) {
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
