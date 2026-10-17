# Assemble the `checks` output: the test entries from `tests/`, plus
# `lint`, which runs statix against the source tree. treefmt-nix adds
# the `treefmt` entry.
{ inputs, pkgs }:
pkgs.lib.attrsets.unionOfDisjoint (import ../tests { inherit inputs pkgs; }) {
  lint =
    pkgs.runCommand "nftzones-lint"
      {
        src = ../.;
        nativeBuildInputs = [ pkgs.statix ];
      }
      ''
        cd "$src"
        statix check .
        touch "$out"
      '';
}
