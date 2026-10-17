# Assemble the `checks` output: the test entries from `tests/`, plus
# `lint`, which runs statix against the source tree. treefmt-nix adds
# the `treefmt` entry.
{ inputs, pkgs }:
let
  inherit (pkgs) lib runCommand statix;
in
lib.attrsets.unionOfDisjoint (import ../tests { inherit inputs pkgs; }) {
  lint = runCommand "nftzones-lint" { nativeBuildInputs = [ statix ]; } ''
    cd ${../.}
    statix check .
    touch "$out"
  '';
}
