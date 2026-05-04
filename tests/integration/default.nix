# Integration tests. Linux-only; placeholder until real tests land.
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
pkgs.runCommand "nftzones-integration-stub" { } ''
  echo "integration tests are not yet implemented"
  touch $out
''
