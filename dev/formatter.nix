{
  nixfmt,
  prettier,
  shfmt,
  treefmt,
  writeShellApplication,
}:
writeShellApplication {
  name = "nftzones-fmt";
  runtimeInputs = [
    treefmt
    nixfmt
    shfmt
    prettier
  ];
  text = ''
    exec treefmt --tree-root . --walk filesystem \
      --config-file ${./treefmt.toml} "$@"
  '';
}
