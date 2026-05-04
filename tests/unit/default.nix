/*
  Unit-test definitions. Each `testFoo` attr is `{ expr; expected; }` and
  is consumed by `tests/runner.nix` via `lib.runTests`. Per-module test
  files under subdirectories (mirroring `lib/`) are merged in here.
*/
args@{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
{
  testVersion = {
    expr = nftzones.version;
    expected = "0.1.0";
  };
}
// import ./internal/zone.nix args
// import ./internal/entry.nix args
// import ./internal/priority.nix args
// import ./internal/node.nix args
// import ./internal/normalize.nix args
// import ./internal/refs.nix args
// import ./internal/expand.nix args
// import ./internal/dispatch.nix args
// import ./internal/emit.nix args
// import ./internal/compile.nix args
// import ./module.nix args
