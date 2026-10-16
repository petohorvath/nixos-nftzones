# Tests of the library entry point, `lib/default.nix`.
{ nftzones, ... }:
{
  testVersion = {
    expr = nftzones.version;
    expected = "0.1.0";
  };
}
