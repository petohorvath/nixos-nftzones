# Tests of the library entry point, `lib/default.nix`.
{ nftzones, ... }:
{
  testVersion = {
    expr = nftzones.version;
    expected = "0.1.0";
  };

  # A type error names the table body it came from, not `<unknown-file>`.
  testMkRulesetTypeErrorNamesTableBody = {
    expr = builtins.toJSON (
      nftzones.mkRuleset "fw" {
        zones.lan.interfaces = [ "eth0" ];
        filters.f = {
          from = [ "lan" ];
          to = [ "local" ];
          rule = [ ];
        };
      }
    );
    expectedError = {
      type = "ThrownError";
      msg = "In `nftzones table body 'fw''";
    };
  };
}
