# Check every scenario fixture's Phase 1 warnings and structured
# assertions, one group per scenario. The build test `scenarios` runs
# `nft -j --check` on the same fixtures. Warnings come from the public
# `diagnose`, which forces the whole table, so every valid scenario
# also proves that forcing rejects nothing valid.
{
  fixtures,
  helpers,
  lib,
  nftzones,
  ...
}:
let
  scenarioTests =
    name: scenario:
    let
      assertions = helpers.scenarioAssertions name scenario;
      # Compare descriptions beside values, so a failure names its
      # assertion.
      describe =
        field:
        map (assertion: {
          inherit (assertion) description;
          value = assertion.${field};
        });
    in
    {
      testWarnings = {
        expr = lib.listToAttrs (
          map (
            table:
            lib.nameValuePair table.name (helpers.dropMessages (nftzones.diagnose table.name table.body))
            .warnings
          ) (helpers.scenarioTables name scenario)
        );
        expected = helpers.scenarioWarnings name scenario;
      };
    }
    // lib.optionalAttrs (assertions != [ ]) {
      testAssertions = {
        expr = describe "expr" assertions;
        expected = describe "expected" assertions;
      };
    };
in
lib.mapAttrs scenarioTests fixtures.scenarios
