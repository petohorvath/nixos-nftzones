/*
  Check that `mkRuleset` rejects every rejection fixture, proving the
  Phase 1 validators are wired into the live pipeline, one group per
  fixture.

  `tryEval` sees only that evaluation threw, not the message. A fixture
  that Phase 1 rejects therefore declares `errors`, its exact list of
  `{ tag; path; }` Diagnostics; exact lists also pin cascades, where one
  mistake produces several errors. A fixture that the table type
  rejects, such as comment injection, fails before Phase 1 runs and
  checks only the throw.
*/
{
  fixtures,
  helpers,
  lib,
  nftzones,
  ...
}:
let
  rejectionTests =
    name: rejection:
    {
      # `deepSeq` forces the whole ruleset; lazy `mkTable` thunks could
      # otherwise leave the validators' throws unforced.
      testThrows = {
        expr = (builtins.tryEval (builtins.deepSeq (nftzones.mkRuleset name rejection.body) null)).success;
        expected = false;
      };
    }
    // lib.optionalAttrs (rejection ? errors) {
      testErrors = {
        expr = (helpers.diagnosticsFor rejection.body).errors;
        expected = rejection.errors;
      };
    };
in
lib.mapAttrs rejectionTests fixtures.rejections
