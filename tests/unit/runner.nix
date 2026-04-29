# Unit-test runner. Wraps `lib.runTests` in a derivation so failures show up
# as a failed `nix flake check`.
{ pkgs }:
let
  inherit (pkgs) lib;

  pretty = lib.generators.toPretty { multiline = true; };

  formatFailure = failure: ''
    ✗ ${failure.name}
        expected: ${pretty failure.expected}
        actual:   ${pretty failure.result}
  '';
in
{
  /*
    Run a `lib.runTests`-shaped attrset of tests. Each test is named
    `testFoo` and shaped as `{ expr; expected; }`. Returns a derivation
    that builds iff every test passes.
  */
  runTests =
    tests:
    let
      failures = lib.runTests tests;
      total = builtins.length (builtins.filter (lib.hasPrefix "test") (builtins.attrNames tests));
      failed = builtins.length failures;
      report = lib.concatMapStringsSep "\n" formatFailure failures;
    in
    pkgs.runCommand "nftzones-unit-tests"
      {
        passthru = { inherit failures total; };
      }
      (
        if failed == 0 then
          ''
            echo "all ${toString total} unit test(s) passed"
            touch $out
          ''
        else
          ''
            echo "${toString failed} of ${toString total} unit test(s) failed:"
            cat <<'EOF'
            ${report}
            EOF
            exit 1
          ''
      );
}
