/*
  Integration test runner. Each scenario is a Nix attrset describing
  one or more `nftzones`-shaped tables; the runner compiles them
  via `mkTable`, renders to libnftables-JSON, and pipes the result
  through `nft -j --check` inside a Nix sandbox.

  `nft --check` ordinarily needs a netlink socket — unavailable in
  the build sandbox. The Linux Kernel Library (`lklWithFirewall`)
  + `libredirect` shim provides a userspace netlink that lets the
  command parse + validate without a running kernel. Lifted from
  the same trick `nixpkgs`' `networking.nftables.checkRuleset`
  uses.

  We validate the JSON form rather than the text form because
  JSON is the canonical libnftables wire format and isn't subject
  to text-renderer quirks in `nftypes` (chain-header trailing-`;`,
  set-reference `@name` syntax).

  Scenario forms (the runner accepts all three):

    1. Attrset (single-table body) — parse-only.

    2. List of `{ name; body; }` (multi-table ruleset) — parse-only.

    3. `{ body; warnings ? [ ]; assertions ? compiled: [ ]; }`
       (wrapper) — parse-check plus structured assertions.
       `body` is either form 1 or form 2 nested. `assertions` is
       a function from the compiled value to a list of
       `{ expr; expected; description ? null; }` records. Any record where
       `expr != expected` throws at evaluation time, before the
       derivation is built — failures surface during
       `nix flake check` rather than buried in build logs.
       Scenarios without a `body` attribute fall through to
       form 1 / 2 (unchanged behaviour).

       The `compiled` argument is `{ tables = { <name> =
       <dsl.table>; ...}; }`, plus a convenience `compiled.table`
       shortcut pointing at the one table for single-table
       scenarios (form 1 body). The shortcut lets assertions
       reference `compiled.table.chains` without hardcoding the
       scenario's filename. Multi-table scenarios (form 2 body)
       have no shortcut and must disambiguate via
       `compiled.tables.<X>`.

  Form 3 lets a scenario assert specific properties of the
  compiled output (rule comments present, policy emitted as tail
  rule, chain naming canonical) that `nft -j --check` is too
  lenient to catch.

  Every scenario also asserts its exact Phase 1 warnings: the
  `{ tag; path; }` projection of `internal.normalize.diagnose`.
  `warnings` defaults to none, so an unexpected warning fails the
  check. A form 1 body declares a list; a form 2 body declares an
  attrset of lists keyed by table name, defaulting to none per
  table. Only form 3 can declare warnings.

  Rejection scenarios (a separate flow, see `mkRejectionCheck`)
  invert the polarity: the input is a deliberate misconfiguration,
  and the build succeeds iff `mkRuleset` *throws*. Used to prove
  Phase 1 validators are wired into the live pipeline, and, through
  their `errors` lists, which Diagnostics they report.
*/
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (pkgs) lib;
  # The unit tests' `{ tag; path; }` projection of Phase 1 diagnostics.
  # It names the table "fw", which Phase 1 never reads.
  inherit (import ../unit/helpers.nix { inherit pkgs nftzones; }) diagnosticsFor;

  /*
    Compile a scenario body into a `{ tables = { <name> = <table>;
    ... }; }` attrset. Single-table scenarios get one entry keyed
    by the scenario name; multi-table list-form scenarios get one
    entry per table keyed by the table's `name` field.

    Mirrors what `renderScenario` does, but stops one step short
    of `nftypes.toJson` so assertions can inspect the structured
    `dsl.table` value directly.
  */
  compileScenario =
    name: body:
    if builtins.isList body then
      {
        tables = lib.listToAttrs (
          map (table: lib.nameValuePair table.name (nftzones.mkTable table.name table.body)) body
        );
      }
    else
      {
        tables = {
          ${name} = nftzones.mkTable name body;
        };
      };

  /*
    Render a scenario body as libnftables-JSON for `nft -j --check`.
    Takes the scenario name and a body in form 1 or form 2; returns
    the JSON string.
  */
  renderScenario =
    name: body:
    if builtins.isList body then
      nftypes.toJson (nftypes.dsl.ruleset (map (table: nftzones.mkTable table.name table.body) body))
    else
      nftypes.toJson (nftzones.mkRuleset name body);

  /*
    Walk every assertion record and collect every failure (not
    just the first) before throwing. Returns `null` if all pass;
    throws an aggregated message listing every failed assertion
    if any fail. Callers should `seq` the result so failures
    surface at evaluation time, before the derivation builds.

    Aggregating beats fail-fast for integration assertions: a
    single scenario typically asserts on a handful of compiled-
    output properties (set names, chain keys, rule contents); if
    two are wrong, one round-trip surfaces both rather than
    "fix, re-run, fix, re-run".
  */
  evaluateAssertions =
    name: checks:
    let
      failures = builtins.filter (check: check.expr != check.expected) checks;
      formatFailure =
        check:
        let
          description = check.description or "(no description)";
        in
        "  - '${description}'\n"
        + "      expected: ${lib.generators.toPretty { } check.expected}\n"
        + "      actual:   ${lib.generators.toPretty { } check.expr}";
    in
    if failures == [ ] then
      null
    else
      throw (
        "nftzones integration scenario '${name}': ${toString (builtins.length failures)} assertion(s) failed:\n"
        + lib.concatMapStringsSep "\n" formatFailure failures
      );

  /*
    Run `nft -j --check` on a rendered scenario, plus any
    structured assertions the scenario carries. The derivation
    builds iff the parse succeeds; assertion failures fire at
    evaluation time and never reach the derivation.
  */
  mkScenarioCheck =
    name: scenario:
    let
      isWrapper = builtins.isAttrs scenario && scenario ? body;

      body = if isWrapper then scenario.body else scenario;

      compiled = compileScenario name body;

      # Single-table convenience: expose the one table at
      # `compiled.table` so assertions don't have to hardcode the
      # scenario's filename. Multi-table (list-form) scenarios
      # skip this — they have to pick a name explicitly.
      compiledForAssertions =
        compiled
        // lib.optionalAttrs (!builtins.isList body) {
          table = compiled.tables.${name};
        };

      assertions =
        if isWrapper && scenario ? assertions then scenario.assertions compiledForAssertions else [ ];

      # A multi-table scenario keys its expected warnings by table name.
      declaredWarnings =
        if isWrapper && scenario ? warnings then
          scenario.warnings
        else if builtins.isList body then
          { }
        else
          [ ];

      checkWarnings = tableName: tableBody: {
        description = "Phase 1 warnings of table '${tableName}'";
        expr = (diagnosticsFor tableBody).warnings;
        expected = if builtins.isList body then declaredWarnings.${tableName} or [ ] else declaredWarnings;
      };

      warningChecks =
        if builtins.isList body then
          map (table: checkWarnings table.name table.body) body
        else
          [ (checkWarnings name body) ];

      checked = evaluateAssertions name (warningChecks ++ assertions);

      rulesetPath = builtins.toFile "${name}.json" (renderScenario name body);

      preloadLibraries = "${pkgs.buildPackages.libredirect}/lib/libredirect.so ${pkgs.buildPackages.lklWithFirewall.lib}/lib/liblkl-hijack.so";
    in
    builtins.seq checked (
      pkgs.runCommand "nftzones-integration-${name}"
        {
          nativeBuildInputs = [
            pkgs.buildPackages.nftables
            pkgs.buildPackages.libredirect
            pkgs.buildPackages.lklWithFirewall
          ];
        }
        ''
          LD_PRELOAD="${preloadLibraries}" \
            nft -j --check --file ${rulesetPath}
          touch $out
        ''
    );

  /*
    Rejection scenario: build succeeds iff `mkRuleset` *throws* on
    the supplied body. Used to prove a Phase 1 validator is wired
    into the live `mkRuleset` pipeline; if the validator gets
    disconnected and the misconfigured body compiles cleanly, the
    eval-time check below fires and the build never starts.

    `builtins.deepSeq` forces full evaluation of the would-be
    rendered ruleset; without it the lazy `mkTable` thunks could
    leave the validator throws unforced and `tryEval` would
    spuriously report success.

    `tryEval` does not capture the throw message, only its
    presence. A scenario that Phase 1 rejects therefore declares
    `errors`, its exact list of `{ tag; path; }` Diagnostics, and
    the check compares it with `diagnose`'s errors; messages are
    ignored. Exact lists also pin cascades, where one mistake
    produces several errors.

    A scenario that the table type rejects (such as comment
    injection) fails before Phase 1 runs, so it has no `errors`
    and keeps only the "it threw" check.
  */
  mkRejectionCheck =
    name: rejection:
    let
      attempt = builtins.tryEval (builtins.deepSeq (nftzones.mkRuleset name rejection.body) null);
      description = rejection.description or "no description";

      checked = evaluateAssertions "rejections/${name}" (
        lib.optional (rejection ? errors) {
          description = "Phase 1 errors";
          expr = (diagnosticsFor rejection.body).errors;
          expected = rejection.errors;
        }
      );
    in
    if attempt.success then
      throw "nftzones rejection scenario '${name}': expected mkRuleset to throw on the supplied body, but it compiled cleanly. (${description})"
    else
      builtins.seq checked (pkgs.runCommand "nftzones-rejection-${name}" { } "touch $out");
in
{
  inherit mkRejectionCheck mkScenarioCheck renderScenario;
}
