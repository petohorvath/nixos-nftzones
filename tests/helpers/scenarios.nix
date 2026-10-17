/*
  Read the scenario fixtures in `tests/fixtures/scenarios/`. The unit
  suite `scenarios` checks their warnings and assertions; the build test
  `scenarios` renders them for `nft -j --check`.

  A scenario takes one of three forms:

    1. Attrset: a single-table body, compiled under the scenario name.

    2. List of `{ name; body; }`: a multi-table ruleset.

    3. `{ body; warnings ? …; assertions ? compiled: [ ]; }`: a wrapper
       around form 1 or form 2.

       `warnings` lists the exact Phase 1 warnings, as `{ tag; path; }`
       records of `internal.normalize.diagnose`. A form 1 body declares
       a list; a form 2 body declares an attrset of lists keyed by
       table name. Undeclared warnings default to none, so every
       scenario asserts that it raises no unexpected warning.

       `assertions` is a function from the compiled value to a list of
       `{ expr; expected; description ? null; }` records, for properties
       of the compiled output that `nft -j --check` is too lenient to
       catch. The compiled value is `{ tables = { <name> = <dsl.table>;
       … }; }`; a form 1 body also gets `table`, the one table, so
       assertions need not name the scenario.

  Takes `lib` and the `nftypes` and `nftzones` libraries. Exports
  `scenarioTables`, `scenarioWarnings`, `scenarioAssertions`, and
  `renderScenario`; each takes the scenario name and the scenario.
*/
{
  lib,
  nftypes,
  nftzones,
}:
let
  isWrapper = scenario: builtins.isAttrs scenario && scenario ? body;

  bodyOf = scenario: if isWrapper scenario then scenario.body else scenario;

  # List the tables of a scenario as `{ name; body; }`, naming a form 1
  # body after the scenario.
  scenarioTables =
    name: scenario:
    let
      body = bodyOf scenario;
    in
    if builtins.isList body then body else [ { inherit name body; } ];
in
{
  inherit scenarioTables;

  # Return the declared Phase 1 warnings as an attrset keyed by table
  # name, with an empty list for each table that declares none.
  scenarioWarnings =
    name: scenario:
    let
      declared = if isWrapper scenario then scenario.warnings or null else null;
      isMultiTable = builtins.isList (bodyOf scenario);
      warningsFor =
        table:
        if declared == null then
          [ ]
        else if isMultiTable then
          declared.${table.name} or [ ]
        else
          declared;
    in
    lib.listToAttrs (
      map (table: lib.nameValuePair table.name (warningsFor table)) (scenarioTables name scenario)
    );

  # Apply the scenario's assertions to its compiled tables. Returns a
  # list of `{ description; expr; expected; }`, empty for a scenario
  # without assertions.
  scenarioAssertions =
    name: scenario:
    let
      tables = lib.listToAttrs (
        map (table: lib.nameValuePair table.name (nftzones.mkTable table.name table.body)) (
          scenarioTables name scenario
        )
      );
      compiled = {
        inherit tables;
      }
      // lib.optionalAttrs (!builtins.isList (bodyOf scenario)) { table = tables.${name}; };
    in
    map (assertion: {
      description = assertion.description or null;
      inherit (assertion) expr expected;
    }) (if isWrapper scenario && scenario ? assertions then scenario.assertions compiled else [ ]);

  # Render a scenario as the libnftables JSON that `nft -j` reads.
  renderScenario =
    name: scenario:
    let
      body = bodyOf scenario;
    in
    if builtins.isList body then
      nftypes.toJson (nftypes.dsl.ruleset (map (table: nftzones.mkTable table.name table.body) body))
    else
      nftypes.toJson (nftzones.mkRuleset name body);
}
