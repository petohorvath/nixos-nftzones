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

    3. `{ body; assertions ? compiled: [ ]; }` (wrapper) — parse-
       check plus structured assertions. `body` is either form 1
       or form 2 nested. `assertions` is a function from the
       compiled value (`{ tables = { <name> = <dsl.table>; ...}; }`)
       to a list of `{ expr; expected; description ? null; }`
       records. Any record where `expr != expected` throws at
       evaluation time, before the derivation is built — failures
       surface during `nix flake check` rather than buried in
       build logs. Scenarios without a `body` attribute fall
       through to form 1 / 2 (unchanged behaviour).

  Form 3 lets a scenario assert specific properties of the
  compiled output (rule comments present, policy emitted as tail
  rule, chain naming canonical) that `nft -j --check` is too
  lenient to catch.

  Rejection scenarios (a separate flow, see `mkRejectionCheck`)
  invert the polarity: the input is a deliberate misconfiguration,
  and the build succeeds iff `mkRuleset` *throws*. Used to prove
  Phase 1 validators are wired into the live pipeline; unit tests
  verify each validator in isolation, but only the rejection
  build proves the orchestrator still calls them.
*/
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (pkgs) lib;

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
        tables = lib.listToAttrs (map (e: lib.nameValuePair e.name (nftzones.mkTable e.name e.body)) body);
      }
    else
      {
        tables = {
          ${name} = nftzones.mkTable name body;
        };
      };

  # Compile a scenario body into libnftables-JSON.
  renderScenario =
    name: body:
    if builtins.isList body then
      nftypes.toJson (nftypes.dsl.ruleset (map (e: nftzones.mkTable e.name e.body) body))
    else
      nftypes.toJson (nftzones.mkRuleset name body);

  /*
    Walk every assertion record; throw on the first whose `expr`
    does not equal `expected`. Returns a sentinel value (`null`)
    when all pass; callers should `seq` it before returning the
    derivation so failures surface at evaluation time.
  */
  evaluateAssertions =
    name: checks:
    lib.foldl' (
      _: a:
      let
        desc = a.description or "(no description)";
      in
      if a.expr == a.expected then
        null
      else
        throw (
          "nftzones integration scenario '${name}': assertion '${desc}' failed\n"
          + "  expected: ${lib.generators.toPretty { } a.expected}\n"
          + "  actual:   ${lib.generators.toPretty { } a.expr}"
        )
    ) null checks;

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

      assertions = if isWrapper && scenario ? assertions then scenario.assertions compiled else [ ];

      checked = evaluateAssertions name assertions;

      rulesetFile = builtins.toFile "${name}.json" (renderScenario name body);
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
          LD_PRELOAD="${pkgs.buildPackages.libredirect}/lib/libredirect.so ${pkgs.buildPackages.lklWithFirewall.lib}/lib/liblkl-hijack.so" \
            nft -j --check --file ${rulesetFile}
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

    `tryEval` does not capture the throw message — only its
    presence — so the unit tests in `tests/unit/internal/normalize.nix`
    remain the source of truth for *which* validator fired and
    *what* it said. The rejection check just pins that something
    in the pipeline rejected the input.
  */
  mkRejectionCheck =
    name: rejection:
    let
      attempt = builtins.tryEval (builtins.deepSeq (nftzones.mkRuleset name rejection.body) null);
    in
    if attempt.success then
      throw (
        "nftzones rejection scenario '${name}': "
        + "expected mkRuleset to throw on the supplied body, "
        + "but it compiled cleanly. "
        + "(${rejection.description or "no description"})"
      )
    else
      pkgs.runCommand "nftzones-rejection-${name}" { } "touch $out";
in
{
  inherit renderScenario mkScenarioCheck mkRejectionCheck;
}
