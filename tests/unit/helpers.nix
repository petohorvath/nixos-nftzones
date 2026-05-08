/*
  tests/unit/helpers — shared test helpers for the per-module unit
  test files. Imported by each `tests/unit/internal/<module>.nix`
  and `tests/unit/types/<module>.nix` to avoid copy-pasted
  boilerplate.

  Exports:
    - `evalTable` — runs a raw user body through `evalModules`
                    against `nftzones.types.table`, returning the
                    evaluated submodule value.
    - `evalType`  — runs a single value through `evalModules`
                    against an arbitrary option type, returning the
                    evaluated value (throws if rejected).
    - `evalFails` — true iff evaluating its argument throws. Used
                    to assert type-level rejections.
*/
{ pkgs, nftzones }:
let
  inherit (pkgs) lib;
in
{
  /*
    Build a realistic `nftzones.types.table` value via evalModules.
    The table type fills in submodule defaults for `settings`,
    rule groups, and `objects`; each test only specifies the
    fields it cares about.

    The hardcoded `fw` option name forces the resulting table's
    `name` field to "fw" (via the submodule's `default = name;`
    mechanism). Tests that need a custom name should construct
    the eval-modules call themselves.
  */
  evalTable =
    body:
    (lib.evalModules {
      modules = [
        { options.fw = lib.mkOption { type = nftzones.types.table; }; }
        { config.fw = body; }
      ];
    }).config.fw;

  /*
    Run `value` through evalModules against `type`. Useful for
    asserting acceptance / shape of leaf option types
    (`zoneName`, `zoneCidrs`, …) without wrapping them in a full
    table body.
  */
  evalType =
    type: value:
    (lib.evalModules {
      modules = [
        { options.x = lib.mkOption { inherit type; }; }
        { config.x = value; }
      ];
    }).config.x;

  /*
    Type-rejection probe. `builtins.tryEval` eats `throw`s but
    not `abort`s; nftzones type errors and submodule `apply`
    throws are all `throw`s, so this catches them. `deepSeq`
    forces the whole result tree — without it, lazy thunks
    (e.g. element-level checks inside `listOf`) silently slip
    past `tryEval`.
  */
  evalFails = result: !(builtins.tryEval (builtins.deepSeq result result)).success;
}
