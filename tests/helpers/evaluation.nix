/*
  Evaluation helpers for the nix-unit suites, which reach them through
  `testContext.helpers`.

  Takes `lib`, the `nftzones` library, its NixOS module `nixosModule`,
  and the package set `pkgs`. Exports `evalTable`, `diagnosticsFor`,
  `membershipFor`, `evalType`, `evalFails`, `evalNixosSystem`, and
  `evalNixosModule`.
*/
{
  lib,
  nftzones,
  nixosModule,
  pkgs,
}:
let
  evalNixosSystem = modules: (pkgs.nixos modules).config;

  /*
    Evaluate a raw user table body against `nftzones.types.table`, so
    fixtures get the table defaults. The option name pins the table name
    to "fw".

    Takes the table body and returns the evaluated submodule value.
  */
  evalTable =
    body:
    (lib.evalModules {
      modules = [
        { options.fw = lib.mkOption { type = nftzones.types.table; }; }
        { config.fw = body; }
      ];
    }).config.fw;
in
{
  inherit evalTable;

  /*
    Run Phase 1 validation on a table body evaluated through the table
    type, for tests that pin which diagnostics fire. Messages are
    dropped so tests never depend on their prose.

    Takes a table body and returns `{ errors; warnings; }`, each a list
    of `{ tag; path; }` in `diagnose` order.
  */
  diagnosticsFor =
    body:
    let
      diagnostics = nftzones.internal.normalize.diagnose (evalTable body);
      project = map (diagnostic: {
        inherit (diagnostic) path tag;
      });
    in
    {
      errors = project diagnostics.errors;
      warnings = project diagnostics.warnings;
    };

  /*
    Resolve zone membership straight from real declarations: the
    evaluated zones plus each node lowered by `internal.node.toZone`.
    Bypassing Phase 1 means malformed hierarchy, such as parent
    cycles, reaches membership instead of failing validation.

    Takes a table body and returns the zone membership interface.
  */
  membershipFor =
    body:
    let
      table = evalTable body;
    in
    nftzones.internal.zone.resolveMembership {
      zones = table.zones // lib.mapAttrs (_: nftzones.internal.node.toZone) table.nodes;
      inherit (table.settings) localZone;
    };

  /*
    Check leaf option types (`zoneName`, `zoneCidrs`, …) without
    wrapping them in a full table body.

    Takes an option `type` and a `value`, runs them through
    `evalModules`, and returns the evaluated value. Throws if the type
    rejects the value.
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
    Probe type-level rejections. `builtins.tryEval` catches `throw` but
    not `abort`; nftzones type errors and submodule `apply` failures are
    all `throw`s, so this catches them. `deepSeq` forces the whole result
    tree; without it, lazy thunks (for example element-level checks
    inside `listOf`) silently slip past `tryEval`.

    Takes any value and returns true if evaluating it throws.
  */
  evalFails = result: !(builtins.tryEval (builtins.deepSeq result result)).success;

  # Evaluate a NixOS system from the given `modules` with `pkgs.nixos`.
  # Returns the evaluated `config`.
  inherit evalNixosSystem;

  # Evaluate a NixOS system with `pkgs.nixos`, importing the nftzones
  # NixOS module beside the given `configuration` module. Returns the
  # evaluated `config`.
  evalNixosModule =
    configuration:
    evalNixosSystem [
      nixosModule
      configuration
    ];
}
