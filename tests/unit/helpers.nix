/*
  Shared helpers for the per-module unit-test files. Each
  `tests/unit/internal/<module>.nix` and `tests/unit/types/<module>.nix`
  imports this file instead of repeating evaluation boilerplate.

  Exports `evalTable`, `membershipFor`, `evalType`, and `evalFails`.
*/
{ pkgs, nftzones }:
let
  inherit (pkgs) lib;

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
    Resolve real declarations through node lowering and the same zone
    interface used by normalization. Deliberately stop before validation
    so grouping zones and malformed hierarchy can be exercised too.

    Takes a table body and returns the zone membership interface.
  */
  membershipFor =
    body:
    let
      state = nftzones.internal.normalize.convertNodesToZones {
        table = evalTable body;
        ctx = { };
      };
    in
    nftzones.internal.zone.resolveMembership {
      zones = state.ctx.mergedZones;
      inherit (state.table.settings) localZone;
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
}
