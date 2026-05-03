/*
  tests/unit/helpers — shared test helpers for the per-module unit
  test files. Imported by each `tests/unit/internal/<module>.nix`
  to avoid copy-pasted boilerplate.

  Currently exports:
    - `evalTable` — runs a raw user body through `evalModules`
                    against `nftzones.types.table`, returning the
                    evaluated submodule value.
*/
{ pkgs, nftzones }:
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
    let
      cfg = pkgs.lib.evalModules {
        modules = [
          {
            options.fw = pkgs.lib.mkOption {
              type = nftzones.types.table;
            };
          }
          { config.fw = body; }
        ];
      };
    in
    cfg.config.fw;
}
