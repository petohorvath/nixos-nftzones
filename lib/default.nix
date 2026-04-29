{ inputs }:
let
  inherit (inputs) lib;

  /*
    Internal building blocks — low-level constructors used to compose
    the higher-level zone / filter surface. `lib/internal/default.nix`
    returns one attrset per source module (`zone`, `filter`, …); each
    module's exports stay under that submodule key, so callers reach
    functions as `nftzones.internal.<module>.<fn>` (e.g.
    `nftzones.internal.zone.genMatch`).
  */
  internal = import ./internal { inherit inputs; };

  /*
    NixOS option types for the public surface. `lib/types/default.nix`
    returns one attrset per source module; we flatten their values
    onto a single `types` namespace (unlike `internal`, which keeps
    the per-module sub-namespaces). `types.zone`'s `match` default
    closes over `internal.zone.genMatch`, so type modules are
    constructed after `internal` is in scope.
  */
  typeModules = import ./types { inherit inputs internal; };
  types = lib.mergeAttrsList (lib.attrValues typeModules);
in
{
  # Library version. Bumped manually per release.
  version = "0.1.0";

  inherit internal types;
}
