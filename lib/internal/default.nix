{ inputs }:
let
  zone = import ./zone.nix { inherit inputs; };
  entry = import ./entry.nix { inherit inputs; };
  priority = import ./priority.nix { inherit inputs; };
  node = import ./node.nix { inherit inputs zone; };

  /*
    Phase-0 modules — leaf helpers. Higher-level modules
    (orchestrators) take this as an `internal` arg, mirroring
    `lib/types/default.nix`.
  */
  base = {
    inherit
      zone
      entry
      priority
      node
      ;
  };

  normalize = import ./normalize.nix {
    inherit inputs;
    internal = base;
  };

  expand = import ./expand.nix {
    inherit inputs;
    internal = base;
  };

  dispatch = import ./dispatch.nix {
    inherit inputs;
    internal = base;
  };

  emit = import ./emit.nix {
    inherit inputs;
    internal = base;
  };
in
base
// {
  inherit
    normalize
    expand
    dispatch
    emit
    ;
}
