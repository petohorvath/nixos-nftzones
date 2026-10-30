{ inputs }:
let
  /*
    Three-layer module hierarchy:

      base       — leaf helpers (compatibility, zone, entry, priority,
                   node, refs, placement); only zone and placement
                   depend on another leaf, compatibility.
      withPhases — leaves + per-phase orchestrators (normalize,
                   expand, dispatch, emit); each phase consumes
                   `base` as its `internal` arg.
      compile    — top-level orchestrator that pipes Phase 1-4
                   together; consumes `withPhases`.

    Each higher layer's import passes the appropriate lower layer
    as the `internal` arg, mirroring `lib/types/default.nix`'s
    submodule-key namespacing (`nftzones.internal.<module>.<fn>`).
  */
  compatibility = import ./compatibility.nix { inherit inputs; };
  zone = import ./zone.nix {
    inherit inputs;
    internal = { inherit compatibility; };
  };
  entry = import ./entry.nix { inherit inputs; };
  priority = import ./priority.nix { inherit inputs; };
  node = import ./node.nix { inherit inputs; };
  refs = import ./refs.nix { inherit inputs; };
  placement = import ./placement.nix {
    inherit inputs;
    internal = { inherit compatibility; };
  };

  base = {
    inherit
      compatibility
      entry
      node
      placement
      priority
      refs
      zone
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

  withPhases = base // {
    inherit
      dispatch
      emit
      expand
      normalize
      ;
  };

  compile = import ./compile.nix {
    inherit inputs;
    internal = withPhases;
  };
in
withPhases // { inherit compile; }
