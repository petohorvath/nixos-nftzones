{ inputs }:
let
  zone = import ./zone.nix { inherit inputs; };
  zonePair = import ./zone-pair.nix { inherit inputs; };
  filter = import ./filter.nix { inherit inputs; };
  priority = import ./priority.nix { inherit inputs; };
  node = import ./node.nix { inherit inputs zone; };
  wildcard = import ./wildcard.nix { inherit inputs; };

  /*
    Phase-0 modules — leaf helpers. Higher-level modules
    (orchestrators) take this as an `internal` arg, mirroring
    `lib/types/default.nix`.
  */
  base = {
    inherit
      zone
      zonePair
      filter
      priority
      node
      wildcard
      ;
  };

  normalize = import ./normalize.nix {
    inherit inputs;
    internal = base;
  };
in
base // { inherit normalize; }
