{ inputs }:
let
  primitives = import ./primitives.nix { inherit inputs; };
  zone = import ./zone.nix { inherit inputs primitives; };
  node = import ./node.nix { inherit inputs primitives zone; };
  filter = import ./filter.nix { inherit inputs primitives zone; };
  snat = import ./snat.nix { inherit inputs primitives zone; };
  dnat = import ./dnat.nix { inherit inputs primitives zone; };
  sroute = import ./sroute.nix { inherit inputs primitives zone; };
  droute = import ./droute.nix { inherit inputs primitives zone; };
  policy = import ./policy.nix { inherit inputs primitives zone; };
  table = import ./table.nix {
    inherit
      inputs
      primitives
      zone
      node
      filter
      snat
      dnat
      sroute
      droute
      policy
      ;
  };
in
{
  inherit
    zone
    node
    filter
    snat
    dnat
    sroute
    droute
    policy
    table
    ;
}
