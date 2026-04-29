{ inputs }:
{
  zone = import ./zone.nix { inherit inputs; };
  zonePair = import ./zone-pair.nix { inherit inputs; };
  filter = import ./filter.nix { inherit inputs; };
  priority = import ./priority.nix { inherit inputs; };
}
