/*
  internal/node — exposes node-related helpers under
  `nftzones.internal.node`.

  Exported functions:
    - `toZone` — lowers a single node to a fully-shaped zone value
                 mirroring the `nftzones.types.zone` submodule's
                 evaluated form. The compile pipeline merges these
                 into the effective zones namespace before chain
                 dispatch.
*/
{ inputs }:
let
  inherit (inputs) lib;

  toZone =
    {
      name,
      zone,
      address,
      ...
    }:
    let
      parent = zone;
      interfaces = [ ];
      cidrs =
        lib.optional (address.ipv4 != null) "${address.ipv4}/32"
        ++ lib.optional (address.ipv6 != null) "${address.ipv6}/128";
    in
    {
      inherit
        cidrs
        interfaces
        name
        parent
        ;
      matchOverride = {
        ingress = { };
        egress = { };
      };
    };
in
{
  inherit toZone;
}
