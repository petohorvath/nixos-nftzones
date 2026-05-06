/*
  internal/node — exposes node-related helpers under
  `nftzones.internal.node`.

  Exported functions:
    - `toZone` — lowers a single node to a fully-shaped zone value
                 mirroring the `nftzones.types.zone` submodule's
                 evaluated form. The compile pipeline merges these
                 into the effective zones namespace before chain
                 dispatch.

  ===== toZone =====

  Input:
    A node value matching `nftzones.types.node` — has `name`,
    `zone` (parent), and `address.ipv4` / `address.ipv6` (at
    least one address must be set, enforced by the type's
    `apply`).

  Output:
    A zone value with every field of the `nftzones.types.zone`
    submodule's evaluated form filled in:
      {
        name          = <node.name>;
        parent        = <node.zone>;     # establishes hierarchy
        interfaces    = [ ];
        cidrs         = optional ipv4 "${ipv4}/32"
                     ++ optional ipv6 "${ipv6}/128";
        matchOverride = { ingress = { }; egress = { }; };
        comment       = <node.comment>;   # propagated; null if unset
      }

    `parent` is load-bearing — it places the lowered zone inside
    the parent's sub-chain via Phase 4 emit's child-dispatch
    jumps. See `docs/specs/zone-parent.md` for the dispatch model.
    The empty per-side attrsets are valid `zoneMatchOverrideSide`
    values: every section defaults to `null`, and downstream
    consumers go through `internal.zone.getActiveMatchOverrides`,
    which filters null/empty sections out — so the all-null shape
    is indistinguishable from `{ }` for any read.

    The output mirrors the zone submodule's defaults so lowered
    nodes can be merged with declared zones (also submodule-
    evaluated) under one uniform shape — no re-evaluation needed
    downstream.

  Example:
    toZone {
      name = "web-server";
      zone = "dmz";
      address = { ipv4 = "10.0.0.5"; ipv6 = "fe80::1"; };
    }
    => {
      name = "web-server";
      parent = "dmz";
      interfaces = [ ];
      cidrs = [ "10.0.0.5/32" "fe80::1/128" ];
      matchOverride = { ingress = { }; egress = { }; };
      comment = null;
    }
*/
{ inputs }:
let
  inherit (inputs) lib;

  toZone =
    {
      name,
      zone,
      address,
      comment ? null,
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
        name
        parent
        interfaces
        cidrs
        comment
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
