/*
  types/zone — exposes zone-related types under `nftzones.types`.

  Exported types:
    - `zone`              — submodule for one zone definition
    - `zoneName`          — string identifier for a zone
    - `zoneParent`        — optional reference to a parent zone
    - `zoneInterfaces`    — list of interface names
    - `zoneCidrs`         — list of CIDR prefixes (mixed v4/v6)
    - `zoneMatchOverride` — per-direction wholesale match override
                            (`{ ingress; egress; }` with nullable
                            sides; `null` means "compute from
                            interfaces / cidrs"); consumed by
                            Phase 1's `checkZoneMatchable`
    - `zoneComment`       — optional free-form comment

  Consumers wire the zone type as `lib.mkOption { type =
  lib.types.attrsOf nftzones.types.zone; }`.

  `zoneName` only validates string shape; cross-cutting concerns —
  that a `parent` reference resolves to an existing zone, or that
  names do not collide with `settings.localZone` /
  `settings.wildcardZone` — are enforced by Phase 1's
  `checkNameCollisions` and `checkSettings` validators.

  Example:
    options.zones = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.zone;
      default = { };
    };

    config.zones.lan = {
      interfaces = [ "eth1" "eth2" ];
      cidrs = [ "10.0.0.0/24" ];
    };
    config.zones.guest = {
      parent = "lan";
      interfaces = [ "eth3" ];
    };
*/
{
  inputs,
  primitives,
}:
let
  inherit (inputs) lib libnet;

  zoneName = primitives.identifier;

  zoneParent = lib.types.nullOr zoneName;

  /*
    libnet.types.interfaceName is strict (kernel dev_valid_name
    parity). Wildcard patterns like `wlan*` are not yet supported.
  */
  zoneInterfaces = lib.types.listOf libnet.types.interfaceName;

  zoneCidrs = lib.types.listOf libnet.types.cidr;

  zoneComment = primitives.comment;

  /*
    One direction's match: a list of rule-body variants. Different
    variants become separate rules sharing the same verdict.
  */
  zoneMatchVariants = lib.types.listOf primitives.rule;

  zoneMatchOverride = lib.types.submodule {
    options = {
      ingress = lib.mkOption {
        type = lib.types.nullOr zoneMatchVariants;
        default = null;
        description = ''
          Per-direction match override. `null` (the default)
          means "derive matchability from interfaces / cidrs";
          a non-null list provides a wholesale replacement.
        '';
      };
      egress = lib.mkOption {
        type = lib.types.nullOr zoneMatchVariants;
        default = null;
        description = ''
          Per-direction match override. `null` (the default)
          means "derive matchability from interfaces / cidrs";
          a non-null list provides a wholesale replacement.
        '';
      };
    };
  };

  zone = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = zoneName;
          readOnly = true;
          default = name;
          example = "trusted";
          description = ''
            The zone's name. Defaults to the attribute name in the
            enclosing `zones` attrset, e.g. `zones.lan.name == "lan"`.
          '';
        };

        parent = lib.mkOption {
          type = zoneParent;
          default = null;
          example = "lan";
          description = ''
            Name of this zone's parent zone, or `null` for a top-level
            zone. The referenced zone must exist in the same `zones`
            attrset; that check is enforced at module level, not by
            the type.
          '';
        };

        interfaces = lib.mkOption {
          type = zoneInterfaces;
          default = [ ];
          example = [
            "eth1"
            "eth2"
          ];
          description = "Interface names that belong to this zone.";
        };

        cidrs = lib.mkOption {
          type = zoneCidrs;
          default = [ ];
          example = [
            "10.0.0.0/24"
            "2001:db8::/32"
          ];
          description = ''
            CIDR prefixes (mixed v4/v6) that belong to this zone.
          '';
        };

        matchOverride = lib.mkOption {
          type = zoneMatchOverride;
          default = { };
          description = ''
            Per-direction match override. Useful for zones whose
            membership cannot be expressed as a plain interface /
            CIDR list. `null` on a side keeps the computed
            matchability (from `interfaces` / `cidrs`); a non-null
            list provides a wholesale replacement.
          '';
        };

        comment = lib.mkOption {
          type = zoneComment;
          default = null;
          example = "trusted internal subnets";
          description = ''
            Free-form comment, attached to the zone for
            documentation. `null` (the default) emits no comment
            downstream.
          '';
        };
      };
    }
  );
in
{
  inherit
    zoneName
    zoneParent
    zoneInterfaces
    zoneCidrs
    zoneMatchOverride
    zoneComment
    zone
    ;
}
