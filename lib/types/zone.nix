/*
  types/zone — exposes zone-related types under `nftzones.types`.

  Exported types:
    - `zone`              — submodule for one zone definition
    - `zoneName`          — string identifier for a zone
    - `zoneParent`        — optional reference to a parent zone
    - `zoneInterfaces`    — list of interface names
    - `zoneCidrs`         — list of CIDR prefixes (mixed v4/v6)
    - `zoneMatch`         — submodule with read-only `ingress` and
                            `egress` variant lists; shape of a zone's
                            computed match
    - `zoneMatchOverride` — same shape as `zoneMatch` but with nullable
                            sides; `null` on a side keeps the computed
                            value untouched
    - `zoneComment`       — optional free-form comment

  `zone`'s `match` field is read-only and computed from `interfaces`,
  `cidrs`, and `matchOverride` via `internal.zone.genMatch`.
  Consumers wire it as `lib.mkOption { type = lib.types.attrsOf
  nftzones.types.zone; }`.

  `zoneName` only validates string shape; cross-cutting concerns —
  that a `parent` reference resolves to an existing zone, or that
  names do not collide with reserved zones (`host`, `all`, `any`,
  `local`, `self`, `firewall`) — belong in module assertions on the
  enclosing `zones` attrset.

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
  internal,
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

  zoneMatch = lib.types.submodule {
    options = {
      ingress = lib.mkOption {
        type = zoneMatchVariants;
        readOnly = true;
        description = "Match variants for the ingress side.";
      };
      egress = lib.mkOption {
        type = zoneMatchVariants;
        readOnly = true;
        description = "Match variants for the egress side.";
      };
    };
  };

  zoneMatchOverride = lib.types.submodule {
    options = {
      ingress = lib.mkOption {
        type = lib.types.nullOr zoneMatchVariants;
        default = null;
        description = "Replace the computed ingress side wholesale.";
      };
      egress = lib.mkOption {
        type = lib.types.nullOr zoneMatchVariants;
        default = null;
        description = "Replace the computed egress side wholesale.";
      };
    };
  };

  /*
    One direction's match: a list of rule-body variants. Different
    variants become separate rules sharing the same verdict.
    Variant count depends on what the zone declares — see
    `internal/zone.nix` for the table.
  */
  zoneMatchVariants = lib.types.listOf primitives.rule;

  zone = lib.types.submodule (
    { name, config, ... }:
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
            Wholesale override for either or both directions. Useful for
            zones whose membership cannot be expressed as a plain
            interface/CIDR list.
          '';
        };

        match = lib.mkOption {
          type = zoneMatch;
          readOnly = true;
          default = internal.zone.genMatch {
            inherit (config) interfaces cidrs;
            override = config.matchOverride;
          };
          description = ''
            Computed nftables match for this zone. Derived from
            `interfaces`, `cidrs`, and `matchOverride`; not user-settable.
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
    zoneMatch
    zoneMatchOverride
    zoneComment
    zone
    ;
}
