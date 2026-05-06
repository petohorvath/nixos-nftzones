/*
  types/zone — exposes zone-related types under `nftzones.types`.

  Exported types:
    - `zone`              — submodule for one zone definition
    - `zoneName`          — string identifier for a zone
    - `zoneParent`        — optional reference to a parent zone
    - `zoneInterfaces`    — list of interface names
    - `zoneCidrs`         — list of CIDR prefixes (mixed v4/v6)
    - `zoneMatchOverride` — per-direction, per-section match override
                            (`{ ingress; egress; }` × four sections:
                            `interfaces`, `ipv4`, `ipv6`, `extra`).
                            Each section is `nullOr primitives.rule`;
                            non-null replaces the corresponding
                            auto-generated clause. Consumed by
                            Phase 1's `checkZoneMatchable` and
                            Phase 4's `mkDirectionVariants`.
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
    Per-direction override sections. Each section is `nullOr (listOf
    statement)`; non-null replaces the corresponding auto-generated
    clause; `null` (the default) leaves the auto path in charge of
    that section.

    Section semantics in `mkDirectionVariants`:
      interfaces — substitutes for `iifname/oifname @<zone>_iifs`.
                   Hook-validity-checked (treated as iif/oif content
                   by convention; user landing this section at a hook
                   without iif/oif gets flagged).
      ipv4       — substitutes for `ip <addr> @<zone>_v4`. One
                   variant per non-empty family section; ANDed with
                   the prefix (interfaces + extra).
      ipv6       — substitutes for `ip6 <addr> @<zone>_v6`. Same.
      extra      — family-agnostic clauses ANDed into every variant
                   (alongside the interfaces section). No auto path —
                   exists only as a user-supplied prefix. Use for
                   `meta mark`, `vlan id`, `meta cgroup`, etc.

    Empty list (`[ ]`) is treated as `null` everywhere — both mean
    "no constraint contributed by this section".
  */
  zoneMatchOverrideSide = lib.types.submodule {
    options = {
      interfaces = lib.mkOption {
        type = lib.types.nullOr primitives.rule;
        default = null;
        description = ''
          Override for the iif/oif section. List of statements that
          replace the auto-generated `<ifField> @<zone>_iifs`
          prefix. Hook-validity is still enforced — putting non-
          iif/oif content here works but defeats the check.
        '';
      };
      ipv4 = lib.mkOption {
        type = lib.types.nullOr primitives.rule;
        default = null;
        description = ''
          Override for the v4 family section. List of statements
          that replace the auto-generated `ip <addr> @<zone>_v4`
          family clause. Emitted as one variant per non-empty
          family section.
        '';
      };
      ipv6 = lib.mkOption {
        type = lib.types.nullOr primitives.rule;
        default = null;
        description = ''
          Override for the v6 family section. List of statements
          that replace the auto-generated `ip6 <addr> @<zone>_v6`
          family clause.
        '';
      };
      extra = lib.mkOption {
        type = lib.types.nullOr primitives.rule;
        default = null;
        description = ''
          Family-agnostic clauses ANDed into every variant
          alongside the interfaces section. Use for `meta mark`,
          `vlan id`, `meta cgroup`, etc. No auto path — exists
          only as a user-supplied prefix.
        '';
      };
    };
  };

  zoneMatchOverride = lib.types.submodule {
    options = {
      ingress = lib.mkOption {
        type = zoneMatchOverrideSide;
        default = { };
        description = "Per-section override for the ingress side.";
      };
      egress = lib.mkOption {
        type = zoneMatchOverrideSide;
        default = { };
        description = "Per-section override for the egress side.";
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
            Name of this zone's parent zone, or `null` for a
            top-level (root) zone. Establishes hierarchical
            from-side dispatch: traffic enters via the parent's
            sub-chain and is dispatched into this zone's sub-chain
            on a match of this zone's from-side expression. Rules
            attached to the parent (with `from = [ "<parent>" ]`)
            run as fallbacks if this zone's sub-chain returns
            without a verdict.

            The referenced zone must exist in the same `zones`
            attrset (or as a node, which lowers to a zone). The
            `localZone` sentinel may not be a parent. Cycles are
            rejected. These checks live in
            `internal.normalize.checkParentRefs` /
            `checkParentCycles`.

            Hierarchy applies to the **from**-side only; the
            to-side stays a flat per-pair match.
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
          example = lib.literalExpression ''
            {
              ingress.extra = [ (eq meta.mark 0x100) ];
              egress.extra  = [ (eq meta.mark 0x100) ];
            }
          '';
          description = ''
            Per-direction, per-section match override. Useful for zones
            whose membership cannot be expressed as a plain interface
            / CIDR list. Each side has four nullable sections —
            `interfaces` / `ipv4` / `ipv6` / `extra` — that
            substitute for the corresponding auto-generated clauses
            in `mkDirectionVariants`. See `zoneMatchOverrideSide` for
            section semantics.
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
