/*
  types/sroute — exposes sroute-related types under `nftzones.types`.

  Exported types:
    - `sroute`         — submodule for one sroute definition
    - `srouteName`     — string identifier for an sroute
    - `srouteRule`     — non-empty list of nftypes statements
                         (mangle / match body)
    - `sroutePriority` — symbol-or-int entry sort key (lower runs first)
    - `srouteComment`  — optional free-form comment

  An sroute is a source-zone-keyed route-mangling rule that applies
  in prerouting (`type filter hook prerouting priority mangle`; the
  kernel attaches `route` chains only at output). It marks or
  mangles incoming packets based on source zone before the routing
  decision — used for mark-based policy routing of forwarded
  traffic. Consumers wire it as `lib.mkOption { type =
  lib.types.attrsOf nftzones.types.sroute; }`.

  Why no `to`: prerouting runs before the routing decision, so the
  destination zone (which depends on routing) isn't determined
  when the entry's emitted rules fire. Same structural reason dnat omits `to`.

  `from` uses the shared `zoneNames` type and the same wildcard
  / localZone behaviour as filter / snat / dnat — see
  `types/filter.nix` for the full discussion.

  `srouteRule` is a flat, non-empty list of nftypes statements —
  typically match conditions plus mangle statements like
  `meta mark set N`. `rule` is required: a sroute without
  statements marks nothing. No verdict is expected: the chain runs
  before the routing decision, which then reads the mark.

  `sroutePriority` orders rules sharing the same `from` zone:
  lower values run first.

  Example:
    options.sroutes = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.sroute;
      default = { };
    };

    config.sroutes.guest-via-vpn = {
      from = [ "guest" ];
      rule = [
        (mangle meta.mark 100)
      ];
      comment = "guest traffic policy-routed via VPN";
    };
*/
{
  inputs,
  primitives,
  zone,
}:
let
  inherit (inputs) lib;
  inherit (zone) zoneNames;

  srouteName = primitives.identifier;

  srouteComment = primitives.comment;

  srouteRule = primitives.nonEmptyRule;

  sroutePriority = primitives.entryPriority;

  sroute = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = srouteName;
          default = name;
          example = "guest-via-vpn";
          description = ''
            The sroute's name. Defaults to the attribute name in
            the enclosing `sroutes` attrset, e.g.
            `sroutes.guest-via-vpn.name == "guest-via-vpn"`.
          '';
        };

        from = lib.mkOption {
          type = zoneNames;
          example = [ "guest" ];
          description = ''
            Source zones for the sroute — non-empty. Each entry
            is either a declared zone name, the configured
            `settings.localZone` (default `"local"`), or
            `settings.wildcardZone` (default `"all"`). Phase 1
            reports any other name as a `zoneRefUnknown`
            diagnostic.
          '';
        };

        rule = lib.mkOption {
          type = srouteRule;
          example = lib.literalExpression ''
            [ (mangle meta.mark 100) ]
          '';
          description = ''
            Flat, non-empty list of nftypes statements — typically
            match conditions plus mangle / mark operations.
            Required. No verdict expected: the sroutes chain runs
            at prerouting, before the routing decision, so policy
            routing rules can match a mark set here.
          '';
        };

        priority = lib.mkOption {
          type = sroutePriority;
          default = "default";
          example = "first";
          description = primitives.entryPriorityDescription;
        };

        comment = lib.mkOption {
          type = srouteComment;
          default = null;
          example = "guest traffic policy-routed via VPN";
          description = ''
            Free-form comment, propagated to the generated
            nftables rule. `null` (the default) emits no comment.
          '';
        };
      };
    }
  );
in
{
  inherit
    sroute
    srouteComment
    srouteName
    sroutePriority
    srouteRule
    ;
}
