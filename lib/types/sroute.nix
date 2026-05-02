/*
  types/sroute — exposes sroute-related types under `nftzones.types`.

  Exported types:
    - `sroute`         — submodule for one sroute definition
    - `srouteName`     — string identifier for an sroute
    - `srouteZones`    — non-empty list of zone references (the
                         shape of `from`)
    - `srouteRule`     — list of nftypes statements (mangle / match
                         body)
    - `sroutePriority` — integer ordering key (lower runs first)
    - `srouteComment`  — optional free-form comment

  An sroute is a source-zone-keyed route-mangling rule that applies
  in prerouting (`type route hook prerouting priority mangle`). It
  marks or mangles incoming packets based on source zone,
  triggering a routing re-evaluation when the chain exits — used
  for mark-based policy routing of forwarded traffic. Consumers
  wire it as `lib.mkOption { type = lib.types.attrsOf
  nftzones.types.sroute; }`.

  Why no `to`: prerouting runs before the routing decision, so the
  destination zone (which depends on routing) isn't determined
  when the rule fires. Same structural reason dnat omits `to`.

  `srouteZones` and the wildcard / reserved-name behaviour are
  identical to filter / snat / dnat — see `types/filter.nix` for
  the full discussion.

  `srouteRule` is a flat list of nftypes statements — typically
  match conditions plus mangle statements like `meta mark set N`.
  No verdict is expected; the chain triggers routing
  re-evaluation, not a verdict.

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
  inherit (zone) zoneName;

  srouteName = primitives.identifier;

  /*
    Non-empty list of `zoneName` strings. Empty fan-out is never
    meaningful, so emptiness is rejected at the type level rather
    than deferred to module assertions.
  */
  srouteZones = lib.types.nonEmptyListOf zoneName;

  srouteComment = primitives.comment;

  srouteRule = primitives.rule;

  sroutePriority = primitives.entryPriority;

  sroute = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = srouteName;
          readOnly = true;
          default = name;
          example = "guest-via-vpn";
          description = ''
            The sroute's name. Defaults to the attribute name in
            the enclosing `sroutes` attrset, e.g.
            `sroutes.guest-via-vpn.name == "guest-via-vpn"`.
          '';
        };

        from = lib.mkOption {
          type = srouteZones;
          example = [ "guest" ];
          description = ''
            Source zones for the sroute — non-empty. Each entry
            is either a declared zone name or one of the reserved
            names (`host`, `local`, `self`, `firewall`, `all`,
            `any`); resolution is enforced at module level, not
            by the type.
          '';
        };

        rule = lib.mkOption {
          type = srouteRule;
          default = [ ];
          example = lib.literalExpression ''
            [ (mangle meta.mark 100) ]
          '';
          description = ''
            Flat list of nftypes statements — typically match
            conditions plus mangle / mark operations. No verdict
            expected; the chain triggers a routing re-evaluation
            when it exits, not a verdict-based decision.
          '';
        };

        priority = lib.mkOption {
          type = sroutePriority;
          default = "default";
          example = "first";
          description = ''
            Sort key for ordering rules within their chain.
            Either a symbol (`first` / `preDispatch` /
            `postDispatch` / `default` / `last`) or any int.
          '';
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
    srouteName
    srouteZones
    srouteRule
    sroutePriority
    srouteComment
    sroute
    ;
}
