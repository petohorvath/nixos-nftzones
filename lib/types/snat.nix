/*
  types/snat — exposes snat-related types under `nftzones.types`.

  Exported types:
    - `snat`         — submodule for one snat definition
    - `snatName`     — string identifier for an snat
    - `snatRule`     — submodule with `match` (default `[ ]`) and
                       `action` (attrTag of `snat` / `masquerade`)
    - `snatPriority` — symbol-or-int entry sort key (`first` /
                       `preDispatch` / `default` / …)
    - `snatComment`  — optional free-form comment

  An snat is a directed `from → to` zone-pair NAT rule that applies
  in postrouting (`type nat hook postrouting priority srcnat`). It
  carries match conditions, an action, an ordering key, and an
  optional comment. Consumers wire it as `lib.mkOption {
  type = lib.types.attrsOf nftzones.types.snat; }`.

  `from` / `to` use the shared `zoneNames` type and the same
  wildcard / localZone behaviour as filter — see
  `types/filter.nix` for the full discussion. Phase 1 runs
  the cross-cutting checks, reporting an unresolved zone as a
  `zoneRefUnknown` diagnostic. The `chain` field is the shared
  `primitives.chainOverride`.

  `snatRule` is the `{ match; action; }` NAT body shared with dnat
  (`primitives.mkNatRule`, ADR-0012), with two fields:
    - `match`  — a list of nftypes statements, e.g.
                 `[ (eq meta.l4proto "tcp") ]`. Defaults to `[ ]`
                 (every packet of the zone pair). The match runs at
                 postrouting, after DNAT and routing, so it sees the
                 translated destination and can use the output
                 interface.
    - `action` — exactly one of:
                 - `snat`       — full address translation; fields
                   `addr`, `port?`, `family?`, `flags?`,
                   `type_flags?`. Reuses
                   `nftypes.types.statementBodies.natBody`.
                 - `masquerade` — auto-target via outgoing
                   interface; fields `port?`, `flags?`. Reuses
                   `nftypes.types.statementBodies.masqueradeBody`.

  Reusing nftypes' shapes keeps flag enums (`natFlag`,
  `natTypeFlag`) and field validation in lock-step with
  libnftables-json.

  `snatPriority` is the entry sort key — symbol or int, default
  `"default"` (= 500). NOT the nftables chain priority (that's
  the `chain.priority` field on the submodule). See
  `primitives.entryPriority` for the symbol → int mapping.

  The default chain placement is postrouting at `srcnat` priority.
  Setting the `chain` field pins the entry to a specific base
  chain instead — useful for output-hook SNAT on locally-generated
  traffic.

  Example:
    options.snats = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.snat;
      default = { };
    };

    config.snats.lan-masquerade = {
      from = [ "lan" "guest" ];
      to = [ "wan" ];
      rule.action.masquerade = { };
      comment = "outbound NAT";
    };
    config.snats.web-snat = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = {
        match = [ (eq tcp.dport 443) ];
        action.snat = {
          addr = "203.0.113.5";
          port = 8080;
        };
      };
    };
*/
{
  inputs,
  primitives,
  zone,
}:
let
  inherit (inputs) lib nftypes;
  inherit (zone) zoneNames;
  inherit (primitives) chainOverride;

  snatName = primitives.identifier;

  snatComment = primitives.comment;

  snatRule = primitives.mkNatRule {
    actions = {
      snat = lib.mkOption {
        type = nftypes.types.statementBodies.natBody;
        description = "Full source address translation.";
      };
      masquerade = lib.mkOption {
        type = nftypes.types.statementBodies.masqueradeBody;
        description = "Source address taken from the outgoing interface.";
      };
    };
    actionDescription = ''
      The action — exactly one of `snat` (full address
      translation) or `masquerade` (auto-target via the
      outgoing interface). Inner submodule shapes are reused
      from nftypes' `natBody` and `masqueradeBody`.
    '';
    matchDescription = ''
      Match conditions selecting the packets to translate.
      Defaults to `[ ]` (every packet of the zone pair). The
      match runs at postrouting, after DNAT and routing, so it
      sees the translated destination and can use the output
      interface.
    '';
  };

  snatPriority = primitives.entryPriority;

  snat = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = snatName;
          default = name;
          example = "lan-masquerade";
          description = ''
            The snat's name. Defaults to the attribute name in the
            enclosing `snats` attrset, e.g.
            `snats.lan-masquerade.name == "lan-masquerade"`.
          '';
        };

        from = lib.mkOption {
          type = zoneNames;
          example = [ "lan" ];
          description = ''
            Source zones for the snat — non-empty. Each entry is
            either a declared zone name, the configured
            `settings.localZone` (default `"local"`), or
            `settings.wildcardZone` (default `"all"`). Phase 1
            reports any other name as a `zoneRefUnknown`
            diagnostic.
          '';
        };

        to = lib.mkOption {
          type = zoneNames;
          example = [ "wan" ];
          description = ''
            Destination zones for the snat. Same shape rules as
            `from`.
          '';
        };

        rule = lib.mkOption {
          type = snatRule;
          example = lib.literalExpression ''
            {
              match = [ (eq tcp.dport 443) ];
              action.masquerade = { };
            }
          '';
          description = ''
            Match conditions and the action. See `snatRule` for
            the field layout.
          '';
        };

        priority = lib.mkOption {
          type = snatPriority;
          default = "default";
          example = "first";
          description = primitives.entryPriorityDescription + ''
            NOT the nftables chain priority — that's `chain.priority`.
          '';
        };

        chain = lib.mkOption {
          type = chainOverride;
          default = null;
          example = {
            hook = "output";
            priority = "srcnat";
          };
          description = ''
            Override the chain placement. `null` (the default)
            uses postrouting at `srcnat` priority. A submodule
            pins the entry to a specific base chain — useful for
            output-hook SNAT on locally-generated traffic.
          '';
        };

        comment = lib.mkOption {
          type = snatComment;
          default = null;
          example = "outbound NAT";
          description = ''
            Free-form comment, propagated to the generated nftables
            rule. `null` (the default) emits no comment.
          '';
        };
      };
    }
  );
in
{
  inherit
    snat
    snatComment
    snatName
    snatPriority
    snatRule
    ;
}
