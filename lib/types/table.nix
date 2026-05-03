/*
  types/table — exposes the top-level table type under
  `nftzones.types`.

  Exported types:
    - `table`            — submodule for one table definition
    - `tableName`        — string identifier for a table
    - `tableFamily`      — nftables family enum (reuses
                           `nftypes.types.family`)
    - `tableFlags`       — list of nftables table flags (reuses
                           `nftypes.types.tableFlag`)
    - `tableComment`     — optional free-form comment
    - `tableSettings`    — submodule with compile-time behaviour
                           knobs (stateful / loopback / rpfilter /
                           chainPolicy / localZone / wildcardZone)
    - `tableChainPolicy` — `accept` / `drop` (reuses
                           `nftypes.types.policy`)
    - `tableZones`       — zone declarations
                           (`attrsOf nftzones.types.zone`)
    - `tableNodes`       — node declarations
                           (`attrsOf nftzones.types.node`)
    - `tableFilters`     — filters group (`attrsOf nftzones.types.filter`)
    - `tablePolicies`    — policies group, per-`(from, to)` defaults
                           (`attrsOf nftzones.types.policy`)
    - `tableSnats`       — snats group (`attrsOf nftzones.types.snat`)
    - `tableDnats`       — dnats group (`attrsOf nftzones.types.dnat`)
    - `tableSroutes`     — sroutes group (`attrsOf nftzones.types.sroute`)
    - `tableDroutes`     — droutes group (`attrsOf nftzones.types.droute`)
    - `tableObjects`     — submodule for user-defined named
                           nftables objects (counters, ct helpers,
                           sets, maps, …); reuses nftypes'
                           `<kind>ObjectBody` types

  A `table` is the input to the nftzones compile pipeline. It
  bundles all the zone-firewall content (zones, nodes, filters,
  snats, dnats, sroutes, droutes, policies), table-level metadata
  (name, family, flags, comment), compile knobs (stateful /
  loopback / rpfilter / chainPolicy), and an escape hatch for
  user-defined nftables objects (`objects`). The compile pipeline
  produces one `inet`-family nftables table from a `table` value.

  Field categories:

    Metadata (mirrors `nftypes.types.objects.tableBody`):
      name, family, flags, comment

    settings (`tableSettings` submodule, best-practice defaults):
      stateful, loopback, rpfilter, chainPolicy,
      localZone (default `"local"`), wildcardZone (default `"all"`)

    Zone-firewall content (each defaults to `{ }`):
      zones, nodes,
      filters, policies,
      snats, dnats,
      sroutes, droutes

    Escape hatch:
      objects — user-defined nftables objects (named counters,
                ct helpers, custom sets / maps, etc.) that the
                compiler doesn't generate from zones. Strict
                per-kind typing via `tableObjects`: each kind
                (`counters`, `ctHelpers`, `sets`, …) is
                `attrsOf` the corresponding nftypes body with
                container fields (`family` / `name` / `table` /
                `handle`) stripped — those are filled in by the
                compile pipeline from context.

  14 top-level fields (the four knobs nest under `settings`).

  Example:
    options.fw = lib.mkOption {
      type = nftzones.types.table;
    };

    config.fw = {
      settings.rpfilter = true;     # opt in; rest of settings stays default
      zones = {
        lan = { interfaces = [ "eth1" ]; cidrs = [ "10.0.0.0/24" ]; };
        wan = { interfaces = [ "eth0" ]; };
      };
      filters.allow-ssh = {
        from = [ "wan" ]; to = [ "local" ];
        rule = [ (eq tcp.dport 22) accept ];
      };
      policies.lan-to-wan = {
        from = [ "lan" ]; to = [ "wan" ];
        verdict = "accept";
      };
      objects.counters.ssh-attempts = { packets = 0; bytes = 0; };
    };
*/
{
  inputs,
  primitives,
  zone,
  node,
  filter,
  snat,
  dnat,
  sroute,
  droute,
  policy,
}:
let
  inherit (inputs) lib nftypes;

  tableName = primitives.identifier;

  tableFamily = nftypes.types.family;

  tableFlags = lib.types.listOf nftypes.types.tableFlag;

  tableComment = primitives.comment;

  tableChainPolicy = nftypes.types.policy;

  /*
    Zone-firewall groups (`filters` / `policies` / `snats` /
    `dnats` / `sroutes` / `droutes`) plus zone declarations
    (`zones` / `nodes`) — each is `attrsOf <entry-submodule>`.
    Named so that consumers (tests, modules, future refactors)
    can reference the type directly instead of inlining
    `lib.types.attrsOf foo.foo` at every use site.
  */
  tableZones = lib.types.attrsOf zone.zone;

  tableNodes = lib.types.attrsOf node.node;

  tableFilters = lib.types.attrsOf filter.filter;

  tablePolicies = lib.types.attrsOf policy.policy;

  tableSnats = lib.types.attrsOf snat.snat;

  tableDnats = lib.types.attrsOf dnat.dnat;

  tableSroutes = lib.types.attrsOf sroute.sroute;

  tableDroutes = lib.types.attrsOf droute.droute;

  /*
    Helper: take an nftypes `<kind>ObjectBody` submodule and
    produce a user-facing version that omits the four container
    fields (`family`, `name`, `table`, `handle`). The compile
    pipeline fills those in from context — `family` from the
    table's `family`, `name` from the attrset key, `table` from
    the table's `name`, `handle` is kernel-assigned (output-only).
    User provides only the per-kind-meaningful fields.
  */
  asUserBody =
    nftypesBody:
    lib.types.submodule {
      options = lib.removeAttrs (nftypesBody.getSubOptions [ ]) [
        "_module"
        "family"
        "name"
        "table"
        "handle"
      ];
    };

  /*
    Strict typed shape for the `objects` field — one option per
    nftables named-object kind, each `attrsOf <userBody>`. Inner
    bodies validate against nftypes' schema with the four
    container fields stripped (filled in at compile time). Cross-
    references from rule bodies (e.g. `counter name "X"`) are
    validated against the keys declared here by the compile
    pipeline.
  */
  tableObjects = lib.types.submodule {
    options = {
      counters = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.counterObjectBody);
        default = { };
        description = "Named counter objects.";
      };
      quotas = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.quotaObjectBody);
        default = { };
        description = "Named quota objects.";
      };
      limits = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.limitObjectBody);
        default = { };
        description = "Named limit objects.";
      };
      ctHelpers = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.ctHelperObjectBody);
        default = { };
        description = "Named ct-helper objects (FTP, IRC DCC, SIP, …).";
      };
      ctTimeouts = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.ctTimeoutObjectBody);
        default = { };
        description = "Named ct-timeout objects.";
      };
      ctExpectations = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.ctExpectationObjectBody);
        default = { };
        description = "Named ct-expectation objects.";
      };
      secmarks = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.secmarkObjectBody);
        default = { };
        description = "Named secmark objects.";
      };
      synproxies = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.synproxyObjectBody);
        default = { };
        description = "Named synproxy objects.";
      };
      tunnels = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.tunnelObjectBody);
        default = { };
        description = "Named tunnel objects.";
      };
      sets = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.setObjectBody);
        default = { };
        description = "Named set objects (blocklists, lookups, …).";
      };
      maps = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.mapObjectBody);
        default = { };
        description = "Named map objects.";
      };
      flowtables = lib.mkOption {
        type = lib.types.attrsOf (asUserBody nftypes.types.objects.flowtableBody);
        default = { };
        description = "Named flowtable objects (hardware offload).";
      };
    };
  };

  /*
    Compile-time behaviour knobs grouped under one submodule.
    Defaults reflect best practice — most users never touch this;
    a `settings = { }` (or omitting it) gets the recommended
    behaviour. Override individual fields when they matter.
  */
  tableSettings = lib.types.submodule {
    options = {
      stateful = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Emit `ct state established,related accept` and
          `ct state invalid drop` at the top of each filter base
          chain. Default `true` — every modern stateful firewall
          wants this. Set to `false` only for stateless setups
          (transparent inspection, niche).
        '';
      };

      loopback = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Emit `iif lo accept` at the top of the input chain to
          allow local-process traffic over the loopback
          interface. Default `true`.
        '';
      };

      rpfilter = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Emit a prerouting reverse-path-filter chain at chain
          priority `raw` (drops packets whose source address
          doesn't route back through the input interface).
          Default `false` — opt in when needed.
        '';
      };

      chainPolicy = lib.mkOption {
        type = tableChainPolicy;
        default = "drop";
        example = "drop";
        description = ''
          nftables chain-level catch-all policy applied to each
          filter base chain (`policy <X>;`). The absolute
          fallback when no rule and no zone-pair policy fires.
          Default `"drop"`. `"accept"` is occasionally useful for
          debugging or specific permissive setups.
        '';
      };

      localZone = lib.mkOption {
        type = primitives.identifier;
        default = "local";
        example = "host";
        description = ''
          Name used for "the firewall machine itself" in `from`
          and `to` fields. Default `"local"`. The compile-time
          chain dispatch (`chainOf`) treats this name as the
          host-position trigger: `to == localZone` → input
          chain, `from == localZone` → output chain.
        '';
      };

      wildcardZone = lib.mkOption {
        type = primitives.identifier;
        default = "all";
        example = "any";
        description = ''
          Name used as the wildcard "any zone" identifier in
          `from` and `to` fields. Default `"all"`. Upstream
          wildcard resolution expands a `from = [ wildcardZone ]`
          (or `to`) entry to the full set of declared zones plus
          `localZone` on the relevant side, before per-pair
          chain dispatch.
        '';
      };
    };
  };

  table = lib.types.submodule (
    { name, ... }:
    {
      options = {

        # ── Metadata ──────────────────────────────────────────────────────

        name = lib.mkOption {
          type = tableName;
          readOnly = true;
          default = name;
          example = "zonefw";
          description = ''
            The nftables table name. Derived from the enclosing
            attribute name — `tables.my-table.name == "my-table"`
            when used inside `attrsOf`, or the option path when
            used as a single-instance option. To pick a different
            name, choose a different attribute key.
          '';
        };

        family = lib.mkOption {
          type = tableFamily;
          default = "inet";
          example = "inet";
          description = ''
            nftables address family — `inet` (combined v4/v6),
            `ip`, `ip6`, `arp`, `bridge`, or `netdev`. Defaults to
            `inet`; most use cases want it.
          '';
        };

        flags = lib.mkOption {
          type = tableFlags;
          default = [ ];
          example = [ "owner" ];
          description = ''
            nftables table flags (`dormant` / `owner` / `persist`).
            Defaults to `[ ]`.
          '';
        };

        comment = lib.mkOption {
          type = tableComment;
          default = null;
          example = "main firewall";
          description = ''
            Free-form table comment, propagated to the generated
            nftables table. `null` (the default) emits no comment.
          '';
        };

        # ── Compile-time settings ─────────────────────────────────────────

        settings = lib.mkOption {
          type = tableSettings;
          default = { };
          description = ''
            Compile-time behaviour knobs (stateful shortcuts,
            loopback shortcut, rpfilter chain emission, base-chain
            policy). Defaults are best practice; override only when
            needed.
          '';
        };

        # ── Zone-firewall content ─────────────────────────────────────────

        zones = lib.mkOption {
          type = tableZones;
          default = { };
          description = ''
            Zone declarations — named groupings of interfaces and
            CIDRs. See `nftzones.types.zone` for the per-zone shape.
          '';
        };

        nodes = lib.mkOption {
          type = tableNodes;
          default = { };
          description = ''
            Node declarations — single-host shortcuts that lower
            to zones at compile time. See `nftzones.types.node`.
          '';
        };

        filters = lib.mkOption {
          type = tableFilters;
          default = { };
          description = ''
            Filter rules — verdict-based zone-pair rules
            (input/forward/output filter chains). See
            `nftzones.types.filter`.
          '';
        };

        policies = lib.mkOption {
          type = tablePolicies;
          default = { };
          description = ''
            Per-pair default verdicts. Compiled as tail rules in
            per-pair sub-chains. See `nftzones.types.policy`.
          '';
        };

        snats = lib.mkOption {
          type = tableSnats;
          default = { };
          description = ''
            SNAT rules (postrouting NAT). See `nftzones.types.snat`.
          '';
        };

        dnats = lib.mkOption {
          type = tableDnats;
          default = { };
          description = ''
            DNAT rules (prerouting NAT). See `nftzones.types.dnat`.
          '';
        };

        sroutes = lib.mkOption {
          type = tableSroutes;
          default = { };
          description = ''
            Source-zone-keyed route mangling (prerouting `type
            route` chain). See `nftzones.types.sroute`.
          '';
        };

        droutes = lib.mkOption {
          type = tableDroutes;
          default = { };
          description = ''
            Destination-zone-keyed route mangling (output `type
            route` chain). See `nftzones.types.droute`.
          '';
        };

        # ── Escape hatch ──────────────────────────────────────────────────

        objects = lib.mkOption {
          type = tableObjects;
          default = { };
          example = lib.literalExpression ''
            {
              counters.ssh-attempts = { packets = 0; bytes = 0; };
              ctHelpers.ftp = { type = "ftp"; protocol = "tcp"; };
              sets.blocklist = {
                type = "ipv4_addr";
                flags = "interval";
                elem = [ ... ];
              };
            }
          '';
          description = ''
            User-defined named nftables objects that the compiler
            doesn't generate from zones — counters, quotas, limits,
            ct helpers, ct timeouts, sets, maps, flowtables, etc.
            Mirrors nftypes' DSL table body container kinds.

            Each kind is `attrsOf <body>`, where the body is
            nftypes' corresponding `<kind>ObjectBody` with the
            four container fields (`family`, `name`, `table`,
            `handle`) stripped — the compile pipeline fills those
            in from context. Cross-references from rule bodies
            (e.g., `counter name "ssh-attempts"`) are validated by
            the compile pipeline against the keys declared here.
          '';
        };
      };
    }
  );
in
{
  inherit
    tableName
    tableFamily
    tableFlags
    tableComment
    tableSettings
    tableChainPolicy
    tableZones
    tableNodes
    tableFilters
    tablePolicies
    tableSnats
    tableDnats
    tableSroutes
    tableDroutes
    tableObjects
    table
    ;
}
