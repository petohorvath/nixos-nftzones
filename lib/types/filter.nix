/*
  types/filter — exposes filter-related types under `nftzones.types`.

  Exported types:
    - `filter`         — submodule for one filter definition
    - `filterName`     — string identifier for a filter
    - `filterZones`    — non-empty list of zone references (the shape
                         of `from` and `to`)
    - `filterRule`     — list of nftypes DSL statements (rule body)
    - `filterPriority` — integer ordering key (lower runs first)
    - `filterChain`    — optional chain-placement override
                         (submodule with `hook` + `priority`)
    - `filterComment`  — optional free-form comment

  A filter is a directed `from → to` zone-pair rule. It carries a
  rule body (matches plus a verdict, expressed as nftypes
  statements), an ordering key, and an optional free-form comment.
  Consumers wire it as `lib.mkOption { type = lib.types.attrsOf
  nftzones.types.filter; }`.

  `filterZones` is a non-empty list of `zoneName` strings; it lets a
  single entry fan out across multiple zones on either side (e.g.
  `from = [ "lan" "guest" ]`). Each entry's shape is validated
  against `zoneName`; whether it resolves to a declared zone or
  one of the reserved names (`host`, `local`, `self`, `firewall`,
  `all`, `any`) is a cross-cutting check that belongs in module
  assertions on the enclosing `filters` attrset.

  `filterRule` entries pass through nftypes' attrTag validation, so
  consumers cannot smuggle hand-rolled libnftables-json shapes. The
  list spans both match conditions (e.g. `eq tcp.dport 22`) and the
  verdict (e.g. `accept`); entries are spliced conjunctively into a
  single nftables rule.

  `filterPriority` orders rules sharing the same `(from, to)` pair
  — an nftzones-internal sort key, NOT the nftables chain priority.
  Either a symbol (`first` / `preDispatch` / `postDispatch` /
  `default` / `last`) or any int. Default `"default"` (= 500).
  Cells are emitted in `(priority asc, name asc)` order. The
  cutoff at 100 splits cells into pre-dispatch (< 100, emitted
  before per-zone matchers) and post-dispatch (>= 100, after).

  `filterChain` is an optional override for chain placement. By
  default (`chain = null`), the entry is dispatched to `input`,
  `forward`, or `output` via the host-position rule:
    - `to` is a host-alias → `input`
    - `from` is a host-alias → `output`
    - neither → `forward`
  Setting `chain` pins the entry to a specific base chain via a
  submodule with `hook` (the nftables hook to attach to) and
  `priority` (the nftables chain priority — `raw`, `filter`, etc.).
  Useful for rpfilter
  (`chain = { hook = "prerouting"; priority = "raw"; }`). At a
  non-default hook, `to` and `from` may not have their usual
  match semantics (notably `to` is meaningless in `prerouting`
  since routing hasn't happened yet); the compiler treats them as
  match expressions where applicable and skips them otherwise.

  Example:
    options.filters = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.filter;
      default = { };
    };

    config.filters.allow-ssh = {
      from = [ "wan" ];
      to = [ "host" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
      comment = "ssh from anywhere";
    };
    config.filters.web-out = {
      from = [ "lan" ];
      to = [ "wan" "vpn" ];
      rule = [
        (eq tcp.dport 443)
        accept
      ];
    };
*/
{
  inputs,
  primitives,
  zone,
}:
let
  inherit (inputs) lib nftypes;
  inherit (zone) zoneName;

  filterName = primitives.identifier;

  /*
    Non-empty list of `zoneName` strings. Empty fan-out is never
    meaningful, so emptiness is rejected at the type level rather
    than deferred to module assertions.
  */
  filterZones = lib.types.nonEmptyListOf zoneName;

  filterComment = primitives.comment;

  filterRule = primitives.rule;

  filterPriority = primitives.entryPriority;

  /*
    Chain-placement override — `null` means dispatch via `chainOf`
    (host position → input/forward/output). A submodule pins the
    rule to a specific base chain at the given priority. `hook`
    and `priority` are the two attributes that uniquely identify
    a base chain at compile time.
  */
  filterChain = lib.types.nullOr (
    lib.types.submodule {
      options = {
        hook = lib.mkOption {
          type = nftypes.types.hook;
          example = "prerouting";
          description = ''
            nftables hook the chain attaches to.
          '';
        };
        priority = lib.mkOption {
          type = primitives.chainPriority;
          example = "raw";
          description = ''
            Chain priority. Either an nftables symbol (`raw`,
            `mangle`, `dstnat`, `filter`, `security`, `srcnat`)
            or any int.
          '';
        };
      };
    }
  );

  filter = lib.types.submodule (
    { name, ... }:
    {
      options = {
        name = lib.mkOption {
          type = filterName;
          readOnly = true;
          default = name;
          example = "allow-ssh";
          description = ''
            The filter's name. Defaults to the attribute name in the
            enclosing `filters` attrset, e.g.
            `filters.allow-ssh.name == "allow-ssh"`.
          '';
        };

        from = lib.mkOption {
          type = filterZones;
          example = [ "wan" ];
          description = ''
            Source zones for the filter — non-empty. Each entry is
            either a declared zone name or one of the reserved
            names (`host`, `local`, `self`, `firewall`, `all`,
            `any`); resolution is enforced at module level, not by
            the type.
          '';
        };

        to = lib.mkOption {
          type = filterZones;
          example = [
            "wan"
            "vpn"
          ];
          description = ''
            Destination zones for the filter. Same shape rules as
            `from`.
          '';
        };

        rule = lib.mkOption {
          type = filterRule;
          example = lib.literalExpression ''
            [
              (eq tcp.dport 22)
              accept
            ]
          '';
          description = ''
            Body of the nftables rule, expressed as a list of
            nftypes DSL statements. Spans both match conditions and
            the verdict; entries are spliced conjunctively into a
            single nftables rule.
          '';
        };

        priority = lib.mkOption {
          type = filterPriority;
          default = "default";
          example = "first";
          description = ''
            Sort key for ordering rules within their chain.
            Either a symbol (`first` / `preDispatch` /
            `postDispatch` / `default` / `last`) or any int.
            Cells are emitted in `(priority asc, name asc)` order.
            See `primitives.entryPriority` for symbol → int
            mapping. NOT the nftables chain priority — that's
            `hook.priority`.
          '';
        };

        chain = lib.mkOption {
          type = filterChain;
          default = null;
          example = {
            hook = "prerouting";
            priority = "raw";
          };
          description = ''
            Override the chain placement. `null` (the default)
            dispatches to `input` / `forward` / `output` via the
            host-position rule based on `from` / `to`. A submodule
            pins the entry to a specific base chain — useful for
            placements like rpfilter
            (`chain = { hook = "prerouting"; priority = "raw"; }`).
            At non-default hooks, `to` / `from` may lose their
            usual match meaning (notably `to` in `prerouting`);
            the compiler emits matches where applicable.
          '';
        };

        comment = lib.mkOption {
          type = filterComment;
          default = null;
          example = "ssh from anywhere";
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
    filterName
    filterZones
    filterRule
    filterPriority
    filterChain
    filterComment
    filter
    ;
}
