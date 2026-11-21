/*
  NixOS module that compiles `nftzones`-shaped table bodies into
  block-form nftables text and feeds them through nixpkgs'
  `networking.nftables.tables.<name>.content` option. nixpkgs owns
  the systemd unit, the per-table deletion tracking, the atomic
  ruleset reload, and the build-time `nft --check` pipeline; this
  module is the typed translator.

  Two-stage function: the outer takes the `libnet` and `nftypes`
  libraries (applied by `flake.nix` with `importApply`); the inner is
  the standard NixOS module function. The module builds `nftzones`
  from the evaluating system's `lib`, so option types match the
  consumer's nixpkgs revision. Keeping these libraries out of
  `_module.args` means user-facing modules never see them as injected
  arguments; both are reached via their own flake inputs.
*/
{
  libnet,
  nftypes,
}:
{
  lib,
  config,
  options,
  ...
}:
let
  cfg = config.networking.nftzones;

  nftzones = import ../lib {
    inputs = {
      inherit lib nftypes;
      libnet = libnet.withLib lib;
    };
  };

  renderTable = if cfg.pretty then nftypes.toTextBlockPretty else nftypes.toTextBlock;

  # Each table as nftypes data, before rendering, so the warnings can
  # read which hooks it has base chains at.
  compiledTables = lib.mapAttrs (_name: nftzones.internal.compile.mkTable) cfg.tables;

  # nixpkgs' `networking.nftables.tables` supplies the
  # `table <fam> <name> { ... }` wrapper; the block renderer writes
  # the table's `flags` and `comment` inside it.
  renderedTables = lib.mapAttrs (_name: table: {
    inherit (table) family;
    content = renderTable table;
  }) compiledTables;

  /*
    Best-effort lexical scans of nftables text read it line by line,
    with each line's `#` comment removed, so they miss a statement
    split across lines. `mentions pattern text` is whether some line
    holds `pattern` with no identifier character on either side.
  */
  boundary = "[^a-z0-9_-]";
  mentions =
    pattern: text:
    lib.any (line: builtins.match "(.*${boundary})?${pattern}(${boundary}.*)?" line != null) (
      map (line: builtins.head (lib.splitString "#" line)) (lib.splitString "\n" text)
    );

  # The families that carry the host's own IP traffic, at the hooks the
  # stock firewall's `inet nixos-fw` table also filters.
  ipFamilies = [
    "inet"
    "ip"
    "ip6"
  ];

  # Whether `families` filter both IPv4 and IPv6.
  coversIp =
    families:
    builtins.elem "inet" families
    || lib.all (family: builtins.elem family families) [
      "ip"
      "ip6"
    ];

  # The families of the nftzones tables with a filter base chain at
  # `hook`. A table with no entries has no `chains`, and a dormant
  # table's base chains are unregistered, so neither filters anything.
  nftzonesFamiliesAt =
    hook:
    lib.pipe compiledTables [
      lib.attrValues
      (builtins.filter (
        table:
        !(builtins.elem "dormant" (table.flags or [ ]))
        && lib.any (chain: chain.type or null == "filter" && chain.hook or null == hook) (
          lib.attrValues (table.chains or { })
        )
      ))
      (map (table: table.family))
    ];

  /*
    Whether some table filters input for both IPv4 and IPv6. Other
    enabled tables are scanned lexically, so a non-filter chain at
    input counts too. The scan of `networking.nftables.ruleset` cannot
    tell which table a chain is in, so any input chain there counts as
    covering both; `networking.nftables.rulesetFile` is not read.
  */
  inputFiltered =
    let
      hooksInput = mentions "hook[[:space:]]+input";
      handWritten = lib.filterAttrs (
        key: table: !(cfg.tables ? ${key}) && table.enable && hooksInput table.content
      ) config.networking.nftables.tables;
    in
    coversIp (nftzonesFamiliesAt "input" ++ lib.mapAttrsToList (_key: table: table.family) handWritten)
    || hooksInput config.networking.nftables.ruleset;

  # Whether an nftzones table shares a hook with a chain of the stock
  # firewall that drops what it does not accept.
  sharesFirewallHook =
    let
      atHook = hook: lib.any (family: builtins.elem family ipFamilies) (nftzonesFamiliesAt hook);
    in
    atHook "input" || (config.networking.firewall.filterForward && atHook "forward");

  firewallCoexistenceWarning = ''
    Both networking.firewall.enable and networking.nftzones.enable are
    true, and an nftzones table has a base chain at a hook that the stock
    `inet nixos-fw` table also filters. nftables runs every base chain on
    a hook, so a packet passes only when both tables accept it. The
    `nixos-fw` input chain drops every packet it does not accept:
    a port opened only in nftzones stays closed. Its forward chain
    narrows forward the same way while networking.firewall.filterForward
    is on. Its rpfilter chain also narrows prerouting unless
    networking.firewall.checkReversePath = false. Set
    networking.firewall.enable = false when nftzones owns these hooks.
  '';

  inputUnfilteredWarning = ''
    Nothing filters traffic to the host: networking.firewall.enable is
    false, and neither networking.nftzones.tables nor any other table has
    a base chain at input for both IPv4 and IPv6. nftzones emits a base
    chain only at a hook where an entry lands. An entry lands at input
    when its `to` names the local zone or the wildcard zone, or when its
    `chain` override puts it there. Without one, the host accepts every
    packet sent to it. Add one, such as a filter that accepts SSH from an
    admin zone, or set networking.firewall.enable = true.
  '';

  /*
    Checks that a compiled table reaches nft as the only body of its
    table. nixpkgs renders each enabled `networking.nftables.tables`
    entry as `table <family> <name> { ... }` and appends
    `networking.nftables.ruleset` to the same file, and nft merges
    every block and statement naming a table into that table. A second
    source could otherwise append rules to a compiled chain.
  */
  tableAssertions =
    name: rendered:
    let
      tables = config.networking.nftables.tables;
      onWire = "table ${rendered.family} ${name}";
      collision = source: ''
        networking.nftzones.tables.${name} collides with ${source}.
        Declare each table in exactly one module.
      '';

      # This module's own definition is in the pre-merge list too, so
      # a second definition naming the key is a second source. The
      # merged config cannot show it: it holds one entry per key.
      keySources = builtins.length (
        builtins.filter (def: def ? ${name}) options.networking.nftables.tables.definitions
      );

      # An entry's `name` is only `mkDefault` its key, so an entry
      # under another key can render as this table.
      sameOnWire = lib.attrNames (
        lib.filterAttrs (
          key: table: key != name && table.enable && table.name == name && table.family == rendered.family
        ) tables
      );

      /*
        `lib.mkForce` on the whole option discards this module's
        definition before the key count sees it, so check the entry
        that survived the merge. Empty when it renders this table
        unchanged.
      */
      own = tables.${name} or null;
      ownProblem =
        if own == null then
          "is missing"
        else if !own.enable then
          "is disabled"
        else if own.name != name || own.family != rendered.family then
          "renders as `table ${own.family} ${own.name}`"
        else if own.content != rendered.content then
          "carries content other than the compiled table"
        else
          "";

      # Best effort: a lexical scan for a statement naming the table. A
      # family-less `table <name>` means the `ip` family. It misses
      # family-less statements other than `table`.
      statement = "(table|chain|rule|set|map|element|flowtable)";
      inherit (config.networking.nftables) ruleset;
      rulesetNamesTable =
        mentions "${statement}[[:space:]]+${rendered.family}[[:space:]]+${name}" ruleset
        || (rendered.family == "ip" && mentions "table[[:space:]]+${name}" ruleset);
    in
    [
      {
        assertion = keySources <= 1;
        message = collision "networking.nftables.tables.${name}";
      }
    ]
    ++ map (key: {
      assertion = false;
      message = collision "networking.nftables.tables.${key}, which also renders as `${onWire}`";
    }) sameOnWire
    ++ [
      {
        # A second source under the key already failed above.
        assertion = keySources > 1 || ownProblem == "";
        message = ''
          networking.nftables.tables.${name} ${ownProblem}, so
          networking.nftzones.tables.${name} does not reach nft as compiled.
          Another module may set networking.nftables.tables with
          lib.mkForce. Declare each table in exactly one module.
        '';
      }
      {
        assertion = !rulesetNamesTable;
        message = collision "networking.nftables.ruleset, which also addresses `${onWire}`";
      }
    ];
in
{
  options.networking.nftzones = {
    enable = lib.mkEnableOption "nftzones-managed nftables tables";

    tables = lib.mkOption {
      /*
        Each table's `name` is its attribute key: inside `attrsOf`, a
        submodule's `name` argument is the key, and the extra module
        defines the table's `name` from it with `mkForce`. A whole
        evaluated table forwarded from a differently keyed facade
        option (`options.myfw = mkOption { type =
        nftzones.types.table; };` then `tables.fw = config.myfw;`)
        carries the source's `name` ('myfw'); the forced key beats it,
        so `tables.<key>.name == <key>` for every reader: the compile
        pipeline, the on-wire ruleset, and introspection tools.
        Defining the key, rather than overriding the evaluated value,
        also checks it against `nftzones.types.tableName`.
      */
      type =
        let
          tableType = nftzones.types.table;
        in
        lib.types.attrsOf (
          tableType.substSubModules (
            tableType.getSubModules
            ++ [
              (
                { name, ... }:
                {
                  config.name = lib.mkForce name;
                }
              )
            ]
          )
        );
      default = { };
      description = ''
        Table bodies keyed by nftables table name. Each entry is
        compiled and translated into `networking.nftables.tables.<name>`
        for activation. A table's `name` is always its attribute key:
        a value forwarded from a differently-keyed option is recompiled
        under the key.
      '';
    };

    pretty = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Emit block-form text in multi-line indented form instead of
        compact. Useful for inspecting the generated ruleset; compact
        keeps `nix store` diffs smaller.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.networking.nftables.enable;
        message = ''
          networking.nftzones.enable requires networking.nftables.enable = true.
          The nftzones module piggy-backs on the nftables module's systemd unit
          and per-table deletion tracking; without it, the compiled tables
          won't be activated.
        '';
      }
      {
        # An enabled nftzones with no tables compiles to no chains. Combined
        # with the typical `networking.firewall.enable = false` that
        # nftzones-managed hosts run with, this silently leaves the host
        # with no firewall at all. Reject the empty-tables case so the
        # user has to opt out explicitly (via `enable = false`) rather
        # than by omission.
        assertion = cfg.tables != { };
        message = ''
          networking.nftzones.enable is true but
          networking.nftzones.tables is empty. This compiles to no nftables
          chains, which — combined with networking.firewall.enable = false —
          leaves the host with no firewall at all. Either declare at least
          one table under networking.nftzones.tables, or set
          networking.nftzones.enable = false.
        '';
      }
    ]
    ++ lib.concatLists (lib.mapAttrsToList tableAssertions renderedTables);

    networking.nftables.tables = renderedTables;

    # Warn (don't error) on both. The stock firewall beside nftzones
    # tables that handle only NAT is a legitimate setup, and so is a
    # host that deliberately accepts every packet sent to it.
    warnings =
      let
        firewallEnabled = config.networking.firewall.enable;
      in
      lib.optional (firewallEnabled && sharesFirewallHook) firewallCoexistenceWarning
      ++ lib.optional (!firewallEnabled && !inputFiltered) inputUnfilteredWarning;
  };
}
