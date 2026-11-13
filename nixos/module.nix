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

  # nixpkgs' `networking.nftables.tables` supplies the
  # `table <fam> <name> { ... }` wrapper; the block renderer writes
  # the table's `flags` and `comment` inside it.
  compiledTables = lib.mapAttrs (
    _name: tableValue:
    let
      table = nftzones.internal.compile.mkTable tableValue;
    in
    {
      inherit (table) family;
      content = renderTable table;
    }
  ) cfg.tables;
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
    ++ lib.mapAttrsToList (name: _: {
      # The nftzones module's own contribution (assigned a few lines
      # below) shows up in
      # `options.networking.nftables.tables.definitions` alongside any
      # user-supplied ones, so the naive "is the key present?" check on
      # the merged config always fires for every table this module
      # owns. Counting contributors of this specific key against the
      # pre-merge definitions list flags the *real* collision: more
      # than one source supplying the same name.
      assertion =
        (builtins.length (
          builtins.filter (def: def ? ${name}) options.networking.nftables.tables.definitions
        )) <= 1;
      message = ''
        networking.nftzones.tables.${name} collides with
        networking.nftables.tables.${name}. Declare each table in exactly
        one module.
      '';
    }) cfg.tables;

    networking.nftables.tables = compiledTables;

    # Warn (don't error): the stock firewall beside nftzones tables
    # that handle only forwarding or NAT is a legitimate setup.
    warnings = lib.optional config.networking.firewall.enable ''
      Both networking.firewall.enable and networking.nftzones.enable are true.
      networking.firewall installs its own `inet nixos-fw` table, whose
      input chain drops every packet it does not accept. The nftzones base
      chain at input shares that hook and priority, and nftables runs every
      base chain on a hook, so a packet reaches the host only when both
      tables accept it: a port opened only in nftzones stays closed. The
      `nixos-fw` rpfilter chain narrows prerouting the same way unless
      networking.firewall.checkReversePath = false, and its forward chain
      narrows forward when networking.firewall.filterForward is on. Set
      networking.firewall.enable = false when nftzones owns the input chain.
    '';
  };
}
