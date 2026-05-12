/*
  NixOS module that compiles `nftzones`-shaped table bodies into
  block-form nftables text and feeds them through nixpkgs'
  `networking.nftables.tables.<name>.content` option. nixpkgs owns
  the systemd unit, the per-table deletion tracking, the atomic
  ruleset reload, and the build-time `nft --check` pipeline; this
  module is the typed translator.
*/
{
  lib,
  config,
  options,
  nftzones,
  ...
}:
let
  cfg = config.networking.nftzones;

  inherit (nftzones) nftypes;

  renderTable = if cfg.pretty then nftypes.toTextBlockPretty else nftypes.toTextBlock;

  # `nftypes.toTextBlock` drops the `add table` self-command (its
  # consumer — here nixpkgs' `networking.nftables.tables` — supplies
  # the `table <fam> <name> { ... }` wrapper itself). That self-
  # command is where `flags` and `comment` live, so the block
  # renderer silently strips them. nftables block syntax permits
  # both inside the braces, so we prepend them ourselves.
  escapeComment =
    builtins.replaceStrings
      [ "\\" "\"" "\n" "\r" "\t" ]
      [ "\\\\" "\\\"" "\\n" "\\r" "\\t" ];

  renderTableMetadata =
    table:
    let
      flagsLine = lib.optional (table.flags != [ ]) "flags ${lib.concatStringsSep ", " table.flags};";
      commentLine = lib.optional (table.comment != null) ''comment "${escapeComment table.comment}";'';
      lines = flagsLine ++ commentLine;
    in
    lib.optionalString (lines != [ ]) (lib.concatStringsSep "\n" lines + "\n");

  compiledTables = lib.mapAttrs (
    _name: tableValue:
    let
      table = nftzones.internal.compile.mkTable tableValue;
    in
    {
      inherit (table) family;
      # `tableValue` carries the user-shape with submodule defaults
      # filled in; `table` is the compiled nftypes value which drops
      # empty / null fields. Reading metadata from the user-shape
      # keeps the prefix renderer predictable.
      content = renderTableMetadata tableValue + renderTable table;
    }
  ) cfg.tables;
in
{
  options.networking.nftzones = {
    enable = lib.mkEnableOption "nftzones-managed nftables tables";

    tables = lib.mkOption {
      type = lib.types.attrsOf nftzones.types.table;
      default = { };
      description = ''
        Table bodies keyed by nftables table name. Each entry is
        compiled and translated into `networking.nftables.tables.<name>`
        for activation.
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
    ]
    ++ lib.mapAttrsToList (name: _: {
      # The nftzones module's own contribution (assigned a few
      # lines below) shows up in `options.networking.nftables.
      # tables.definitions` alongside any user-supplied ones, so
      # the naive "is the key present?" check on the merged
      # config always fires for every table this module owns.
      # Counting contributors of this specific key against the
      # pre-merge definitions list lets us flag the *real*
      # collision: more than one source supplying the same name.
      assertion =
        (builtins.length (
          builtins.filter (def: def ? ${name}) options.networking.nftables.tables.definitions
        )) <= 1;
      message = ''
        networking.nftzones.tables.${name} collides with networking.nftables.tables.${name}.
        Declare each table in exactly one module.
      '';
    }) cfg.tables;

    networking.nftables.tables = compiledTables;
  };
}
