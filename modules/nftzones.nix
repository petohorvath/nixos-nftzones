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
  nftzones,
  nftypes,
  ...
}:
let
  cfg = config.networking.nftzones;

  renderTable = if cfg.pretty then nftypes.toTextBlockPretty else nftypes.toTextBlock;

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
      assertion = !(config.networking.nftables.tables ? ${name});
      message = ''
        networking.nftzones.tables.${name} collides with networking.nftables.tables.${name}.
        Declare each table in exactly one module.
      '';
    }) cfg.tables;

    networking.nftables.tables = compiledTables;
  };
}
