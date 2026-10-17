# Unit tests for the NixOS module (`nixos/module.nix`) that need no
# NixOS evaluation. The integration suite `nixos-module` evaluates the
# module itself.
{
  lib,
  nftypes,
  nftzones,
  ...
}:
{
  # ===== module — pretty mode flips renderer to multi-line =====

  testModulePrettyMode = {
    # The pretty flag only controls which nftypes renderer is
    # applied — `mkDirectionVariants` and the rest of the compile
    # pipeline produce the same output. So we don't need to spin
    # up two NixOS evaluations: render the once-compiled table
    # both ways and compare.
    expr =
      let
        body = {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.allow-ssh = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
          };
        };
        table = nftzones.mkTable "fw" body;
        compact = nftypes.toTextBlock table;
        pretty = nftypes.toTextBlockPretty table;
      in
      {
        prettyHasMoreLines =
          lib.length (lib.splitString "\n" pretty) > lib.length (lib.splitString "\n" compact);
      };
    expected = {
      prettyHasMoreLines = true;
    };
  };
}
