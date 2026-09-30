{
  actionlint,
  deadnix,
  formatter,
  git,
  mkShellNoCC,
  nftables,
  nil,
  nix,
  nix-unit,
  nixfmt,
  prettier,
  shfmt,
  statix,
}:
mkShellNoCC {
  # `nftables` supplies `nft --check` for hand-checking rendered rulesets.
  packages = [
    nix
    nix-unit
    nil
    nixfmt
    statix
    deadnix
    git
    shfmt
    prettier
    actionlint
    nftables
    formatter
  ];
}
