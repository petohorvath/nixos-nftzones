{
  git,
  mkShellNoCC,
  nftables,
  nil,
  nix,
  nix-unit,
  statix,
  treefmtShell,
}:
mkShellNoCC {
  inputsFrom = [ treefmtShell ];
  # `nftables` supplies `nft --check` for hand-checking rendered rulesets.
  packages = [
    nix
    nix-unit
    nil
    statix
    git
    nftables
  ];
}
