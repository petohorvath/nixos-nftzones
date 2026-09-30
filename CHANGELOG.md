# Changelog

## Unreleased

### Added

- Root formatting for Nix, shell, Markdown, YAML, and JSON through `nix fmt`, plus `formatting` and `lint` checks (statix, deadnix, actionlint).
- A shared-policy CI caller and an MIT license.

### Changed

- **Breaking:** `lib` is system-independent. Replace `inputs.nftzones.lib.${system}` with `inputs.nftzones.lib`.
- Build the root flake with flake-parts. A `dev` partition provides `checks`, `devShells`, `formatter`, and `legacyPackages`, so public outputs evaluate without development wiring.
- Move the NixOS module from `modules/nftzones.nix` to `nixos/module.nix`. It builds the library from the evaluating system's `lib`, and `nixosModules.default` is unchanged.
- Track `nixos-26.05` in the root `nixpkgs` input, and pin `libnet` and `nftypes` to commits.
- Run the unit tests with nix-unit, one evaluator per test file.
- **Breaking (development interface):** move the VM tests from `checks.<system>.vm` to `legacyPackages.<system>.vmTests.<name>`, and the examples check from `examples/default.nix` to `tests/examples.nix`.
- **Breaking (CI statuses):** replace the `CI` workflow with shared policy `v0.5`. It runs `nix flake check` with the locked, stable, and unstable nixpkgs revisions, and the VM tests with the locked revision.

### Removed

- **Breaking:** the `nixpkgs-unstable` input and the `*-unstable` checks. Select another revision with `--override-input nixpkgs`.
- **Breaking:** the Darwin systems. Outputs are provided for `x86_64-linux` and `aarch64-linux`.
- The `git-hooks` input, the `pre-commit` check, and the pre-commit and pre-push hooks installed by the development shell.

### Migration

Replace `inputs.nftzones.lib.${pkgs.system}` with `inputs.nftzones.lib`, for example `inherit (inputs.nftzones.lib.snippets) accept;`.

Remove `follows` or overrides for the `nftzones` inputs `nixpkgs-unstable` and `git-hooks`. Keep `nftzones.inputs.nixpkgs.follows`; the `nftypes` input name is unchanged.

Replace `nix build .#checks.<system>.vm.entries.<name>` with `nix build .#vmTests.<name>`. Replace `.#checks.<system>.<tier>-unstable` with the matching check under a native override:

```bash
nix flake check --override-input nixpkgs "github:NixOS/nixpkgs/$NIXPKGS_REV" \
  --no-write-lock-file --print-build-logs
```

Replace the branch protection statuses of the old `CI` workflow with `Policy / Check (<system>)`, `Policy / Tests (locked|stable|unstable, <system>)`, and `Policy / VM tests`. Remove the hooks installed by the old development shell with `rm .git/hooks/pre-commit .git/hooks/pre-push .pre-commit-config.yaml`.
