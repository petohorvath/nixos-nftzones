# Changelog

## Unreleased

### Added

- Root formatting and linting through treefmt-nix: `nix fmt` runs nixfmt, deadnix, actionlint, prettier, ruff-format, and ruff-check, configured in `dev/treefmt.nix`. The `treefmt` check fails when `nix fmt` would change a file or a tool reports a finding it cannot fix, and the `lint` check runs statix. Consumers lock the new `treefmt-nix` input, which follows their `nixpkgs`; drop it with `inputs.nftzones.inputs.treefmt-nix.follows = "";`.
- A shared-policy CI caller and an MIT license.

### Changed

- **Breaking:** `lib` is system-independent. Replace `inputs.nftzones.lib.${system}` with `inputs.nftzones.lib`.
- Build the root flake with flake-parts. A `dev` partition provides `checks`, `devShells`, and `formatter`, so public outputs evaluate without development wiring.
- Move the NixOS module from `modules/nftzones.nix` to `nixos/module.nix`. It builds the library from the evaluating system's `lib`, and `nixosModules.default` is unchanged.
- Track `nixos-26.05` in the root `nixpkgs` input, and pin `libnet` to its `v0.1.0` release.
- **Breaking:** track the `main` branch of nftypes, past its `v0.1.0` release. A flake whose `nftypes` input follows `nftzones/nftypes` gets the new DSL, so rules written with the nftypes DSL may need the changes its [changelog](https://github.com/petohorvath/nix-nftypes/blob/main/CHANGELOG.md) lists, such as `reject { }` for `reject.plain` and `counter.auto` for `counter { }`. A filter with `rule = [ ]` no longer compiles, because nftypes refuses a rule with no statements, and a `snat` or `dnat` body needs an `addr` or a `port`.
- Run the unit and integration tests with nix-unit's flake-parts module, which adds the `nix-unit` input and the `tests` output.
- **Breaking (development interface):** move the VM tests from `checks.<system>.vm` to one check per test, `checks.<system>.vm-<name>`.
- **Breaking (development interface):** organize the tests by the devnix-labs test standard. The `nix-unit` check replaces `unit`, `integration`, and `examples`: its unit suites also compile the examples and check the warnings and assertions of the scenarios and the rejections, and `build-scenarios` runs `nft -j --check` on the scenarios. Run one unit suite with `nix-unit --flake .#tests.systems.<system>.unit.<suite>`, and one test with `--attr <test>`.
- **Breaking (CI statuses):** replace the `CI` workflow with shared policy `v0.6`. It builds the checks with the locked, stable, and unstable nixpkgs revisions, and the VM tests in separate jobs with the same revisions.
- **`internal` only:** Phase 3 builds one dispatch tree per base chain in `ctx.dispatchTrees`, replacing `ctx.chainBuckets` and `ctx.effectiveSubChainsByBucket`. `internal.emit` drops `buildEffectiveSubChains`, `computeEffectiveSubChains` and `mkChildDispatchJumpRules`, and `mkRootJumpRules`, `mkSubChain`, `mkBaseChain` and `mkBaseChains` take the tree instead of a bucket. The generated ruleset is unchanged.
- **Breaking (validation messages):** Phase 1 errors and warnings render as `[tag] path: message`, for example `[zoneParentUnknown] zones.lan.parent: references unknown zone 'ghost'`, and the failure lists its errors sorted by path, then tag ([#22](https://github.com/petohorvath/nixos-nftzones/issues/22)). Every diagnostic names one declaration by its dotted path, including overlaps, collisions and cycles, and warnings gain tags as well. Validation itself is unchanged.
- **`internal` only:** `internal.normalize` exports only `diagnose`, which returns Phase 1's errors and warnings as `{ tag; path; message; }` data, and `normalizeTable`. Its compute steps and validators are private, and `normalizeTable`'s `ctx` keeps only `zoneMembership`, `expandedGroups` and `resolvedPriorities`.

### Removed

- **Breaking:** the `nixpkgs-unstable` input and the `*-unstable` checks. Select another revision with `--override-input nixpkgs`.
- **Breaking:** the Darwin systems. Outputs are provided for `x86_64-linux` and `aarch64-linux`.
- The `git-hooks` input, the `pre-commit` check, and the pre-commit and pre-push hooks installed by the development shell.

### Fixed

- **Breaking (generated chain names):** separate the zones in a zone pair's sub-chain name with an uppercase `-TO-`, for example `forward-at-filter__lan-TO-wan` ([#18](https://github.com/petohorvath/nixos-nftzones/issues/18)). With the lowercase `-to-`, zones `a`, `a-to`, `b` and `to-b` made the pairs `a-to → b` and `a → to-b` share the sub-chain `forward-at-filter__a-to-to-b` behind one jump, so one pair's rules matched the other pair's traffic. Single-zone sub-chains keep their names. Base chains jump to sub-chains in name order, so root zones where one name extends the other, such as `lan` and `lan-guest`, now jump in the opposite order; this decides the verdict only when their matches overlap.
- The `wildcardZoneMixed` warning no longer calls a child zone listed beside a `from`-side wildcard redundant ([#30](https://github.com/petohorvath/nixos-nftzones/issues/30)). A `from`-side wildcard expands only to root zones and the local zone, so the child gets its own sub-chain and removing it changed the ruleset. The warning now names only the zones the wildcard already covers, and its message says what the wildcard covers there and advises removing only those zones. An unknown zone beside a `to`-side wildcard gets only its `invalidZoneRef` error, without the warning. A list that repeats the wildcard, such as `[ "all" "all" ]`, no longer warns.

### Migration

Replace `inputs.nftzones.lib.${pkgs.system}` with `inputs.nftzones.lib`, for example `inherit (inputs.nftzones.lib.snippets) accept;`.

Update rules written with the nftypes DSL as the nftypes [changelog](https://github.com/petohorvath/nix-nftypes/blob/main/CHANGELOG.md) describes, and give each filter at least one statement, such as `rule = [ accept ];`.

Remove `follows` or overrides for the `nftzones` inputs `nixpkgs-unstable` and `git-hooks`. Keep `nftzones.inputs.nixpkgs.follows`; the `nftypes` input name is unchanged.

Update anything that names a zone pair's sub-chain, such as `nft list chain` commands, counters, or monitoring, from `<base>__<from>-to-<to>` to `<base>__<from>-TO-<to>`.

Update anything that matches the text of Phase 1 validation failures or warnings, such as log filters, to the `[tag] path: message` form. Match on the tag rather than the prose.

Replace `nix build .#checks.<system>.vm.entries.<name>` with `nix build .#checks.<system>.vm-<name>`. Replace `.#checks.<system>.<tier>-unstable` with the matching check under a native override:

```bash
nix flake check --override-input nixpkgs "github:NixOS/nixpkgs/$NIXPKGS_REV" \
  --no-write-lock-file --print-build-logs
```

Replace the branch protection statuses of the old `CI` workflow with `Policy / Check (<system>)`, `Policy / Tests (locked|stable|unstable, <system>)`, and `Policy / VM tests (locked|stable|unstable, <system>)`. Remove the hooks installed by the old development shell with `rm .git/hooks/pre-commit .git/hooks/pre-push .pre-commit-config.yaml`.
