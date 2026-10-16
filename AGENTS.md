# AGENTS.md

nftzones compiles zone-keyed Nix configs into vanilla nftables rulesets.
Start with `README.md`, the glossary in `GLOSSARY.md`, and the reference
docs under `docs/`.

## Required checks

The development shell, loaded by `nix develop` or by direnv through
`.envrc`, supplies Nix, nix-unit, the formatters, the linters, and
`nft`.

```sh
nix fmt                     # fix a failing `formatting` check
nix-unit tests/unit --attr internal.compile  # one unit suite
nix flake check -L          # every check with the locked nixpkgs; needs KVM
nix build -L .#checks.x86_64-linux.vm-<name>  # one VM test; needs KVM
```

CI calls the shared
[project policy](https://github.com/petohorvath/nixos-project-policy)
from `.github/workflows/check.yml`; `docs/testing.md` describes the
test tiers, the VM tests, and the nixpkgs revisions CI runs against.
To run the policy checks locally:

```sh
nix run github:petohorvath/nixos-project-policy/v0.6 -- check .
nix run github:petohorvath/nixos-project-policy/v0.6 -- test . --nixpkgs locked
nix run github:petohorvath/nixos-project-policy/v0.6 -- test . --nixpkgs locked --vm
```

`test` also accepts `--nixpkgs stable` and `--nixpkgs unstable`. With
`--vm` it builds only the VM tests, and skips them on a host without
KVM.

## Agent skills

### Issue tracker

Issues live in GitHub Issues for `petohorvath/nixos-nftzones`, managed
with the `gh` CLI. See `docs/agents/issue-tracker.md`.

### Triage labels

Uses the five default labels: `needs-triage`, `needs-info`,
`ready-for-agent`, `ready-for-human` and `wontfix`. See
`docs/agents/triage-labels.md`.

### Domain docs

Single-context: a root `GLOSSARY.md` plus `docs/adr/`. See
`docs/agents/domain.md`.
