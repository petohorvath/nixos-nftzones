---
status: accepted
---

# Adopt flake-parts and the shared project policy

The root flake returns `flake-parts.lib.mkFlake` directly and follows the same conventions as nixos-cross-config, so both projects can be checked by the shared [project policy](https://github.com/petohorvath/nixos-project-policy). A `dev` partition provides `checks`, `devShells`, and `formatter`; public `lib` and `nixosModules.default` evaluate without it.

The root flake has one nixpkgs input, named `nixpkgs`. The policy runs `nix flake check` with the locked revision and with its own stable and unstable pins through `--override-input`, replacing the earlier `nixpkgs-unstable` input and the `*-unstable` checks. Consumers therefore lock only one nixpkgs through nftzones.

The VM tests are checks named `vm-<name>`. NixOS tests require the `nixos-test` and `kvm` system features, so policy v0.6 builds them in its VM jobs against the locked revision and both pins, and skips them on a runner without KVM.

`lib` is system-independent because it only depends on `nixpkgs.lib`. The NixOS module builds the library from the evaluating system's `lib`, so its option types follow the consumer's nixpkgs revision.

The unit tests run through nix-unit inside the build sandbox. `tests/helpers/offline-flake.nix` rebuilds the root flake from the store paths of its inputs, so the tests exercise the public exports without fetching.
