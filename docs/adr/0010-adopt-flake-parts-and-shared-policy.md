---
status: accepted
---

# Adopt flake-parts and the shared project policy

The root flake returns `flake-parts.lib.mkFlake` directly and follows the same conventions as nixos-cross-config, so both projects can be checked by the shared [project policy](https://github.com/petohorvath/nixos-project-policy). A `dev` partition provides `checks`, `devShells`, `formatter`, and `legacyPackages`; public `lib` and `nixosModules.default` evaluate without it.

The root flake has one nixpkgs input, named `nixpkgs`. The policy runs `nix flake check` with the locked revision and with its own stable and unstable pins through `--override-input`, replacing the earlier `nixpkgs-unstable` input and the `*-unstable` checks. Consumers therefore lock only one nixpkgs through nftzones.

The VM tests live at `legacyPackages.<system>.vmTests.<name>`, not in `checks`. The policy builds that attribute in its KVM-enabled job and runs everything in `checks` on runners without KVM. The VM tests therefore run only against the locked nixpkgs revision; unstable coverage for them was traded for a shared CI that needs no project-specific workflow.

`lib` is system-independent because it only depends on `nixpkgs.lib`. The NixOS module builds the library from the evaluating system's `lib`, so its option types follow the consumer's nixpkgs revision.

The unit tests run through nix-unit inside the build sandbox. `tests/helpers/offline-flake.nix` rebuilds the root flake from the store paths of its inputs, so the tests exercise the public exports without fetching.
