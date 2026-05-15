{
  description = "nix-nftzones — library for zone-based nftables firewall configuration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    libnet.url = "github:petohorvath/nix-libnet";
    libnet.inputs.nixpkgs.follows = "nixpkgs";

    nftypes.url = "github:petohorvath/nix-nftypes";
    nftypes.inputs.nixpkgs.follows = "nixpkgs";

    # Build-time only: drives the pre-commit / pre-push git
    # hooks installed by the devShell. Not a runtime dep of the
    # library or NixOS module.
    git-hooks.url = "github:cachix/git-hooks.nix";
    git-hooks.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      libnet,
      nftypes,
      git-hooks,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      mkLib =
        pkgs:
        import ./lib {
          inputs = {
            inherit (pkgs) lib;
            libnet = libnet.lib.withLib pkgs.lib;
            nftypes = nftypes.lib;
          };
        };

      # Compute the per-system library once. `mkLib`'s `import
      # ./lib` is already memoized by file path, but threading
      # one canonical `libBySystem` through downstream consumers
      # keeps the wiring explicit and removes the temptation to
      # call `mkLib pkgs` ad-hoc in new code paths.
      libBySystem = forAllSystems mkLib;

      # `./modules/nftzones.nix` is a function `{ nftzones, nftypes
      # }: { ... } NixOS module`. Partial-applying both libs here
      # keeps them private compile-time deps of the module rather
      # than something leaking onto `_module.args` and surfacing in
      # every sibling module's argument list. User code reaches
      # nftzones / nftypes via their own flake inputs, not via
      # module args.
      nftzonesModule =
        { pkgs, ... }:
        {
          imports = [
            (import ./modules/nftzones.nix {
              nftzones = libBySystem.${pkgs.stdenv.hostPlatform.system};
              nftypes = nftypes.lib;
            })
          ];
        };

      mkChecks =
        pkgs:
        let
          nftzones = libBySystem.${pkgs.stdenv.hostPlatform.system};
          testArgs = {
            inherit pkgs nftzonesModule nftzones;
            nftypes = nftypes.lib;
            libnet = libnet.lib.withLib pkgs.lib;
          };
          runner = import ./tests/unit/runner.nix { inherit pkgs; };
          unitTests = import ./tests/unit/default.nix testArgs;
          vmTestsLinux = nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
            vm = import ./tests/vm/default.nix testArgs;
          };
        in
        {
          unit = runner.runTests unitTests;
          integration = import ./tests/integration/default.nix testArgs;
          examples = import ./examples/default.nix testArgs;
          pre-commit = gitHooksBySystem.${pkgs.stdenv.hostPlatform.system};
        }
        // vmTestsLinux;

      # Pre-commit + pre-push git hooks managed by git-hooks.nix.
      # The devShell's `shellHook` installs them into
      # `.git/hooks/` on every `nix develop` / direnv reload;
      # `--no-verify` remains the per-invocation escape hatch.
      #
      # Two tiers:
      #
      # - pre-commit (default stage): `treefmt` driven by
      #   `pkgs.nixfmt-tree` — the same binary `nix fmt` runs, so
      #   the hook can never disagree with `nix fmt` / CI's
      #   `git diff --exit-code` formatting gate.
      # - pre-push: builds the fast `nix flake check` tiers
      #   (unit + integration + examples). VM tests stay
      #   CI-only — they need `/dev/kvm` and the NixOS test
      #   machinery is multiple GB, too slow even for pre-push.
      #
      # The `pre-commit` stage hook is also exposed under
      # `checks.<system>.pre-commit` so `nix flake check` (and
      # CI) verify the configured hooks pass. The `pre-push`
      # hook is stage-restricted, so it does NOT recurse into
      # `nix build .#checks…` from inside that derivation.
      gitHooksBySystem = forAllSystems (
        pkgs:
        let
          system = pkgs.stdenv.hostPlatform.system;
          fastCheckTargets = nixpkgs.lib.concatStringsSep " " [
            ".#checks.${system}.unit"
            ".#checks.${system}.integration"
            ".#checks.${system}.examples"
          ];
        in
        git-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            # Format with the same `treefmt` binary `nix fmt`
            # invokes (`nixfmt-tree` ships a wrapped
            # `bin/treefmt` with config baked in). Keeps the
            # hook locked to `nix fmt`'s output — no risk of the
            # hook passing while CI's `git diff --exit-code`
            # gate fails, or vice versa.
            treefmt = {
              enable = true;
              package = pkgs.nixfmt-tree;
            };

            flake-check-fast = {
              enable = true;
              name = "nix flake check (unit + integration + examples)";
              entry = "nix build --no-link --print-build-logs ${fastCheckTargets}";
              pass_filenames = false;
              stages = [ "pre-push" ];
            };
          };
        }
      );
    in
    {
      lib = libBySystem;
      formatter = forAllSystems (pkgs: pkgs.nixfmt-tree);
      checks = forAllSystems mkChecks;
      nixosModules.default = nftzonesModule;

      devShells = forAllSystems (
        pkgs:
        let
          system = pkgs.stdenv.hostPlatform.system;
        in
        {
          default = pkgs.mkShellNoCC {
            # Tools a contributor reaches for when working on
            # this repo: nixfmt-tree for formatting (matches
            # `nix fmt`), nftables for hand-running `nft --check`
            # against rendered scenarios, and nix-output-monitor
            # for the `nix build` UX.
            packages = [
              pkgs.nixfmt-tree
              pkgs.nftables
              pkgs.nix-output-monitor
            ];

            # Install/refresh `.git/hooks/{pre-commit,pre-push}`
            # from the git-hooks.nix config above. Idempotent —
            # safe to re-run on every shell entry.
            shellHook = gitHooksBySystem.${system}.shellHook;
          };
        }
      );
    };
}
