/*
  Unit tests for the NixOS module (`modules/nftzones.nix`, exposed
  as `nixosModules.default`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by
  `tests/unit/default.nix`.

  Pure module evaluations — no VM boot. We use `pkgs.nixos` (the
  nixpkgs-provided NixOS evaluator) with the flake's
  `nftzonesModule` plus a minimal-but-valid context (loader /
  filesystems / stateVersion stubs), then read back the resulting
  `config` for assertions. Going through `nftzonesModule` instead
  of importing the module file directly means tests exercise the
  same wiring production consumers see.

  VM tests live elsewhere (deferred for v1).
*/
{
  pkgs,
  nftzonesModule,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (pkgs) lib;

  minimalContext = {
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "none";
      fsType = "tmpfs";
    };
    system.stateVersion = "24.11";
    networking.hostName = "test";
  };

  /*
    Build a minimal NixOS system with the nftzones module imported
    and the test-specific config layered on. Returns the evaluated
    `config`.
  */
  evalSystem =
    extraConfig:
    (pkgs.nixos [
      nftzonesModule
      minimalContext
      extraConfig
    ]).config;

  /*
    Convenience for the common shape: nftables enabled,
    nftzones module enabled, with the supplied `tables`.
  */
  evalEnabled =
    tables:
    evalSystem {
      networking.nftables.enable = true;
      networking.nftzones = {
        enable = true;
        inherit tables;
      };
    };

  /*
    Returns the names of any failing assertions for the supplied
    config — bypasses the expensive `system.build.toplevel`
    derivation that NixOS normally uses to surface assertion
    failures. Each test asserts on the count or the message
    content directly.
  */
  failingAssertions = config: lib.filter (a: !a.assertion) config.assertions;
in
{
  # ===== module — disabled produces no nftzones-managed table =====

  testModuleDisabled = {
    # NixOS may inject default tables (e.g. `nixos-fw`); only check
    # the key we declared isn't present.
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = false;
          networking.nftzones.tables.fw = { };
        };
      in
      cfg.networking.nftables.tables ? fw;
    expected = false;
  };

  # ===== module — enabled with empty tables adds no entries =====

  testModuleEnabledEmptyTables = {
    expr =
      (evalSystem {
        networking.nftables.enable = true;
        networking.nftzones.enable = true;
      }).networking.nftzones.tables == { };
    expected = true;
  };

  # ===== module — single table compiles to block-form content =====

  testModuleSingleTable = {
    expr =
      let
        table =
          (evalEnabled {
            fw.zones.lan.interfaces = [ "lan0" ];
          }).networking.nftables.tables.fw;
      in
      {
        family = table.family;
        hasLanIifs = lib.hasInfix "set lan_iifs" table.content;
        hasLan0 = lib.hasInfix "lan0" table.content;
      };
    expected = {
      family = "inet";
      hasLanIifs = true;
      hasLan0 = true;
    };
  };

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

  # ===== module — pretty option is actually wired through to content =====
  # The bypass-evaluation test above proves the renderers behave
  # differently. This one proves the module's `pretty` option
  # actually selects between them — same body, two real
  # evaluations, content must differ.

  testModulePrettyWiring = {
    expr =
      let
        body.fw = {
          zones.lan.interfaces = [ "lan0" ];
          zones.wan.interfaces = [ "wan0" ];
          filters.allow-ssh = {
            from = [ "wan" ];
            to = [ "local" ];
            rule = [ ];
          };
        };
        compact =
          (evalSystem {
            networking.nftables.enable = true;
            networking.nftzones = {
              enable = true;
              pretty = false;
              tables = body;
            };
          }).networking.nftables.tables.fw.content;
        pretty =
          (evalSystem {
            networking.nftables.enable = true;
            networking.nftzones = {
              enable = true;
              pretty = true;
              tables = body;
            };
          }).networking.nftables.tables.fw.content;
      in
      {
        differ = compact != pretty;
        prettyLonger =
          lib.length (lib.splitString "\n" pretty)
          > lib.length (lib.splitString "\n" compact);
      };
    expected = {
      differ = true;
      prettyLonger = true;
    };
  };

  # ===== module — multi-table produces an entry per name =====

  testModuleMultipleTables = {
    expr =
      let
        ours =
          (evalEnabled {
            fw-v4 = {
              family = "ip";
              zones.lan.interfaces = [ "lan0" ];
            };
            fw-v6 = {
              family = "ip6";
              zones.lan.interfaces = [ "lan0" ];
            };
          }).networking.nftables.tables;
      in
      {
        hasV4 = ours ? fw-v4;
        hasV6 = ours ? fw-v6;
        v4Family = ours.fw-v4.family;
        v6Family = ours.fw-v6.family;
      };
    expected = {
      hasV4 = true;
      hasV6 = true;
      v4Family = "ip";
      v6Family = "ip6";
    };
  };

  # ===== module — collision with networking.nftables.tables.<n> trips assertion =====

  testModuleCollisionAssertion = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables = {
            enable = true;
            tables.fw = {
              family = "inet";
              content = "# manual content";
            };
          };
          networking.nftzones = {
            enable = true;
            tables.fw = { };
          };
        };
      in
      lib.any (a: lib.hasInfix "collides with" a.message) (failingAssertions cfg);
    expected = true;
  };

  # ===== module — requires networking.nftables.enable =====

  testModuleRequiresNftablesEnabled = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = false;
          networking.nftzones = {
            enable = true;
            tables.fw = { };
          };
        };
      in
      lib.any (a: lib.hasInfix "requires networking.nftables.enable" a.message) (failingAssertions cfg);
    expected = true;
  };
}
