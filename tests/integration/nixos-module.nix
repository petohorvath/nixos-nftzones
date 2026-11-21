/*
  Integration tests for the NixOS module (`nixos/module.nix`, exposed
  as `nixosModules.default`).

  Pure module evaluations, with no VM boot: `helpers.evalNixosModule`
  evaluates a NixOS system with `pkgs.nixos` and the module, beside a
  minimal but valid context (loader, filesystems, and stateVersion
  stubs), and the tests read back the resulting `config`.

  The VM tests in `tests/vm/` boot real routers and check traffic.
*/
{
  helpers,
  lib,
  nftypes,
  nftzones,
  ...
}:
let
  minimalContext = {
    boot.loader.grub.enable = false;
    fileSystems."/" = {
      device = "none";
      fsType = "tmpfs";
    };
    # Derive from the pinned nixpkgs so the test doesn't need a
    # manual bump every NixOS release. Always matches the version
    # of NixOS we're evaluating against.
    system.stateVersion = lib.trivial.release;
    networking.hostName = "test";
  };

  # Build a minimal NixOS system with the nftzones module imported
  # and the test-specific config layered on. Returns the evaluated
  # `config`.
  evalSystem =
    extraConfig:
    helpers.evalNixosModule {
      imports = [
        minimalContext
        extraConfig
      ];
    };

  # Convenience for the common shape: nftables enabled,
  # nftzones module enabled, with the supplied `tables`.
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
  failingAssertions = config: lib.filter (assertion: !assertion.assertion) config.assertions;

  # The messages of the failing assertions on a system that declares
  # the nftzones table `fw` beside the supplied `networking.nftables`
  # settings.
  collisionMessages =
    nftables:
    map (assertion: assertion.message) (
      failingAssertions (evalSystem {
        networking.nftables = {
          enable = true;
        }
        // nftables;
        networking.nftzones = {
          enable = true;
          tables.fw = { };
        };
      })
    );

  collidesWith = source: ''
    networking.nftzones.tables.fw collides with ${source}.
    Declare each table in exactly one module.
  '';

  # A hand-written entry under another key that renders as `inet fw`.
  extraFw = {
    name = "fw";
    family = "inet";
    content = "chain input-at-filter { accept; }";
  };

  # How many times `needle` occurs in `text`.
  occurrences = needle: text: builtins.length (lib.splitString needle text) - 1;

  # A table whose only entry lands at input, which gives it an input
  # base chain.
  inputTable = {
    zones.lan.interfaces = [ "lan0" ];
    filters.lan-ssh = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = nftzones.snippets.accept.tcp 22;
    };
  };

  # A table whose only entry lands at forward, which leaves it no
  # input base chain.
  forwardTable = {
    zones = {
      lan = {
        interfaces = [ "lan0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      wan.interfaces = [ "wan0" ];
    };
    filters.lan-out = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ nftypes.dsl.accept ];
    };
  };

  # The nftzones warnings of a system with the supplied settings.
  nftzonesWarnings =
    extraConfig:
    lib.filter (lib.hasInfix "networking.nftzones")
      (evalSystem (
        lib.recursiveUpdate {
          networking.nftables.enable = true;
          networking.nftzones.enable = true;
        } extraConfig
      )).warnings;

  # Whether the warnings include the one for unfiltered input.
  warnsInputUnfiltered = lib.any (lib.hasInfix "Nothing filters traffic to the host");
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

  # ===== module — enabled with empty tables fails its assertion =====

  testModuleEnabledEmptyTablesAssertion = {
    # `enable = true` + `tables = { }` previously compiled silently to
    # an empty ruleset — combined with `networking.firewall.enable =
    # false` (the typical nftzones-managed host setup), that's a
    # firewall-less host. The assertion makes the misconfig loud.
    expr =
      let
        failing = failingAssertions (evalSystem {
          networking.nftables.enable = true;
          networking.nftzones.enable = true;
        });
      in
      {
        count = lib.length failing;
        mentionsEmpty = lib.any (assertion: lib.hasInfix "tables is empty" assertion.message) failing;
      };
    expected = {
      count = 1;
      mentionsEmpty = true;
    };
  };

  # ===== module — disabled empty tables pass (mkIf-gated assertion) =====

  testModuleDisabledEmptyTablesNoAssertion = {
    expr = failingAssertions (evalSystem {
      networking.nftables.enable = false;
      networking.nftzones.enable = false;
    });
    expected = [ ];
  };

  # ===== module — warns when nftzones coexists with networking.firewall =====

  testModuleWarnsOnFirewallCoexistence = {
    # The warning fires once, names the stock `nixos-fw` table, and
    # says that both firewalls must accept a packet, so a port opened
    # only in nftzones stays closed.
    expr =
      let
        warnings = nftzonesWarnings {
          networking.firewall.enable = true;
          networking.nftzones.tables.fw = inputTable;
        };
      in
      {
        count = lib.length warnings;
        mentionsFirewall = lib.any (lib.hasInfix "networking.firewall.enable") warnings;
        namesStockTable = lib.any (lib.hasInfix "nixos-fw") warnings;
        saysNftzonesOnlyPortStaysClosed = lib.any (lib.hasInfix "a port opened only in nftzones stays closed") warnings;
      };
    expected = {
      count = 1;
      mentionsFirewall = true;
      namesStockTable = true;
      saysNftzonesOnlyPortStaysClosed = true;
    };
  };

  # ===== module — no firewall-coexistence warning when firewall disabled =====

  testModuleNoFirewallCoexistenceWarn = {
    # nixpkgs defaults `networking.firewall.enable` to true, so the
    # test must explicitly disable it to verify the warning DOESN'T
    # fire when firewall is off.
    expr = nftzonesWarnings {
      networking.firewall.enable = false;
      networking.nftzones.tables.fw = inputTable;
    };
    expected = [ ];
  };

  # ===== module — coexistence at forward depends on filterForward =====

  testModuleFirewallCoexistenceAtForward = {
    # A table that handles only forwarding shares a hook with the stock
    # firewall only while the stock forward chain filters.
    expr = lib.genAttrs [ "filtered" "unfiltered" ] (
      state:
      lib.length (nftzonesWarnings {
        networking.firewall = {
          enable = true;
          filterForward = state == "filtered";
        };
        networking.nftzones.tables.fw = forwardTable;
      })
    );
    expected = {
      filtered = 1;
      unfiltered = 0;
    };
  };

  # ===== module — warns when input is unfiltered =====

  testModuleWarnsInputUnfiltered = {
    # With the stock firewall off and no entry that lands at input, no
    # table hooks input, so the host accepts every packet sent to it.
    expr =
      let
        warnings = nftzonesWarnings {
          networking.firewall.enable = false;
          networking.nftzones.tables.fw = forwardTable;
        };
      in
      {
        count = lib.length warnings;
        warnsInputUnfiltered = warnsInputUnfiltered warnings;
      };
    expected = {
      count = 1;
      warnsInputUnfiltered = true;
    };
  };

  # ===== module — each kind of entry at input filters input =====

  testModuleInputUnfilteredWarnByEntry = {
    # The local zone, the wildcard zone and a `chain` override each put
    # an entry at input, which gives the table its input base chain.
    expr =
      lib.mapAttrs
        (
          _kind: placement:
          warnsInputUnfiltered (nftzonesWarnings {
            networking.firewall.enable = false;
            networking.nftzones.tables.fw = forwardTable // {
              filters.at-input = {
                from = [ "lan" ];
                rule = nftzones.snippets.accept.tcp 22;
              }
              // placement;
            };
          })
        )
        {
          local.to = [ "local" ];
          wildcard.to = [ "all" ];
          override = {
            # At input, a zone matches as a destination by its CIDRs.
            to = [ "lan" ];
            chain = {
              hook = "input";
              priority = "filter";
            };
          };
        };
    expected = {
      local = false;
      override = false;
      wildcard = false;
    };
  };

  # ===== module — input must be filtered for both IP families =====

  testModuleInputUnfilteredWarnPerIpFamily = {
    expr =
      lib.mapAttrs
        (
          _families: tables:
          warnsInputUnfiltered (nftzonesWarnings {
            networking.firewall.enable = false;
            networking.nftzones.tables = tables;
          })
        )
        {
          ip.fw = inputTable // {
            family = "ip";
          };
          ipAndIp6 = {
            fw = inputTable // {
              family = "ip";
            };
            fw6 = inputTable // {
              family = "ip6";
            };
          };
        };
    expected = {
      ip = true;
      ipAndIp6 = false;
    };
  };

  # ===== module — the warnings read a table with no chains =====

  testModuleWarningsForTableWithoutEntries = {
    # A table with zones but no entries compiles to no `chains`.
    expr =
      let
        warningsWith =
          firewall:
          nftzonesWarnings {
            networking.firewall.enable = firewall;
            networking.nftzones.tables.fw.zones.lan.interfaces = [ "lan0" ];
          };
      in
      {
        firewallOff = warnsInputUnfiltered (warningsWith false);
        firewallOn = warningsWith true;
      };
    expected = {
      firewallOff = true;
      firewallOn = [ ];
    };
  };

  # ===== module — a dormant table filters nothing =====

  testModuleDormantTableFiltersNothing = {
    # A dormant table's base chains are unregistered, so its input
    # chain neither filters input nor shares the stock firewall's hook.
    expr = lib.genAttrs [ "firewallOff" "firewallOn" ] (
      state:
      lib.length (nftzonesWarnings {
        networking.firewall.enable = state == "firewallOn";
        networking.nftzones.tables.fw = inputTable // {
          flags = [ "dormant" ];
        };
      })
    );
    expected = {
      # The unfiltered-input warning.
      firewallOff = 1;
      # No coexistence warning.
      firewallOn = 0;
    };
  };

  # ===== module — a hand-written input chain filters input =====

  testModuleInputUnfilteredWarnBesideHandWrittenInput = {
    # A bridge input chain sees only bridged frames, so it does not
    # count.
    expr =
      let
        chain = "chain input { type filter hook input priority 0; policy drop; }";
        handWritten = family: {
          tables.host = {
            inherit family;
            content = chain;
          };
        };
      in
      lib.mapAttrs
        (
          _source: nftables:
          warnsInputUnfiltered (nftzonesWarnings {
            networking.firewall.enable = false;
            networking.nftzones.tables.fw = forwardTable;
            networking.nftables = nftables;
          })
        )
        {
          bridgeTable = handWritten "bridge";
          inetTable = handWritten "inet";
          ruleset.ruleset = "table inet host { ${chain} }";
        };
    expected = {
      bridgeTable = true;
      inetTable = false;
      ruleset = false;
    };
  };

  # ===== module — a commented-out input chain does not count =====

  testModuleInputUnfilteredWarnIgnoresComments = {
    expr = warnsInputUnfiltered (nftzonesWarnings {
      networking.firewall.enable = false;
      networking.nftzones.tables.fw = forwardTable;
      networking.nftables.ruleset = "# chain input { type filter hook input priority 0; }";
    });
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
        inherit (table) family;
        hasLanIifs = lib.hasInfix "set lan_iifs" table.content;
        hasLan0 = lib.hasInfix "lan0" table.content;
      };
    expected = {
      family = "inet";
      hasLanIifs = true;
      hasLan0 = true;
    };
  };

  # ===== module — pretty option is actually wired through to content =====
  # The unit suite `nixos.module` proves the renderers behave
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
            rule = [ nftypes.dsl.accept ];
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
        prettyLonger = lib.length (lib.splitString "\n" pretty) > lib.length (lib.splitString "\n" compact);
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

  # ===== module — a facade `table` option forwards into tables.<key> =====
  # Reproduction from the `name`-projection fix: a standalone option
  # of type `nftzones.types.table` (whose `name` defaults to the
  # option path `myfw`) forwarded into `networking.nftzones.tables.fw`
  # under a *different* key. Pre-fix this threw — the table's `name`
  # `apply` compared the facade option path against the tables key
  # ('myfw' != 'fw'). Post-fix the module projects the on-wire name
  # from the real attr key, so the whole evaluated table compiles
  # under `fw` without copying it field-by-field.

  testModuleFacadeForward = {
    expr =
      let
        cfg = evalSystem (
          { config, ... }:
          {
            options.myfw = lib.mkOption {
              type = nftzones.types.table;
              default = { };
            };
            config = {
              networking.nftables.enable = true;
              networking.firewall.enable = false;
              myfw.zones.lan.interfaces = [ "lan0" ];
              myfw.filters.web = {
                from = [ "lan" ];
                to = [ "local" ];
                rule = [ nftypes.dsl.accept ];
              };
              networking.nftzones = {
                enable = true;
                tables.fw = config.myfw;
              };
            };
          }
        );
        # Forcing the content surfaces any boundary / Phase-1 throw —
        # this is exactly what threw on the pre-fix code.
        content = cfg.networking.nftables.tables.fw.content;
      in
      {
        noFailingAssertions = (failingAssertions cfg) == [ ];
        compiles = builtins.isString content && content != "";
        hasLanIifs = lib.hasInfix "set lan_iifs" content;
        # The `tables` option forces each entry's `name` to its attr
        # key, overriding the forwarded value's `name` ('myfw'), so
        # every reader — not just the compiled ruleset — sees the key.
        optionNameProjected = cfg.networking.nftzones.tables.fw.name;
      };
    expected = {
      noFailingAssertions = true;
      compiles = true;
      hasLanIifs = true;
      optionNameProjected = "fw";
    };
  };

  # ===== module — a tables key that fails the table name type =====
  # The key sets each table's `name` through the module system, so a
  # key failing `nftzones.types.tableName` throws the standard type
  # error at evaluation, before nixpkgs' `checkRuleset` would see it.

  testModuleRejectsBadTableKey = {
    expr = (evalEnabled { "Bad Table" = { }; }).networking.nftzones.tables."Bad Table".name;
    expectedError = {
      type = "ThrownError";
      msg = "networking\\.nftzones\\.tables\\.\"Bad Table\"\\.name' is not of type `string matching the pattern";
    };
  };

  # ===== module — hand-written nftables.tables.<other> coexists =====

  testModuleHandWrittenCoexists = {
    # Users mixing zone-managed and hand-written tables under
    # different names should hit no assertion. The collision check
    # only fires on same-name conflicts (see the next test); raw
    # tables under any other key flow through nixpkgs' own
    # `networking.nftables.tables` machinery untouched.
    expr =
      let
        cfg = evalSystem {
          networking.nftables = {
            enable = true;
            tables.legacy-raw = {
              family = "inet";
              content = "# manual content";
            };
          };
          networking.nftzones = {
            enable = true;
            tables.zonefw.zones.lan.interfaces = [ "lan0" ];
          };
        };
      in
      {
        noFailingAssertions = (failingAssertions cfg) == [ ];
        hasZonefw = cfg.networking.nftables.tables ? zonefw;
        hasLegacyRaw = cfg.networking.nftables.tables ? legacy-raw;
        legacyContent = cfg.networking.nftables.tables.legacy-raw.content;
      };
    expected = {
      noFailingAssertions = true;
      hasZonefw = true;
      hasLegacyRaw = true;
      legacyContent = "# manual content";
    };
  };

  # ===== module — a second source for an nftzones table trips assertion =====

  /*
    Each test pins the exact messages of every failing assertion, not
    an infix match: a rephrasing that dropped the colliding source or
    the "exactly one module" remediation hint would otherwise regress
    the user-facing diagnostic silently, and an extra message for the
    same collision would go unnoticed.
  */

  testModuleCollisionAssertion = {
    expr = collisionMessages {
      tables.fw = {
        family = "inet";
        content = "# manual content";
      };
    };
    expected = [ (collidesWith "networking.nftables.tables.fw") ];
  };

  # A same-key override also changes the merged entry; the key check
  # reports it alone.
  testModuleForcedContentReportsKeyCollisionOnly = {
    expr = collisionMessages { tables.fw.content = lib.mkForce "chain input-at-filter { accept; }"; };
    expected = [ (collidesWith "networking.nftables.tables.fw") ];
  };

  /*
    nixpkgs renders each `networking.nftables.tables` entry as
    `table <family> <name> { ... }`, and `name` is only `mkDefault`
    the key. A differently keyed entry naming itself `fw` in the same
    family renders a second `table inet fw` block, which nft merges
    into the nftzones table.
  */
  testModuleCollisionOnWireName = {
    expr = collisionMessages { tables.zz-extra = extraFw; };
    expected = [
      (collidesWith "networking.nftables.tables.zz-extra, which also renders as `table inet fw`")
    ];
  };

  # Rendered first, the extra block fails `nft --check` instead of
  # merging, but evaluation rejects it in either order.
  testModuleCollisionOnWireNameSortsFirst = {
    expr = collisionMessages { tables.aa-extra = extraFw; };
    expected = [
      (collidesWith "networking.nftables.tables.aa-extra, which also renders as `table inet fw`")
    ];
  };

  # nixpkgs renders only enabled entries.
  testModuleDisabledSameNameCoexists = {
    expr = collisionMessages {
      tables.zz-extra = extraFw // {
        enable = false;
      };
    };
    expected = [ ];
  };

  # The on-wire identity is the family and the name together, so the
  # same name in another family is a separate table.
  testModuleSameNameOtherFamilyCoexists = {
    expr = collisionMessages {
      tables.fw-bridge = extraFw // {
        family = "bridge";
      };
    };
    expected = [ ];
  };

  # `mkForce` on the whole option discards the nftzones definition, so
  # the key check sees one source; the merged entries show the loss.
  testModuleForcedTablesDropCompiledTable = {
    expr = collisionMessages {
      tables = lib.mkForce {
        extra = extraFw // {
          name = "extra";
        };
      };
    };
    expected = [
      ''
        networking.nftables.tables.fw is missing, so
        networking.nftzones.tables.fw does not reach nft as compiled.
        Another module may set networking.nftables.tables with
        lib.mkForce. Declare each table in exactly one module.
      ''
    ];
  };

  # nixpkgs appends `networking.nftables.ruleset` to the tables in one
  # file, so a block there for `inet fw` merges into the nftzones table.
  testModuleRulesetTableBlockCollides = {
    expr = collisionMessages {
      ruleset = ''
        table inet fw {
          chain input-at-filter { accept; }
        }
      '';
    };
    expected = [ (collidesWith "networking.nftables.ruleset, which also addresses `table inet fw`") ];
  };

  testModuleRulesetStatementCollides = {
    expr = collisionMessages { ruleset = "add rule inet fw input-at-filter accept"; };
    expected = [ (collidesWith "networking.nftables.ruleset, which also addresses `table inet fw`") ];
  };

  # Names that only contain the table name, other families, comments
  # and objects named like the table are other tables.
  testModuleRulesetOtherTablesCoexist = {
    expr = collisionMessages {
      ruleset = ''
        # table inet fw is the nftzones table.
        table fw { }
        table inet fw-extra { }
        table inet extra {
          chain fw { }
          set fw { type ipv4_addr; }
        }
      '';
    };
    expected = [ ];
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
      lib.any (assertion: lib.hasInfix "requires networking.nftables.enable" assertion.message) (
        failingAssertions cfg
      );
    expected = true;
  };

  # ===== module — table-level `flags` and `comment` in the block =====
  # The nixpkgs wrapper supplies `table <fam> <name> { ... }`;
  # `nftypes.toTextBlock` writes `flags` / `comment` inside it.
  # Each must land in the rendered text exactly once.

  testModuleRendersTableFlags = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              flags = [ "owner" ];
              zones.lan.interfaces = [ "lan0" ];
            };
          };
        };
      in
      occurrences "flags owner;" cfg.networking.nftables.tables.fw.content;
    expected = 1;
  };

  testModuleRendersTableFlagsMulti = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              flags = [
                "dormant"
                "owner"
              ];
              zones.lan.interfaces = [ "lan0" ];
            };
          };
        };
      in
      occurrences "flags dormant, owner;" cfg.networking.nftables.tables.fw.content;
    expected = 1;
  };

  testModuleRendersTableComment = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              comment = "main firewall";
              zones.lan.interfaces = [ "lan0" ];
            };
          };
        };
      in
      occurrences "comment \"main firewall\";" cfg.networking.nftables.tables.fw.content;
    expected = 1;
  };

  # ===== module — Phase 1 validator throws surface at module eval =====
  # Pins that the module path doesn't swallow Phase 1 throws.
  # The unit suite `rejections` proves `mkRuleset` itself throws on
  # bad bodies; this proves the throw still bubbles out when
  # the body is reached via the NixOS option machinery (the
  # module routes through `internal.compile.mkTable` directly,
  # bypassing the public `mkTable` wrapper — see
  # `lib/default.nix` and `nixos/module.nix`).
  #
  # Trigger: two zones declaring overlapping interfaces, which
  # Phase 1 rejects with an `interfaceOverlap` error.
  testModulePhase1ValidatorPropagates = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw = {
              zones.lan-a.interfaces = [ "lan0" ];
              zones.lan-b.interfaces = [ "lan0" ];
            };
          };
        };
        attempt = builtins.tryEval (builtins.deepSeq cfg.networking.nftables.tables.fw.content null);
      in
      attempt.success;
    expected = false;
  };

  # Default values must not leak into the content — verifies the
  # prefix is empty when neither field is set.
  testModuleNoMetadataPrefixByDefault = {
    expr =
      let
        cfg = evalSystem {
          networking.nftables.enable = true;
          networking.nftzones = {
            enable = true;
            tables.fw.zones.lan.interfaces = [ "lan0" ];
          };
        };
        content = cfg.networking.nftables.tables.fw.content;
      in
      {
        hasFlags = lib.hasInfix "flags" content;
        hasComment = lib.hasInfix "comment " content;
      };
    expected = {
      hasFlags = false;
      hasComment = false;
    };
  };
}
