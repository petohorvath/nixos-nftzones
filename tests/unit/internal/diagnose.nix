# Unit tests for Phase 1's diagnostics interface: `diagnose` and the
# throwing `normalizeTable` adapter over it. Tests compare the
# `{ tag; path; }` projection of each diagnostic list, never messages.
{ pkgs, nftzones, ... }:
let
  inherit (nftzones.internal.normalize) diagnose normalizeTable;

  inherit (import ../helpers.nix { inherit pkgs nftzones; }) diagnosticsFor evalTable;

  # Two errors from different validators, reported in reverse order
  # of their paths.
  invalidBody = {
    zones.lan = {
      interfaces = [ "lan0" ];
      parent = "ghost";
    };
    filters.f = {
      from = [ "nowhere" ];
      to = [ "local" ];
    };
  };

  # Valid, but mixes the wildcard with an explicit zone.
  warningBody = {
    zones.lan.interfaces = [ "lan0" ];
    zones.wan.interfaces = [ "wan0" ];
    policies.mixed = {
      from = [
        "all"
        "lan"
      ];
      to = [ "wan" ];
    };
  };
in
{
  # Validators and compute steps are private; tests reach Phase 1
  # only through these two functions.
  testPhase1ExportsOnlyDiagnoseAndNormalizeTable = {
    expr = builtins.attrNames nftzones.internal.normalize;
    expected = [
      "diagnose"
      "normalizeTable"
    ];
  };

  testDiagnoseCleanTableReportsNothing = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      zones.wan.interfaces = [ "wan0" ];
      filters.ssh = {
        from = [ "lan" ];
        to = [ "local" ];
      };
    };
    expected = {
      errors = [ ];
      warnings = [ ];
    };
  };

  testDiagnoseErrorCarriesTagAndPath = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        parent = "ghost";
      };
    };
    expected = {
      errors = [
        {
          tag = "zoneParentUnknown";
          path = [
            "zones"
            "lan"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  # Name collisions run before node-address checks, but both land on
  # `nodes.web`, so the tag decides the order.
  testDiagnoseSortsByPathThenTag = {
    expr = diagnosticsFor {
      zones.lan = {
        interfaces = [ "lan0" ];
        parent = "ghost";
      };
      zones.web.interfaces = [ "web0" ];
      nodes.web.zone = "lan";
      filters.f = {
        from = [ "nowhere" ];
        to = [ "local" ];
      };
    };
    expected = {
      errors = [
        {
          tag = "invalidZoneRef";
          path = [
            "filters"
            "f"
            "from"
            "0"
          ];
        }
        {
          tag = "nodeAddressMissing";
          path = [
            "nodes"
            "web"
          ];
        }
        {
          tag = "zoneNameCollision";
          path = [
            "nodes"
            "web"
          ];
        }
        {
          tag = "zoneParentUnknown";
          path = [
            "zones"
            "lan"
            "parent"
          ];
        }
      ];
      warnings = [ ];
    };
  };

  testDiagnoseWarningCarriesTagAndPath = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      zones.wan.interfaces = [ "wan0" ];
      policies.mixed = {
        from = [
          "all"
          "lan"
        ];
        to = [ "wan" ];
      };
    };
    expected = {
      errors = [ ];
      warnings = [
        {
          tag = "wildcardZoneMixed";
          path = [
            "policies"
            "mixed"
            "from"
          ];
        }
      ];
    };
  };

  # Every validator runs and none short-circuits (ADR-0009): one table
  # with several unrelated mistakes reports each of them.
  testDiagnoseAggregatesEveryError = {
    expr =
      (diagnosticsFor {
        zones = {
          lan.interfaces = [ "eth0" ];
          dmz.interfaces = [ "eth0" ];
          a = {
            interfaces = [ "a0" ];
            parent = "b";
          };
          b = {
            interfaces = [ "b0" ];
            parent = "a";
          };
        };
        nodes.web.zone = "lan";
        filters.f = {
          from = [ "ghost" ];
          to = [ "local" ];
        };
        policies = {
          p1 = {
            from = [ "lan" ];
            to = [ "dmz" ];
          };
          p2 = {
            from = [ "lan" ];
            to = [ "dmz" ];
          };
        };
      }).errors;
    expected = [
      {
        tag = "invalidZoneRef";
        path = [
          "filters"
          "f"
          "from"
          "0"
        ];
      }
      {
        tag = "nodeAddressMissing";
        path = [
          "nodes"
          "web"
        ];
      }
      {
        tag = "policyConflict";
        path = [
          "policies"
          "p1"
        ];
      }
      {
        tag = "zoneParentCycle";
        path = [
          "zones"
          "a"
          "parent"
        ];
      }
      {
        tag = "interfaceOverlap";
        path = [
          "zones"
          "dmz"
          "interfaces"
        ];
      }
    ];
  };

  # ===== normalizeTable — the throwing adapter over diagnose =====

  testNormalizeTableThrowsWhenDiagnoseHasErrors = {
    expr =
      let
        table = evalTable invalidBody;
      in
      {
        hasErrors = (diagnose table).errors != [ ];
        throws = !(builtins.tryEval (normalizeTable table)).success;
      };
    expected = {
      hasErrors = true;
      throws = true;
    };
  };

  testNormalizeTablePassesThroughWarnings = {
    expr =
      let
        table = evalTable warningBody;
        diagnostics = diagnose table;
      in
      {
        hasErrors = diagnostics.errors != [ ];
        hasWarnings = diagnostics.warnings != [ ];
        passes = (builtins.tryEval (normalizeTable table)).success;
      };
    expected = {
      hasErrors = false;
      hasWarnings = true;
      passes = true;
    };
  };

  # Errors render as `[tag] path: message`, in `diagnose` order.
  testNormalizeTableRendersEveryErrorWithTagAndPath = {
    expr = normalizeTable (evalTable invalidBody);
    expectedError = {
      type = "ThrownError";
      msg = "validation failed:\n  - \\[invalidZoneRef\\] filters\\.f\\.from\\.0: [^\n]*\n  - \\[zoneParentUnknown\\] zones\\.lan\\.parent: ";
    };
  };
}
