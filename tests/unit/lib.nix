# Tests of the library entry point, `lib/default.nix`.
{
  helpers,
  nftypes,
  nftzones,
  ...
}:
let
  inherit (helpers) diagnosticsFor dropMessages;
  inherit (nftypes) dsl;

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
      rule = [ dsl.accept ];
    };
  };
in
{
  testVersion = {
    expr = nftzones.version;
    expected = "0.1.0";
  };

  # Adding or removing a public name changes the interface consumers
  # depend on, so it must change this list too.
  testPublicNames = {
    expr = builtins.attrNames nftzones;
    expected = [
      "diagnose"
      "internal"
      "mkRuleset"
      "mkTable"
      "snippets"
      "types"
      "version"
    ];
  };

  testDiagnoseCleanBodyReportsNothing = {
    expr = nftzones.diagnose "fw" {
      zones.lan.interfaces = [ "lan0" ];
      filters.ssh = {
        from = [ "lan" ];
        to = [ "local" ];
        rule = [ dsl.accept ];
      };
    };
    expected = {
      errors = [ ];
      warnings = [ ];
    };
  };

  # Errors come back as data, where `mkRuleset` would throw.
  testDiagnoseReturnsErrorsWithoutThrowing = {
    expr = dropMessages (nftzones.diagnose "fw" invalidBody);
    expected = {
      errors = [
        {
          tag = "zoneRefUnknown";
          path = [
            "filters"
            "f"
            "from"
            "0"
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

  # The public function reports what Phase 1 reports for the same body.
  testDiagnoseAgreesWithPhase1 = {
    expr = dropMessages (nftzones.diagnose "fw" invalidBody);
    expected = diagnosticsFor invalidBody;
  };

  # Warnings come back as data beside the errors.
  testDiagnoseReturnsWarnings = {
    expr = dropMessages (
      nftzones.diagnose "fw" {
        zones.lan.interfaces = [ "lan0" ];
        zones.wan.interfaces = [ "wan0" ];
        policies.mixed = {
          from = [
            "all"
            "lan"
          ];
          to = [ "wan" ];
          verdict = "accept";
        };
      }
    );
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

  # A table read from a `nftzones.types.table` option carries its own
  # `name`; `diagnose` takes it whole, as `mkTable` does.
  testDiagnoseAcceptsEvaluatedTable = {
    expr = nftzones.diagnose "fw" (
      helpers.evalTable {
        zones.lan.interfaces = [ "lan0" ];
      }
    );
    expected = {
      errors = [ ];
      warnings = [ ];
    };
  };

  # The table type rejects the body before Phase 1 runs, so the type
  # error still throws rather than becoming a Diagnostic.
  testDiagnoseTypeErrorThrows = {
    expr = builtins.deepSeq (nftzones.diagnose "fw" {
      zones.Lan.interfaces = [ "lan0" ];
    }) null;
    expectedError = {
      type = "ThrownError";
      msg = "fw\\.zones\\.Lan\\.name' is not of type `string matching the pattern";
    };
  };

  # Phase 1 never reads `settings.stateful`, yet a mistyped value
  # must still throw rather than look clean.
  testDiagnoseTypeErrorOutsidePhase1Throws = {
    expr = builtins.deepSeq (nftzones.diagnose "fw" {
      settings.stateful = "yes";
    }) null;
    expectedError = {
      type = "ThrownError";
      msg = "fw\\.settings\\.stateful' is not of type `boolean'";
    };
  };

  # A type error names the table body it came from, not `<unknown-file>`.
  testMkRulesetTypeErrorNamesTableBody = {
    expr = builtins.toJSON (
      nftzones.mkRuleset "fw" {
        zones.lan.interfaces = [ "eth0" ];
        filters.f = {
          from = [ "lan" ];
          to = [ "local" ];
          rule = [ ];
        };
      }
    );
    expectedError = {
      type = "ThrownError";
      msg = "In `nftzones table body 'fw''";
    };
  };

  # A zone's `name` derives from its key, so a key that fails the
  # name type names the table body too.
  testMkRulesetZoneKeyTypeErrorNamesTableBody = {
    expr = builtins.toJSON (nftzones.mkRuleset "fw" { zones.Lan.interfaces = [ "lan0" ]; });
    expectedError = {
      type = "ThrownError";
      msg = "fw\\.zones\\.Lan\\.name' is not of type `string matching the pattern \\[a-z]\\[a-z0-9_-]\\*'\\. Definition values:\n- In `nftzones table body 'fw'': \"Lan\"";
    };
  };

  # Every group entry derives `name` from its key as a zone does, and
  # `diagnose` evaluates the body as `mkRuleset` does.
  testDiagnoseFilterKeyTypeErrorNamesTableBody = {
    expr = builtins.deepSeq (nftzones.diagnose "fw" {
      zones.lan.interfaces = [ "eth0" ];
      filters.F = {
        from = [ "lan" ];
        to = [ "local" ];
        rule = [ dsl.accept ];
      };
    }) null;
    expectedError = {
      type = "ThrownError";
      msg = "fw\\.filters\\.F\\.name' is not of type `string matching the pattern \\[a-z]\\[a-z0-9_-]\\*'\\. Definition values:\n- In `nftzones table body 'fw'': \"F\"";
    };
  };
}
