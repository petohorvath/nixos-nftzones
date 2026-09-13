/*
  Unit tests for `lib/internal/placement.nix` (exposed as
  `nftzones.internal.placement`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by
  `tests/unit/default.nix`.
*/
{
  nftzones,
  ...
}:
let
  inherit (nftzones.internal.placement)
    chainAttrsForCell
    chainAttrsForEntry
    baseChainNameOf
    subChainKeyOf
    ;
in
{
  testChainAttrsForCellOverridePrecedesLocalZone = {
    expr = chainAttrsForCell "filters" "host" {
      from = "wan";
      to = "host";
      chain = {
        hook = "prerouting";
        priority = -300;
      };
    };
    expected = {
      hook = "prerouting";
      priority = -300;
    };
  };

  testChainAttrsForEntryCustomLocalZone = {
    expr = chainAttrsForEntry "filters" "host" {
      from = [
        "host"
        "lan"
        "guest"
      ];
      to = [
        "host"
        "wan"
        "vpn"
      ];
    };
    expected = [
      {
        hook = "input";
        priority = "filter";
      }
      {
        hook = "output";
        priority = "filter";
      }
      {
        hook = "forward";
        priority = "filter";
      }
    ];
  };

  # ===== chainAttrsForCell — defaults and host position =====

  testChainAttrsForCellSnats = {
    expr = chainAttrsForCell "snats" "local" {
      from = "lan";
      to = "wan";
    };
    expected = {
      hook = "postrouting";
      priority = "srcnat";
    };
  };

  testChainAttrsForCellDnats = {
    expr = chainAttrsForCell "dnats" "local" { from = "wan"; };
    expected = {
      hook = "prerouting";
      priority = "dstnat";
    };
  };

  testChainAttrsForCellSroutes = {
    expr = chainAttrsForCell "sroutes" "local" { from = "wan"; };
    expected = {
      hook = "prerouting";
      priority = "mangle";
    };
  };

  testChainAttrsForCellDroutes = {
    expr = chainAttrsForCell "droutes" "local" { to = "wan"; };
    expected = {
      hook = "output";
      priority = "mangle";
    };
  };

  testChainAttrsForCellToLocalIsInput = {
    expr = chainAttrsForCell "filters" "local" {
      from = "wan";
      to = "local";
      chain = null;
    };
    expected = {
      hook = "input";
      priority = "filter";
    };
  };

  testChainAttrsForCellPolicyFromCustomLocalIsOutput = {
    expr = chainAttrsForCell "policies" "host" {
      from = "host";
      to = "wan";
    };
    expected = {
      hook = "output";
      priority = "filter";
    };
  };

  testChainAttrsForCellNeitherIsForward = {
    expr = chainAttrsForCell "filters" "local" {
      from = "lan";
      to = "wan";
    };
    expected = {
      hook = "forward";
      priority = "filter";
    };
  };

  testChainAttrsForCellLocalToLocalPrefersInput = {
    expr = chainAttrsForCell "filters" "host" {
      from = "host";
      to = "host";
    };
    expected = {
      hook = "input";
      priority = "filter";
    };
  };

  testChainAttrsForCellOverridePrecedesGroupDefault = {
    expr = chainAttrsForCell "dnats" "local" {
      from = "wan";
      chain = {
        hook = "output";
        priority = "dstnat";
      };
    };
    expected = {
      hook = "output";
      priority = "dstnat";
    };
  };

  # ===== chainAttrsForEntry — validation candidates =====

  testChainAttrsForEntryOverridePrecedesAllFilterHooks = {
    expr = chainAttrsForEntry "filters" "host" {
      from = [
        "host"
        "lan"
      ];
      to = [
        "host"
        "wan"
      ];
      chain = {
        hook = "prerouting";
        priority = "raw";
      };
    };
    expected = [
      {
        hook = "prerouting";
        priority = "raw";
      }
    ];
  };

  testChainAttrsForEntryPolicyHooks = {
    expr = chainAttrsForEntry "policies" "host" {
      from = [
        "host"
        "lan"
      ];
      to = [ "wan" ];
    };
    expected = [
      {
        hook = "output";
        priority = "filter";
      }
      {
        hook = "forward";
        priority = "filter";
      }
    ];
  };

  testChainAttrsForEntryGroupDefaults = {
    expr = {
      snats = chainAttrsForEntry "snats" "host" {
        from = [ "lan" ];
        to = [ "wan" ];
      };
      dnats = chainAttrsForEntry "dnats" "host" { from = [ "wan" ]; };
      sroutes = chainAttrsForEntry "sroutes" "host" { from = [ "wan" ]; };
      droutes = chainAttrsForEntry "droutes" "host" { to = [ "wan" ]; };
    };
    expected = {
      snats = [
        {
          hook = "postrouting";
          priority = "srcnat";
        }
      ];
      dnats = [
        {
          hook = "prerouting";
          priority = "dstnat";
        }
      ];
      sroutes = [
        {
          hook = "prerouting";
          priority = "mangle";
        }
      ];
      droutes = [
        {
          hook = "output";
          priority = "mangle";
        }
      ];
    };
  };

  # Validation remains conservative even for entries that produce
  # no cells. Fixed placements are still checked, and each local
  # direction contributes its hook independently of the other side.
  testChainAttrsForEntryEmptyDirections = {
    expr = {
      empty = chainAttrsForEntry "filters" "host" {
        from = [ ];
        to = [ ];
      };
      nonLocalFrom = chainAttrsForEntry "filters" "host" {
        from = [ "lan" ];
        to = [ ];
      };
      nonLocalTo = chainAttrsForEntry "filters" "host" {
        from = [ ];
        to = [ "wan" ];
      };
      localFrom = chainAttrsForEntry "policies" "host" {
        from = [ "host" ];
        to = [ ];
      };
      localTo = chainAttrsForEntry "filters" "host" {
        from = [ ];
        to = [ "host" ];
      };
      snats = chainAttrsForEntry "snats" "host" {
        from = [ ];
        to = [ ];
      };
      dnats = chainAttrsForEntry "dnats" "host" { from = [ ]; };
      sroutes = chainAttrsForEntry "sroutes" "host" { from = [ ]; };
      droutes = chainAttrsForEntry "droutes" "host" { to = [ ]; };
      override = chainAttrsForEntry "dnats" "host" {
        from = [ ];
        chain = {
          hook = "output";
          priority = -100;
        };
      };
    };
    expected = {
      empty = [ ];
      nonLocalFrom = [ ];
      nonLocalTo = [ ];
      localFrom = [
        {
          hook = "output";
          priority = "filter";
        }
      ];
      localTo = [
        {
          hook = "input";
          priority = "filter";
        }
      ];
      snats = [
        {
          hook = "postrouting";
          priority = "srcnat";
        }
      ];
      dnats = [
        {
          hook = "prerouting";
          priority = "dstnat";
        }
      ];
      sroutes = [
        {
          hook = "prerouting";
          priority = "mangle";
        }
      ];
      droutes = [
        {
          hook = "output";
          priority = "mangle";
        }
      ];
      override = [
        {
          hook = "output";
          priority = -100;
        }
      ];
    };
  };

  testChainAttrsForEntryLocalToLocalChecksBothHooks = {
    expr = chainAttrsForEntry "filters" "host" {
      from = [ "host" ];
      to = [ "host" ];
    };
    expected = [
      {
        hook = "input";
        priority = "filter";
      }
      {
        hook = "output";
        priority = "filter";
      }
    ];
  };

  # ===== baseChainNameOf — bucket-key / chain-name format =====

  testBaseChainNameOfSymbol = {
    expr = baseChainNameOf "inet" {
      hook = "input";
      priority = "filter";
    };
    expected = "input-at-filter";
  };

  # Int form of a canonical symbol must collapse to the same key
  # (so user-overrides written as int don't bypass collision
  # checks that consult the key).
  testBaseChainNameOfIntCanonicalizes = {
    expr = baseChainNameOf "inet" {
      hook = "prerouting";
      priority = -300;
    };
    expected = "prerouting-at-raw";
  };

  # Family-aware: bridge's `filter = -200` canonicalizes through
  # `priorityIntsBridge`, not `priorityIntsDefault`.
  testBaseChainNameOfBridgeFamily = {
    expr = baseChainNameOf "bridge" {
      hook = "input";
      priority = -200;
    };
    expected = "input-at-filter";
  };

  # Non-canonical ints (no symbol matches) pass through unchanged.
  testBaseChainNameOfUnknownInt = {
    expr = baseChainNameOf "inet" {
      hook = "input";
      priority = 42;
    };
    expected = "input-at-42";
  };

  # ===== subChainKeyOf — bucket-local sub-chain key =====

  testSubChainKeyOfBidirectional = {
    expr = subChainKeyOf {
      from = "lan";
      to = "wan";
    };
    expected = "lan-to-wan";
  };

  testSubChainKeyOfFromOnly = {
    expr = subChainKeyOf { from = "lan"; };
    expected = "lan";
  };

  testSubChainKeyOfToOnly = {
    expr = subChainKeyOf { to = "wan"; };
    expected = "wan";
  };

  # Extra fields (rule, priority, etc.) are ignored — works on
  # cell-shaped inputs directly.
  testSubChainKeyOfIgnoresExtraFields = {
    expr = subChainKeyOf {
      from = "lan";
      to = "wan";
      rule = [ ];
      priority = "default";
    };
    expected = "lan-to-wan";
  };

}
