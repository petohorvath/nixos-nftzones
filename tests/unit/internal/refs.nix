/*
  Unit tests for `lib/internal/refs.nix` (exposed as
  `nftzones.internal.refs`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.

  All test fixtures use `nftypes.dsl.*` builders — no hand-rolled
  libnftables-json shapes. The walker recognizes whatever the DSL
  emits; if the DSL changes shape, these tests catch it.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.refs) extractRefs;
  inherit (nftypes.dsl) fields;
  dsl = nftypes.dsl;

  # Order-insensitive comparison: extractRefs is recursion-order
  # dependent, but tests assert presence/absence not order.
  sortRefs = pkgs.lib.sort (a: b: a.kind + a.name < b.kind + b.name);
in
{
  # ===== extractRefs — primitives and empty input have no refs =====

  testRefsEmptyList = {
    expr = extractRefs [ ];
    expected = [ ];
  };

  testRefsPrimitive = {
    expr = extractRefs "just a string";
    expected = [ ];
  };

  testRefsNullSafe = {
    expr = extractRefs null;
    expected = [ ];
  };

  # ===== extractRefs — string-bodied statement refs (one per kind) =====

  testRefsCounter = {
    expr = extractRefs [ (dsl.counter.ref "ssh-attempts") ];
    expected = [
      {
        kind = "counters";
        name = "ssh-attempts";
      }
    ];
  };

  testRefsCounterAutoNoRef = {
    # `counter = null` is the stateless form, not a ref.
    expr = extractRefs [ dsl.counter.auto ];
    expected = [ ];
  };

  testRefsCounterInlineNoRef = {
    # `counter = { packets; bytes; }` is anonymous, not a ref.
    expr = extractRefs [
      (dsl.counter {
        packets = 0;
        bytes = 0;
      })
    ];
    expected = [ ];
  };

  testRefsLimit = {
    expr = extractRefs [ (dsl.limit.ref "rate-1") ];
    expected = [
      {
        kind = "limits";
        name = "rate-1";
      }
    ];
  };

  testRefsQuota = {
    expr = extractRefs [ (dsl.quota.ref "monthly-cap") ];
    expected = [
      {
        kind = "quotas";
        name = "monthly-cap";
      }
    ];
  };

  testRefsCtHelper = {
    expr = extractRefs [ (dsl.ctHelper "ftp-helper") ];
    expected = [
      {
        kind = "ctHelpers";
        name = "ftp-helper";
      }
    ];
  };

  testRefsCtTimeout = {
    expr = extractRefs [ (dsl.ctTimeout "long-tcp") ];
    expected = [
      {
        kind = "ctTimeouts";
        name = "long-tcp";
      }
    ];
  };

  testRefsCtExpectation = {
    expr = extractRefs [ (dsl.ctExpectation "exp-1") ];
    expected = [
      {
        kind = "ctExpectations";
        name = "exp-1";
      }
    ];
  };

  testRefsSecmark = {
    expr = extractRefs [ (dsl.secmark "internal") ];
    expected = [
      {
        kind = "secmarks";
        name = "internal";
      }
    ];
  };

  testRefsTunnel = {
    expr = extractRefs [ (dsl.tunnel "vpn-1") ];
    expected = [
      {
        kind = "tunnels";
        name = "vpn-1";
      }
    ];
  };

  testRefsSynproxyRef = {
    expr = extractRefs [ (dsl.synproxy.ref "syn-prof") ];
    expected = [
      {
        kind = "synproxies";
        name = "syn-prof";
      }
    ];
  };

  testRefsSynproxyAutoNoRef = {
    expr = extractRefs [ dsl.synproxy.auto ];
    expected = [ ];
  };

  # ===== extractRefs — set/map STATEMENTS (dynamic add/update) =====

  testRefsSetStatement = {
    expr = extractRefs [
      (dsl.setStmt {
        op = "add";
        elem = fields.ip.saddr;
        set = "blocklist";
      })
    ];
    expected = [
      {
        kind = "sets";
        name = "blocklist";
      }
    ];
  };

  testRefsMapStatement = {
    expr = extractRefs [
      (dsl.mapStmt {
        op = "add";
        elem = fields.ip.saddr;
        data = "v1";
        map = "verdict-map";
      })
    ];
    expected = [
      {
        kind = "maps";
        name = "verdict-map";
      }
    ];
  };

  # ===== extractRefs — flow statement (flowtable ref) =====

  testRefsFlow = {
    # The walker strips the `@` prefix from named-reference strings
    # (per libnftables-JSON convention) so refs match
    # `objects.flowtables.<name>` keys.
    expr = extractRefs [ (dsl.flow { flowtable = "@offload"; }) ];
    expected = [
      {
        kind = "flowtables";
        name = "offload";
      }
    ];
  };

  # ===== extractRefs — set-lookup expression nested in match.right =====

  testRefsSetLookupInMatch = {
    expr = extractRefs [ (dsl.inSet fields.ip.saddr (dsl.expr.setRef "blocklist")) ];
    expected = [
      {
        kind = "sets";
        name = "blocklist";
      }
    ];
  };

  testRefsAnonymousSetLookupNoRef = {
    # Anonymous set (list body) has no name — should NOT be flagged.
    expr = extractRefs [
      (dsl.inSet fields.ip.saddr (
        dsl.expr.set [
          "1.2.3.4"
          "5.6.7.8"
        ]
      ))
    ];
    expected = [ ];
  };

  # ===== extractRefs — map-lookup expression =====

  testRefsMapLookupExpr = {
    expr = extractRefs [
      (dsl.eq (dsl.expr.map {
        key = fields.ip.saddr;
        data = "verdict-map";
      }) "drop")
    ];
    expected = [
      {
        kind = "maps";
        name = "verdict-map";
      }
    ];
  };

  # ===== extractRefs — vmap statement (named verdict map) =====

  testRefsVmap = {
    expr = extractRefs [ (dsl.vmap fields.ip.saddr "verdict-map") ];
    expected = [
      {
        kind = "maps";
        name = "verdict-map";
      }
    ];
  };

  # ===== extractRefs — multiple refs in one rule body =====

  testRefsMultipleInRule = {
    expr = sortRefs (extractRefs [
      (dsl.inSet fields.ip.saddr (dsl.expr.setRef "blocklist"))
      (dsl.counter.ref "drops")
      (dsl.limit.ref "burst-1")
      dsl.drop
    ]);
    expected = sortRefs [
      {
        kind = "sets";
        name = "blocklist";
      }
      {
        kind = "counters";
        name = "drops";
      }
      {
        kind = "limits";
        name = "burst-1";
      }
    ];
  };

  # ===== extractRefs — refs nested inside set-statement's stmt sub-list =====

  testRefsNestedInSetStmt = {
    # `setStmt.stmt` is a list of statements attached to the
    # element being added. Refs in there must be picked up by
    # the recursion.
    expr = sortRefs (extractRefs [
      (dsl.setStmt {
        op = "add";
        elem = fields.ip.saddr;
        set = "tracker";
        stmt = [ (dsl.counter.ref "additions") ];
      })
    ]);
    expected = sortRefs [
      {
        kind = "sets";
        name = "tracker";
      }
      {
        kind = "counters";
        name = "additions";
      }
    ];
  };

  # ===== extractRefs — non-rule attrset structure has no false positives =====

  testRefsRuleShapeWithMatchClauses = {
    # A typical filter rule with payload+verdict contains no
    # named refs — extractor must return [ ].
    expr = extractRefs [
      (dsl.eq fields.tcp.dport 22)
      dsl.accept
    ];
    expected = [ ];
  };

  # ===== extractRefs — dnat-shaped rule with embedded match list =====

  testRefsDnatShape = {
    # dnat rules are { match = [ ... ]; action = ...; } — the
    # walker's recursion must traverse both fields.
    expr = sortRefs (extractRefs {
      match = [
        (dsl.eq fields.tcp.dport 443)
        (dsl.counter.ref "https-hits")
      ];
      action.dnat = {
        addr = "10.0.0.5";
        port = 443;
      };
    });
    expected = [
      {
        kind = "counters";
        name = "https-hits";
      }
    ];
  };

  # ===== extractRefs — singleton-only contract: extra keys disqualify =====
  # A statement attrset with a `counter` key but additional sibling
  # keys is NOT the singleton form `dsl.counter.ref` produces, so
  # the walker must NOT treat it as a named-ref.

  testRefsSingletonOnly = {
    expr = extractRefs [
      {
        counter = "looks-named";
        unrelated = "sibling";
      }
    ];
    expected = [ ];
  };

  # ===== extractRefs — duplicate refs not deduplicated =====
  # The walker reports every occurrence; dedup (if needed) is the
  # caller's job. Locks in the contract so callers don't accidentally
  # rely on dedup that isn't there.

  testRefsDuplicatesPreserved = {
    expr = sortRefs (extractRefs [
      (dsl.counter.ref "hits")
      (dsl.counter.ref "hits")
    ]);
    expected = [
      {
        kind = "counters";
        name = "hits";
      }
      {
        kind = "counters";
        name = "hits";
      }
    ];
  };

  # ===== extractRefs — deeply nested ref via several attrset levels =====
  # The walker must traverse arbitrary attrset depth, not just the
  # one or two levels the common rule shapes use.

  testRefsDeeplyNested = {
    expr = extractRefs {
      outer = {
        middle = {
          inner = [ (dsl.counter.ref "deep-hits") ];
        };
      };
    };
    expected = [
      {
        kind = "counters";
        name = "deep-hits";
      }
    ];
  };
}
