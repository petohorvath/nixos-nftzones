/*
  Unit tests for `nftzones.snippets` — rule-body shorthand. Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.

  All assertions construct expected values via `nftypes.dsl.*` so
  the tests exercise real DSL shapes. If `nftypes` changes a
  combinator's encoding, both the snippet output and the expected
  value move together — no false positives.

  Throw paths use `builtins.tryEval` over `builtins.deepSeq` to
  force the snippet's body fully; `tryEval` alone only catches
  errors thrown during the outer reduction, and snippet returns are
  lists whose elements stay as thunks until forced.
*/
{
  pkgs,
  nftzones,
  nftypes,
  libnet,
  ...
}:
let
  inherit (nftzones) snippets;
  inherit (nftypes.dsl)
    accept
    drop
    reject
    eq
    inSet
    within
    ;
  inherit (nftypes.dsl) expr;
  inherit (nftypes.dsl.fields)
    tcp
    udp
    icmp
    icmpv6
    ;

  range = lo: hi: expr.range lo hi;

  # Helper for throw-path tests: deepSeq forces the full structure
  # so a thunked throw inside the returned list actually fires.
  evalDeep = x: builtins.tryEval (builtins.deepSeq x null);
  throwExpected = {
    success = false;
    value = false;
  };
in
{
  # ===== TCP / UDP — single-port input forms =====

  testTcpAcceptInt = {
    expr = snippets.accept.tcp 22;
    expected = [
      (eq tcp.dport 22)
      accept
    ];
  };

  testTcpAcceptString = {
    expr = snippets.accept.tcp "22";
    expected = [
      (eq tcp.dport 22)
      accept
    ];
  };

  testTcpAcceptListSingle = {
    expr = snippets.accept.tcp [ 22 ];
    expected = [
      (eq tcp.dport 22)
      accept
    ];
  };

  # ===== TCP / UDP — range input forms =====

  testTcpAcceptRangeString = {
    expr = snippets.accept.tcp "8000-8100";
    expected = [
      (within tcp.dport (range 8000 8100))
      accept
    ];
  };

  testTcpAcceptRangeColon = {
    expr = snippets.accept.tcp "8000:8100";
    expected = [
      (within tcp.dport (range 8000 8100))
      accept
    ];
  };

  # ===== TCP / UDP — multi-element lists, sort/dedup, mixed types =====

  testTcpAcceptList = {
    expr = snippets.accept.tcp [
      22
      80
    ];
    expected = [
      (inSet tcp.dport [
        22
        80
      ])
      accept
    ];
  };

  testTcpAcceptListMixed = {
    expr = snippets.accept.tcp [
      22
      80
      "8000-8100"
    ];
    expected = [
      (inSet tcp.dport [
        22
        80
        (range 8000 8100)
      ])
      accept
    ];
  };

  testTcpAcceptDedup = {
    expr = snippets.accept.tcp [
      80
      22
      80
    ];
    expected = [
      (inSet tcp.dport [
        22
        80
      ])
      accept
    ];
  };

  testTcpAcceptSingletonRangeCollapses = {
    # `"22-22"` parses as a portRange whose `from == to`; the
    # canonical form drops the range wrapper so emitted text is
    # `tcp dport 22`, not `tcp dport 22-22`.
    expr = snippets.accept.tcp [ "22-22" ];
    expected = [
      (eq tcp.dport 22)
      accept
    ];
  };

  testTcpAcceptStringIntDedup = {
    # `22` and `"22"` normalize to the same int; dedup collapses
    # the list to a single-element form (and emits `eq`, not
    # `inSet`).
    expr = snippets.accept.tcp [
      22
      "22"
    ];
    expected = [
      (eq tcp.dport 22)
      accept
    ];
  };

  testTcpAcceptOverlapNoMerge = {
    # Overlapping but non-identical ranges are preserved.
    # Merging is deferred — see plan §Normalization rules §2.
    expr = snippets.accept.tcp [
      "8000-8100"
      "8050-8200"
    ];
    expected = [
      (inSet tcp.dport [
        (range 8000 8100)
        (range 8050 8200)
      ])
      accept
    ];
  };

  # ===== drop / reject verdicts =====

  testTcpDropSinglePort = {
    expr = snippets.drop.tcp 22;
    expected = [
      (eq tcp.dport 22)
      drop
    ];
  };

  testTcpRejectUsesTcpReset = {
    expr = snippets.reject.tcp 22;
    expected = [
      (eq tcp.dport 22)
      reject.tcpReset
    ];
  };

  testUdpRejectUsesPlain = {
    expr = snippets.reject.udp 53;
    expected = [
      (eq udp.dport 53)
      reject.plain
    ];
  };

  # ===== ICMP v4 — input forms =====

  testIcmpV4AcceptInt = {
    expr = snippets.accept.icmp.v4 8;
    expected = [
      (eq icmp.type 8)
      accept
    ];
  };

  testIcmpV4AcceptString = {
    expr = snippets.accept.icmp.v4 "echo-request";
    expected = [
      (eq icmp.type "echo-request")
      accept
    ];
  };

  testIcmpV4AcceptList = {
    expr = snippets.accept.icmp.v4 [
      0
      8
    ];
    expected = [
      (inSet icmp.type [
        0
        8
      ])
      accept
    ];
  };

  testIcmpV4AcceptViaRegistry = {
    # Registry path goes through the same int branch as a bare 8.
    expr = snippets.accept.icmp.v4 libnet.registry.icmpTypes.ipv4.echoRequest;
    expected = [
      (eq icmp.type 8)
      accept
    ];
  };

  # ===== ICMP v6 uses the icmpv6 field, not icmp =====

  testIcmpV6UsesIcmpv6Field = {
    expr = snippets.accept.icmp.v6 128;
    expected = [
      (eq icmpv6.type 128)
      accept
    ];
  };

  # ===== Throw paths =====

  testEmptyListThrows = {
    expr = evalDeep (snippets.accept.tcp [ ]);
    expected = throwExpected;
  };

  testInvalidPortThrows = {
    # libnet rejects 70000 — our wrapper does not re-wrap, so the
    # libnet.port message bubbles up. We assert only that it threw.
    expr = evalDeep (snippets.accept.tcp 70000);
    expected = throwExpected;
  };

  testInvalidIcmpTypeThrows = {
    expr = evalDeep (snippets.accept.icmp.v4 256);
    expected = throwExpected;
  };

  testIcmpMixedFormsThrow = {
    # Mixed int+string ICMP types throw — see normalizeIcmpTypes
    # for the rationale (no safe cross-form dedup).
    expr = evalDeep (
      snippets.accept.icmp.v4 [
        8
        "echo-reply"
      ]
    );
    expected = throwExpected;
  };
}
