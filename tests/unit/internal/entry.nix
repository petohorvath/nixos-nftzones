/*
  Unit tests for `lib/internal/entry.nix` (exposed as
  `nftzones.internal.entry.toCells`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;

  inherit (nftzones.internal.entry) toCells;

  ruleBody = [
    (eq tcp.dport 22)
    accept
  ];

  baseEntry = {
    name = "ssh";
    from = [ "wan" ];
    to = [ "host" ];
    rule = ruleBody;
    priority = 0;
    comment = "ssh from anywhere";
  };

  bidirCellOf = f: t: {
    name = "ssh";
    from = f;
    to = t;
    rule = ruleBody;
    priority = 0;
    comment = "ssh from anywhere";
  };
in
{
  # ===== toCells — bidirectional, single (from, to) pair =====

  testToCellsSinglePair = {
    expr = toCells baseEntry;
    expected = [ (bidirCellOf "wan" "host") ];
  };

  # ===== toCells — bidirectional, fan-out on `to` only =====

  testToCellsFanOutTo = {
    expr = toCells (
      baseEntry
      // {
        to = [
          "wan"
          "vpn"
        ];
      }
    );
    expected = [
      (bidirCellOf "wan" "wan")
      (bidirCellOf "wan" "vpn")
    ];
  };

  # ===== toCells — bidirectional, fan-out on `from` only =====

  testToCellsFanOutFrom = {
    expr = toCells (
      baseEntry
      // {
        from = [
          "lan"
          "guest"
        ];
      }
    );
    expected = [
      (bidirCellOf "lan" "host")
      (bidirCellOf "guest" "host")
    ];
  };

  # ===== toCells — bidirectional, full cartesian product (from-major) =====

  testToCellsFullProduct = {
    expr = toCells (
      baseEntry
      // {
        from = [
          "lan"
          "guest"
        ];
        to = [
          "wan"
          "vpn"
        ];
      }
    );
    expected = [
      (bidirCellOf "lan" "wan")
      (bidirCellOf "lan" "vpn")
      (bidirCellOf "guest" "wan")
      (bidirCellOf "guest" "vpn")
    ];
  };

  # ===== toCells — single-direction (from only) =====
  # Models dnat / sroute entries, which carry no `to` field.

  testToCellsFromOnly = {
    expr = toCells {
      name = "web-fwd";
      from = [
        "wan"
        "vpn"
      ];
      rule = "dummy";
    };
    expected = [
      {
        name = "web-fwd";
        from = "wan";
        rule = "dummy";
      }
      {
        name = "web-fwd";
        from = "vpn";
        rule = "dummy";
      }
    ];
  };

  # ===== toCells — single-direction (to only) =====
  # Models droute entries, which carry no `from` field.

  testToCellsToOnly = {
    expr = toCells {
      name = "mark-vpn";
      to = [
        "vpn"
        "lan"
      ];
      rule = "dummy";
    };
    expected = [
      {
        name = "mark-vpn";
        to = "vpn";
        rule = "dummy";
      }
      {
        name = "mark-vpn";
        to = "lan";
        rule = "dummy";
      }
    ];
  };

  # ===== toCells — pass-through fields preserved =====

  testToCellsPassThrough = {
    expr = toCells {
      from = [ "a" ];
      to = [ "b" ];
      anyCustomField = "hello";
    };
    expected = [
      {
        from = "a";
        to = "b";
        anyCustomField = "hello";
      }
    ];
  };

  # ===== toCells — empty direction list collapses the product to zero cells =====
  # `from = [ ]` is "direction present but empty" — distinct from
  # "direction absent" — and `mapCartesianProduct` correctly emits
  # no cells for the empty side.

  testToCellsEmptyFrom = {
    expr = toCells (baseEntry // { from = [ ]; });
    expected = [ ];
  };

  testToCellsEmptyTo = {
    expr = toCells (baseEntry // { to = [ ]; });
    expected = [ ];
  };

  # ===== toCells — entry with no direction fields yields one pass-through cell =====
  # When neither `from` nor `to` is present, the cartesian product
  # over an empty attrset is `[ { } ]`, so the entry passes through
  # as a single cell with no direction fields added.

  testToCellsNoDirectionFields = {
    expr = toCells {
      name = "global";
      rule = "dummy";
      priority = 0;
    };
    expected = [
      {
        name = "global";
        rule = "dummy";
        priority = 0;
      }
    ];
  };
}
