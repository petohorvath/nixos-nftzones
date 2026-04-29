# Unit tests for `lib/internal/zone-pair.nix` (exposed as
# `nftzones.internal.zonePair.genExpansions`). Same
# `testFoo = { expr; expected; }` shape as every other unit test;
# aggregated by `tests/unit/default.nix`.
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;

  inherit (nftzones.internal.zonePair) genExpansions;

  ruleBody = [
    (eq tcp.dport 22)
    accept
  ];

  baseInput = {
    name = "ssh";
    from = [ "wan" ];
    to = [ "host" ];
    rule = ruleBody;
    priority = 0;
    comment = "ssh from anywhere";
  };

  expansionOf = f: t: {
    name = "ssh";
    from = f;
    to = t;
    rule = ruleBody;
    priority = 0;
    comment = "ssh from anywhere";
  };
in
{
  # ===== genExpansions — single (from, to) pair =====

  testExpansionSinglePair = {
    expr = genExpansions baseInput;
    expected = [ (expansionOf "wan" "host") ];
  };

  # ===== genExpansions — fan-out on `to` only =====

  testExpansionFanOutTo = {
    expr = genExpansions (
      baseInput
      // {
        to = [
          "wan"
          "vpn"
        ];
      }
    );
    expected = [
      (expansionOf "wan" "wan")
      (expansionOf "wan" "vpn")
    ];
  };

  # ===== genExpansions — fan-out on `from` only =====

  testExpansionFanOutFrom = {
    expr = genExpansions (
      baseInput
      // {
        from = [
          "lan"
          "guest"
        ];
      }
    );
    expected = [
      (expansionOf "lan" "host")
      (expansionOf "guest" "host")
    ];
  };

  # ===== genExpansions — full cartesian product, from-major order =====

  testExpansionFullProduct = {
    expr = genExpansions (
      baseInput
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
      (expansionOf "lan" "wan")
      (expansionOf "lan" "vpn")
      (expansionOf "guest" "wan")
      (expansionOf "guest" "vpn")
    ];
  };

  # ===== genExpansions — arbitrary pass-through fields preserved =====

  testExpansionPassThrough = {
    expr = genExpansions {
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
}
