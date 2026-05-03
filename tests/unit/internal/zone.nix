/*
  Unit tests for `lib/internal/zone.nix` (exposed as
  `nftzones.internal.zone.genSets`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftypes.dsl) expr;
  inherit (nftzones.internal.zone) genSets;

  cidrV4 = "10.0.0.0/24";
  cidrV6 = "2001:db8::/32";
  ifs = [
    "eth1"
    "eth2"
  ];
in
{
  # ===== genSets — empty zone produces no sets =====

  testGenSetsEmpty = {
    expr = genSets "lan" {
      interfaces = [ ];
      cidrs = [ ];
    };
    expected = { };
  };

  # ===== genSets — interface-only zone gets `_iifs` only =====

  testGenSetsIfsOnly = {
    expr = genSets "lan" {
      interfaces = [ "lan0" ];
      cidrs = [ ];
    };
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = [ "lan0" ];
      };
    };
  };

  # ===== genSets — v4-only CIDR zone gets `_v4` only =====

  testGenSetsV4Only = {
    expr = genSets "lan" {
      interfaces = [ ];
      cidrs = [ cidrV4 ];
    };
    expected = {
      lan_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "10.0.0.0" 24) ];
      };
    };
  };

  # ===== genSets — full dual-stack zone gets all three suffixes =====

  testGenSetsAll = {
    expr = pkgs.lib.attrNames (genSets "lan" {
      interfaces = ifs;
      cidrs = [
        cidrV4
        cidrV6
      ];
    });
    expected = [
      "lan_iifs"
      "lan_v4"
      "lan_v6"
    ];
  };

  # ===== genSets — set names always carry the zone-name prefix =====

  testGenSetsNamePrefix = {
    expr = pkgs.lib.attrNames (genSets "guest" {
      interfaces = [ "guest0" ];
      cidrs = [ cidrV4 ];
    });
    expected = [
      "guest_iifs"
      "guest_v4"
    ];
  };
}
