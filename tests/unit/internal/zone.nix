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
  inherit (nftzones.internal.zone) genSets getActiveMatchOverrides;

  mockZoneOverride = sections: { matchOverride = { ingress = sections; egress = { }; }; };

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

  # ===== getActiveMatchOverrides — empty side produces empty active set =====

  testGetActiveMatchOverridesEmpty = {
    expr = getActiveMatchOverrides (mockZoneOverride { }) "ingress";
    expected = { };
  };

  # ===== getActiveMatchOverrides — null sections filtered out =====

  testGetActiveMatchOverridesNullsFiltered = {
    # All-null sections (the type's default) → empty active set.
    expr = getActiveMatchOverrides (mockZoneOverride {
      interfaces = null;
      ipv4 = null;
      ipv6 = null;
      extra = null;
    }) "ingress";
    expected = { };
  };

  # ===== getActiveMatchOverrides — empty list sections filtered out =====

  testGetActiveMatchOverridesEmptyListsFiltered = {
    # `[ ]` is treated the same as `null` — both mean "no
    # constraint contributed".
    expr = getActiveMatchOverrides (mockZoneOverride {
      ipv4 = [ ];
      extra = [ ];
    }) "ingress";
    expected = { };
  };

  # ===== getActiveMatchOverrides — mixed: some sections active, others null =====

  testGetActiveMatchOverridesMixed = {
    expr = getActiveMatchOverrides (mockZoneOverride {
      interfaces = null;
      ipv4 = [ "v4-clause" ];
      ipv6 = [ ];
      extra = [ "extra-clause" ];
    }) "ingress";
    expected = {
      ipv4 = [ "v4-clause" ];
      extra = [ "extra-clause" ];
    };
  };

  # ===== getActiveMatchOverrides — side parameter selects the right side =====

  testGetActiveMatchOverridesSideSelection = {
    # Construct a zone where ingress and egress have different
    # active sections; verify each side is read independently.
    expr =
      let
        zone = {
          matchOverride = {
            ingress = { ipv4 = [ "ing-v4" ]; };
            egress = { extra = [ "egr-extra" ]; };
          };
        };
      in
      {
        ing = getActiveMatchOverrides zone "ingress";
        egr = getActiveMatchOverrides zone "egress";
      };
    expected = {
      ing = { ipv4 = [ "ing-v4" ]; };
      egr = { extra = [ "egr-extra" ]; };
    };
  };
}
