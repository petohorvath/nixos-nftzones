/*
  Unit tests for `lib/internal/zone.nix` (exposed as
  `nftzones.internal.zone.genMatch` / `genSets`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
}:
let
  inherit (nftypes.dsl) inSet expr;
  inherit (nftypes.dsl.fields) meta ip ip6;

  inherit (nftzones.internal.zone) genMatch genSets;

  cidrV4 = "10.0.0.0/24";
  cidrV6 = "2001:db8::/32";
  ifs = [
    "eth1"
    "eth2"
  ];

  ifIngress = inSet meta.iifname ifs;
  ifEgress = inSet meta.oifname ifs;
  saddrMatchV4 = inSet ip.saddr [ (expr.prefix "10.0.0.0" 24) ];
  daddrMatchV4 = inSet ip.daddr [ (expr.prefix "10.0.0.0" 24) ];
  saddrMatchV6 = inSet ip6.saddr [ (expr.prefix "2001:db8::" 32) ];
  daddrMatchV6 = inSet ip6.daddr [ (expr.prefix "2001:db8::" 32) ];
in
{
  # ===== genMatch — interface-only zone (1 family-agnostic variant) =====

  testZoneIfacesOnlyIngress = {
    expr = (genMatch { interfaces = ifs; }).ingress;
    expected = [ [ ifIngress ] ];
  };

  testZoneIfacesOnlyEgress = {
    expr = (genMatch { interfaces = ifs; }).egress;
    expected = [ [ ifEgress ] ];
  };

  # ===== genMatch — single-family CIDR zone (1 variant) =====

  testZoneV4OnlyIngress = {
    expr = (genMatch { cidrs = [ cidrV4 ]; }).ingress;
    expected = [ [ saddrMatchV4 ] ];
  };

  testZoneV4OnlyEgress = {
    expr = (genMatch { cidrs = [ cidrV4 ]; }).egress;
    expected = [ [ daddrMatchV4 ] ];
  };

  testZoneV6OnlyIngress = {
    expr = (genMatch { cidrs = [ cidrV6 ]; }).ingress;
    expected = [ [ saddrMatchV6 ] ];
  };

  # ===== genMatch — iface + single-family CIDR (1 variant w/ prefix) =====

  testZoneIfaceV4Ingress = {
    expr =
      (genMatch {
        interfaces = ifs;
        cidrs = [ cidrV4 ];
      }).ingress;
    expected = [
      [
        ifIngress
        saddrMatchV4
      ]
    ];
  };

  # ===== genMatch — v4 + v6 without iface (2 variants, no prefix) =====

  testZoneV4V6Ingress = {
    expr =
      (genMatch {
        cidrs = [
          cidrV4
          cidrV6
        ];
      }).ingress;
    expected = [
      [ saddrMatchV4 ]
      [ saddrMatchV6 ]
    ];
  };

  # ===== genMatch — iface + v4 + v6 (2 variants, each with prefix) =====

  testZoneMixedIngress = {
    expr =
      (genMatch {
        interfaces = ifs;
        cidrs = [
          cidrV4
          cidrV6
        ];
      }).ingress;
    expected = [
      [
        ifIngress
        saddrMatchV4
      ]
      [
        ifIngress
        saddrMatchV6
      ]
    ];
  };

  testZoneMixedEgress = {
    expr =
      (genMatch {
        interfaces = ifs;
        cidrs = [
          cidrV4
          cidrV6
        ];
      }).egress;
    expected = [
      [
        ifEgress
        daddrMatchV4
      ]
      [
        ifEgress
        daddrMatchV6
      ]
    ];
  };

  # ===== genMatch — empty inputs yield zero variants =====

  testZoneEmpty = {
    expr = genMatch { };
    expected = {
      ingress = [ ];
      egress = [ ];
    };
  };

  # ===== genMatch — overrides replace the computed side wholesale =====

  testZoneIngressOverride = {
    expr =
      (genMatch {
        interfaces = ifs;
        cidrs = [ cidrV4 ];
        override = {
          ingress = [
            [ (inSet meta.iifname [ "wg0" ]) ]
          ];
        };
      }).ingress;
    expected = [
      [ (inSet meta.iifname [ "wg0" ]) ]
    ];
  };

  testZoneIngressOverrideLeavesEgressIntact = {
    expr =
      (genMatch {
        interfaces = ifs;
        cidrs = [ cidrV4 ];
        override = {
          ingress = [ ];
        };
      }).egress;
    expected = [
      [
        ifEgress
        daddrMatchV4
      ]
    ];
  };

  testZoneEgressOverride = {
    expr =
      (genMatch {
        interfaces = ifs;
        cidrs = [ cidrV4 ];
        override = {
          egress = [
            [ (inSet ip.daddr [ (expr.prefix "0.0.0.0" 0) ]) ]
            [ (inSet ip6.daddr [ (expr.prefix "::" 0) ]) ]
          ];
        };
      }).egress;
    expected = [
      [ (inSet ip.daddr [ (expr.prefix "0.0.0.0" 0) ]) ]
      [ (inSet ip6.daddr [ (expr.prefix "::" 0) ]) ]
    ];
  };

  # ===== genSets — empty zone produces no sets =====

  testDerivedSetsEmpty = {
    expr = genSets "lan" {
      interfaces = [ ];
      cidrs = [ ];
    };
    expected = { };
  };

  # ===== genSets — interface-only zone gets `_iifs` only =====

  testDerivedSetsIfsOnly = {
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

  testDerivedSetsV4Only = {
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

  testDerivedSetsAll = {
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

  testDerivedSetsNamePrefix = {
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
