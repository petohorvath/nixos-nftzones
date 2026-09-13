/*
  Zone membership tests use real zone/node declarations through the
  same resolved interface consumed by validation and emission. Expected
  sets and dispatch clauses describe observable membership semantics;
  no synthetic set bodies or separately selected overrides are inputs.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftypes.dsl) expr;
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) membershipFor;

  setsForZone = name: zone: (membershipFor { zones.${name} = zone; }).sets;
  setsFor =
    name: body:
    pkgs.lib.filterAttrs (
      setName: _:
      builtins.elem setName [
        "${name}_iifs"
        "${name}_v4"
        "${name}_v6"
      ]
    ) (membershipFor body).sets;
  activeFor =
    sections: side:
    (membershipFor { zones.lan.matchOverride.ingress = sections; }).activeOverrides "lan" side;

  cidrV4 = "10.0.0.0/24";
  cidrV6 = "2001:db8::/32";
  ifs = [
    "eth1"
    "eth2"
  ];
in
{
  # ===== membership sets — empty zone produces no sets =====

  testMembershipSetsEmpty = {
    expr = setsForZone "lan" {
      interfaces = [ ];
      cidrs = [ ];
    };
    expected = { };
  };

  # ===== membership sets — interface-only zone gets `_iifs` only =====

  testMembershipSetsIfsOnly = {
    expr = setsForZone "lan" {
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

  # ===== membership sets — v4-only CIDR zone gets `_v4` only =====

  testMembershipSetsV4Only = {
    expr = setsForZone "lan" {
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

  # ===== membership sets — v6-only CIDR zone gets `_v6` only =====

  testMembershipSetsV6Only = {
    expr = setsForZone "lan" {
      interfaces = [ ];
      cidrs = [ cidrV6 ];
    };
    expected = {
      lan_v6 = {
        type = "ipv6_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "2001:db8::" 32) ];
      };
    };
  };

  # ===== membership sets — multiple CIDRs of the same family preserve order =====

  testMembershipSetsMultipleSameFamily = {
    expr =
      (setsForZone "lan" {
        interfaces = [ ];
        cidrs = [
          "10.0.0.0/24"
          "192.168.0.0/16"
        ];
      }).lan_v4.elements;
    expected = [
      (expr.prefix "10.0.0.0" 24)
      (expr.prefix "192.168.0.0" 16)
    ];
  };

  # ===== membership sets — full dual-stack zone gets all three suffixes (full bodies) =====

  testMembershipSetsAll = {
    expr = setsForZone "lan" {
      interfaces = ifs;
      cidrs = [
        cidrV4
        cidrV6
      ];
    };
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = ifs;
      };
      lan_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "10.0.0.0" 24) ];
      };
      lan_v6 = {
        type = "ipv6_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "2001:db8::" 32) ];
      };
    };
  };

  # ===== membership sets — set names always carry the zone-name prefix =====

  testMembershipSetsNamePrefix = {
    expr = pkgs.lib.attrNames (
      setsForZone "guest" {
        interfaces = [ "guest0" ];
        cidrs = [ cidrV4 ];
      }
    );
    expected = [
      "guest_iifs"
      "guest_v4"
    ];
  };

  # ===== membership sets — parent zone's _iifs includes child interfaces transitively =====

  testMembershipSetsParentIncludesChildIfaces = {
    # Models the canonical hierarchy: `lan` (lan0) + `lan-guest`
    # (parent = lan, guest0). The parent's `_iifs` should
    # transitively include guest0 so base-chain dispatch into
    # `lan`'s sub-chain catches guest traffic; the child-dispatch
    # jump inside lan's sub-chain then routes specifically to
    # lan-guest's sub-chain.
    expr = setsFor "lan" {
      zones = {
        lan = {
          interfaces = [ "lan0" ];
          cidrs = [ ];
        };
        lan-guest = {
          parent = "lan";
          interfaces = [ "guest0" ];
          cidrs = [ ];
        };
      };
    };
    expected = {
      lan_iifs = {
        type = "ifname";
        elements = [
          "lan0"
          "guest0"
        ];
      };
    };
  };

  # ===== membership sets — descendant's own set covers only itself =====

  testMembershipSetsChildOwnsItself = {
    # `lan-guest` (no further descendants) emits a set with just
    # its own interfaces. Confirms the transitive walk is rooted
    # at the named zone, not at all roots.
    expr = setsFor "lan-guest" {
      zones = {
        lan = {
          interfaces = [ "lan0" ];
          cidrs = [ ];
        };
        lan-guest = {
          parent = "lan";
          interfaces = [ "guest0" ];
          cidrs = [ ];
        };
      };
    };
    expected = {
      lan-guest_iifs = {
        type = "ifname";
        elements = [ "guest0" ];
      };
    };
  };

  # ===== membership sets — multi-level hierarchy walks transitively =====

  testMembershipSetsMultiLevelHierarchy = {
    # Three-level chain: lan ← lan-trusted ← lan-trusted-admin.
    # `lan`'s set should include all three interfaces;
    # `lan-trusted`'s set should include its own + admin's.
    expr =
      let
        zones = {
          lan = {
            interfaces = [ "lan0" ];
            cidrs = [ ];
          };
          lan-trusted = {
            parent = "lan";
            interfaces = [ "trust0" ];
            cidrs = [ ];
          };
          lan-trusted-admin = {
            parent = "lan-trusted";
            interfaces = [ "admin0" ];
            cidrs = [ ];
          };
        };
        membership = membershipFor { inherit zones; };
      in
      {
        lan = membership.sets.lan_iifs.elements;
        trusted = membership.sets.lan-trusted_iifs.elements;
        admin = membership.sets.lan-trusted-admin_iifs.elements;
      };
    expected = {
      lan = [
        "lan0"
        "trust0"
        "admin0"
      ];
      trusted = [
        "trust0"
        "admin0"
      ];
      admin = [ "admin0" ];
    };
  };

  # ===== membership sets — parent with no own interfaces still emits set from descendants =====

  testMembershipSetsParentWithNoOwnIfaces = {
    # Common pattern: a "group" zone with no interfaces of its
    # own, used as a synthetic dispatcher for its children. The
    # group's `_iifs` should still be emitted (so the group's
    # sub-chain has a base-chain jump that catches descendant
    # traffic) — sourced entirely from descendants.
    expr = setsFor "internal" {
      zones = {
        internal = {
          interfaces = [ ];
          cidrs = [ ];
        };
        int-trusted = {
          parent = "internal";
          interfaces = [ "trust0" ];
          cidrs = [ ];
        };
        int-guest = {
          parent = "internal";
          interfaces = [ "guest0" ];
          cidrs = [ ];
        };
      };
    };
    expected = {
      internal_iifs = {
        type = "ifname";
        elements = [
          "guest0"
          "trust0"
        ];
      };
    };
  };

  # ===== membership sets — exact-duplicate CIDRs deduped =====

  testMembershipSetsCidrDedup = {
    # Parent and child both write `10.0.0.0/24` (silly but legal —
    # `checkCidrOverlap` skips ancestor/descendant pairs).
    # `libnet.cidr.summarize` collapses the duplicate at compile
    # time so the rendered set carries one element, not two.
    expr =
      (setsFor "parent" {
        zones = {
          parent = {
            interfaces = [ ];
            cidrs = [ "10.0.0.0/24" ];
          };
          child = {
            parent = "parent";
            interfaces = [ ];
            cidrs = [ "10.0.0.0/24" ];
          };
        };
      }).parent_v4.elements;
    expected = [ (expr.prefix "10.0.0.0" 24) ];
  };

  # ===== membership sets — descendant CIDR contained in ancestor's drops out =====

  testMembershipSetsCidrSubsetCoalesced = {
    # Parent has the broader prefix; child has a CIDR strictly
    # inside it. `summarize`'s `containsCidr` check drops the
    # child's redundant element, leaving just the parent's CIDR
    # in the rendered set — `10.0.0.0/8` covers all of
    # `10.0.0.0/24` so the latter adds no addresses.
    expr =
      (setsFor "big" {
        zones = {
          big = {
            interfaces = [ ];
            cidrs = [ "10.0.0.0/8" ];
          };
          small = {
            parent = "big";
            interfaces = [ ];
            cidrs = [ "10.0.0.0/24" ];
          };
        };
      }).big_v4.elements;
    expected = [ (expr.prefix "10.0.0.0" 8) ];
  };

  # ===== membership sets — sibling CIDRs fuse into a single supernet =====

  testMembershipSetsCidrSiblingsFuse = {
    # Two adjacent canonical `/24`s (`10.0.0.0/24` + `10.0.1.0/24`)
    # are siblings of `10.0.0.0/23` and summarize collapses them
    # into that supernet. Edge case worth pinning: the rendered
    # ruleset diverges from user input — this is intentional and
    # semantically equivalent.
    expr =
      (setsFor "parent" {
        zones = {
          parent = {
            interfaces = [ ];
            cidrs = [
              "10.0.0.0/24"
              "10.0.1.0/24"
            ];
          };
        };
      }).parent_v4.elements;
    expected = [ (expr.prefix "10.0.0.0" 23) ];
  };

  # ===== membership sets — descendant with no contributions adds nothing =====

  testMembershipSetsEmptyDescendantContributesNothing = {
    # A parent with one interface and a descendant zone that has
    # no interfaces / CIDRs of its own. The parent's set should be
    # unchanged from the no-descendants case.
    expr = setsFor "parent" {
      zones = {
        parent = {
          interfaces = [ "p0" ];
          cidrs = [ ];
        };
        child = {
          parent = "parent";
          interfaces = [ ];
          cidrs = [ ];
        };
      };
    };
    expected = {
      parent_iifs = {
        type = "ifname";
        elements = [ "p0" ];
      };
    };
  };

  # ===== membership sets — cycle in zone parents doesn't stack-overflow =====

  testMembershipSetsCycleGuard = {
    # `computeZoneMembership` runs before `checkParentCycles` in the
    # validator pipeline, so a cyclic parent declarations would otherwise
    # exhaust Nix's max-call-depth before the dedicated cycle
    # check reports the error. The `descendantsOf` walker's
    # `visited` guard short-circuits the revisit; the eventual
    # `checkParentCycles` then reports a clean error. This test
    # pins the defense.
    expr =
      let
        ws = setsFor "a" {
          zones = {
            a = {
              parent = "b";
              interfaces = [ "a0" ];
              cidrs = [ ];
            };
            b = {
              parent = "a";
              interfaces = [ "b0" ];
              cidrs = [ ];
            };
          };
        };
      in
      ws.a_iifs.elements;
    # Order is parent-first, then descendants discovered during
    # the walk. The cycle is short-circuited before revisit.
    expected = [
      "a0"
      "b0"
    ];
  };

  # ===== membership sets — descendant CIDRs union with parent CIDRs via summarize =====

  testMembershipSetsParentIncludesChildCidrs = {
    # Parent with CIDR `10.0.0.0/24` and a lowered-node child
    # contributing `10.0.0.5/32` (a typical node-in-zone case).
    # The child's `/32` is contained in the parent's `/24`, so
    # `summarize` drops it from the parent's `_v4` set — the
    # rendered set is the minimal cover.
    expr = setsFor "dmz" {
      zones = {
        dmz = {
          interfaces = [ ];
          cidrs = [ "10.0.0.0/24" ];
        };
        web = {
          parent = "dmz";
          interfaces = [ ];
          cidrs = [ "10.0.0.5/32" ];
        };
      };
    };
    expected = {
      dmz_v4 = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = [ (expr.prefix "10.0.0.0" 24) ];
      };
    };
  };

  # ===== active override sections — empty side produces empty active set =====

  testMembershipActiveOverridesEmpty = {
    expr = activeFor ({ }) "ingress";
    expected = { };
  };

  # ===== active override sections — null sections filtered out =====

  testMembershipActiveOverridesNullsFiltered = {
    # All-null sections (the type's default) → empty active set.
    expr = activeFor ({
      interfaces = null;
      ipv4 = null;
      ipv6 = null;
      extra = null;
    }) "ingress";
    expected = { };
  };

  # ===== active override sections — empty list sections filtered out =====

  testMembershipActiveOverridesEmptyListsFiltered = {
    # `[ ]` is treated the same as `null` — both mean "no
    # constraint contributed".
    expr = activeFor ({
      ipv4 = [ ];
      extra = [ ];
    }) "ingress";
    expected = { };
  };

  # ===== active override sections — mixed: some sections active, others null =====

  testMembershipActiveOverridesMixed = {
    expr = activeFor ({
      interfaces = null;
      ipv4 = [ (nftypes.dsl.eq nftypes.dsl.fields.ip.saddr "10.0.0.5") ];
      ipv6 = [ ];
      extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
    }) "ingress";
    expected = {
      ipv4 = [ (nftypes.dsl.eq nftypes.dsl.fields.ip.saddr "10.0.0.5") ];
      extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
    };
  };

  # ===== active override sections — side parameter selects the right side =====

  testMembershipActiveOverridesSideSelection = {
    # Construct a zone where ingress and egress have different
    # active sections; verify each side is read independently.
    expr =
      let
        zone = {
          matchOverride = {
            ingress = {
              ipv4 = [ (nftypes.dsl.eq nftypes.dsl.fields.ip.saddr "10.0.0.5") ];
            };
            egress = {
              extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 512) ];
            };
          };
        };
      in
      {
        ing = (membershipFor { zones.lan = zone; }).activeOverrides "lan" "ingress";
        egr = (membershipFor { zones.lan = zone; }).activeOverrides "lan" "egress";
      };
    expected = {
      ing = {
        ipv4 = [ (nftypes.dsl.eq nftypes.dsl.fields.ip.saddr "10.0.0.5") ];
      };
      egr = {
        extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 512) ];
      };
    };
  };
  testMembershipVariantsLocalZone = {
    expr = (membershipFor { }).directionVariants {
      hook = "input";
      direction = "to";
      zoneName = "local";
    };
    expected = [ [ ] ];
  };

  testMembershipVariantsNullDirection = {
    expr = (membershipFor { }).directionVariants {
      hook = "prerouting";
      direction = "to";
      zoneName = null;
    };
    expected = [ [ ] ];
  };

  testMembershipVariantsInterfaceOnly = {
    expr =
      (membershipFor {
        zones.lan = {
          interfaces = [ "lan0" ];
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs")) ]
    ];
  };

  testMembershipVariantsUnreachable = {
    expr =
      (membershipFor {
        zones.wan = {
          interfaces = [ "wan0" ];
        };
      }).directionVariants
        {
          hook = "output";
          direction = "from";
          zoneName = "wan";
        };
    expected = [ ];
  };

  testMembershipVariantsV4Only = {
    expr =
      (membershipFor {
        zones.lan = {
          cidrs = [ "10.0.0.0/24" ];
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
    ];
  };

  testMembershipVariantsV4AndV6 = {
    expr =
      (membershipFor {
        zones.lan = {
          cidrs = [
            "10.0.0.0/24"
            "fd00::/64"
          ];
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6")) ]
    ];
  };

  testMembershipVariantsIfPlusV4V6 = {
    expr =
      (membershipFor {
        zones.lan = {
          interfaces = [ "lan0" ];
          cidrs = [
            "10.0.0.0/24"
            "fd00::/64"
          ];
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4"))
      ]
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6"))
      ]
    ];
  };

  testMembershipVariantsInheritedFamilySuppressed = {
    expr =
      (membershipFor {
        zones.lan = {
          interfaces = [ "lan0" ];
        };
        nodes.web = {
          zone = "lan";
          address.ipv4 = "10.0.0.5";
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs")) ]
    ];
  };

  testMembershipVariantsInheritedIfsStandalone = {
    expr =
      (membershipFor {
        zones.lan = {
          cidrs = [ "10.0.0.0/24" ];
        };
        zones.guest = {
          parent = "lan";
          interfaces = [ "guest0" ];
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs")) ]
    ];
  };

  testMembershipVariantsInheritedFamilyWidens = {
    expr =
      (membershipFor {
        zones.lan = {
          interfaces = [ "lan0" ];
          cidrs = [ "10.0.0.0/24" ];
        };
        zones.v6 = {
          parent = "lan";
          cidrs = [ "fd00::/64" ];
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4"))
      ]
      [
        (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "lan_iifs"))
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6"))
      ]
    ];
  };

  testMembershipVariantsGroupingZone = {
    expr =
      (membershipFor {
        zones.internal = { };
        zones.guest = {
          parent = "internal";
          interfaces = [ "guest0" ];
        };
        nodes.web = {
          zone = "internal";
          address.ipv4 = "10.0.0.5";
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "internal";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "internal_v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "internal_iifs")) ]
    ];
  };

  testMembershipVariantsExtraSection = {
    expr =
      (membershipFor {
        zones.vpn-users = {
          cidrs = [
            "10.8.0.0/24"
            "fd42::/64"
          ];
          matchOverride.ingress = {
            extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
          };
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "vpn-users";
        };
    expected = [
      [
        (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256)
        (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "vpn-users_v4"))
      ]
      [
        (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256)
        (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "vpn-users_v6"))
      ]
    ];
  };

  testMembershipVariantsExtraOnly = {
    expr =
      (membershipFor {
        zones.marked = {
          matchOverride.ingress = {
            extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
          };
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "marked";
        };
    expected = [
      [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ]
    ];
  };

  testMembershipVariantsIpv4Override = {
    expr =
      (membershipFor {
        zones.lan = {
          cidrs = [ "fd00::/64" ];
          matchOverride.ingress = {
            ipv4 = [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "user-v4")) ];
          };
        };
      }).directionVariants
        {
          hook = "forward";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "user-v4")) ]
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip6.saddr (nftypes.dsl.expr.setRef "lan_v6")) ]
    ];
  };

  testMembershipVariantsInterfacesGatedByHook = {
    expr =
      (membershipFor {
        zones.lan = {
          cidrs = [ "10.0.0.0/24" ];
          matchOverride.ingress = {
            interfaces = [
              (nftypes.dsl.inSet nftypes.dsl.fields.meta.iifname (nftypes.dsl.expr.setRef "user-iifs"))
            ];
          };
        };
      }).directionVariants
        {
          hook = "output";
          direction = "from";
          zoneName = "lan";
        };
    expected = [
      [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (nftypes.dsl.expr.setRef "lan_v4")) ]
    ];
  };

  testMembershipEmptyHierarchy = {
    expr =
      let
        membership = membershipFor { };
      in
      {
        inherit (membership) rootZoneNames childrenOf;
        missingDirectionAncestors = membership.ancestorsOf null;
      };
    expected = {
      rootZoneNames = [ "local" ];
      childrenOf = { };
      missingDirectionAncestors = [ ];
    };
  };

  testMembershipHierarchyIncludesLoweredNodes = {
    expr =
      let
        membership = membershipFor {
          settings.localZone = "self";
          zones.dmz.interfaces = [ "dmz0" ];
          zones.group.parent = "dmz";
          nodes.web = {
            zone = "group";
            address.ipv4 = "10.0.0.5";
          };
          zones.wan.interfaces = [ "wan0" ];
        };
      in
      {
        inherit (membership) rootZoneNames childrenOf;
        ancestors = membership.ancestorsOf "web";
        related = membership.related "web" "dmz";
        unrelated = membership.related "wan" "web";
      };
    expected = {
      rootZoneNames = [
        "dmz"
        "wan"
        "self"
      ];
      childrenOf = {
        dmz = [ "group" ];
        group = [ "web" ];
      };
      ancestors = [
        "group"
        "dmz"
      ];
      related = true;
      unrelated = false;
    };
  };

  testMembershipUnresolvedParentStopsWalk = {
    expr = (membershipFor { zones.lan.parent = "missing"; }).ancestorsOf "lan";
    expected = [ ];
  };

  testMembershipCycleStopsWalk = {
    expr =
      (membershipFor {
        zones.a.parent = "b";
        zones.b.parent = "a";
      }).ancestorsOf
        "a";
    expected = [ "b" ];
  };

  testMembershipSetOwnersPreserveUnderscores = {
    expr =
      (membershipFor {
        zones.lan_guest.interfaces = [ "guest0" ];
        nodes.web = {
          zone = "lan_guest";
          address.ipv4 = "10.0.0.5";
        };
      }).setOwners;
    expected = {
      lan_guest_iifs = "lan_guest";
      lan_guest_v4 = "lan_guest";
      web_v4 = "web";
    };
  };

  # Grouping dispatch and reference validation ask different questions.
  testMembershipGroupingHasNoOwnMatch = {
    expr =
      let
        membership = membershipFor {
          zones.group = { };
          nodes.web = {
            zone = "group";
            address.ipv4 = "10.0.0.5";
          };
        };
      in
      {
        hasOwnMatch = membership.hasOwnMatch "group" "ingress";
        reachable = membership.reachableAt "group" {
          hook = "input";
          direction = "from";
        };
        variants = membership.directionVariants {
          zoneName = "group";
          hook = "input";
          direction = "from";
        };
      };
    expected = {
      hasOwnMatch = false;
      reachable = false;
      variants = [ [ (nftypes.dsl.inSet nftypes.dsl.fields.ip.saddr (expr.setRef "group_v4")) ] ];
    };
  };

  testMembershipOverrideIsSideSpecific = {
    expr =
      let
        membership = membershipFor {
          zones.marked.matchOverride.ingress.extra = [ (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256) ];
        };
      in
      {
        ingress = membership.hasOwnMatch "marked" "ingress";
        egress = membership.hasOwnMatch "marked" "egress";
        reachable = membership.reachableAt "marked" {
          hook = "output";
          direction = "from";
        };
      };
    expected = {
      ingress = true;
      egress = false;
      reachable = true;
    };
  };

  testMembershipHookVisibility = {
    expr =
      let
        membership = membershipFor { zones.lan.interfaces = [ "lan0" ]; };
      in
      map
        (hook: {
          from = membership.reachableAt "lan" {
            inherit hook;
            direction = "from";
          };
          to = membership.reachableAt "lan" {
            inherit hook;
            direction = "to";
          };
        })
        [
          "prerouting"
          "input"
          "forward"
          "output"
          "postrouting"
          "ingress"
        ];
    expected = [
      {
        from = true;
        to = false;
      }
      {
        from = true;
        to = false;
      }
      {
        from = true;
        to = true;
      }
      {
        from = false;
        to = true;
      }
      {
        from = true;
        to = true;
      }
      {
        from = false;
        to = false;
      }
    ];
  };
}
