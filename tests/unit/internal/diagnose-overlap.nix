# Unit tests for the overlap Diagnostics of Phase 1: interface and
# CIDR overlap errors, and cross-axis overlap warnings. Each test
# compares the whole `{ tag; path; }` lists from `diagnose`.
{ pkgs, nftzones, ... }:
let
  inherit (import ../helpers.nix { inherit pkgs nftzones; }) diagnosticsFor;

  clean = {
    errors = [ ];
    warnings = [ ];
  };

  interfaceOverlapAt = zone: {
    tag = "interfaceOverlap";
    path = [
      "zones"
      zone
      "interfaces"
    ];
  };

  cidrOverlapAt = zone: {
    tag = "cidrOverlap";
    path = [
      "zones"
      zone
      "cidrs"
    ];
  };

  crossAxisOverlapAt = zone: {
    tag = "crossAxisOverlap";
    path = [
      "zones"
      zone
    ];
  };
in
{
  testOverlapEmptyTableReportsNothing = {
    expr = diagnosticsFor { };
    expected = clean;
  };

  # ===== Interface overlap =====

  testInterfaceOverlapDisjointInterfaces = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "eth1" ];
      zones.wan.interfaces = [ "eth0" ];
    };
    expected = clean;
  };

  # One diagnostic per pair, on the lexically first zone.
  testInterfaceOverlapUnrelatedZones = {
    expr = diagnosticsFor {
      zones.guest.interfaces = [ "eth1" ];
      zones.lan.interfaces = [ "eth1" ];
    };
    expected = clean // {
      errors = [ (interfaceOverlapAt "guest") ];
    };
  };

  # Hierarchy is intentional overlap.
  testInterfaceOverlapParentAndChildAllowed = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "eth1" ];
      zones.lan-guests = {
        parent = "lan";
        interfaces = [ "eth1" ];
      };
    };
    expected = clean;
  };

  testInterfaceOverlapSameZoneListsTwice = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [
        "eth1"
        "eth1"
      ];
    };
    expected = clean // {
      errors = [ (interfaceOverlapAt "lan") ];
    };
  };

  # Pair-wise: (a,b) and (a,c) land on `a`, (b,c) on `b`.
  testInterfaceOverlapThreeZonesFlagEachPair = {
    expr = diagnosticsFor {
      zones = {
        a.interfaces = [ "eth1" ];
        b.interfaces = [ "eth1" ];
        c.interfaces = [ "eth1" ];
      };
    };
    expected = clean // {
      errors = [
        (interfaceOverlapAt "a")
        (interfaceOverlapAt "a")
        (interfaceOverlapAt "b")
      ];
    };
  };

  # ===== CIDR overlap =====

  testCidrOverlapDisjointCidrs = {
    expr = diagnosticsFor {
      zones.lan.cidrs = [ "10.0.0.0/24" ];
      zones.guest.cidrs = [ "192.168.1.0/24" ];
    };
    expected = clean;
  };

  testCidrOverlapUnrelatedZones = {
    expr = diagnosticsFor {
      zones.lan.cidrs = [ "10.0.0.0/24" ];
      zones.mgmt.cidrs = [ "10.0.0.0/28" ];
    };
    expected = clean // {
      errors = [ (cidrOverlapAt "lan") ];
    };
  };

  # Hierarchical containment is intentional.
  testCidrOverlapParentContainsChildAllowed = {
    expr = diagnosticsFor {
      zones.dmz.cidrs = [ "10.0.0.0/24" ];
      zones.web = {
        parent = "dmz";
        cidrs = [ "10.0.0.0/28" ];
      };
    };
    expected = clean;
  };

  # Each sibling sits inside the parent (skipped), but the siblings
  # have no ancestor relation to each other.
  testCidrOverlapSiblingsFlagged = {
    expr = diagnosticsFor {
      zones = {
        dmz.cidrs = [ "10.0.0.0/24" ];
        a = {
          parent = "dmz";
          cidrs = [ "10.0.0.0/28" ];
        };
        b = {
          parent = "dmz";
          cidrs = [ "10.0.0.0/29" ];
        };
      };
    };
    expected = clean // {
      errors = [ (cidrOverlapAt "a") ];
    };
  };

  testCidrOverlapIpv4AndIpv6NeverOverlap = {
    expr = diagnosticsFor {
      zones.a.cidrs = [ "10.0.0.0/24" ];
      zones.b.cidrs = [ "fe80::/64" ];
    };
    expected = clean;
  };

  testCidrOverlapSameZoneOverlap = {
    expr = diagnosticsFor {
      zones.lan.cidrs = [
        "10.0.0.0/24"
        "10.0.0.0/28"
      ];
    };
    expected = clean // {
      errors = [ (cidrOverlapAt "lan") ];
    };
  };

  # A lowered node is a child of its zone, so its address may sit
  # inside the zone's CIDR.
  testCidrOverlapNodeInsideItsZoneAllowed = {
    expr = diagnosticsFor {
      zones.dmz.cidrs = [ "10.0.0.0/24" ];
      nodes.web-server = {
        zone = "dmz";
        address.ipv4 = "10.0.0.5";
      };
    };
    expected = clean;
  };

  # ===== Cross-axis overlap =====

  testCrossAxisOverlapInterfaceZonesOnly = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        wan.interfaces = [ "wan0" ];
        dmz.interfaces = [ "dmz0" ];
      };
    };
    expected = clean;
  };

  # A packet from 10.0.0.5 on lan0 matches both zones, and dispatch
  # order is alphabetical: silent shadowing.
  testCrossAxisOverlapInterfaceAndCidrZones = {
    expr = diagnosticsFor {
      zones.lan-iface.interfaces = [ "lan0" ];
      zones.lan-cidr.cidrs = [ "10.0.0.0/24" ];
    };
    expected = clean // {
      warnings = [ (crossAxisOverlapAt "lan-cidr") ];
    };
  };

  # The canonical refinement: child traffic dispatches through the
  # parent's chain first.
  testCrossAxisOverlapParentAndChildSkipped = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      zones.web = {
        parent = "lan";
        cidrs = [ "10.0.0.5/32" ];
      };
    };
    expected = clean;
  };

  # A child is reached only after its parent's interface gate matched,
  # so `web` is effectively interface-and-CIDR bound, not a CIDR-only
  # peer of the unrelated `vpn`.
  testCrossAxisOverlapParentedChildVsUnrelatedSkipped = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        vpn.interfaces = [ "vpn0" ];
        web = {
          parent = "lan";
          cidrs = [ "10.0.0.5/32" ];
        };
      };
    };
    expected = clean;
  };

  # The same through the public `nodes` shape: `web` lowers to a
  # CIDR-only child of `lan`.
  testCrossAxisOverlapNodeVsUnrelatedSkipped = {
    expr = diagnosticsFor {
      zones.lan.interfaces = [ "lan0" ];
      zones.vpn.interfaces = [ "vpn0" ];
      nodes.web = {
        zone = "lan";
        address.ipv4 = "10.0.0.5";
      };
    };
    expected = clean;
  };

  # `web` inherits the interface axis through the empty `apps`
  # grouping zone: classification walks every strict ancestor.
  testCrossAxisOverlapGrandchildInheritsAxes = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        vpn.interfaces = [ "vpn0" ];
        apps.parent = "lan";
        web = {
          parent = "apps";
          cidrs = [ "10.0.0.5/32" ];
        };
      };
    };
    expected = clean;
  };

  # `apps` has no own axis. Classifying it through its parent would
  # duplicate `lan`'s genuine warning against `raw-cidr`.
  testCrossAxisOverlapEmptyGroupingZoneUnclassified = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        apps.parent = "lan";
        raw-cidr.cidrs = [ "192.168.0.0/24" ];
        web = {
          parent = "apps";
          cidrs = [ "10.0.0.5/32" ];
        };
      };
    };
    expected = clean // {
      warnings = [ (crossAxisOverlapAt "lan") ];
    };
  };

  /*
    A deliberate narrowing: `printers` (interface-only) and `web`
    (CIDR-only) share an interface-bound parent, so `web` is multi-axis
    through the inherited interface axis and the pair goes unflagged,
    even though key-order shadowing can still occur among the child
    jumps inside `lan`'s sub-chain.
  */
  testCrossAxisOverlapSiblingsSplitAcrossAxesSkipped = {
    expr = diagnosticsFor {
      zones = {
        lan.interfaces = [ "lan0" ];
        printers = {
          parent = "lan";
          interfaces = [ "prt0" ];
        };
        web = {
          parent = "lan";
          cidrs = [ "10.0.0.5/32" ];
        };
      };
    };
    expected = clean;
  };

  # Mirror of the parented-child case: `mgmt` inherits the CIDR axis,
  # so it is no interface-only peer of the unrelated `raw-cidr`.
  testCrossAxisOverlapInterfaceChildOfCidrParentSkipped = {
    expr = diagnosticsFor {
      zones = {
        dbnet.cidrs = [ "10.9.0.0/24" ];
        mgmt = {
          parent = "dbnet";
          interfaces = [ "mgmt0" ];
        };
        raw-cidr.cidrs = [ "192.168.0.0/24" ];
      };
    };
    expected = clean;
  };

  # Each interface zone pairs with each CIDR zone. Same-axis pairs
  # belong to the interface and CIDR overlap checks.
  testCrossAxisOverlapFlagsEveryPair = {
    expr = diagnosticsFor {
      zones = {
        a-iface.interfaces = [ "a0" ];
        b-iface.interfaces = [ "b0" ];
        c-cidr.cidrs = [ "10.0.0.0/24" ];
        d-cidr.cidrs = [ "10.1.0.0/24" ];
      };
    };
    expected = clean // {
      warnings = [
        (crossAxisOverlapAt "a-iface")
        (crossAxisOverlapAt "a-iface")
        (crossAxisOverlapAt "b-iface")
        (crossAxisOverlapAt "b-iface")
      ];
    };
  };

  # A zone with both axes ("eth0 plus 10.0.0.0/24") is the common
  # real-world shape, skipped to keep false positives down.
  testCrossAxisOverlapMultiAxisZoneSkipped = {
    expr = diagnosticsFor {
      zones.multi = {
        interfaces = [ "multi0" ];
        cidrs = [ "10.0.0.0/24" ];
      };
      zones.iface-only.interfaces = [ "iface0" ];
    };
    expected = clean;
  };
}
