/*
  Unit tests for `lib/types/node.nix` (exposed as
  `nftzones.types.{node,nodeName,nodeAddress}`). Same
  `testFoo = { expr; expected; }` shape as every other unit test;
  aggregated by `tests/unit/default.nix`.
*/
{ helpers, nftzones, ... }:
let
  inherit (helpers) evalFails evalTable evalType;

  nodeIn =
    body:
    (evalTable {
      nodes.web-server = body;
    }).nodes.web-server;
in
{
  # ===== nodeName — same identifier shape as zoneName =====

  testNodeNameAcceptsKebab = {
    expr = evalType nftzones.types.nodeName "web-server";
    expected = "web-server";
  };

  testNodeNameRejectsUppercase = {
    expr = evalFails (evalType nftzones.types.nodeName "Web-Server");
    expected = true;
  };

  # ===== node.name — derives from attrset key =====

  testNodeNameDerivedFromKey = {
    expr =
      (nodeIn {
        parent = "dmz";
        address.ipv4 = "10.0.0.5";
      }).name;
    expected = "web-server";
  };

  # ===== node.parent — required (no default) =====

  testNodeParentRequired = {
    # parent is required — omitting throws "option not defined".
    expr = evalFails (nodeIn { address.ipv4 = "10.0.0.5"; }).parent;
    expected = true;
  };

  testNodeParentAccepted = {
    expr =
      (nodeIn {
        parent = "dmz";
        address.ipv4 = "10.0.0.5";
      }).parent;
    expected = "dmz";
  };

  # `zone` is the old spelling, removed with no alias.
  testNodeZoneRejected = {
    expr =
      evalFails
        (nodeIn {
          zone = "dmz";
          address.ipv4 = "10.0.0.5";
        }).address;
    expected = true;
  };

  # ===== node.address — at least one of ipv4 / ipv6 (apply throws) =====

  testNodeAddressV4Only = {
    expr =
      (nodeIn {
        parent = "dmz";
        address.ipv4 = "10.0.0.5";
      }).address;
    expected = {
      ipv4 = "10.0.0.5";
      ipv6 = null;
    };
  };

  testNodeAddressV6Only = {
    expr =
      (nodeIn {
        parent = "dmz";
        address.ipv6 = "fe80::1";
      }).address;
    expected = {
      ipv4 = null;
      ipv6 = "fe80::1";
    };
  };

  testNodeAddressBoth = {
    expr =
      (nodeIn {
        parent = "dmz";
        address = {
          ipv4 = "10.0.0.5";
          ipv6 = "fe80::1";
        };
      }).address;
    expected = {
      ipv4 = "10.0.0.5";
      ipv6 = "fe80::1";
    };
  };

  testNodeAddressBothNullTypeAccepts = {
    # The type accepts both-null (both fields default to `null`).
    # The "at least one address required" rule is enforced by
    # Phase 1's `nodeAddressMissing` diagnostic so the error
    # aggregates with the rest of Phase 1 instead of throwing at
    # type-apply time. See `tests/unit/internal/diagnose-hierarchy.nix`
    # for the rejection tests.
    expr =
      (nodeIn {
        parent = "dmz";
        address = { };
      }).address;
    expected = {
      ipv4 = null;
      ipv6 = null;
    };
  };

  # ===== node.address.ipv4 / ipv6 — libnet's strict address checks =====

  testNodeAddressV4InvalidRejected = {
    expr =
      evalFails
        (nodeIn {
          parent = "dmz";
          address.ipv4 = "999.0.0.1";
        }).address;
    expected = true;
  };

  testNodeAddressV4WithCidrRejected = {
    # nodeAddress takes BARE addresses, not CIDRs — node lowering
    # adds /32 (or /128) itself.
    expr =
      evalFails
        (nodeIn {
          parent = "dmz";
          address.ipv4 = "10.0.0.5/32";
        }).address;
    expected = true;
  };

  testNodeAddressV6InvalidRejected = {
    expr =
      evalFails
        (nodeIn {
          parent = "dmz";
          address.ipv6 = "not-an-address";
        }).address;
    expected = true;
  };
}
