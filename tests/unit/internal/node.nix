/*
  Unit tests for `lib/internal/node.nix` (exposed as
  `nftzones.internal.node.toZone`). Same `testFoo = { expr; expected; }`
  shape as every other unit test; aggregated by `tests/unit/default.nix`.
*/
{
  pkgs,
  nftzones,
  nftypes,
  ...
}:
let
  inherit (nftzones.internal.node) toZone;

  /*
    Pull out the input-derivable fields of a `toZone` result —
    the ones whose values come straight from the node. The
    remaining `matchOverride` field carries submodule defaults
    whose shape is exercised separately.
  */
  inputFields = z: {
    inherit (z)
      name
      parent
      interfaces
      cidrs
      ;
  };
in
{
  # ===== toZone — v4-only node =====

  testToZoneV4Only = {
    expr = inputFields (toZone {
      name = "web";
      zone = "dmz";
      address = {
        ipv4 = "10.0.0.5";
        ipv6 = null;
      };
    });
    expected = {
      name = "web";
      parent = "dmz";
      interfaces = [ ];
      cidrs = [ "10.0.0.5/32" ];
    };
  };

  # ===== toZone — v6-only node =====

  testToZoneV6Only = {
    expr = inputFields (toZone {
      name = "ipv6-host";
      zone = "lan";
      address = {
        ipv4 = null;
        ipv6 = "fe80::1";
      };
    });
    expected = {
      name = "ipv6-host";
      parent = "lan";
      interfaces = [ ];
      cidrs = [ "fe80::1/128" ];
    };
  };

  # ===== toZone — dual-stack node =====

  testToZoneDualStack = {
    expr = inputFields (toZone {
      name = "dual";
      zone = "dmz";
      address = {
        ipv4 = "10.0.0.5";
        ipv6 = "fe80::1";
      };
    });
    expected = {
      name = "dual";
      parent = "dmz";
      interfaces = [ ];
      cidrs = [
        "10.0.0.5/32"
        "fe80::1/128"
      ];
    };
  };

  # ===== toZone — interfaces is always empty =====

  testToZoneInterfacesEmpty = {
    expr =
      (toZone {
        name = "x";
        zone = "any";
        address = {
          ipv4 = "1.2.3.4";
          ipv6 = null;
        };
      }).interfaces;
    expected = [ ];
  };

  # ===== toZone — parent reflects node.zone =====

  testToZoneParentPropagation = {
    expr =
      (toZone {
        name = "x";
        zone = "my-zone";
        address = {
          ipv4 = "1.2.3.4";
          ipv6 = null;
        };
      }).parent;
    expected = "my-zone";
  };

  # ===== toZone — produces full zone-submodule shape =====
  # All fields the evaluated zone submodule has must be present.

  testToZoneProducesFullShape = {
    expr = pkgs.lib.sort (a: b: a < b) (
      builtins.attrNames (toZone {
        name = "x";
        zone = "z";
        address = {
          ipv4 = "1.2.3.4";
          ipv6 = null;
        };
      })
    );
    expected = [
      "cidrs"
      "interfaces"
      "matchOverride"
      "name"
      "parent"
    ];
  };

  # ===== toZone — submodule-default field values =====

  testToZoneSubmoduleDefaults = {
    expr =
      let
        z = toZone {
          name = "x";
          zone = "z";
          address = {
            ipv4 = "1.2.3.4";
            ipv6 = null;
          };
        };
      in
      {
        inherit (z) matchOverride;
      };
    expected = {
      matchOverride = {
        ingress = { };
        egress = { };
      };
    };
  };
}
