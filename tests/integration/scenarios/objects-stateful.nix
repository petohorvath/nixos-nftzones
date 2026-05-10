/*
  Stateful-object scenario — exercises object kinds beyond the
  counters + sets covered by `named-objects.nix`. Declares one
  of each common stateful kind (limit, quota, ctHelper,
  ctTimeout, map) so `mkUserObjects` passthrough and
  `checkObjectRefs` resolution touch every kind's nftypes body
  shape.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    objects = {
      limits.ssh-rate = {
        rate = 5;
        per = "second";
      };

      quotas.daily-cap = {
        bytes = 1073741824; # 1 GiB
      };

      ctHelpers.ftp-helper = {
        type = "ftp";
        protocol = "tcp";
      };

      ctTimeouts.long-tcp = {
        protocol = "tcp";
        policy.established = 86400;
      };

      # Empty body — just verifies the maps passthrough path. The
      # tagged-element shape lives in nftypes and is exercised by
      # its own tests.
      maps.port-redirect = {
        type = "inet_service";
        map = "inet_service";
      };
    };

    filters.allow-ssh = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 22)
        accept
      ];
    };
  };

  assertions = compiled: [
    {
      description = "every declared object kind passes through to the rendered table";
      expr = {
        limits =
          compiled.tables.objects-stateful ? limits && compiled.tables.objects-stateful.limits ? "ssh-rate";
        quotas =
          compiled.tables.objects-stateful ? quotas && compiled.tables.objects-stateful.quotas ? "daily-cap";
        ctHelpers =
          compiled.tables.objects-stateful ? ctHelpers
          && compiled.tables.objects-stateful.ctHelpers ? "ftp-helper";
        ctTimeouts =
          compiled.tables.objects-stateful ? ctTimeouts
          && compiled.tables.objects-stateful.ctTimeouts ? "long-tcp";
        maps =
          compiled.tables.objects-stateful ? maps && compiled.tables.objects-stateful.maps ? "port-redirect";
      };
      expected = {
        limits = true;
        quotas = true;
        ctHelpers = true;
        ctTimeouts = true;
        maps = true;
      };
    }
  ];
}
