/*
  Named-objects scenario — rule body references a counter and a
  set declared in `objects`. Exercises object-ref validation and
  user objects in the rendered table, including every object field
  whose nft JSON name differs from its nftypes DSL name (`elem`,
  `stmt`, `gc-interval`, `auto-merge`, `map`, `rate_unit`,
  `burst_unit`): each must render back under its JSON name.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl)
    accept
    counter
    expr
    inSet
    ;
  inherit (nftypes.dsl.fields) ip;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
    };

    objects = {
      counters.lan-out-hits = { };
      sets = {
        trusted-v4 = {
          type = "ipv4_addr";
          flags = [ "interval" ];
          auto-merge = true;
          # Structured prefix avoids nft's NSS path on bare-string CIDRs.
          elem = [ (expr.prefix "10.0.0.0" 24) ];
        };
        seen-v4 = {
          type = "ipv4_addr";
          flags = [
            "dynamic"
            "timeout"
          ];
          timeout = 3600;
          gc-interval = 60;
          stmt = [
            (counter {
              packets = 0;
              bytes = 0;
            })
          ];
        };
      };
      maps.port-redirect = {
        type = "inet_service";
        map = "inet_service";
      };
      limits.slow = {
        rate = 5;
        per = "second";
        rate_unit = "kbytes";
        burst = 100;
        burst_unit = "kbytes";
      };
    };

    filters.allow-trusted = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [
        (inSet ip.saddr (expr.setRef "trusted-v4"))
        (counter.ref "lan-out-hits")
        accept
      ];
    };
  };

  assertions =
    compiled:
    let
      # The bodies of the rendered ruleset's `add <kind>` commands,
      # by object name, without the scope fields the table supplies.
      added =
        kind:
        builtins.listToAttrs (
          map
            (command: {
              inherit (command.add.${kind}) name;
              value = removeAttrs command.add.${kind} [
                "family"
                "table"
                "name"
              ];
            })
            (
              builtins.filter (command: command ? add && command.add ? ${kind})
                (builtins.fromJSON (nftypes.toJson (nftypes.dsl.ruleset [ compiled.table ]))).nftables
            )
        );
    in
    [
      {
        description = "user counter passes through to the rendered table";
        expr =
          compiled.tables.named-objects ? counters && compiled.tables.named-objects.counters ? lan-out-hits;
        expected = true;
      }
      {
        description = "user set merges with auto zone-derived sets under one body.sets";
        expr = compiled.tables.named-objects.sets ? "trusted-v4";
        expected = true;
      }
      {
        description = "set fields render under their nft JSON names";
        expr = {
          inherit (added "set") seen-v4 trusted-v4;
        };
        expected = {
          seen-v4 = {
            type = "ipv4_addr";
            flags = [
              "dynamic"
              "timeout"
            ];
            timeout = 3600;
            gc-interval = 60;
            stmt = [
              {
                counter = {
                  packets = 0;
                  bytes = 0;
                };
              }
            ];
          };
          trusted-v4 = {
            type = "ipv4_addr";
            flags = [ "interval" ];
            auto-merge = true;
            elem = [
              {
                prefix = {
                  addr = "10.0.0.0";
                  len = 24;
                };
              }
            ];
          };
        };
      }
      {
        description = "map and limit fields render under their nft JSON names";
        expr = {
          map = (added "map").port-redirect;
          limit = (added "limit").slow;
        };
        expected = {
          map = {
            type = "inet_service";
            map = "inet_service";
          };
          limit = {
            rate = 5;
            per = "second";
            rate_unit = "kbytes";
            burst = 100;
            burst_unit = "kbytes";
          };
        };
      }
    ];
}
