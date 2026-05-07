/*
  Settings-toggle scenario — exercises four `settings` knobs
  away from their defaults: `rpfilter` synthesizes a dedicated
  prerouting@raw chain; `chainPolicy = "accept"` flips the base
  chain default verdict; `stateful = false` drops the conntrack
  prelude; `loopback = false` drops the `iif lo accept` prelude
  on input. None of these have integration coverage otherwise.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    settings = {
      rpfilter = true;
      chainPolicy = "accept";
      stateful = false;
      loopback = false;
    };

    zones = {
      lan.interfaces = [ "lan0" ];
      wan.interfaces = [ "wan0" ];
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
      description = "rpfilter=true synthesizes a prerouting-at-raw chain";
      expr = compiled.tables.settings-toggles.chains ? "prerouting-at-raw";
      expected = true;
    }
    {
      description = "chainPolicy='accept' surfaces on the filter base chain";
      expr = compiled.tables.settings-toggles.chains."input-at-filter".policy;
      expected = "accept";
    }
    {
      description = "stateful=false + loopback=false drops both preludes — base chain has only the dispatch jump";
      expr = builtins.length compiled.tables.settings-toggles.chains."input-at-filter".rules;
      expected = 1;
    }
  ];
}
