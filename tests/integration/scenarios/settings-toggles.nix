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
}
