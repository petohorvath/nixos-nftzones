/*
  Rejection scenario for `checkChainOverridePlacement` — a
  filter routed via `chain = { hook = "prerouting"; ... }` with
  `to = [ "iface-only" ]`, where the to-side zone is matchable
  only via interface (oifname). At prerouting, the output
  interface isn't decided yet, so oifname-based matches are
  invalid; the validator must reject.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  description = "checkChainOverridePlacement: oifname-only zone at prerouting hook";

  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      iface-only.interfaces = [ "eth1" ];
    };

    filters.bad-hook = {
      from = [ "lan" ];
      to = [ "iface-only" ];
      chain = {
        hook = "prerouting";
        priority = "raw";
      };
      rule = [ accept ];
    };
  };
}
