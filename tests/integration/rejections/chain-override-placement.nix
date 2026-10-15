/*
  Rejection scenario for `chainOverrideUnreachable` — a
  filter routed via `chain = { hook = "prerouting"; ... }` with
  `to = [ "iface-only" ]`, where the to-side zone is matchable
  only via interface (oifname). At prerouting, the output
  interface isn't decided yet, so oifname-based matches are
  invalid; Phase 1 must reject.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  description = "chainOverrideUnreachable: oifname-only zone at prerouting hook";

  errors = [
    {
      tag = "chainOverrideUnreachable";
      path = [
        "filters"
        "bad-hook"
        "to"
      ];
    }
  ];

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
