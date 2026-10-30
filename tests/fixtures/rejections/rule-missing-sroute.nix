/*
  Rejection scenario for the required `rule` on sroutes. An sroute
  without a `rule` marks nothing, and used to fail inside nftypes at
  the generated `prerouting-at-mangle__<zone>` chain. The type
  rejects it before Phase 1 runs, so this scenario checks only that
  `mkRuleset` throws; the `tests/unit/types/sroute.nix` suite pins
  the rejection at `sroutes.<name>.rule`.
*/
_: {
  description = "sroute rule type: rejects a missing rule";

  body = {
    zones.guest.interfaces = [ "guest0" ];

    sroutes.guest-via-vpn.from = [ "guest" ];
  };
}
