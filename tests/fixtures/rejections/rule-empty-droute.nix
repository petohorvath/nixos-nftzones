/*
  Rejection scenario for the non-empty `rule` type on droutes. A
  droute with `rule = [ ]` marks nothing, and used to fail inside
  nftypes at the generated `output-at-mangle__<zone>` chain. The
  type rejects it before Phase 1 runs, so this scenario checks only
  that `mkRuleset` throws; the `tests/unit/types/droute.nix` suite
  pins the rejection at `droutes.<name>.rule`.
*/
_: {
  description = "droute rule type: rejects an empty rule";

  body = {
    zones.remote.cidrs = [ "10.9.0.0/24" ];

    droutes.remote-via-vpn = {
      to = [ "remote" ];
      rule = [ ];
    };
  };
}
