/*
  Rejection scenario for the non-empty `rule` type on filters. A
  filter with `rule = [ ]` would compile to a rule with no
  statements, which nftypes refuses at a generated chain the user
  never wrote. The type rejects it before Phase 1 runs, so this
  scenario checks only that `mkRuleset` throws; the
  `tests/unit/types/filter.nix` suite pins the rejection at
  `filters.<name>.rule`.
*/
_: {
  description = "filter rule type: rejects an empty rule";

  body = {
    zones.lan.interfaces = [ "lan0" ];

    filters.empty = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = [ ];
    };
  };
}
