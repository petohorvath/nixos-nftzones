/*
  Rejection scenario for `checkMatchOverrideContent`. The
  `matchOverride.<side>.<section>` sections are spliced as
  prefix-match clauses into every dispatch rule for the zone;
  a verdict there would short-circuit zone dispatch before the
  per-pair sub-chain jump fires, silently changing the rule's
  meaning. Side-effecting statements (counter / log / limit /
  mark-set / …) would fire on every packet matching the zone
  rather than just the packets the user's filter rule targets.

  This scenario embeds a `jump` verdict in `extra` to pin that
  the structural check is wired into the live `mkRuleset`
  pipeline. Per-statement-kind acceptance / rejection is
  covered exhaustively by the unit tests in
  `tests/unit/internal/normalize.nix`.
*/
{ nftypes }:
{
  description = "checkMatchOverrideContent: rejects verdict statements in matchOverride sections";

  body = {
    zones.lan = {
      interfaces = [ "lan0" ];
      matchOverride.ingress.extra = [
        (nftypes.dsl.eq nftypes.dsl.fields.meta.mark 256)
        (nftypes.dsl.jump "bypass")
      ];
    };
    filters.allow-ssh = {
      from = [ "lan" ];
      to = [ "local" ];
      rule = [
        (nftypes.dsl.eq nftypes.dsl.fields.tcp.dport 22)
        nftypes.dsl.accept
      ];
    };
  };
}
