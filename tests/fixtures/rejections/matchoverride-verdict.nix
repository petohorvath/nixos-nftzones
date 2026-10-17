/*
  Type-layer rejection scenario for verdicts in `matchOverride`. The
  `matchOverride.<side>.<section>` sections are spliced as
  prefix-match clauses into every dispatch rule for the zone; a
  verdict there would short-circuit zone dispatch before the
  per-pair sub-chain jump fires, silently changing the rule's
  meaning. Side-effecting statements (counter / log / limit /
  mark-set / ...) would fire on every packet matching the zone
  rather than just the packets the user's filter rule targets.

  The table type rejects both: each section is a
  `primitives.matchRule`, a list of nftypes' `matchStatement`, so
  `mkRuleset` fails while evaluating the body, before Phase 1 runs.
  This scenario embeds a `jump` verdict in `extra` to pin that the
  restriction is reached through the nftzones type surface.
  Per-statement-kind acceptance and rejection is covered upstream
  in nftypes.
*/
{ nftypes }:
{
  description = "primitives.matchRule: rejects verdict statements in matchOverride sections";

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
