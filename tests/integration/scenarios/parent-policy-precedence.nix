/*
  Hierarchical-policy precedence scenario — pins the current
  cascading-with-terminal-verdicts semantics. With a parent zone
  (`lan`, default-accept-to-wan) and a child zone (`lan-guest`,
  drop-to-wan), both policies emit tail rules in their own
  sub-chains:

    forward-at-filter__lan-to-wan       { ... ; accept; }
    forward-at-filter__lan-guest-to-wan { ... ; drop;   }

  Cascade at runtime: a packet on `guest0` enters
  `__lan-to-wan` via the transitive parent dispatch jump, hits
  the child-dispatch jump narrowing to `__lan-guest-to-wan`,
  and the child's `drop` fires terminally. A packet on `lan0`
  doesn't match the child's dispatch and falls to lan's tail
  `accept`. Both verdicts are terminal in nftables (`accept` /
  `drop` end rule processing), so the cascade is well-defined.

  This scenario exists as a *regression guard*: if a future
  `policyVerdict` extension adds a non-terminal value
  (`continue` / `return`), the child's verdict could fall back
  to the parent's, silently changing semantics. The
  assertion-level checks pin both tail rules' presence and
  which sub-chain each lives in, so the regression would
  surface as a failed integration check rather than a quiet
  behavioural change.
*/
{ nftypes, ... }:
{
  body = {
    zones = {
      lan = {
        interfaces = [ "lan0" ];
      };
      lan-guest = {
        parent = "lan";
        interfaces = [ "guest0" ];
      };
      wan = {
        interfaces = [ "wan0" ];
      };
    };

    policies.lan-to-wan-allow = {
      from = [ "lan" ];
      to = [ "wan" ];
      verdict = "accept";
    };
    policies.lan-guest-to-wan-deny = {
      from = [ "lan-guest" ];
      to = [ "wan" ];
      verdict = "drop";
    };
  };

  assertions =
    compiled:
    let
      parentRules = compiled.table.chains."forward-at-filter__lan-to-wan".rules;
      childRules = compiled.table.chains."forward-at-filter__lan-guest-to-wan".rules;
      lastOf = xs: builtins.elemAt xs (builtins.length xs - 1);
    in
    [
      {
        description = "parent's sub-chain has its policy verdict as the *tail* rule (after child-dispatch jumps)";
        expr = lastOf parentRules;
        expected = [ { accept = null; } ];
      }
      {
        description = "child's sub-chain has its own (terminal, non-cascading) policy verdict as a tail rule";
        expr = lastOf childRules;
        expected = [ { drop = null; } ];
      }
      {
        description = "parent's sub-chain emits the child-dispatch jump ahead of its tail policy (cascade ordering)";
        expr =
          let
            r = builtins.elemAt parentRules 0;
          in
          {
            childMatch = (builtins.elemAt r 0).match.left.meta.key or null;
            jumpTarget = (builtins.elemAt r 1).jump.target or null;
          };
        expected = {
          childMatch = "iifname";
          jumpTarget = "forward-at-filter__lan-guest-to-wan";
        };
      }
      {
        description = "both sub-chains exist (regression guard: missing one would mean dispatch can't reach the verdict)";
        expr = {
          parent = compiled.table.chains ? "forward-at-filter__lan-to-wan";
          child = compiled.table.chains ? "forward-at-filter__lan-guest-to-wan";
        };
        expected = {
          parent = true;
          child = true;
        };
      }
    ];
}
