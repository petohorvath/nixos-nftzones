/*
  nftzones.snippets — rule-body shorthand for the common
  verdict + protocol + port/type combinations.

  Each leaf function returns an nftypes statement list suitable
  for splicing into `filters.<name>.rule = ...`. The compile
  pipeline never sees these helpers — the returned statements are
  ordinary `nftypes.dsl.*` shapes, validated by the same rule
  primitive type as any hand-written body.

  Public surface:

    nftzones.snippets.{accept|drop|reject}.tcp ports
    nftzones.snippets.{accept|drop|reject}.udp ports
    nftzones.snippets.{accept|drop|reject}.icmp types
    nftzones.snippets.{accept|drop|reject}.icmpv6 types

  `ports` accepts ints, decimal strings, range strings (`"8000-8100"`
  or `"8000:8100"`), `libnet.port` values, `libnet.portRange`
  values, or lists thereof. `types` accepts ints (0..255), symbolic
  strings (`"echo-request"`), or lists of one form (mixed-form
  lists throw). See `snippets/ports.nix` and `snippets/matchers.nix`
  for the full input / output contract.

  Reject variant per protocol:
    - `reject.tcp`     → `reject { type = "tcp reset"; }` (TCP RST)
    - `reject.udp`     → `reject { }` (ICMP port-unreachable)
    - `reject.icmp`    → `reject { }` (family-aware default)
    - `reject.icmpv6`  → `reject { }` (family-aware default)

  Field-name mapping:
    - `icmp`   → `nftypes.dsl.fields.icmp.type`
    - `icmpv6` → `nftypes.dsl.fields.icmpv6.type`
    The snippet names are the nftables protocol names, so they
    match the `icmp.type` and `icmpv6.type` fields of a
    hand-written rule.
*/
{ inputs }:
let
  inherit (inputs) nftypes;
  inherit (nftypes.dsl)
    accept
    drop
    reject
    ;
  inherit (nftypes.dsl.fields)
    icmp
    icmpv6
    tcp
    udp
    ;

  matchers = import ./snippets/matchers.nix { inherit inputs; };
  inherit (matchers) mkIcmpMatch mkPortMatch;

  /*
    One verdict's snippet set: each protocol's match followed by
    `verdict`. `tcpVerdict` replaces `verdict` after the TCP port
    match, for a verdict whose TCP form differs, as `reject`'s TCP
    reset does.
  */
  mkVerdictSnippets =
    {
      verdict,
      tcpVerdict ? verdict,
    }:
    {
      tcp = ports: [
        (mkPortMatch tcp.dport ports)
        tcpVerdict
      ];
      udp = ports: [
        (mkPortMatch udp.dport ports)
        verdict
      ];
      icmp = types: [
        (mkIcmpMatch icmp.type types)
        verdict
      ];
      icmpv6 = types: [
        (mkIcmpMatch icmpv6.type types)
        verdict
      ];
    };
in
{
  accept = mkVerdictSnippets { verdict = accept; };

  drop = mkVerdictSnippets { verdict = drop; };

  # `reject { }` is the family-aware default reject, used after the
  # UDP, ICMP and ICMPv6 matches; a TCP match answers with a reset.
  reject = mkVerdictSnippets {
    verdict = reject { };
    tcpVerdict = reject { type = "tcp reset"; };
  };
}
