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
    nftzones.snippets.{accept|drop|reject}.icmp.v4 types
    nftzones.snippets.{accept|drop|reject}.icmp.v6 types

  `ports` accepts ints, decimal strings, range strings (`"8000-8100"`
  or `"8000:8100"`), `libnet.port` values, `libnet.portRange`
  values, or lists thereof. `types` accepts ints (0..255), symbolic
  strings (`"echo-request"`), or lists of one form (mixed-form
  lists throw). See `docs/plans/snippets.md` for the full input /
  output contract.

  Reject variant per protocol:
    - `reject.tcp`      → `reject.tcpReset`  (TCP RST, clean closure)
    - `reject.udp`      → `reject.plain`     (ICMP port-unreachable)
    - `reject.icmp.v4`  → `reject.plain`     (family-aware default)
    - `reject.icmp.v6`  → `reject.plain`     (family-aware default)

  Field-name mapping:
    - `icmp.v4` → `nftypes.dsl.fields.icmp.type`
    - `icmp.v6` → `nftypes.dsl.fields.icmpv6.type`
    The leaf keys (`v4` / `v6`) match the existing nftzones zone
    convention (`zones.<name>.v4` / `<zone>_v4` sets); the `icmpv6`
    spelling at the field path is nftypes' own.
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
    tcp
    udp
    icmp
    icmpv6
    ;

  matchers = import ./snippets/matchers.nix { inherit inputs; };
  inherit (matchers) mkPortMatch mkIcmpMatch;
in
{
  accept = {
    tcp = ports: [
      (mkPortMatch tcp.dport ports)
      accept
    ];
    udp = ports: [
      (mkPortMatch udp.dport ports)
      accept
    ];
    icmp = {
      v4 = types: [
        (mkIcmpMatch icmp.type types)
        accept
      ];
      v6 = types: [
        (mkIcmpMatch icmpv6.type types)
        accept
      ];
    };
  };

  drop = {
    tcp = ports: [
      (mkPortMatch tcp.dport ports)
      drop
    ];
    udp = ports: [
      (mkPortMatch udp.dport ports)
      drop
    ];
    icmp = {
      v4 = types: [
        (mkIcmpMatch icmp.type types)
        drop
      ];
      v6 = types: [
        (mkIcmpMatch icmpv6.type types)
        drop
      ];
    };
  };

  reject = {
    tcp = ports: [
      (mkPortMatch tcp.dport ports)
      reject.tcpReset
    ];
    udp = ports: [
      (mkPortMatch udp.dport ports)
      reject.plain
    ];
    icmp = {
      v4 = types: [
        (mkIcmpMatch icmp.type types)
        reject.plain
      ];
      v6 = types: [
        (mkIcmpMatch icmpv6.type types)
        reject.plain
      ];
    };
  };
}
