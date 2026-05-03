/*
  internal/zone — exposes zone-related helpers under
  `nftzones.internal.zone`.

  Exported functions:
    - `genMatch`    — generates nftables match statements that
                      select traffic for a zone, based on member
                      interfaces and CIDRs.
    - `genSets` — emits the per-zone nftables sets a zone
                      contributes to the table (`<name>_iifs` /
                      `<name>_v4` / `<name>_v6`). Single source of
                      truth for naming and content of zone-derived
                      sets — folded once by Phase 1's
                      `computeZoneSets` into `ctx.zoneSets`, then
                      consumed by Phase 1 validators (names only)
                      and Phase 4 emit (full bodies).

  Wired into the surface from `lib/internal/default.nix`.

  ===== genMatch =====

  Inputs:
    interfaces  — list of ifnames; default [ ].
    cidrs       — list of CIDR strings (mixed v4/v6); default [ ].
    override    — { ingress?, egress? }; each direction is either
                  omitted / null (compute it from interfaces+cidrs)
                  or a family-keyed override that replaces the
                  computed direction wholesale. Same shape as the
                  returned values.

  Output:
    {
      ingress = [ <variant>... ];
      egress  = [ <variant>... ];
    }

  A <variant> is a list of nftypes DSL statements spliced
  conjunctively into a single rule. The number of variants per
  direction depends on what the zone declares:

    zone has        | variants emitted
    ----------------|-----------------------
    empty           | 0
    iface only      | 1 (family-agnostic)
    v4 only         | 1
    v6 only         | 1
    v4 + v6         | 2
    iface + v4      | 1 (iface prefix + v4)
    iface + v6      | 1 (iface prefix + v6)
    iface + v4 + v6 | 2 (each with iface prefix)

  Example:
    genMatch {
      interfaces = [ "eth1" "eth2" ];
      cidrs = [ "10.0.0.0/24" "2001:db8::/32" ];
    }
    => {
      ingress = [
        # variant: iface + v4
        [
          (inSet meta.iifname [ "eth1" "eth2" ])
          (inSet ip.saddr [ (expr.prefix "10.0.0.0" 24) ])
        ]
        # variant: iface + v6
        [
          (inSet meta.iifname [ "eth1" "eth2" ])
          (inSet ip6.saddr [ (expr.prefix "2001:db8::" 32) ])
        ]
      ];
      egress = [ ... ];  # same shape with oifname / daddr
    }

  ===== genSets =====

  Inputs:
    name — zone name (used to prefix every emitted set key).
    zone — zone value (`interfaces`, `cidrs` are the only fields
           consulted).

  Output:
    Attrset of `{ "<name>_<suffix>" = <set body>; }` pairs where
    `<suffix>` is one of `iifs` / `v4` / `v6`. Suffixes are emitted
    iff the corresponding zone field is non-empty (interfaces for
    `_iifs`, v4 CIDRs for `_v4`, v6 CIDRs for `_v6`); empty
    suffixes are absent from the result, not present-with-empty.

    Set bodies are nftables `add set` payload shapes consumed by
    Phase 4's `assembleOutput`.

  Why this exists: both Phase 1's validators (which need the
  *names* to validate user refs against zone-derived sets) and
  Phase 4's `assembleOutput` (which needs the full bodies to
  emit) produce the same naming scheme. Centralizing here keeps
  them in lock-step. The fold runs once per compile in
  `internal.normalize.computeZoneSets`; both consumers read
  from `ctx.zoneSets`.

  Example:
    genSets "lan" {
      interfaces = [ "lan0" ];
      cidrs = [ "10.0.0.0/24" ];
    }
    => {
      lan_iifs = { type = "ifname";   elements = [ "lan0" ]; };
      lan_v4   = { type = "ipv4_addr"; flags = [ "interval" ];
                   elements = [ (expr.prefix "10.0.0.0" 24) ]; };
    }
*/
{ inputs }:
let
  inherit (inputs) lib libnet nftypes;
  inherit (nftypes.dsl) inSet expr;
  inherit (nftypes.dsl.fields) meta ip ip6;

  cidrToPrefix =
    isV4: parsed:
    let
      addrStr = if isV4 then libnet.ipv4.toString parsed.address else libnet.ipv6.toString parsed.address;
    in
    expr.prefix addrStr parsed.prefix;

  buildDirection =
    {
      ifField,
      addrFieldV4,
      addrFieldV6,
      interfaces,
      cidrs,
    }:
    let
      parsed = map libnet.cidr.parse cidrs;
      parsedV4 = builtins.filter libnet.cidr.isIpv4 parsed;
      parsedV6 = builtins.filter libnet.cidr.isIpv6 parsed;

      hasIfs = interfaces != [ ];
      hasV4 = parsedV4 != [ ];
      hasV6 = parsedV6 != [ ];
      hasCidrs = hasV4 || hasV6;

      ifMatch = inSet ifField interfaces;
      matchV4 = inSet addrFieldV4 (map (cidrToPrefix true) parsedV4);
      matchV6 = inSet addrFieldV6 (map (cidrToPrefix false) parsedV6);

      ifPrefix = lib.optional hasIfs ifMatch;
    in
    if hasCidrs then
      lib.optional hasV4 (ifPrefix ++ [ matchV4 ]) ++ lib.optional hasV6 (ifPrefix ++ [ matchV6 ])
    else if hasIfs then
      [ [ ifMatch ] ]
    else
      [ ];

  genMatch =
    {
      interfaces ? [ ],
      cidrs ? [ ],
      override ? { },
    }:
    let
      ingressOverride = override.ingress or null;
      egressOverride = override.egress or null;
    in
    {
      ingress =
        if ingressOverride != null then
          ingressOverride
        else
          buildDirection {
            ifField = meta.iifname;
            addrFieldV4 = ip.saddr;
            addrFieldV6 = ip6.saddr;
            inherit interfaces cidrs;
          };
      egress =
        if egressOverride != null then
          egressOverride
        else
          buildDirection {
            ifField = meta.oifname;
            addrFieldV4 = ip.daddr;
            addrFieldV6 = ip6.daddr;
            inherit interfaces cidrs;
          };
    };

  genSets =
    name: zone:
    let
      parsed = map libnet.cidr.parse zone.cidrs;
      parsedV4 = builtins.filter libnet.cidr.isIpv4 parsed;
      parsedV6 = builtins.filter libnet.cidr.isIpv6 parsed;
    in
    lib.optionalAttrs (zone.interfaces != [ ]) {
      "${name}_iifs" = {
        type = "ifname";
        elements = zone.interfaces;
      };
    }
    // lib.optionalAttrs (parsedV4 != [ ]) {
      "${name}_v4" = {
        type = "ipv4_addr";
        flags = [ "interval" ];
        elements = map (cidrToPrefix true) parsedV4;
      };
    }
    // lib.optionalAttrs (parsedV6 != [ ]) {
      "${name}_v6" = {
        type = "ipv6_addr";
        flags = [ "interval" ];
        elements = map (cidrToPrefix false) parsedV6;
      };
    };
in
{
  inherit genMatch genSets;
}
