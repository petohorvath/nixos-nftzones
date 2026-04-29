/*
  internal/zone — exposes zone-related helpers under
  `nftzones.internal.zone`.

  Exported functions:
    - `genMatch` — generates nftables match statements that select
                   traffic for a zone, based on member interfaces
                   and CIDRs.

  Wired into the surface from `lib/default.nix`.

  ===== genMatch =====

  Inputs:
    interfaces  — list of ifnames; default [ ].
    cidrs       — list of CIDR strings (mixed v4/v6); default [ ].
    override    — { ingress?, egress? }; each side is either omitted /
                  null (compute it from interfaces+cidrs) or a
                  family-keyed override that replaces the computed side
                  wholesale. Same shape as the returned values.

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
in
{
  inherit genMatch;
}
