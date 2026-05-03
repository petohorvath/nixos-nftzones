/*
  internal/zone — exposes zone-related helpers under
  `nftzones.internal.zone`.

  Exported functions:
    - `genSets` — emits the per-zone nftables sets a zone
                  contributes to the table (`<name>_iifs` /
                  `<name>_v4` / `<name>_v6`). Single source of
                  truth for naming and content of zone-derived
                  sets — folded once by Phase 1's
                  `computeZoneSets` into `ctx.zoneSets`, then
                  consumed by Phase 1 validators (names only)
                  and Phase 4 emit (full bodies).

  Wired into the surface from `lib/internal/default.nix`.

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
  inherit (nftypes.dsl) expr;

  cidrToPrefix =
    isV4: parsed:
    let
      addrStr = if isV4 then libnet.ipv4.toString parsed.address else libnet.ipv6.toString parsed.address;
    in
    expr.prefix addrStr parsed.prefix;

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
  inherit genSets;
}
