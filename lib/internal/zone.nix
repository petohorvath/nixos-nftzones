/*
  internal/zone — exposes zone-related helpers under
  `nftzones.internal.zone`.

  Exported functions:
    - `genSets` — emits the per-zone nftables sets a zone
                  contributes to the table (`<name>_iifs` /
                  `<name>_v4` / `<name>_v6`). Each set contains
                  the zone's own interfaces/CIDRs PLUS the
                  transitive union of every descendant zone's
                  interfaces/CIDRs. This is the standard zone
                  hierarchy semantics: a child zone is a
                  *refinement* of its parent — anything that
                  matches the child also matches the parent.
                  The base-chain dispatch jump for the parent
                  therefore catches descendant traffic too, and
                  the child-dispatch jump inside the parent's
                  sub-chain routes it into the more specific
                  child sub-chain (cf. Phase 4's
                  `mkChildDispatchJumpRules`). Single source of
                  truth for naming and content — folded once by
                  Phase 1's `computeZoneSets` into `ctx.zoneSets`,
                  then consumed by Phase 1 validators (names
                  only) and Phase 4 emit (full bodies).
    - `getActiveMatchOverrides` — returns the active sections of
                  a zone's matchOverride for a given side, with
                  null and empty-list sections filtered out. The
                  result is an attrset whose keys are the active
                  section names (`interfaces` / `ipv4` / `ipv6`
                  / `extra`); callers test presence with `?` or
                  read with `or` defaults. Consumed by every
                  validator and emit helper that needs to ask
                  "which sections did the user override?".

  Wired into the surface from `lib/internal/default.nix`.

  ===== genSets =====

  Inputs:
    mergedZones — full zone attrset from `ctx.mergedZones`
                  (declared zones plus lowered nodes). Needed
                  to look up descendants' interfaces and CIDRs
                  by name during the transitive walk.
    childrenOf  — inverse-parent map from `ctx.childrenOf`
                  (`{ parent → [child, ...] }`). Used to walk
                  descendants transitively.
    name        — zone name to emit sets for. Used as the
                  set-name prefix and as the starting point of
                  the descendant walk.

  Output:
    Attrset of `{ "<name>_<suffix>" = <set body>; }` pairs where
    `<suffix>` is one of `iifs` / `v4` / `v6`. Suffixes are
    emitted iff the corresponding union (self + descendants) is
    non-empty.

    Per-family CIDR sets are coalesced via `libnet.cidr.summarize`
    at compile time: exact duplicates collapse, descendant CIDRs
    contained in an ancestor CIDR (e.g. `10.0.0.5/32` inside
    `10.0.0.0/24`) drop out, and sibling CIDRs that fuse into a
    parent (e.g. `10.0.0.0/24` + `10.0.1.0/24` → `10.0.0.0/23`)
    are merged. The rendered set therefore equals the live kernel
    state, with no reliance on `auto-merge` to clean up overlaps
    at load time. Order is sorted (family, network, prefix).

  Why this exists: both Phase 1's validators (which need the
  *names* to validate user refs against zone-derived sets) and
  Phase 4's `assembleOutput` (which needs the full bodies) read
  from `ctx.zoneSets` populated by a single fold over
  `mergedZones` in `internal.normalize.computeZoneSets`.

  Example:
    genSets
      { lan       = { interfaces = [ "lan0" ];   cidrs = [];
                      parent = null;  matchOverride = ...; };
        lan-guest = { interfaces = [ "guest0" ]; cidrs = [];
                      parent = "lan"; matchOverride = ...; };
      }
      { lan = [ "lan-guest" ]; }
      "lan"
    => {
      lan_iifs = { type = "ifname"; elements = [ "lan0" "guest0" ]; };
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

  /*
    Transitive descendants of `name`. DFS over `childrenOf`, not
    including `name` itself. Order is parent-before-child (each
    level appears before its children's children).

    Defensive cycle guard: `computeZoneSets` runs before Phase 1's
    `checkParentCycles` in the validator pipeline, so a cycle
    here would stack-overflow before the dedicated validator
    reports it. The `visited` set short-circuits any revisit so
    a cyclic input fails the eventual `checkParentCycles` check
    with a clean error rather than hitting Nix's max-call-depth.
  */
  descendantsOf =
    childrenOf: name:
    let
      step =
        visited: cur:
        let
          direct = builtins.filter (c: !(builtins.elem c visited)) (childrenOf.${cur} or [ ]);
          visited' = visited ++ direct;
        in
        direct ++ lib.concatMap (step visited') direct;
    in
    step [ name ] name;

  genSets =
    mergedZones: childrenOf: name:
    let
      contributingZones = [ name ] ++ descendantsOf childrenOf name;
      contributing = map (z: mergedZones.${z}) contributingZones;

      # Interfaces: dedup at the string level — `lib.unique`
      # preserves first-occurrence order, so parent's interfaces
      # come before descendants' (matching the contribution
      # order). nft's ifname set has no notion of overlap; exact
      # duplicates are the only thing to remove.
      allIfaces = lib.unique (lib.concatMap (z: z.interfaces) contributing);

      # CIDRs: `libnet.cidr.summarize` handles family separation,
      # canonicalisation (network bits masked), and the full
      # set-coalescing algebra — exact duplicates, subset overlaps
      # (a descendant CIDR contained in an ancestor), and sibling
      # fusion (two adjacent same-prefix blocks → one supernet).
      # Doing this at compile time means the rendered set equals
      # the live kernel state — no `auto-merge` post-processing
      # needed.
      summarised = libnet.cidr.summarize (
        map libnet.cidr.parse (lib.concatMap (z: z.cidrs) contributing)
      );
      parsedV4 = builtins.filter libnet.cidr.isIpv4 summarised;
      parsedV6 = builtins.filter libnet.cidr.isIpv6 summarised;
    in
    lib.optionalAttrs (allIfaces != [ ]) {
      "${name}_iifs" = {
        type = "ifname";
        elements = allIfaces;
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

  /*
    Returns the active sections of `zone.matchOverride.<side>` —
    sections whose value is non-null AND non-empty. Sections set
    to `null` (default) or `[ ]` (explicitly empty) are filtered
    out. Both encode "no constraint contributed by this section".

    Result is an attrset keyed by the surviving section names
    (`interfaces` / `ipv4` / `ipv6` / `extra`). Callers test
    presence with `?` (`active ? ipv4`) or read with defaults
    (`active.ipv4 or autoV4`).
  */
  getActiveMatchOverrides =
    zone: side:
    lib.filterAttrs (_: section: section != null && section != [ ]) zone.matchOverride.${side};
in
{
  inherit genSets getActiveMatchOverrides;
}
