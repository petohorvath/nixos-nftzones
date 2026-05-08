# Cross-Zone Validation (Superseded)

> **Status**: this document is preserved for historical context. The actual validation work landed inline in `lib/internal/normalize.nix` as a sequence of Phase 1 validators (`checkParentRefs`, `checkParentCycles`, `checkNameCollisions`, `checkSettings`, `checkZoneRefs`, `checkZoneMatchable`, `checkChainOverridePlacement`, `checkChainPlacement`, `checkRpfilterOverride`, `checkPolicyUniqueness`, `checkSetNameCollisions`, `checkInterfaceOverlap`, `checkCidrOverlap`, `checkObjectRefs`) — see `docs/compile-pipeline.md` §1.3 for the current shape and `docs/specs/zone-parent.md` for the parent-related ones. The "Where the validation lives" / "Open questions" sections below reflect choices that were made differently in implementation.

This document captures the design discussion around validating zone configurations across the whole `zones` attrset, beyond what per-zone NixOS option types can express.

## Motivation

The `zone` submodule type validates one zone in isolation: that `name` is a valid identifier, that `parent` (if set) is a valid identifier, that `interfaces` is a list of `interfaceName` values, etc. It does not — and cannot — see other zones. Several useful checks need that whole-collection view:

- **Parent resolution.** A zone's `parent` (if non-null) must be a key in the same `zones` attrset; a `parent = "lan"` reference is meaningless if no `zones.lan` exists.
- **Parent cycles.** A chain like `lan → guest → lan` produces an infinite loop in any consumer that walks the parent relation. The validator must reject it.
- **Interface and CIDR overlap.** Two distinct zones claiming the same interface or overlapping prefixes is almost always a misconfiguration; flagging it requires comparing every pair of zones. Landed as `checkInterfaceOverlap` and `checkCidrOverlap` in `lib/internal/normalize.nix`; both skip ancestor/descendant pairs (intentional containment) and also flag intra-zone duplicates.

## Where the validation lives

Two reasonable approaches; the standard NixOS pattern is the first.

### Module-level `assertions` (idiomatic)

The dominant convention in nixpkgs, home-manager, sops-nix, disko, and similar projects is to express cross-cutting checks via `config.assertions` declared inside the module that owns the option. The module evaluates predicates inline, emitting `{ assertion = bool; message = string; }` records. Nothing extra gets exposed as a top-level library namespace.

This pattern fits nftzones cleanly: a future `nftzones.modules.zones` module owns the `zones` option and emits its own assertions. Consumers `imports = [ nftzones.modules.zones ];` and get validation for free.

### Pure validator function plus module wrapper (hybrid)

An alternative is to extract the predicates into a pure function the module calls. The function is testable in isolation and reusable for consumers who define their own `zones` option at a different path (e.g. `networking.firewall.zones`).

Trade-off versus baking the checks into the module directly: two surfaces to maintain instead of one, in exchange for testability and location-agnostic reuse.

## Sketch: validator function

A pure function from a zones attrset to a list of error strings. Empty list means valid.

```nix
# nftzones.<somewhere>.validateZones :: Attrset Zone -> [ String ]
validateZones = zones:
  checkParents zones
  ++ checkCycles zones;
```

### Parent resolution

```nix
checkParents = zones:
  lib.concatLists (lib.mapAttrsToList (name: zone:
    if zone.parent != null && !(zones ? ${zone.parent}) then
      [ "zone '${name}' references unknown parent '${zone.parent}'" ]
    else
      [ ]
  ) zones);
```

### Parent cycles (sketch)

Walk each zone's parent chain; if a name is revisited on the same walk, report a cycle.

```nix
checkCycles = zones:
  let
    walk = visited: name:
      let parent = zones.${name}.parent or null; in
      if parent == null || !(zones ? ${parent}) then [ ]
      else if lib.elem parent visited then
        [ "parent cycle: ${lib.concatStringsSep " → " (visited ++ [ parent ])}" ]
      else
        walk (visited ++ [ parent ]) parent;
  in
  lib.unique (lib.concatMap (n: walk [ n ] n) (lib.attrNames zones));
```

Caveat: every member of a cycle finds the same cycle starting from a different position, so `lib.unique` filters byte-identical strings but does not normalize rotated paths. Acceptable for a first pass; a normalized representation (e.g. starting from the lexicographically smallest member) can replace it later.

## Consumer wiring

If the validator is exposed as a function, a consumer NixOS module wires it like this:

```nix
{ config, lib, nftzones, ... }: {
  options.zones = lib.mkOption {
    type = lib.types.attrsOf nftzones.types.zone;
    default = { };
  };

  config.assertions = map (msg: {
    assertion = false;
    message = msg;
  }) (nftzones.<path>.validateZones config.zones);
}
```

If validation is baked into a library-provided module, the consumer just imports the module and assigns `zones`.

## Library convention check

A dedicated `lib/validate/` namespace is **not** an established Nix/NixOS convention. Most libraries either inline the checks in their NixOS module's `config.assertions` or expose a single helper function alongside whatever else they provide; nixpkgs has `lib.asserts` for assertion *combinators* (`assertMsg`, `assertOneOf`) but nothing analogous to a domain-specific validators namespace. Whichever location nftzones picks is project-internal taste.

## Open questions

1. **Function-plus-module split, or module-only?** Module-only is idiomatic; the split is more testable but adds a second surface.
2. **If keeping a function, where does it live?** Candidates: `lib/validate.nix` (single flat file), `lib/validate/zones.nix` (room for siblings), `lib/zones.nix` (zones-collection ops generally), `lib/internal/validate-zones.nix` (hidden building block). All work; none is conventional in the wider ecosystem.
3. **Return shape.** List of strings (framework-agnostic, the wiring site maps to assertion records) versus list of `{ assertion; message; }` records (drop-in for `config.assertions`, less reusable outside NixOS).
4. **`checkCycles` reporting.** Tolerate duplicate-but-rotated cycle messages, or normalize to canonical form?
5. ~~**Future overlap checks.** Interface- and CIDR-overlap detection between zones — same module, separate validator, or deferred until needed?~~ Resolved: separate validators (`checkInterfaceOverlap`, `checkCidrOverlap`) inline in `normalize.nix`, sharing a `relatedByHierarchy` helper that walks the parent chain to skip intentional parent/child overlap. CIDR overlap uses `libnet.cidr.overlaps` (family-aware).

## Status

Parent resolution and parent-cycle detection landed in
`lib/internal/normalize.nix` as `checkParentRefs` and
`checkParentCycles`. The validators run during Phase 1 of the
compile pipeline and emit aggregated errors with the rest of
Phase 1's validators. See `docs/specs/zone-parent.md` for the
hierarchical-dispatch model that gives `parent` its observable
behaviour and the rejected validator-shape alternatives discussed
above.

There is no fixed reserved-names list. The only zone-name slots
with reserved semantics are the configurable `settings.localZone`
(default `"local"`) and `settings.wildcardZone` (default `"all"`),
and `checkSettings` already enforces that they differ from each
other and from any declared zone or node name.

Interface- and CIDR-overlap detection landed in
`lib/internal/normalize.nix` as `checkInterfaceOverlap` and
`checkCidrOverlap`. Both validators skip pairs in
ancestor/descendant relationship (intentional containment, e.g. a
node lowered into its parent zone) and also flag intra-zone
duplicates (`interfaces = [ "eth1" "eth1" ]` /
`cidrs = [ "10.0.0.0/24" "10.0.0.0/28" ]`). CIDR overlap uses
`libnet.cidr.overlaps`, which is family-aware (v4 vs v6 never
overlap).
