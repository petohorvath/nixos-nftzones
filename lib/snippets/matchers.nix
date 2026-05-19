/*
  snippets/matchers — match-statement builders for `nftzones.snippets.*`.

  `mkPortMatch` and `mkIcmpMatch` consume a normalized list and a
  field expression and emit one nftypes match statement, choosing
  between `eq` (single bare value), `within` (single range), and
  `inSet` (multi-element) according to the list shape. Port and
  ICMP-type input normalization are split into separate functions
  because their validation rules differ (libnet covers ports;
  ICMP uses an inline range check + form-uniformity rule).

  ===== normalizeIcmpTypes =====

  Inputs:
    types — int | string | list of either.

  Output:
    Sorted, deduped list of canonical elements (ints sorted
    ascending, strings sorted lexicographically). Mixed-form lists
    throw — see body for rationale.

  ===== mkPortMatch =====

  Inputs:
    field — nftypes field expression (e.g. `tcp.dport`, `udp.dport`)
    ports — accepted by `normalizePorts` (see snippets/ports.nix)

  Output:
    One nftypes match statement.

  ===== mkIcmpMatch =====

  Inputs:
    field — nftypes field expression (`icmp.type` or `icmpv6.type`)
    types — accepted by `normalizeIcmpTypes`

  Output:
    One nftypes match statement.
*/
{ inputs }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes.dsl) eq inSet within;

  ports = import ./ports.nix { inherit inputs; };
  inherit (ports) normalizePorts;

  isIntElem = x: builtins.isInt x;
  isStringElem = x: builtins.isString x;
  isRangeElem = x: builtins.isAttrs x && x ? range;

  /*
    ===== normalizeIcmpTypes =====

    Validate the all-ints-or-all-strings rule, range-check ints,
    sort and dedupe. Mixed-form lists throw because we have no
    safe way to dedupe across forms (e.g. `8` and
    `"echo-request"` refer to the same ICMP type but we'd need a
    symbol table to know that, and maintaining one would couple
    nftzones to the nftables symbol set).

    NOTE: string-form ICMP types are passed through unvalidated.
    Neither libnet nor nftypes maintains a closed enum of nft's
    symbolic constants (`echo-request`, `destination-unreachable`,
    `packet-too-big`, …); nft itself rejects unknown symbols at
    parse / `nft -j --check` time with "Could not parse symbolic
    constant", so a typo surfaces at activation / integration
    rather than at eval. We deliberately don't add a regex /
    character-class check here because the value is delivered to
    the renderer as a single JSON-encoded atom (`{"set":[...]}`
    or scalar RHS), so the only way a non-symbol string could
    "smuggle" anything is via the text-mode renderer that emits
    expression strings bare — and that renderer already fails on
    any string the nft parser can't recognise.

    Prefer integer constants where you can: `libnet.registry.
    icmpTypes.ipv4.echoRequest == 8` /
    `icmpTypes.ipv6.packetTooBig == 2` give you the numeric
    type code with a typed Nix attribute name, which is both
    enum-validated (typo → eval error) and protocol-version-
    correct. The string form is supported for users who prefer
    the symbolic-constant style nft itself emits.
  */
  normalizeIcmpTypes =
    types:
    let
      asList = if builtins.isList types then types else [ types ];
      allInts = builtins.all isIntElem asList;
      allStrings = builtins.all isStringElem asList;
      validateInt =
        n:
        if n < 0 || n > 255 then
          throw "snippets: ICMP type ${builtins.toString n} out of range [0, 255]"
        else
          n;
    in
    if asList == [ ] then
      asList
    else if allInts then
      lib.unique (lib.sort (a: b: a < b) (map validateInt asList))
    else if allStrings then
      lib.unique (lib.sort (a: b: a < b) asList)
    else
      throw "snippets: ICMP types must be all ints or all strings, not mixed";

  /*
    ===== mkPortMatch =====

    Branch by normalized list length and singleton kind:
      - empty       → throw
      - single int  → `eq    field N`
      - single rng  → `within field { range = [lo hi]; }`
      - multi       → `inSet  field [ ... ]`

    `within` is an alias for `inSet` in nftypes; using it for the
    single-range case is purely a readability choice.
  */
  mkPortMatch =
    field: ports:
    let
      normalized = normalizePorts ports;
      n = builtins.length normalized;
      head = builtins.head normalized;
    in
    if n == 0 then
      throw "snippets: ports list is empty"
    else if n == 1 && isIntElem head then
      eq field head
    else if n == 1 && isRangeElem head then
      within field head
    else
      inSet field normalized;

  /*
    ===== mkIcmpMatch =====

    Same length-driven branching as `mkPortMatch`, but ICMP types
    are scalar (int or string) — no range case, so single-element
    lists always emit `eq`.
  */
  mkIcmpMatch =
    field: types:
    let
      normalized = normalizeIcmpTypes types;
      n = builtins.length normalized;
    in
    if n == 0 then
      throw "snippets: types list is empty"
    else if n == 1 then
      eq field (builtins.head normalized)
    else
      inSet field normalized;
in
{
  inherit normalizeIcmpTypes mkPortMatch mkIcmpMatch;
}
