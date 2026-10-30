/*
  internal/compatibility — exposes nftzones' chain-placement conventions
  under `nftzones.internal.compatibility`.

  nftypes' `compatibility` helpers answer what nft accepts at one hook.
  nftzones names a chain priority per family instead, so these helpers
  read a family's symbols across all of its hooks, as nftypes 0.1 did.

  Exported:
    - `priorityInts`     — `family → { symbol → int }`. Every symbolic
                           priority the family accepts at any hook.
    - `resolvePriority`  — `family → (int | symbol) → int`. Throws on a
                           symbol the family lacks.
    - `priorityNameOf`   — `family → (int | symbol) → (symbol | int)`.
                           The symbol for an int, or the int when no
                           symbol has its value; a symbol passes through.
    - `chainTypeFor`     — `family → hook → (int | symbol) →
                           (chainType | null)`. `"nat"` at `srcnat` or
                           `dstnat`, `"route"` at `mangle`, else
                           `"filter"`, falling back to `"filter"` where
                           nftypes' `validChainPlacement` rejects the
                           type. Null for a symbol the family lacks.
    - `hooksWithOifname` — the hooks where an `oifname` match can
                           succeed.

  Wired into the surface from `lib/internal/default.nix` as a layer-0
  leaf with no inter-module dependencies.
*/
{ inputs }:
let
  inherit (inputs) lib nftypes;
  inherit (nftypes.compatibility) prioritiesByFamily validChainPlacement;

  priorityInts = family: lib.mergeAttrsList (builtins.attrValues prioritiesByFamily.${family});

  resolvePriority =
    family: priority:
    let
      table = priorityInts family;
    in
    if builtins.isInt priority then
      priority
    else
      table.${priority}
        or (throw "nftzones: unknown priority symbol '${toString priority}' for family '${family}'. Valid symbols: ${builtins.concatStringsSep ", " (builtins.attrNames table)}.");

  priorityNameOf =
    family: priority:
    let
      table = priorityInts family;
      matching = builtins.filter (symbol: table.${symbol} == priority) (builtins.attrNames table);
    in
    if !(builtins.isInt priority) || matching == [ ] then priority else builtins.head matching;

  chainTypeFor =
    family: hook: priority:
    let
      table = priorityInts family;
      priorityInt = if builtins.isInt priority then priority else table.${priority} or null;
      classified =
        if priorityInt == (table.srcnat or null) || priorityInt == (table.dstnat or null) then
          "nat"
        else if priorityInt == (table.mangle or null) then
          "route"
        else
          "filter";
    in
    if priorityInt == null then
      null
    else if validChainPlacement family classified hook then
      classified
    else
      "filter";

  hooksWithOifname = [
    "forward"
    "output"
    "postrouting"
  ];
in
{
  inherit
    chainTypeFor
    hooksWithOifname
    priorityInts
    priorityNameOf
    resolvePriority
    ;
}
