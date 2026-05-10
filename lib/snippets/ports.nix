/*
  snippets/ports — port-input normalization for `nftzones.snippets.*`.

  Accepts a port input in any of the shapes documented in
  `docs/plans/snippets.md` and returns a canonical sorted, deduped
  list of elements where each element is either a bare int (single
  port) or a `nftypes.dsl.expr.range`-shaped attrset (`{ range = [
  lo hi ]; }`) ready to splice into an `eq` / `within` / `inSet`
  call.

  Validation routes through `libnet.port` / `libnet.portRange` so
  out-of-range and malformed inputs throw with libnet's own error
  messages.

  ===== normalizePorts =====

  Inputs:
    ports — int | string | libnet.port-value | libnet.portRange-value
            | list of any of the above.

  Output:
    Sorted, deduped list of canonical elements:
      - int            (a single port)
      - { range = [lo hi]; }  (a port range, lo < hi)

  Singleton ranges (where libnet's `portRange.parse "22"` produces
  `{ from = 22; to = 22; }`) collapse to bare ints. This keeps the
  emitted nftables text minimal — never `tcp dport 22-22`.

  Sort is by lower-bound (ints by value; ranges by `from`); dedupe
  is by exact equality. Overlapping non-identical ranges are
  preserved as-is — merging would change semantics and requires
  `libnet.portRange.merge`, which is deferred until a real consumer
  asks for it.
*/
{ inputs }:
let
  inherit (inputs) lib libnet;
  inherit (libnet) port portRange;

  /*
    ===== portRangeToCanonical =====

    Collapse a `libnet.portRange` value to either a bare int (when
    `from == to`) or the `{ range = [lo hi]; }` shape that
    `nftypes.dsl.expr.range` produces. Both forms are valid set /
    match operands; the bare-int form is preferred for singletons
    so emitted text reads as `tcp dport 22` rather than
    `tcp dport 22-22`.
  */
  portRangeToCanonical =
    pr:
    if pr.from == pr.to then
      pr.from
    else
      {
        range = [
          pr.from
          pr.to
        ];
      };

  /*
    ===== normalizeOne =====

    Convert one user-supplied port element to its canonical form.
    Routes ints through `libnet.port.fromInt` and strings through
    `libnet.portRange.parse` so libnet owns all validation; libnet
    values pass through unwrap / collapse only.
  */
  normalizeOne =
    x:
    if builtins.isInt x then
      port.toInt (port.fromInt x)
    else if builtins.isString x then
      portRangeToCanonical (portRange.parse x)
    else if builtins.isAttrs x && port.is x then
      port.toInt x
    else if builtins.isAttrs x && portRange.is x then
      portRangeToCanonical x
    else
      throw "snippets: ports element must be an int, string, libnet.port, or libnet.portRange — got ${builtins.typeOf x}";

  /*
    ===== sortKey =====

    Total order on canonical elements: ints by value, ranges by
    their lower bound. Stable enough for dedupe; full equality is
    used for the dedupe pass after sort.
  */
  sortKey = x: if builtins.isInt x then x else builtins.elemAt x.range 0;

  /*
    ===== normalizePorts =====

    Public entry. Wraps non-list input in a list, normalizes per
    element, sorts by lower-bound, dedupes by exact equality.
  */
  normalizePorts =
    ports:
    let
      asList = if builtins.isList ports then ports else [ ports ];
      normalized = map normalizeOne asList;
      sorted = lib.sort (a: b: sortKey a < sortKey b) normalized;
    in
    lib.unique sorted;
in
{
  inherit normalizePorts;
}
