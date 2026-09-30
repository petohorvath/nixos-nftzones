/*
  snippets/ports — port-input normalization for `nftzones.snippets.*`.

  Accepts a port input in any of the shapes `nftzones.snippets`
  documents and returns a canonical sorted, deduped list of elements
  where each element is either a bare int (single port) or a
  `nftypes.dsl.expr.range`-shaped attrset (`{ range = [ lo hi ]; }`)
  ready to splice into an `eq` / `within` / `inSet` call.

  Validation routes through `libnet.port` / `libnet.portRange` so
  out-of-range and malformed inputs throw with libnet's own error
  messages.
*/
{ inputs }:
let
  inherit (inputs) lib libnet;
  inherit (libnet) port portRange;

  /*
    Collapse a `libnet.portRange` value to either a bare int (when
    `from == to`) or the `{ range = [lo hi]; }` shape that
    `nftypes.dsl.expr.range` produces. `range.from` / `range.to` are
    tagged `libnet.port` values, so unwrap them through `port.toInt`
    before comparing / emitting. Both forms are valid set / match
    operands; the bare-int form is preferred for singletons so
    emitted text reads as `tcp dport 22` rather than `tcp dport
    22-22`.
  */
  portRangeToCanonical =
    range:
    let
      from = port.toInt range.from;
      to = port.toInt range.to;
    in
    if from == to then
      from
    else
      {
        range = [
          from
          to
        ];
      };

  /*
    Convert one user-supplied port element to its canonical form.
    Routes ints through `libnet.port.fromInt` and strings through
    `libnet.portRange.parse` so libnet owns all validation; libnet
    values pass through unwrap / collapse only.
  */
  normalizePort =
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

  # Sort key for canonical elements: ints by value, ranges by their lower
  # bound. Ties are fine; the dedupe pass after sorting uses full equality.
  lowerBound = x: if builtins.isInt x then x else builtins.elemAt x.range 0;

  /*
    Normalize user port input for the snippet match builders.

    Inputs:
      ports — int | string | libnet.port-value | libnet.portRange-value
              | list of any of the above.

    Returns a list sorted by lower bound (ints by value; ranges by
    `from`) and deduped by exact equality, with elements:
      - int                   (a single port)
      - { range = [lo hi]; }  (a port range, lo < hi)

    Singleton ranges (where libnet's `portRange.parse "22"` produces
    a range whose `from` and `to` are the same `libnet.port` value)
    collapse to bare ints. This keeps the emitted nftables text
    minimal — never `tcp dport 22-22`. Overlapping non-identical
    ranges are preserved as-is — merging would change semantics and
    requires `libnet.portRange.merge`, which is deferred until a real
    consumer asks for it.
  */
  normalizePorts =
    ports:
    lib.pipe ports [
      lib.toList
      (map normalizePort)
      (lib.sort (a: b: lowerBound a < lowerBound b))
      lib.unique
    ];
in
{
  inherit normalizePorts;
}
