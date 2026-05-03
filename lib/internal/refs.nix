/*
  internal/refs — extracts named-object references from rule bodies,
  exposed under `nftzones.internal.refs`.

  Consumed by `internal.normalize.checkObjectRefs` (Phase 1) to
  verify every named ref in a user's rule body resolves to a key
  in `table.objects.<kind>`. Independent helper so the walker can
  be unit-tested without booting Phase 1.

  ===== extractRefs =====

  Inputs:
    value — any subtree of a rule body (a list of statements, a
            single statement, an expression, or a primitive). The
            walker recurses uniformly over lists and attrsets and
            ignores primitives.

  Output:
    A list of `{ kind; name; }` records, one per named ref found.
    `kind` is the `table.objects.<kind>` plural key (e.g.
    `"counters"`, `"ctHelpers"`, `"flowtables"`) — chosen so the
    caller can resolve refs as `table.objects.${kind} ? ${name}`.

  Recognized patterns (all produced by `nftypes.dsl.*` helpers —
  see `tests/unit/internal/refs.nix` for the spike that confirmed
  each shape):

    String-bodied statement refs (single-key attrset, body is str)
      { counter         = "n"; }  → { kind = "counters";       …}
      { quota           = "n"; }  → { kind = "quotas";         …}
      { limit           = "n"; }  → { kind = "limits";         …}
      { secmark         = "n"; }  → { kind = "secmarks";       …}
      { tunnel          = "n"; }  → { kind = "tunnels";        …}
      { synproxy        = "n"; }  → { kind = "synproxies";     …}
      { "ct helper"     = "n"; }  → { kind = "ctHelpers";      …}
      { "ct timeout"    = "n"; }  → { kind = "ctTimeouts";     …}
      { "ct expectation"= "n"; }  → { kind = "ctExpectations"; …}

    Attrset-bodied refs (named field inside the body)
      { set  = { op; elem; set = "n"; }; }      → sets       (set statement)
      { map  = { op; elem; data; map = "n"; }; }→ maps       (map statement)
      { flow = { op; flowtable = "n"; }; }      → flowtables (flow statement)

    Expression-level refs (single-key attrset, recursed under
    `match.right`, `vmap.data`, etc.)
      { set  = "n"; }                           → sets  (named set lookup)
      { map  = { key; data = "n"; }; }          → maps  (named map lookup)
      { vmap = { key; data = "n"; }; }          → maps  (vmap statement)

  Disambiguation between statement-`set`/-`map` and expression-
  `set`/-`map` (which share the outer key) is done by inspecting
  the body shape: statement form is an attrset carrying an `op`
  field; expression `set` is either a string (named) or a list
  (anonymous); expression `map` is `{ key; data; }`.

  Recursion: the walker descends into every attrset value and
  every list element after extracting at the current level, so
  nested refs (e.g. a set lookup inside a `match.right`, or a
  named ref inside `set` statement's `stmt` sub-list) are picked
  up automatically. Primitives (strings, ints, nulls, booleans)
  are leaves with no refs.
*/
{ inputs }:
let
  inherit (inputs) lib;

  /*
    Detect named-ref patterns at THIS attrset level only. Nested
    refs (sub-statements, sub-expressions) are picked up by the
    recursive `walkValue` over the attrset's values.
  */
  refsAtAttrs =
    v:
    let
      keys = builtins.attrNames v;
      isSingleton = tag: keys == [ tag ];

      stringRef =
        kind: tag:
        lib.optional (isSingleton tag && builtins.isString v.${tag}) {
          inherit kind;
          name = v.${tag};
        };

      setRef =
        # `set` key carries either an expression form (string =
        # named lookup, list = anonymous) or a statement form
        # (attrset with `op`, `elem`, `set`). Statement form's
        # named-set field is `body.set` (same key, nested).
        let
          body = v.set or null;
        in
        if !(isSingleton "set") then
          [ ]
        else if builtins.isString body then
          [
            {
              kind = "sets";
              name = body;
            }
          ]
        else if builtins.isAttrs body && body ? set then
          [
            {
              kind = "sets";
              name = body.set;
            }
          ]
        else
          [ ];

      mapRef =
        # `map` key: statement form (attrset with `op` AND a
        # `map` field) or expression form (attrset with `key` /
        # `data`). Statement: ref is `body.map`. Expression: ref
        # is `body.data` if string.
        let
          body = v.map or null;
        in
        if !(isSingleton "map") || !(builtins.isAttrs body) then
          [ ]
        else if body ? map then
          [
            {
              kind = "maps";
              name = body.map;
            }
          ]
        else if (body ? data) && builtins.isString body.data then
          [
            {
              kind = "maps";
              name = body.data;
            }
          ]
        else
          [ ];

      vmapRef =
        let
          body = v.vmap or null;
        in
        lib.optional (
          isSingleton "vmap"
          && builtins.isAttrs body
          && (body ? data)
          && builtins.isString body.data
        ) {
          kind = "maps";
          name = body.data;
        };

      flowRef =
        let
          body = v.flow or null;
        in
        lib.optional (
          isSingleton "flow" && builtins.isAttrs body && (body ? flowtable)
        ) {
          kind = "flowtables";
          name = body.flowtable;
        };
    in
    lib.concatLists [
      (stringRef "counters" "counter")
      (stringRef "quotas" "quota")
      (stringRef "limits" "limit")
      (stringRef "secmarks" "secmark")
      (stringRef "tunnels" "tunnel")
      (stringRef "synproxies" "synproxy")
      (stringRef "ctHelpers" "ct helper")
      (stringRef "ctTimeouts" "ct timeout")
      (stringRef "ctExpectations" "ct expectation")
      setRef
      mapRef
      vmapRef
      flowRef
    ];

  /*
    Recursively walk any value. Lists fan out, attrsets are
    inspected for ref patterns then their values are recursed,
    primitives terminate. Returns a flat list of refs.
  */
  walkValue =
    v:
    if builtins.isList v then
      lib.concatMap walkValue v
    else if builtins.isAttrs v then
      refsAtAttrs v ++ lib.concatMap walkValue (builtins.attrValues v)
    else
      [ ];

  extractRefs = walkValue;
in
{
  inherit extractRefs;
}
