/*
  internal/refs — extracts named-object references from rule bodies,
  exposed under `nftzones.internal.refs`.

  Consumed by `internal.normalize.checkObjectRefs` (Phase 1) to
  verify every named ref in a user's rule body resolves to a key
  in `table.objects.<kind>`. Independent helper so the walker can
  be unit-tested without booting Phase 1.
*/
{ inputs }:
let
  inherit (inputs) lib;

  # Named-reference strings in expression position carry a leading
  # `@` per libnftables-JSON convention (e.g. `{ set = "@blocklist"; }`).
  # Statement-form names are bare. Strip the prefix uniformly so
  # refs match `table.objects.<kind>.<name>` keys regardless of
  # which DSL form produced them. `removePrefix` is a no-op when
  # the prefix is absent, so no guard is needed.
  stripAt = lib.removePrefix "@";

  /*
    Detect named-ref patterns at THIS attrset level only. Nested
    refs (sub-statements, sub-expressions) are picked up by the
    recursive `extractRefs` over the attrset's values.
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
              name = stripAt body;
            }
          ]
        else if builtins.isAttrs body && body ? set then
          [
            {
              kind = "sets";
              name = stripAt body.set;
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
              name = stripAt body.map;
            }
          ]
        else if (body ? data) && builtins.isString body.data then
          [
            {
              kind = "maps";
              name = stripAt body.data;
            }
          ]
        else
          [ ];

      vmapRef =
        let
          body = v.vmap or null;
        in
        lib.optional
          (isSingleton "vmap" && builtins.isAttrs body && (body ? data) && builtins.isString body.data)
          {
            kind = "maps";
            name = stripAt body.data;
          };

      flowRef =
        let
          body = v.flow or null;
        in
        lib.optional (isSingleton "flow" && builtins.isAttrs body && (body ? flowtable)) {
          kind = "flowtables";
          name = stripAt body.flowtable;
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
  extractRefs =
    v:
    if builtins.isList v then
      lib.concatMap extractRefs v
    else if builtins.isAttrs v then
      refsAtAttrs v ++ lib.concatMap extractRefs (builtins.attrValues v)
    else
      [ ];
in
{
  inherit extractRefs;
}
