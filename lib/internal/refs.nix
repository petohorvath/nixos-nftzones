/*
  internal/refs — extracts named-object references from rule bodies,
  exposed under `nftzones.internal.refs`.

  Consumed by Phase 1's object-reference validator, which reports
  an `objectRefUnknown` diagnostic for every named ref in a user's
  rule body that does not resolve to a key in `table.objects.<kind>`.
  Independent helper so the walker can be unit-tested without
  booting Phase 1.
*/
{ inputs }:
let
  inherit (inputs) lib;

  # Named-reference strings in expression position carry a leading
  # `@` per libnftables-JSON convention (e.g. a match `right` of
  # `"@blocklist"`). Statement-form names are bare. Strip the prefix
  # uniformly so refs match `table.objects.<kind>.<name>` keys regardless of
  # which DSL form produced them. `removePrefix` is a no-op when
  # the prefix is absent, so no guard is needed.
  stripAt = lib.removePrefix "@";

  namedSetRef = name: {
    kind = "sets";
    name = stripAt name;
  };

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
        # named lookup in raw libnftables JSON, list = anonymous) or
        # a statement form (attrset with `op`, `elem`, `set`).
        # Statement form's named-set field is `body.set` (same key,
        # nested). The DSL builds named lookups as a bare `"@name"`
        # match operand instead, which `matchRef` handles.
        let
          body = v.set or null;
        in
        if !(isSingleton "set") then
          [ ]
        else if builtins.isString body then
          [ (namedSetRef body) ]
        else if builtins.isAttrs body && body ? set then
          [ (namedSetRef body.set) ]
        else
          [ ];

      # A match whose right side is an `@name` string looks the
      # packet up in a named set, as `dsl.inSet` and
      # `dsl.expr.setRef` build it.
      matchRef =
        let
          body = v.match or null;
          right = body.right or null;
        in
        lib.optional (
          isSingleton "match" && builtins.isAttrs body && builtins.isString right && lib.hasPrefix "@" right
        ) (namedSetRef right);

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
      matchRef
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
