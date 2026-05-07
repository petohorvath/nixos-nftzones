/*
  Rejection scenario for `checkParentRefs` — a zone declares a
  `parent` that doesn't exist in the same zones attrset. The
  validator must reject this; if disconnected, parent dispatch
  would silently fail at runtime (the child would be unreachable
  via its non-existent parent's chain).
*/
_: {
  description = "checkParentRefs: zone references unknown parent";

  body = {
    zones.guests = {
      interfaces = [ "eth1" ];
      parent = "nonexistent";
    };
  };
}
