/*
  Rejection scenario for `zoneParentUnknown` — a zone declares a
  `parent` that doesn't exist in the same zones attrset. Phase 1
  must reject this; otherwise parent dispatch would silently fail
  at runtime (the child would be unreachable via its non-existent
  parent's chain).
*/
_: {
  description = "zoneParentUnknown: zone references unknown parent";

  errors = [
    {
      tag = "zoneParentUnknown";
      path = [
        "zones"
        "guests"
        "parent"
      ];
    }
  ];

  body = {
    zones.guests = {
      interfaces = [ "eth1" ];
      parent = "nonexistent";
    };
  };
}
