/*
  Rejection scenario for `zoneNameCollision` — a node and a
  zone share a name. The lowering would silently overwrite one
  with the other in the zone namespace; Phase 1 must reject so
  the user fixes the ambiguity.

  The lowered node clobbers the zone, so the node's `zone = "web"`
  also reads as a self-parent cycle. The expected errors pin that
  cascade (#7); fixing the clobber removes the second error.
*/
_: {
  description = "zoneNameCollision: node name collides with zone name";

  errors = [
    {
      tag = "zoneNameCollision";
      path = [
        "nodes"
        "web"
      ];
    }
    {
      tag = "zoneParentCycle";
      path = [
        "zones"
        "web"
        "parent"
      ];
    }
  ];

  body = {
    zones.web = {
      interfaces = [ "eth1" ];
    };

    nodes.web = {
      zone = "web";
      address.ipv4 = "10.0.0.5";
    };
  };
}
