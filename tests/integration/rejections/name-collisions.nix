/*
  Rejection scenario for `checkNameCollisions` — a node and a
  zone share a name. The lowering would silently overwrite one
  with the other in `mergedZones`; the validator must reject so
  the user fixes the ambiguity.
*/
_: {
  description = "checkNameCollisions: node name collides with zone name";

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
