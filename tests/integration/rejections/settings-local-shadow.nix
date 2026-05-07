/*
  Rejection scenario for `checkSettings` — the localZone
  sentinel ("local" by default) matches a declared zone or
  node. The localZone is the chain-dispatch trigger for input
  and output hooks; if a real zone or node shares the name,
  dispatch routing becomes ambiguous.
*/
_: {
  description = "checkSettings: localZone shadows a declared node";

  body = {
    zones.lan.interfaces = [ "eth1" ];
    # Default localZone is "local"; lowering nodes.local to a
    # zone named "local" is the collision.
    nodes.local = {
      zone = "lan";
      address.ipv4 = "10.0.0.1";
    };
  };
}
