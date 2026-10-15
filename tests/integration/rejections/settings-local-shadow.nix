/*
  Rejection scenario for `settingsConflict` — the localZone
  sentinel ("local" by default) matches a declared zone or
  node. The localZone is the chain-dispatch trigger for input
  and output hooks; if a real zone or node shares the name,
  dispatch routing becomes ambiguous.
*/
_: {
  description = "settingsConflict: localZone shadows a declared node";

  errors = [
    {
      tag = "settingsConflict";
      path = [
        "nodes"
        "local"
      ];
    }
  ];

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
