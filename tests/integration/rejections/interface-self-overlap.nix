/*
  Rejection scenario for `interfaceOverlap` — a single
  zone lists the same interface twice in its `interfaces`
  list. Probably a copy-paste typo; without rejection the
  duplicate sits silently in the rendered `<zone>_iifs` set.
  The complementary case (two zones sharing an interface) is
  covered by interface-overlap.nix.
*/
_: {
  description = "interfaceOverlap: zone lists same interface twice";

  errors = [
    {
      tag = "interfaceOverlap";
      path = [
        "zones"
        "lan"
        "interfaces"
      ];
    }
  ];

  body = {
    zones.lan.interfaces = [
      "eth1"
      "eth1"
    ];
  };
}
