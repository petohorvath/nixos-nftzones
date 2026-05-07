/*
  Rejection scenario for `checkInterfaceOverlap` — a single
  zone lists the same interface twice in its `interfaces`
  list. Probably a copy-paste typo; without rejection the
  duplicate sits silently in the rendered `<zone>_iifs` set.
  The complementary case (two zones sharing an interface) is
  covered by interface-overlap.nix.
*/
_: {
  description = "checkInterfaceOverlap: zone lists same interface twice";

  body = {
    zones.lan.interfaces = [
      "eth1"
      "eth1"
    ];
  };
}
