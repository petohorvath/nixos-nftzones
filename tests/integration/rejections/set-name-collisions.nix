/*
  Rejection scenario for `checkSetNameCollisions` — user declares
  `objects.sets.lan_iifs`, which collides with the auto-generated
  zone-derived set name for the `lan` zone's interfaces. Without
  rejection, Phase 4's `assembleOutput` merges both into one
  `body.sets`; the user-declared set silently wins, breaking
  every jump rule that referenced the auto set.
*/
_: {
  description = "checkSetNameCollisions: user set name matches auto zone-derived set name";

  body = {
    zones.lan = {
      interfaces = [ "eth1" ];
    };

    objects.sets.lan_iifs = {
      type = "ipv4_addr";
      flags = [ "interval" ];
    };
  };
}
