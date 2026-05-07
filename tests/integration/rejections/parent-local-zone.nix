/*
  Rejection scenario for `checkParentRefs` — a zone declares
  `parent = localZone`. The localZone sentinel represents the
  firewall machine itself and is reserved for chain dispatch
  (input / output hooks); it cannot anchor a zone hierarchy.
  Phase 4 would otherwise try to emit jumps into a slot that
  isn't a parent chain. The complementary case (parent
  references unknown zone) is covered by parent-refs.nix.
*/
_: {
  description = "checkParentRefs: zone parent is the localZone sentinel";

  body = {
    zones.web = {
      cidrs = [ "10.0.0.5/32" ];
      parent = "local";
    };
  };
}
