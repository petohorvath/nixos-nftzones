/*
  Rejection scenario for the removed `nodes.<name>.zone` option. A
  node names its parent zone with `parent`, as a zone does; `zone`
  was renamed without an alias, so a stale configuration must fail
  at evaluation instead of compiling silently. The node type rejects
  the unknown option before Phase 1 runs, so this checks only the
  throw.
*/
_: {
  description = "node type: rejects the removed `zone` option";

  body = {
    zones.dmz.interfaces = [ "dmz0" ];
    nodes.web = {
      zone = "dmz";
      address.ipv4 = "10.0.0.5";
    };
  };
}
