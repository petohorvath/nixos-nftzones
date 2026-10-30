/*
  Rejection scenario for `nodeAddressMissing` — a node with both
  `ipv4` and `ipv6` set to `null` produces no CIDR when lowered to
  a zone, leaving the zone unmatchable. The type accepts both-null
  (each field defaults to `null`); Phase 1 catches it, so the
  error aggregates rather than throwing at type-apply time.
*/
_: {
  description = "nodeAddressMissing: node.address with both ipv4 and ipv6 null";

  errors = [
    {
      tag = "nodeAddressMissing";
      path = [
        "nodes"
        "web"
      ];
    }
  ];

  body = {
    zones.dmz.interfaces = [ "dmz0" ];

    nodes.web = {
      parent = "dmz";
      address = { };
    };
  };
}
