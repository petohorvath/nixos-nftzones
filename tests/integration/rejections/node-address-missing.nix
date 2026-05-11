/*
  Rejection scenario for `checkNodeAddresses` — a node with both
  `ipv4` and `ipv6` set to `null` produces no CIDR when lowered to
  a zone, leaving the zone unmatchable. The type accepts both-null
  (each field defaults to `null`); the validator catches it during
  Phase 1 so the error aggregates rather than throwing at type-
  apply time.
*/
_: {
  description = "checkNodeAddresses: node.address with both ipv4 and ipv6 null";

  body = {
    zones.dmz.interfaces = [ "dmz0" ];

    nodes.web = {
      zone = "dmz";
      address = { };
    };
  };
}
