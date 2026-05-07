/*
  Rejection scenario for `checkCidrOverlap` — two unrelated
  zones with overlapping CIDR prefixes. Without rejection,
  packets from the overlap range match both zones' v4 sets and
  the dispatcher's first jump wins.
*/
_: {
  description = "checkCidrOverlap: two unrelated zones overlap CIDRs";

  body = {
    zones = {
      lan.cidrs = [ "10.0.0.0/24" ];
      mgmt.cidrs = [ "10.0.0.0/28" ];
    };
  };
}
