/*
  Source-route scenario — mark inbound packets from `guest` so a
  policy-routing rule outside nftables can steer them onto an
  alternate routing table. Lands in
  `prerouting-at-mangle__guest` as `type filter` (the kernel
  reserves `type route` for the `output` hook; mark-set at
  prerouting then `ip rule` is the kernel-correct shape for
  forwarded traffic). Exercises the sroute group dispatch path
  end-to-end.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;
in
{
  zones.guest = {
    interfaces = [ "guest0" ];
    cidrs = [ "10.0.1.0/24" ];
  };

  sroutes.guest-via-vpn = {
    from = [ "guest" ];
    rule = [ (mangle meta.mark 100) ];
    comment = "guest traffic policy-routed via VPN";
  };
}
