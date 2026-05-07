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
  body = {
    zones.guest = {
      interfaces = [ "guest0" ];
      cidrs = [ "10.0.1.0/24" ];
    };

    sroutes.guest-via-vpn = {
      from = [ "guest" ];
      rule = [ (mangle meta.mark 100) ];
      comment = "guest traffic policy-routed via VPN";
    };
  };

  assertions = compiled: [
    {
      description = "sroute lands at prerouting-at-mangle__guest";
      expr = compiled.tables.sroute-mark.chains ? "prerouting-at-mangle__guest";
      expected = true;
    }
    {
      description = "base chain type is filter (mangle priority on filter type)";
      expr = compiled.tables.sroute-mark.chains."prerouting-at-mangle".type;
      expected = "filter";
    }
    {
      description = "rule body is the bare mangle statement, comment-wrapped";
      expr = builtins.elemAt compiled.tables.sroute-mark.chains."prerouting-at-mangle__guest".rules 0;
      expected = {
        expr = [ (mangle meta.mark 100) ];
        comment = "guest traffic policy-routed via VPN";
      };
    }
  ];
}
