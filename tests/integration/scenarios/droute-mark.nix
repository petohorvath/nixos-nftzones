/*
  Destination-route scenario — mark locally-generated packets
  bound for `lan-remote` so a downstream policy-routing rule can
  steer them through a VPN tunnel. Lands in
  `output-at-mangle__lan-remote` with `type route`. Exercises
  the droute group dispatch path end-to-end.

  Caveat: `nftypes.compatibility.familiesByChainType` lists
  `route` as `[ "ip" "ip6" ]` (no `inet`), but the LKL kernel in
  this sandbox accepts `inet route` at `output`. Whether real
  kernels also accept it is an open question tracked in the
  upstream prompt at `../nix-nftypes/prompt-fix.md` §3.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;
in
{
  body = {
    zones.lan-remote = {
      cidrs = [ "10.99.0.0/16" ];
    };

    droutes.lan-remote-via-vpn = {
      to = [ "lan-remote" ];
      rule = [ (mangle meta.mark 200) ];
      comment = "local traffic to remote-lan via VPN";
    };
  };

  assertions = compiled: [
    {
      description = "droute lands at output-at-mangle__lan-remote";
      expr = compiled.tables.droute-mark.chains ? "output-at-mangle__lan-remote";
      expected = true;
    }
    {
      description = "base chain type is route (output-hook routing decision tap)";
      expr = compiled.tables.droute-mark.chains."output-at-mangle".type;
      expected = "route";
    }
    {
      description = "rule comment surfaces on the rendered rule";
      expr =
        (builtins.elemAt compiled.tables.droute-mark.chains."output-at-mangle__lan-remote".rules 0).comment;
      expected = "local traffic to remote-lan via VPN";
    }
  ];
}
