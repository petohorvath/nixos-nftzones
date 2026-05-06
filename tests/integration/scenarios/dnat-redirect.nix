/*
  DNAT redirect scenario — bounce inbound port 2222 to the
  firewall's local sshd on port 22. Single-direction (`from`
  only) lands in prerouting@dstnat with `type nat`. Exercises
  the `action.redirect` rule-body emission path (distinct from
  `action.dnat` which uses a `natBody`-shaped target).
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq;
  inherit (nftypes.dsl.fields) tcp;
in
{
  zones.wan.interfaces = [ "wan0" ];

  dnats.ssh-redirect = {
    from = [ "wan" ];
    rule = {
      match = [ (eq tcp.dport 2222) ];
      action.redirect = { port = 22; };
    };
    comment = "expose sshd via 2222";
  };
}
