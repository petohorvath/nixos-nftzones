/*
  Rejection scenario for `checkChainPlacement` — bridge family
  with an snat rule. Bridge family doesn't support `nat` chain
  type at the kernel level; without rejection, the rendered
  ruleset would parse but fail at `nft -f` time.
*/
{ nftypes }:
{
  description = "checkChainPlacement: bridge family + snat (no nat support)";

  body = {
    family = "bridge";

    zones = {
      lan.interfaces = [ "br0" ];
      wan.interfaces = [ "br1" ];
    };

    snats.bad-bridge-nat = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule.masquerade = { };
    };
  };
}
