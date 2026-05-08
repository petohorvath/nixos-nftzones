/*
  Rejection scenario for `checkChainPlacement` — bridge family
  with one *valid* filter alongside an *invalid* snat in the same
  table. Pins that checkChainPlacement iterates every entry and
  doesn't short-circuit on the first valid placement: the snat
  must still be rejected even when a sibling filter compiles.
*/
{ nftypes }:
{
  description = "checkChainPlacement: bridge filter (valid) + snat (invalid) in one table";

  body = {
    family = "bridge";

    zones = {
      lan.interfaces = [ "br0" ];
      wan.interfaces = [ "br1" ];
    };

    # Valid for bridge family.
    filters.allow-lan = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ nftypes.dsl.accept ];
    };

    # Invalid: bridge has no nat support.
    snats.bad-bridge-nat = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule.masquerade = { };
    };
  };
}
