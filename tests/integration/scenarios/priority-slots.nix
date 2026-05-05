/*
  Priority-slots scenario — one entry per slot (preDispatch /
  subChain / postDispatch) in a single chain. Validates that the
  base-chain rule order (stateful → preDispatch → jumps →
  postDispatch) renders into a syntactically valid chain.
*/
{ nftypes }:
let
  inherit (nftypes.dsl) accept;
in
{
  zones = {
    lan.interfaces = [ "lan0" ];
    wan.interfaces = [ "wan0" ];
  };

  filters = {
    early = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ accept ];
      priority = "first";
    };
    regular = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ accept ];
    };
    late = {
      from = [ "lan" ];
      to = [ "wan" ];
      rule = [ accept ];
      priority = "last";
    };
  };
}
