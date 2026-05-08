/*
  Rejection scenario for `checkChainPlacement` — bridge family
  with a droute rule. Symmetric to chain-placement-bridge-sroute:
  bridge has no `mangle` priority symbol, so destination-route
  mangling is unsupported at the kernel level. Pins that
  checkChainPlacement walks the droute group too, not just sroute.
*/
_: {
  description = "checkChainPlacement: bridge family + droute (no mangle priority)";

  body = {
    family = "bridge";

    zones.lan.interfaces = [ "br0" ];

    droutes.mark-it = {
      to = [ "lan" ];
      rule = [ ];
    };
  };
}
