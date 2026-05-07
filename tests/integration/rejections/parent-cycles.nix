/*
  Rejection scenario for `checkParentCycles` — three-zone cycle
  a → b → c → a in the parent chain. Without rejection, ancestor
  walks would loop indefinitely in downstream phases.
*/
_: {
  description = "checkParentCycles: three-zone parent cycle";

  body = {
    zones = {
      a = {
        interfaces = [ "eth1" ];
        parent = "b";
      };
      b = {
        interfaces = [ "eth2" ];
        parent = "c";
      };
      c = {
        interfaces = [ "eth3" ];
        parent = "a";
      };
    };
  };
}
