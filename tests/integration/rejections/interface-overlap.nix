/*
  Rejection scenario for `checkInterfaceOverlap` — two unrelated
  zones both claim `eth1`. Without rejection, packets matching
  the shared interface get whichever zone's chain is jumped to
  first, silently breaking the intended policy split.
*/
_: {
  description = "checkInterfaceOverlap: two unrelated zones share an interface";

  body = {
    zones = {
      lan.interfaces = [ "eth1" ];
      guest.interfaces = [ "eth1" ];
    };
  };
}
