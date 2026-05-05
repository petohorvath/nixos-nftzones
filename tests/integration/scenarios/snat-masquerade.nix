/*
  SNAT scenario — masquerade lan-out traffic. Lands in the
  postrouting@srcnat base chain with type=nat. Exercises the
  snat-via-rule.masquerade dispatch path.
*/
_:
{
  zones = {
    lan.interfaces = [ "lan0" ];
    wan.interfaces = [ "wan0" ];
  };

  snats.lan-out = {
    from = [ "lan" ];
    to = [ "wan" ];
    rule.masquerade = { };
  };
}
