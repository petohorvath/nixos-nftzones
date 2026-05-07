/*
  Rejection scenario for `checkSettings` — `localZone` and
  `wildcardZone` share the same name. The two play different
  semantic roles (one is the firewall machine itself; the other
  is a wildcard expansion target) and conflating them at
  dispatch-time would produce incoherent rules.
*/
_: {
  description = "checkSettings: localZone equals wildcardZone";

  body = {
    settings = {
      localZone = "anywhere";
      wildcardZone = "anywhere";
    };

    zones.lan.interfaces = [ "eth1" ];
  };
}
