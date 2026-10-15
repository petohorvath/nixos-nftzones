/*
  Rejection scenario for `settingsConflict` — the wildcardZone
  sentinel ("all" by default) matches a declared zone. The
  wildcard expands `from = [ wildcardZone ]` to every root
  plus localZone; if a real zone shares the name, dispatch
  cannot tell membership-by-zone from wildcard expansion.
  The equal-name case (wildcardZone == localZone) is covered
  by settings.nix; this one pins the shadow case.
*/
_: {
  description = "settingsConflict: wildcardZone shadows a declared zone";

  errors = [
    {
      tag = "settingsConflict";
      path = [
        "zones"
        "all"
      ];
    }
  ];

  body = {
    # Default wildcardZone is "all"; declaring zones.all is the
    # collision.
    zones.all.interfaces = [ "eth0" ];
  };
}
