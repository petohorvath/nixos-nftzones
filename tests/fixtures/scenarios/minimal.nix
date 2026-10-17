/*
  Minimal scenario — one zone, no rules. Smoke-tests the
  render + `nft --check` pipeline itself: an empty table with a
  single set should parse cleanly. Assertions pin the table name
  and the auto-generated zone set.
*/
_: {
  body = {
    zones.lan = {
      interfaces = [ "lan0" ];
    };
  };

  assertions = compiled: [
    {
      description = "table renders with the scenario name";
      expr = compiled.tables.minimal.name;
      expected = "minimal";
    }
    {
      description = "zone with interfaces produces an iifs set";
      expr = compiled.tables.minimal.sets ? lan_iifs;
      expected = true;
    }
    {
      description = "no chains emitted when no rules are declared";
      expr = compiled.tables.minimal ? chains;
      expected = false;
    }
  ];
}
