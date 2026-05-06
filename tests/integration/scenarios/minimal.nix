/*
  Minimal scenario — one zone, no rules. Smoke-tests the
  render + `nft --check` pipeline itself: an empty table with a
  single set should parse cleanly.
*/
_: {
  zones.lan = {
    interfaces = [ "lan0" ];
  };
}
