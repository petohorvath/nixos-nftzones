/*
  Source-route scenario — two sroutes mark traffic from two
  different zones with two different marks. Exercises the
  multi-entry fanout inside the `sroutes` group (multiple
  sub-chains under one `prerouting-at-mangle` base chain) and
  the per-entry rule-body distinction, complementing
  `sroute-mark.nix` which only covers a single entry.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;
in
{
  body = {
    zones = {
      guest = {
        interfaces = [ "guest0" ];
        cidrs = [ "10.0.1.0/24" ];
      };
      iot = {
        interfaces = [ "iot0" ];
        cidrs = [ "10.0.2.0/24" ];
      };
    };

    sroutes = {
      guest-via-vpn = {
        from = [ "guest" ];
        rule = [ (mangle meta.mark 100) ];
      };
      iot-isolated = {
        from = [ "iot" ];
        rule = [ (mangle meta.mark 200) ];
      };
    };
  };

  assertions = compiled: [
    {
      description = "guest sub-chain present at prerouting-at-mangle";
      expr = compiled.tables.sroute-multi-zone.chains ? "prerouting-at-mangle__guest";
      expected = true;
    }
    {
      description = "iot sub-chain present at prerouting-at-mangle";
      expr = compiled.tables.sroute-multi-zone.chains ? "prerouting-at-mangle__iot";
      expected = true;
    }
    {
      description = "guest rule marks with 100";
      expr =
        builtins.elemAt compiled.tables.sroute-multi-zone.chains."prerouting-at-mangle__guest".rules
          0;
      expected = [ (mangle meta.mark 100) ];
    }
    {
      description = "iot rule marks with 200 (distinct from guest)";
      expr = builtins.elemAt compiled.tables.sroute-multi-zone.chains."prerouting-at-mangle__iot".rules 0;
      expected = [ (mangle meta.mark 200) ];
    }
  ];
}
