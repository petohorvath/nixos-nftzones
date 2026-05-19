/*
  Destination-route scenario — two droutes mark locally-
  generated traffic bound for two different remote networks
  with distinct marks. Exercises the multi-entry fanout
  inside the `droutes` group (multiple sub-chains under one
  `output-at-mangle` base chain) plus the per-entry
  comment-bearing rule shape, complementing `droute-mark.nix`
  which only covers a single entry.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) mangle;
  inherit (nftypes.dsl.fields) meta;
in
{
  body = {
    zones = {
      remote-east.cidrs = [ "10.10.0.0/16" ];
      remote-west.cidrs = [ "10.20.0.0/16" ];
    };

    droutes = {
      east-via-vpn-a = {
        to = [ "remote-east" ];
        rule = [ (mangle meta.mark 300) ];
        comment = "east via tunnel A";
      };
      west-via-vpn-b = {
        to = [ "remote-west" ];
        rule = [ (mangle meta.mark 400) ];
        comment = "west via tunnel B";
      };
    };
  };

  assertions = compiled: [
    {
      description = "remote-east sub-chain present at output-at-mangle";
      expr = compiled.tables.droute-multi-zone.chains ? "output-at-mangle__remote-east";
      expected = true;
    }
    {
      description = "remote-west sub-chain present at output-at-mangle";
      expr = compiled.tables.droute-multi-zone.chains ? "output-at-mangle__remote-west";
      expected = true;
    }
    {
      description = "base chain type is route";
      expr = compiled.tables.droute-multi-zone.chains."output-at-mangle".type;
      expected = "route";
    }
    {
      description = "east rule comment surfaces on the rendered rule";
      expr =
        (builtins.elemAt compiled.tables.droute-multi-zone.chains."output-at-mangle__remote-east".rules 0)
        .comment;
      expected = "east via tunnel A";
    }
    {
      description = "west rule body marks with 400";
      expr =
        (builtins.elemAt compiled.tables.droute-multi-zone.chains."output-at-mangle__remote-west".rules 0)
        .expr;
      expected = [ (mangle meta.mark 400) ];
    }
  ];
}
