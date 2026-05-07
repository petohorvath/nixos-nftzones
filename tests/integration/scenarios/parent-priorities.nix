/*
  Parent-priorities scenario — pre-child vs post-child slot
  semantics around the child-dispatch jump. The `early` rule
  (priority < 100) lands in dmz's preChildCells (fires before
  child dispatch); `late` (priority >= 100) lands in
  postChildCells (fires after child returns).
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq accept drop;
  inherit (nftypes.dsl.fields) tcp ip;
in
{
  body = {
    zones.dmz = {
      interfaces = [ "dmz0" ];
      cidrs = [ "10.0.0.0/24" ];
    };

    nodes.web-server = {
      zone = "dmz";
      address.ipv4 = "10.0.0.5";
    };

    filters = {
      early-block = {
        from = [ "dmz" ];
        to = [ "local" ];
        priority = "preDispatch";
        rule = [
          (eq ip.saddr "10.0.0.99")
          drop
        ];
      };

      late-rate-limit = {
        from = [ "dmz" ];
        to = [ "local" ];
        priority = "last";
        rule = [
          (eq tcp.dport 22)
          accept
        ];
      };

      web-server-http = {
        from = [ "web-server" ];
        to = [ "local" ];
        rule = [
          (eq tcp.dport 80)
          accept
        ];
      };
    };
  };

  assertions =
    compiled:
    let
      dmzRules = compiled.tables.parent-priorities.chains."input-at-filter__dmz-to-local".rules;
    in
    [
      {
        description = "dmz dispatcher has 3 rules (preChild + jump + postChild)";
        expr = builtins.length dmzRules;
        expected = 3;
      }
      {
        description = "preChild (early-block) fires first — at index 0, before child dispatch";
        expr = builtins.elemAt dmzRules 0;
        expected = [
          (eq ip.saddr "10.0.0.99")
          drop
        ];
      }
      {
        description = "postChild (late-rate-limit) fires last — at index 2, after child dispatch";
        expr = builtins.elemAt dmzRules 2;
        expected = [
          (eq tcp.dport 22)
          accept
        ];
      }
    ];
}
