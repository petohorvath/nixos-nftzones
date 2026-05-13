/*
  Log-statement scenario — pins that `nftypes.dsl.log` in a
  rule body survives the emit pipeline unchanged. nftzones'
  compile phases (normalize → expand → dispatch → emit) all
  see the rule's `expr` list; none of them should strip,
  rewrite, or reorder the `log` statement out of existence.
  Without an explicit test, a future refactor that filters
  statements by some property could silently drop logs and
  no compile-time assertion would catch it.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl)
    eq
    accept
    log
    ;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    zones.wan.interfaces = [ "wan0" ];

    filters.allow-ssh-logged = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = [
        (eq tcp.dport 22)
        (log { prefix = "wan-ssh: "; })
        accept
      ];
    };
  };

  assertions =
    compiled:
    let
      rule0 =
        builtins.elemAt compiled.tables.log-statement.chains."input-at-filter__wan-to-local".rules
          0;
      # The runner wraps rule bodies in `{ expr; comment; }`
      # when a comment is set, but rules without comments may
      # still arrive as either shape across the pipeline —
      # unwrap defensively.
      body = if builtins.isList rule0 then rule0 else rule0.expr;
      logStmts = builtins.filter (s: builtins.isAttrs s && s ? log) body;
    in
    [
      {
        description = "log statement is preserved in the compiled rule body";
        expr = builtins.length logStmts;
        expected = 1;
      }
      {
        description = "log statement preserves its prefix";
        expr = (builtins.head logStmts).log.prefix or null;
        expected = "wan-ssh: ";
      }
    ];
}
