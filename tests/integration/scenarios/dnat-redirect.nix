/*
  DNAT redirect scenario — bounce inbound port 2222 to the
  firewall's local sshd on port 22. Single-direction (`from`
  only) lands in prerouting@dstnat with `type nat`. Exercises
  the `action.redirect` rule-body emission path (distinct from
  `action.dnat` which uses a `natBody`-shaped target).
*/
{ nftypes }:
let
  inherit (nftypes.dsl) eq redirect;
  inherit (nftypes.dsl.fields) tcp;
in
{
  body = {
    zones.wan.interfaces = [ "wan0" ];

    dnats.ssh-redirect = {
      from = [ "wan" ];
      rule = {
        match = [ (eq tcp.dport 2222) ];
        action.redirect = { port = 22; };
      };
      comment = "expose sshd via 2222";
    };
  };

  assertions = compiled: [
    {
      description = "redirect rule lands at prerouting-at-dstnat__wan";
      expr = compiled.tables.dnat-redirect.chains ? "prerouting-at-dstnat__wan";
      expected = true;
    }
    {
      description = "redirect path emits a redirect statement (not dnat)";
      expr = (builtins.elemAt compiled.tables.dnat-redirect.chains."prerouting-at-dstnat__wan".rules 0).expr;
      expected = [
        (eq tcp.dport 2222)
        (redirect { port = 22; })
      ];
    }
    {
      description = "rule comment surfaces on the rendered rule";
      expr = (builtins.elemAt compiled.tables.dnat-redirect.chains."prerouting-at-dstnat__wan".rules 0).comment;
      expected = "expose sshd via 2222";
    }
  ];
}
