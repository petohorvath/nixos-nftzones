/*
  matchOverride.<side>.interfaces scenario — the user supplies an
  explicit interface match that replaces the auto-derived
  `@<zone>_iifs` / `@<zone>_oifs` set lookups. Sister to
  `match-override-sections.nix` (which covers `ipv4` / `ipv6`)
  and `match-override.nix` (which covers `extra`); this one fills
  the `interfaces` section gap so every `matchOverride.<side>`
  sub-key has end-to-end coverage.

  Why a real use case: VLAN sub-interfaces named `vlan100`,
  `vlan200`, … can be lumped into one zone via a prefix match
  (`iifname "vlan*"`) without enumerating each VLAN's name. The
  auto path would require every VLAN to be in the zone's
  `interfaces` list explicitly.
*/
{ nftypes, ... }:
let
  inherit (nftypes.dsl) eq accept;
  inherit (nftypes.dsl.fields) meta;
in
{
  body = {
    zones = {
      lan.interfaces = [ "lan0" ];
      vlans = {
        # VLAN zone: no interfaces of its own — the user-supplied
        # `interfaces` section matches every device whose name
        # starts with `vlan` directly.
        matchOverride = {
          ingress.interfaces = [ (eq meta.iifname "vlan*") ];
          egress.interfaces = [ (eq meta.oifname "vlan*") ];
        };
      };
    };

    filters.lan-to-vlans = {
      from = [ "lan" ];
      to = [ "vlans" ];
      rule = [ accept ];
    };
  };

  assertions = compiled: [
    {
      description = "override zone produces no auto interface set — `interfaces` section takes over";
      expr = compiled.table.sets ? vlans_iifs;
      expected = false;
    }
    {
      description = "lan-to-vlans sub-chain emits with the user rule";
      expr = compiled.table.chains ? "forward-at-filter__lan-to-vlans";
      expected = true;
    }
  ];
}
