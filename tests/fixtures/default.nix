/*
  Shared test data. `scenarios` holds valid tables, each in one of the
  forms `helpers/scenarios.nix` describes; `rejections` holds deliberate
  misconfigurations, each `{ description; body; errors ? [ … ]; }`; and
  `examples` holds the table body of each `examples/*.nix`.

  Takes the `nftypes` and `nftzones` libraries the fixtures build on.
  Adding a fixture means listing it here.
*/
{ nftypes, nftzones }:
let
  libraryArgs = { inherit nftypes nftzones; };
  rejectionArgs = { inherit nftypes; };
in
{
  examples = {
    dmz-hierarchy = import ../../examples/dmz-hierarchy.nix libraryArgs;
    home-router = import ../../examples/home-router.nix libraryArgs;
    policy-routed-vpn = import ../../examples/policy-routed-vpn.nix libraryArgs;
    vlan-segmentation = import ../../examples/vlan-segmentation.nix libraryArgs;
  };

  scenarios = {
    bridge-filter = import ./scenarios/bridge-filter.nix libraryArgs;
    chain-override = import ./scenarios/chain-override.nix libraryArgs;
    chain-placement = import ./scenarios/chain-placement.nix libraryArgs;
    comments = import ./scenarios/comments.nix libraryArgs;
    dnat-port-forward = import ./scenarios/dnat-port-forward.nix libraryArgs;
    dnat-redirect = import ./scenarios/dnat-redirect.nix libraryArgs;
    droute-mark = import ./scenarios/droute-mark.nix libraryArgs;
    droute-multi-zone = import ./scenarios/droute-multi-zone.nix libraryArgs;
    dual-stack = import ./scenarios/dual-stack.nix libraryArgs;
    family-ip6 = import ./scenarios/family-ip6.nix libraryArgs;
    family-ip = import ./scenarios/family-ip.nix libraryArgs;
    filter-basic = import ./scenarios/filter-basic.nix libraryArgs;
    log-statement = import ./scenarios/log-statement.nix libraryArgs;
    match-override-interfaces = import ./scenarios/match-override-interfaces.nix libraryArgs;
    match-override = import ./scenarios/match-override.nix libraryArgs;
    match-override-sections = import ./scenarios/match-override-sections.nix libraryArgs;
    minimal = import ./scenarios/minimal.nix libraryArgs;
    multi-table = import ./scenarios/multi-table.nix libraryArgs;
    multi-zone-fanout = import ./scenarios/multi-zone-fanout.nix libraryArgs;
    named-objects = import ./scenarios/named-objects.nix libraryArgs;
    objects-stateful = import ./scenarios/objects-stateful.nix libraryArgs;
    parent-basic = import ./scenarios/parent-basic.nix libraryArgs;
    parent-deep-nesting = import ./scenarios/parent-deep-nesting.nix libraryArgs;
    parent-empty-intermediate = import ./scenarios/parent-empty-intermediate.nix libraryArgs;
    parent-mixed-sections-mirror = import ./scenarios/parent-mixed-sections-mirror.nix libraryArgs;
    parent-mixed-sections = import ./scenarios/parent-mixed-sections.nix libraryArgs;
    parent-policy-precedence = import ./scenarios/parent-policy-precedence.nix libraryArgs;
    parent-priorities = import ./scenarios/parent-priorities.nix libraryArgs;
    parent-transitive-sets = import ./scenarios/parent-transitive-sets.nix libraryArgs;
    policy-default = import ./scenarios/policy-default.nix libraryArgs;
    priority-slots = import ./scenarios/priority-slots.nix libraryArgs;
    settings-toggles = import ./scenarios/settings-toggles.nix libraryArgs;
    snat-explicit-rewrite = import ./scenarios/snat-explicit-rewrite.nix libraryArgs;
    snat-masquerade = import ./scenarios/snat-masquerade.nix libraryArgs;
    snippets-acceptance = import ./scenarios/snippets-acceptance.nix libraryArgs;
    sroute-mark = import ./scenarios/sroute-mark.nix libraryArgs;
    sroute-multi-zone = import ./scenarios/sroute-multi-zone.nix libraryArgs;
    wildcard-child-mix = import ./scenarios/wildcard-child-mix.nix libraryArgs;
    wildcard-expansion = import ./scenarios/wildcard-expansion.nix libraryArgs;
    zone-names-with-to = import ./scenarios/zone-names-with-to.nix libraryArgs;
    zone-set-ref = import ./scenarios/zone-set-ref.nix libraryArgs;
  };

  rejections = {
    chain-override-placement = import ./rejections/chain-override-placement.nix rejectionArgs;
    chain-placement-bridge-droute = import ./rejections/chain-placement-bridge-droute.nix rejectionArgs;
    chain-placement-bridge-mixed = import ./rejections/chain-placement-bridge-mixed.nix rejectionArgs;
    chain-placement-bridge-sroute = import ./rejections/chain-placement-bridge-sroute.nix rejectionArgs;
    chain-placement = import ./rejections/chain-placement.nix rejectionArgs;
    cidr-overlap = import ./rejections/cidr-overlap.nix rejectionArgs;
    comment-injection = import ./rejections/comment-injection.nix rejectionArgs;
    interface-overlap = import ./rejections/interface-overlap.nix rejectionArgs;
    interface-self-overlap = import ./rejections/interface-self-overlap.nix rejectionArgs;
    matchoverride-verdict = import ./rejections/matchoverride-verdict.nix rejectionArgs;
    name-collisions = import ./rejections/name-collisions.nix rejectionArgs;
    nat-body-no-addr-dnat = import ./rejections/nat-body-no-addr-dnat.nix rejectionArgs;
    nat-body-no-addr-snat = import ./rejections/nat-body-no-addr-snat.nix rejectionArgs;
    node-address-missing = import ./rejections/node-address-missing.nix rejectionArgs;
    object-comment-injection = import ./rejections/object-comment-injection.nix rejectionArgs;
    object-refs = import ./rejections/object-refs.nix rejectionArgs;
    parent-cycles = import ./rejections/parent-cycles.nix rejectionArgs;
    parent-local-zone = import ./rejections/parent-local-zone.nix rejectionArgs;
    parent-refs = import ./rejections/parent-refs.nix rejectionArgs;
    policy-uniqueness = import ./rejections/policy-uniqueness.nix rejectionArgs;
    policy-wildcard-conflict = import ./rejections/policy-wildcard-conflict.nix rejectionArgs;
    rule-empty-droute = import ./rejections/rule-empty-droute.nix rejectionArgs;
    rule-empty-filter = import ./rejections/rule-empty-filter.nix rejectionArgs;
    rule-missing-sroute = import ./rejections/rule-missing-sroute.nix rejectionArgs;
    set-elem-comment-injection = import ./rejections/set-elem-comment-injection.nix rejectionArgs;
    set-name-collisions = import ./rejections/set-name-collisions.nix rejectionArgs;
    settings-local-shadow = import ./rejections/settings-local-shadow.nix rejectionArgs;
    settings = import ./rejections/settings.nix rejectionArgs;
    settings-wildcard-shadow = import ./rejections/settings-wildcard-shadow.nix rejectionArgs;
    zone-matchable = import ./rejections/zone-matchable.nix rejectionArgs;
    zone-refs = import ./rejections/zone-refs.nix rejectionArgs;
  };
}
