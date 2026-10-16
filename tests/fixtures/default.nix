/*
  Shared test data. `scenarios` holds valid tables, each in one of the
  forms `helpers/scenarios.nix` describes; `rejections` holds deliberate
  misconfigurations, each `{ description; body; errors ? [ … ]; }`.

  Takes the `nftypes` and `nftzones` libraries the fixtures build on.
  Adding a fixture means listing it here.
*/
{ nftypes, nftzones }:
let
  scenarioArgs = { inherit nftypes nftzones; };
  rejectionArgs = { inherit nftypes; };
in
{
  scenarios = {
    bridge-filter = import ./scenarios/bridge-filter.nix scenarioArgs;
    chain-override = import ./scenarios/chain-override.nix scenarioArgs;
    chain-placement = import ./scenarios/chain-placement.nix scenarioArgs;
    comments = import ./scenarios/comments.nix scenarioArgs;
    dnat-port-forward = import ./scenarios/dnat-port-forward.nix scenarioArgs;
    dnat-redirect = import ./scenarios/dnat-redirect.nix scenarioArgs;
    droute-mark = import ./scenarios/droute-mark.nix scenarioArgs;
    droute-multi-zone = import ./scenarios/droute-multi-zone.nix scenarioArgs;
    dual-stack = import ./scenarios/dual-stack.nix scenarioArgs;
    family-ip6 = import ./scenarios/family-ip6.nix scenarioArgs;
    family-ip = import ./scenarios/family-ip.nix scenarioArgs;
    filter-basic = import ./scenarios/filter-basic.nix scenarioArgs;
    log-statement = import ./scenarios/log-statement.nix scenarioArgs;
    match-override-interfaces = import ./scenarios/match-override-interfaces.nix scenarioArgs;
    match-override = import ./scenarios/match-override.nix scenarioArgs;
    match-override-sections = import ./scenarios/match-override-sections.nix scenarioArgs;
    minimal = import ./scenarios/minimal.nix scenarioArgs;
    multi-table = import ./scenarios/multi-table.nix scenarioArgs;
    multi-zone-fanout = import ./scenarios/multi-zone-fanout.nix scenarioArgs;
    named-objects = import ./scenarios/named-objects.nix scenarioArgs;
    objects-stateful = import ./scenarios/objects-stateful.nix scenarioArgs;
    parent-basic = import ./scenarios/parent-basic.nix scenarioArgs;
    parent-deep-nesting = import ./scenarios/parent-deep-nesting.nix scenarioArgs;
    parent-empty-intermediate = import ./scenarios/parent-empty-intermediate.nix scenarioArgs;
    parent-mixed-sections-mirror = import ./scenarios/parent-mixed-sections-mirror.nix scenarioArgs;
    parent-mixed-sections = import ./scenarios/parent-mixed-sections.nix scenarioArgs;
    parent-policy-precedence = import ./scenarios/parent-policy-precedence.nix scenarioArgs;
    parent-priorities = import ./scenarios/parent-priorities.nix scenarioArgs;
    parent-transitive-sets = import ./scenarios/parent-transitive-sets.nix scenarioArgs;
    policy-default = import ./scenarios/policy-default.nix scenarioArgs;
    priority-slots = import ./scenarios/priority-slots.nix scenarioArgs;
    settings-toggles = import ./scenarios/settings-toggles.nix scenarioArgs;
    snat-explicit-rewrite = import ./scenarios/snat-explicit-rewrite.nix scenarioArgs;
    snat-masquerade = import ./scenarios/snat-masquerade.nix scenarioArgs;
    snippets-acceptance = import ./scenarios/snippets-acceptance.nix scenarioArgs;
    sroute-mark = import ./scenarios/sroute-mark.nix scenarioArgs;
    sroute-multi-zone = import ./scenarios/sroute-multi-zone.nix scenarioArgs;
    wildcard-child-mix = import ./scenarios/wildcard-child-mix.nix scenarioArgs;
    wildcard-expansion = import ./scenarios/wildcard-expansion.nix scenarioArgs;
    zone-names-with-to = import ./scenarios/zone-names-with-to.nix scenarioArgs;
    zone-set-ref = import ./scenarios/zone-set-ref.nix scenarioArgs;
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
    nat-body-empty-dnat = import ./rejections/nat-body-empty-dnat.nix rejectionArgs;
    nat-body-empty-snat = import ./rejections/nat-body-empty-snat.nix rejectionArgs;
    node-address-missing = import ./rejections/node-address-missing.nix rejectionArgs;
    object-comment-injection = import ./rejections/object-comment-injection.nix rejectionArgs;
    object-refs = import ./rejections/object-refs.nix rejectionArgs;
    object-refs-set-elem-stmt = import ./rejections/object-refs-set-elem-stmt.nix rejectionArgs;
    parent-cycles = import ./rejections/parent-cycles.nix rejectionArgs;
    parent-local-zone = import ./rejections/parent-local-zone.nix rejectionArgs;
    parent-refs = import ./rejections/parent-refs.nix rejectionArgs;
    policy-uniqueness = import ./rejections/policy-uniqueness.nix rejectionArgs;
    policy-wildcard-conflict = import ./rejections/policy-wildcard-conflict.nix rejectionArgs;
    set-elem-comment-injection = import ./rejections/set-elem-comment-injection.nix rejectionArgs;
    set-name-collisions = import ./rejections/set-name-collisions.nix rejectionArgs;
    settings-local-shadow = import ./rejections/settings-local-shadow.nix rejectionArgs;
    settings = import ./rejections/settings.nix rejectionArgs;
    settings-wildcard-shadow = import ./rejections/settings-wildcard-shadow.nix rejectionArgs;
    zone-matchable = import ./rejections/zone-matchable.nix rejectionArgs;
    zone-refs = import ./rejections/zone-refs.nix rejectionArgs;
  };
}
