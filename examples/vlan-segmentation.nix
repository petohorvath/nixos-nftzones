/*
  Example: VLAN-segmented network.

  A router-on-a-stick carving the internal network into four
  security zones plus the WAN uplink. Each internal zone is an
  802.1Q VLAN on the trunk; inter-zone reachability is granted
  rule-by-rule, and everything unstated is dropped.

    vlan-mgmt    10.0.1.0/24  ─┐
    vlan-trusted 10.0.2.0/24  ─┤
    vlan-iot     10.0.3.0/24  ─┼─ trunk ── [router] ── wan0 ── [internet]
    vlan-guest   10.0.4.0/24  ─┘

  Reachability matrix (→ = "may initiate to"):

    mgmt    → wan, trusted, iot, guest   (full admin reach)
              local, SSH only            (administer the router)
    trusted → wan, iot                   (control IoT devices)
    iot     → wan                        (cloud connectivity only)
    guest   → wan                        (internet, nothing else)

  Everything not listed — iot→trusted, guest→mgmt, wan→local,
  etc. — is dropped by the chain-policy default
  (`settings.chainPolicy` defaults to `drop`). No explicit deny
  rules are needed; the allow-list above *is* the policy.

  The chain policy applies only at a hook that has a base chain,
  and nftzones emits one only where an entry lands. The
  `mgmt-admin-ssh` filter is what gives the router an input
  chain: without an entry at input, nothing in this table
  filters traffic to the router itself. The router serves
  nothing else to the VLANs; grant DHCP, DNS or any other router
  service with its own `to = [ "local" ]` filter.

  Wire it into a NixOS host:

    networking.nftzones.tables.fw = import ./examples/vlan-segmentation.nix {
      nftypes = inputs.nix-nftypes.lib;
      nftzones = inputs.nftzones.lib;
    };
*/
{
  nftypes,
  nftzones,
  ...
}:
let
  inherit (nftypes.dsl) accept;
  inherit (nftzones) snippets;
in
{
  zones = {
    mgmt = {
      interfaces = [ "vlan-mgmt" ];
      cidrs = [ "10.0.1.0/24" ];
    };
    trusted = {
      interfaces = [ "vlan-trusted" ];
      cidrs = [ "10.0.2.0/24" ];
    };
    iot = {
      interfaces = [ "vlan-iot" ];
      cidrs = [ "10.0.3.0/24" ];
    };
    guest = {
      interfaces = [ "vlan-guest" ];
      cidrs = [ "10.0.4.0/24" ];
    };
    wan = {
      interfaces = [ "wan0" ];
    };
  };

  filters = {
    # Every internal zone reaches the internet. One filter,
    # four source zones — `from` fans out, so this is the
    # cartesian product of {mgmt,trusted,iot,guest} × {wan}.
    internal-out = {
      from = [
        "mgmt"
        "trusted"
        "iot"
        "guest"
      ];
      to = [ "wan" ];
      rule = [ accept ];
    };

    # mgmt administers every other internal zone.
    mgmt-to-internal = {
      from = [ "mgmt" ];
      to = [
        "trusted"
        "iot"
        "guest"
      ];
      rule = [ accept ];
    };

    # Trusted hosts may reach IoT devices (control apps, local
    # dashboards). IoT cannot initiate back — there is no
    # iot→trusted rule, so the chain-policy default drops it.
    trusted-to-iot = {
      from = [ "trusted" ];
      to = [ "iot" ];
      rule = [ accept ];
    };

    # The router accepts SSH from mgmt only. `to = [ "local" ]`
    # lands in the router's input chain, so this entry also gives
    # input its chain-policy drop for every other zone.
    mgmt-admin-ssh = {
      from = [ "mgmt" ];
      to = [ "local" ];
      rule = snippets.accept.tcp 22;
    };
  };

  # Masquerade every internal zone behind the WAN address.
  snats.uplink = {
    from = [
      "mgmt"
      "trusted"
      "iot"
      "guest"
    ];
    to = [ "wan" ];
    rule.action.masquerade = { };
  };

  # No `policies` block: the chain-policy default (`drop`)
  # already discards every flow not allowed by a filter above —
  # iot→mgmt, guest→trusted, wan→anything, and so on, at both
  # the forward chain and the input chain `mgmt-admin-ssh`
  # creates. Adding explicit `verdict = "drop"` policies would
  # be redundant noise here; the filter allow-list is the
  # single source of truth.
}
