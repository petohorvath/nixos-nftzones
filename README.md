# nix-nftzones

Compile zone-based firewall configurations into nftables rulesets, in Nix.

> **Pre-release** (`0.1.0`, no tagged release yet). Expect API tweaks before 1.0.

Most nftables configs hardwire interfaces and addresses into every rule. nftzones describes zone membership once — "lan is `eth1` plus `10.0.0.0/24`", "wan is `eth0`" — and expresses rules between **zones** instead. The library compiles a zone-keyed config into a vanilla nftables ruleset; the underlying nftables knows nothing about zones. See [`docs/zone-based-firewall.md`](docs/zone-based-firewall.md) for the model and [`docs/compile-pipeline.md`](docs/compile-pipeline.md) for the four-phase pipeline.

## Quick start

### Add the flake inputs

Both nftzones and nftypes are typically declared as inputs — nftzones provides the zone abstraction; nftypes provides the DSL helpers (`eq`, `accept`, `tcp.dport`, etc.) used in rule bodies.

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    nftzones.url = "github:petohorvath/nix-nftzones";
    nftzones.inputs.nixpkgs.follows = "nixpkgs";

    nftypes.url = "github:petohorvath/nix-nftypes";
    nftypes.inputs.nixpkgs.follows = "nixpkgs";
  };
}
```

### NixOS module (recommended)

Import the module into a NixOS configuration; declare tables under `networking.nftzones.tables`. nixpkgs' `networking.nftables` machinery handles activation, atomic reload, and per-table cleanup on rebuild.

```nix
# flake.nix outputs
nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
  system = "x86_64-linux";
  modules = [
    inputs.nftzones.nixosModules.default
    ./configuration.nix
  ];
  specialArgs = { inherit inputs; };
};
```

```nix
# configuration.nix
{ inputs, ... }:
let
  inherit (inputs.nftypes.lib.dsl) eq accept limit;
  inherit (inputs.nftypes.lib.dsl.fields) tcp;
in
{
  networking.nftables.enable = true;
  networking.nftzones = {
    enable = true;
    tables.fw = {
      zones = {
        lan = { interfaces = [ "eth1" ]; cidrs = [ "10.0.0.0/24" ]; };
        wan = { interfaces = [ "eth0" ]; };
      };
      filters.allow-ssh = {
        from = [ "wan" ];
        to = [ "local" ];
        rule = [ (eq tcp.dport 22) accept ];
      };
      policies.lan-out = {
        from = [ "lan" ];
        to = [ "wan" ];
        verdict = "accept";
      };
    };
  };
}
```

The module compiles each table, renders to nftables block-form text via nftypes, and feeds the result into `networking.nftables.tables.<name>.content`. Build-time assertions catch missing `networking.nftables.enable` and table-name collisions.

#### Mixing with hand-written tables

Zone-managed and hand-written tables coexist freely as long as their names differ — the module's collision assertion only fires when the same name is declared in both `networking.nftzones.tables` and `networking.nftables.tables`. Use `networking.nftables.tables.<name>` directly for any table that doesn't fit the zone model:

```nix
networking.nftables = {
  enable = true;
  tables.legacy-raw = {
    family = "inet";
    content = ''
      chain output { type filter hook output priority 0; ... }
    '';
  };
};
networking.nftzones.tables.zonefw = {
  zones.lan.interfaces = [ "eth1" ];
  # ...
};
```

### Direct library (without the NixOS module)

```nix
{ inputs, pkgs, ... }:
let
  nftzones = inputs.nftzones.lib.${pkgs.system};
  inherit (inputs.nftypes.lib) toJson toText dsl;
  inherit (dsl) eq accept;
  inherit (dsl.fields) tcp;

  table = nftzones.mkTable "fw" {
    zones.lan.interfaces = [ "eth1" ];
    zones.wan.interfaces = [ "eth0" ];
    filters.allow-ssh = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = [ (eq tcp.dport 22) accept ];
    };
  };
in {
  # Compose into a multi-table ruleset and serialize.
  rulesetJson = toJson (dsl.ruleset [ table ]);
  rulesetText = toText (dsl.ruleset [ table ]);
}
```

`mkTable` returns an `nftypes.dsl.table` value; `mkRuleset name body` is a shortcut that wraps a single table in `nftypes.dsl.ruleset`. Either is renderable to JSON (`toJson`) for `nft -j -f`, or to text (`toText`) for `nft -f`.

### Snippets — rule-body shorthand

Constructing rule bodies by hand requires reaching into the `nftypes.dsl` surface (`eq`, `accept`, `inSet`, `tcp.dport`, …). For the common "open / drop / reject these ports" case, `nftzones.snippets.*` returns a ready-made statement list:

```nix
{ inputs, ... }:
let
  inherit (inputs.nftzones.lib.${pkgs.system}.snippets) accept drop reject;
  inherit (inputs.libnet.lib.registry) wellKnownPorts;
in
{
  networking.nftzones.tables.fw = {
    zones.lan.interfaces = [ "eth1" ];

    filters.allow-ssh   = { from = [ "all" ]; to = [ "local" ]; rule = accept.tcp 22; };
    filters.allow-web   = { from = [ "all" ]; to = [ "local" ]; rule = accept.tcp [ 80 443 "8000-8100" ]; };
    filters.allow-dns-u = { from = [ "lan" ]; to = [ "local" ]; rule = accept.udp wellKnownPorts.udp.dns; };
    filters.allow-ping  = { from = [ "all" ]; to = [ "local" ]; rule = accept.icmp.v4 8; };
    filters.kick-rdp    = { from = [ "all" ]; to = [ "local" ]; rule = reject.tcp wellKnownPorts.tcp.rdp; };
  };
}
```

Twelve leaf functions across `accept` / `drop` / `reject` × `tcp` / `udp` / `icmp.v4` / `icmp.v6`. Port arguments accept ints, decimal strings, range strings (`"8000-8100"` / `"8000:8100"`), `libnet.port` / `libnet.portRange` values, or lists thereof — validation routes through `libnet`. ICMP-type arguments accept ints (`0`..`255`) or symbolic strings (`"echo-request"`); mixed-form lists throw.

### Hierarchical zones

Zones can declare a `parent` (and a node's `zone` field becomes its lowered child's parent). Traffic dispatches into the most-specific child sub-chain via the parent's chain; rules attached to the parent run as fallbacks if no child handles the packet first. See [`docs/specs/zone-parent.md`](docs/specs/zone-parent.md) for semantics.

```nix
zones.dmz = { interfaces = [ "dmz0" ]; cidrs = [ "10.0.0.0/24" ]; };
nodes.web-server = { zone = "dmz"; address.ipv4 = "10.0.0.5"; };

filters.dmz-rate-limit = {
  from = [ "dmz" ]; to = [ "local" ];
  rule = [ (eq tcp.dport 22) (limit { rate = 100; per = "second"; }) accept ];
};
filters.web-server-http = {
  from = [ "web-server" ]; to = [ "local" ];
  rule = [ (eq tcp.dport 80) accept ];
};
```

## Examples

Complete, commented configurations under [`examples/`](examples/), each a
`{ nftypes, nftzones, ... }: body` function ready to drop into
`networking.nftzones.tables.<name>`:

| File | Scenario |
|---|---|
| [`examples/home-router.nix`](examples/home-router.nix) | SOHO router — LAN/WAN, masquerade, a port-forward, default-deny inbound. |
| [`examples/vlan-segmentation.nix`](examples/vlan-segmentation.nix) | Four VLAN security zones with a rule-by-rule reachability matrix. |
| [`examples/dmz-hierarchy.nix`](examples/dmz-hierarchy.nix) | A DMZ whose hosts are `nodes` — per-host child zones under a shared parent. |

Each is compiled by the `examples` check tier on every CI run, so they
stay valid against the current type surface.

## Documentation

| File | Audience |
|---|---|
| [`docs/zone-based-firewall.md`](docs/zone-based-firewall.md) | Newcomers to the zone-based firewall model. |
| [`docs/compile-pipeline.md`](docs/compile-pipeline.md) | Integrators, debuggers, contributors. |
| [`docs/specs/zone-parent.md`](docs/specs/zone-parent.md) | Zone hierarchy semantics, dispatch model, prior art. |

## Requirements

**Requires** Nix 2.17+ with flakes, and (for the NixOS module path) NixOS 24.11+.

## Known limitations

- **Supported table families: `inet`, `ip`, `ip6`, `bridge`.** `arp` and `netdev` are rejected at the type level. `netdev` in particular needs a per-chain `device` binding that the chain submodule doesn't model today; `arp` is too rare to justify the testing investment without a concrete use case.
- **Bridge family supports `filter` chains only.** `nat` (not supported by the bridge family) and `route` (no `mangle` priority on bridge) placements are rejected at compile time by `checkChainPlacement` so users get a clear error rather than a kernel-level rejection.
- See `Pending follow-ups` in [`docs/compile-pipeline.md`](docs/compile-pipeline.md) for tracked design gaps.

## Testing

Four tiers, each runnable via `nix flake check`:

- **Unit** (`tests/unit/`): per-module tests of the compile pipeline's helpers and validators.
- **Integration** (`tests/integration/`): structured assertions on the rendered nftables JSON for representative scenarios, plus negative tests that confirm Phase 1 validators reject known-bad inputs in the live `mkRuleset` pipeline.
- **Examples** (`examples/`): compile-checks every `examples/*.nix` through `mkRuleset` so the shipped example configs can't drift out of sync with the type surface.
- **VM** (`tests/vm/`): real-kernel multi-VM scenarios via `pkgs.testers.nixosTest`. One topology per feature, each requiring `/dev/kvm` on the builder. Verification is conntrack-on-router for NAT and deny-path tests, packet-content for everything else:

  | File | VMs | Coverage |
  |---|---|---|
  | [`forward.nix`](tests/vm/forward.nix) | client + router + server + external | L3 forwarding, ICMP, SSH, SNAT masquerade, DNAT port-forward, DNS redirect, default-deny wan→lan, non-DNAT'd port, stateful prelude `[ASSURED]` + INVALID drop, `reject` verdict, `log` statement |
  | [`vlan.nix`](tests/vm/vlan.nix) | router + vlan-iot + vlan-admin (single 802.1Q trunk) | inter-VLAN allow, inter-VLAN default-deny |
  | [`rpfilter.nix`](tests/vm/rpfilter.nix) | client + router + spoofer (wan-side host with a lan-range /32 alias) | `settings.rpfilter = true` accepts legit src, drops spoofed |
  | [`marks.nix`](tests/vm/marks.nix) | client + router + server (with `ip rule fwmark X table Y`) | `sroutes` mark steers forwarded traffic to an alternate routing table |
  | [`droutes.nix`](tests/vm/droutes.nix) | router + target | `droutes` mark steers router-originated traffic (OUTPUT hook) |
  | [`dualstack.nix`](tests/vm/dualstack.nix) | client + router + server, IPv4 + IPv6 | dual-stack forwarding on an `inet` table, v6 conntrack tracking |
  | [`bridge.nix`](tests/vm/bridge.nix) | vmA + bridge + vmB | `family = "bridge"` L2 filter across a Linux bridge |
  | [`atomic-reload.nix`](tests/vm/atomic-reload.nix) | client + router + server | mid-flight `nft -f` ruleset swap preserves established connections |

CI runs the VM suite against three nixpkgs refs in parallel — `pinned` (this repo's `flake.lock`), `nixos-25.11`, and `nixos-unstable` — so upstream regressions surface alongside changes here.

## Contributing

Issues and PRs welcome on [github.com/petohorvath/nix-nftzones](https://github.com/petohorvath/nix-nftzones). Run tests with `nix flake check`.
