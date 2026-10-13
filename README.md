# nixos-nftzones

nixos-nftzones is pre-release: version 0.1.0 has no tagged release, and the interface can change before 1.0.

nixos-nftzones provides `nftzones`, a Nix library and NixOS module that compile zone-based firewall configurations into vanilla nftables rulesets. A configuration declares each zone's interfaces and addresses once, such as `lan` for `eth1` and `10.0.0.0/24`, and writes rules between zones instead of repeating interfaces and addresses in every rule. It serves NixOS routers and hosts whose firewall policy reads naturally as traffic between network segments.

## Overview

A table body declares zones and named entries in rule groups. Each entry selects traffic with `from` and `to` zone lists, and the compiler expands it into one rule per zone pair. The output is one ordinary nftables table of base chains, per-pair sub-chains, sets, and jumps; the loaded ruleset has no notion of zones.

| Group      | Compiles to                                                           |
| ---------- | --------------------------------------------------------------------- |
| `filters`  | Rules in the input, forward, or output filter chain                   |
| `policies` | The default verdict for a zone pair, applied when no filter matches   |
| `snats`    | Source NAT at postrouting, such as masquerade                         |
| `dnats`    | Destination NAT at prerouting, such as a port forward                 |
| `sroutes`  | Packet marks at prerouting, keyed by source zone, for policy routing  |
| `droutes`  | Packet marks at output, keyed by destination zone, for policy routing |

Two zone names are reserved. `local` is the firewall host itself: `to = [ "local" ]` lands in the input chain and `from = [ "local" ]` in the output chain. `all` matches every zone. `settings.localZone` and `settings.wildcardZone` rename them.

Rule bodies are statement lists built with the [nftypes](https://github.com/petohorvath/nix-nftypes) DSL. A zone can name a `parent` to refine it, and `nodes` declare single hosts inside a zone; traffic dispatches to the most specific child first and falls back to the parent's rules.

[`docs/zone-based-firewall.md`](docs/zone-based-firewall.md) explains the model, [`docs/zone-hierarchy.md`](docs/zone-hierarchy.md) the parent and node semantics, and [`docs/compile-pipeline.md`](docs/compile-pipeline.md) how a table compiles. [`GLOSSARY.md`](GLOSSARY.md) defines the project's terms, and [`docs/adr/`](docs/adr/) records the design decisions.

## Install

Add nftzones as a flake input, and take nftypes from it for the rule-body DSL:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    nftzones = {
      url = "github:petohorvath/nixos-nftzones";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    nftypes.follows = "nftzones/nftypes";
  };
}
```

Following `nftzones/nftypes` keeps the DSL at the commit nftzones pins and tests against. nftzones pins its `nftypes` and `libnet` inputs by commit until those projects publish release tags.

The flake exposes the library as the system-independent `lib` output and the NixOS module as `nixosModules.default`. [`CHANGELOG.md`](CHANGELOG.md) lists breaking changes and their migration steps.

## Usage

This flake compiles a table with two zones, an SSH rule, and a zone-pair policy, and renders it as nftables text:

```nix
{
  inputs = {
    nftzones.url = "github:petohorvath/nixos-nftzones";
    nftypes.follows = "nftzones/nftypes";
  };

  outputs =
    { nftzones, nftypes, ... }:
    let
      inherit (nftypes.lib.dsl) accept eq;
      inherit (nftypes.lib.dsl.fields) tcp;
    in
    {
      ruleset = nftypes.lib.toTextPretty (
        nftzones.lib.mkRuleset "fw" {
          zones = {
            lan.interfaces = [ "eth1" ];
            wan.interfaces = [ "eth0" ];
          };
          filters.allow-ssh = {
            from = [ "lan" ];
            to = [ "local" ];
            rule = [
              (eq tcp.dport 22)
              accept
            ];
          };
          policies.lan-to-wan = {
            from = [ "lan" ];
            to = [ "wan" ];
            verdict = "accept";
          };
        }
      );
    };
}
```

```console
$ nix eval --raw .#ruleset
add table inet fw
add chain inet fw forward-at-filter {
  type filter hook forward priority 0;
  policy drop;
}
add chain inet fw forward-at-filter__lan-to-wan
add chain inet fw input-at-filter {
  type filter hook input priority 0;
  policy drop;
}
add chain inet fw input-at-filter__lan-to-local
add set inet fw lan_iifs {
  type ifname;
  elements = { eth1 };
}
add set inet fw wan_iifs {
  type ifname;
  elements = { eth0 };
}
add rule inet fw forward-at-filter ct state { established, related } accept
add rule inet fw forward-at-filter ct state invalid drop
add rule inet fw forward-at-filter meta iifname @lan_iifs meta oifname @wan_iifs jump forward-at-filter__lan-to-wan
add rule inet fw forward-at-filter__lan-to-wan accept
add rule inet fw input-at-filter ct state { established, related } accept
add rule inet fw input-at-filter ct state invalid drop
add rule inet fw input-at-filter meta iif lo accept
add rule inet fw input-at-filter meta iifname @lan_iifs jump input-at-filter__lan-to-local
add rule inet fw input-at-filter__lan-to-local tcp dport 22 accept
```

The connection-tracking, loopback, and `policy drop` lines come from the table's default `settings`. Load the text with `nft -f`, or render with `nftypes.lib.toJson` and load the JSON with `nft -j -f`.

The [`examples`](examples/) directory holds complete, commented tables. Each file is a function of `{ nftypes, nftzones, ... }` that returns a table body, and the `examples` check compiles every one:

- [`home-router.nix`](examples/home-router.nix): a home router with LAN and WAN zones, masquerade, a port forward, and default-deny inbound traffic.
- [`vlan-segmentation.nix`](examples/vlan-segmentation.nix): four VLAN security zones with a reachability matrix.
- [`dmz-hierarchy.nix`](examples/dmz-hierarchy.nix): a DMZ whose hosts are nodes under a shared parent zone.
- [`policy-routed-vpn.nix`](examples/policy-routed-vpn.nix): a router that marks guest traffic and remote-office traffic for routing through a VPN tunnel.

## Configure a NixOS host

The NixOS module compiles each table under `networking.nftzones.tables` and passes it to `networking.nftables.tables.<name>`, so nixpkgs handles activation, atomic reload, the build-time `nft --check`, and removal of dropped tables. Add the module to the system and pass the flake inputs to its modules:

```nix
nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
  system = "x86_64-linux";
  modules = [
    inputs.nftzones.nixosModules.default
    ./configuration.nix
  ];
  specialArgs = { inherit inputs; };
};
```

Then declare tables in `configuration.nix`:

```nix
{ inputs, ... }:
let
  inherit (inputs.nftypes.lib.dsl) accept eq;
  inherit (inputs.nftypes.lib.dsl.fields) tcp;
in
{
  networking = {
    firewall.enable = false;
    nftables.enable = true;
    nftzones = {
      enable = true;
      tables.fw = {
        zones = {
          lan = {
            interfaces = [ "eth1" ];
            cidrs = [ "10.0.0.0/24" ];
          };
          wan.interfaces = [ "eth0" ];
        };
        filters.allow-ssh = {
          from = [ "lan" ];
          to = [ "local" ];
          rule = [
            (eq tcp.dport 22)
            accept
          ];
        };
        policies.lan-to-wan = {
          from = [ "lan" ];
          to = [ "wan" ];
          verdict = "accept";
        };
      };
    };
  };
}
```

The module has three options:

| Option                       | Default | Effect                                                   |
| ---------------------------- | ------- | -------------------------------------------------------- |
| `networking.nftzones.enable` | `false` | Compiles and installs the declared tables                |
| `networking.nftzones.tables` | `{ }`   | Table bodies, keyed by nftables table name               |
| `networking.nftzones.pretty` | `false` | Renders multi-line indented text instead of compact text |

With the module enabled, the build fails when `networking.nftables.enable` is false, when no tables are declared, or when a table name is also declared in `networking.nftables.tables`.

### Disable the stock firewall

Set `networking.firewall.enable = false` when nftzones owns the input chain, as the example does. The stock firewall installs its own `inet filter` table on the same input hook and priority, so nftables runs both chains and accepts every port either one opens. The module warns at build time when both are enabled.

### Keep hand-written tables

Tables in `networking.nftables.tables` coexist with nftzones tables as long as the names differ. Use them for rules that do not fit the zone model:

```nix
networking.nftables.tables.raw-output = {
  family = "inet";
  content = ''
    chain output {
      type filter hook output priority 0; policy accept;
    }
  '';
};
```

## Write rule bodies with snippets

`nftzones.lib.snippets` returns ready-made rule bodies for opening, dropping, or rejecting ports and ICMP types:

```nix
{ inputs, ... }:
let
  inherit (inputs.nftzones.lib) snippets;
in
{
  networking.nftzones.tables.fw.filters = {
    allow-web = {
      from = [ "all" ];
      to = [ "local" ];
      rule = snippets.accept.tcp [
        80
        443
        "8000-8100"
      ];
    };
    allow-ping = {
      from = [ "all" ];
      to = [ "local" ];
      rule = snippets.accept.icmp.v4 "echo-request";
    };
    reject-rdp = {
      from = [ "wan" ];
      to = [ "local" ];
      rule = snippets.reject.tcp 3389;
    };
  };
}
```

Each of `accept`, `drop`, and `reject` provides `tcp`, `udp`, `icmp.v4`, and `icmp.v6`. Port arguments take an integer, a decimal string, a range string such as `"8000-8100"` or `"8000:8100"`, a `libnet` port or port range, or a list of these. ICMP arguments take type numbers from 0 to 255 or names such as `"echo-request"`, or a list of one form. `reject.tcp` answers with a TCP reset; the other `reject` variants send the nftables default ICMP port-unreachable reply. [`lib/snippets.nix`](lib/snippets.nix) and the files in [`lib/snippets/`](lib/snippets/) document the full contract.

## Compose several tables

`mkTable name body` compiles one table body into an nftypes table value, and `mkRuleset name body` wraps one table in a complete ruleset. To build a ruleset of several tables, pass the `mkTable` results to `nftypes.lib.dsl.ruleset`, where `nftzones` and `nftypes` are the flake inputs:

```nix
let
  inherit (nftypes.lib) dsl toText;
  ipv4Table = nftzones.lib.mkTable "fw-v4" {
    family = "ip";
    zones.lan.interfaces = [ "eth1" ];
  };
  ipv6Table = nftzones.lib.mkTable "fw-v6" {
    family = "ip6";
    zones.lan.interfaces = [ "eth1" ];
  };
in
toText (
  dsl.ruleset [
    ipv4Table
    ipv6Table
  ]
)
```

The `name` argument sets the nftables table name and overrides any `name` in the body. `nftzones.lib.types.table` is the option type for a table body, for modules that accept tables from their own users.

## Limitations

- Tables support the `inet`, `ip`, `ip6`, and `bridge` families. `arp` and `netdev` are rejected: `netdev` needs a per-chain device binding that the chain model lacks, and `arp` has no use case yet to justify testing it.
- Bridge tables support `filters` and `policies` only. The bridge family has no NAT chains and no `mangle` priority for route marks, so the compiler rejects `snats`, `dnats`, `sroutes`, and `droutes` in a bridge table.
- Zone interfaces take exact names; wildcard patterns such as `wlan*` are not supported.

[GitHub issues](https://github.com/petohorvath/nixos-nftzones/issues) track the known design gaps.

## Contributing

Report bugs, ask questions, and open pull requests on [GitHub](https://github.com/petohorvath/nixos-nftzones). [`AGENTS.md`](AGENTS.md) lists the development shell and the required checks, and [`docs/testing.md`](docs/testing.md) describes the test tiers and VM tests.

## License

[MIT](LICENSE)
