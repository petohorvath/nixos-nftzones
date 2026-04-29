# nftables Structure and Constructs

Reference for the object hierarchy and concepts of the Linux `nf_tables` kernel subsystem.

## Object Hierarchy

```
ruleset
└── table (per address family: ip | ip6 | inet | arp | bridge | netdev)
    ├── chain (base only)   type, hook, priority, policy, [device]
    │   └── rule
    │       └── statements
    │           ├── matches    predicate expressions  (tcp dport 22, ip saddr 10.0.0.0/8, ct state ...)
    │           └── actions    verdicts and effects   (accept, drop, jump, log, counter, snat, ...)
    ├── set
    ├── map
    ├── flowtable
    └── stateful object   (counter | quota | limit | ct helper | ...)
```

A ruleset is the union of every table installed in the kernel. Tables hold chains and other objects; chains hold rules; rules are sequences of statements. A statement is either a match (a predicate expression filtering the rule) or an action (a verdict or other effect).

## Ruleset

The ruleset is the logical top-level: the union of every table currently installed in the kernel, across every address family. It is a view, not a kernel object — there is no `ruleset` object the kernel stores. Operations such as listing or flushing the ruleset iterate over every table the caller can see.

A ruleset script consists of declarative top-level objects (tables, with their chains and other contents) and is applied as a single transaction.

## Table

A table is a named, family-scoped container that groups chains, sets, maps, flowtables, and stateful objects. Tables themselves do not affect packet evaluation — they exist for organization and lifecycle.

Each table is a real kernel object owned by `nf_tables`. The kernel holds the authoritative state, so a table persists until it is explicitly deleted, until the `nf_tables` module unloads, or — for tables created with the `owner` flag and without `persist` — until the owning process exits.

```
table inet filter {
    # chains, sets, maps, flowtables, stateful objects go here
}

table inet filter {
    flags dormant      # disable: base chains are unregistered
}
```

| Flag | Effect |
|---|---|
| `dormant` | Base chains are unregistered; rules are not evaluated. |
| `owner` | Table is bound to the creating process; removed when it exits. |
| `persist` | Pairs with `owner`; orphaned table survives and accepts a new owner. |

### Address Families

Each table belongs to exactly one address family. The family selects which packet types the table sees and which hooks are available. Identifiers are namespaced by family: `inet filter` and `ip filter` are distinct tables.

| Family | Packets | Notes |
|---|---|---|
| `ip` | IPv4 | Default if family is omitted. |
| `ip6` | IPv6 | |
| `inet` | IPv4 + IPv6 | Hybrid; lets one table cover both. |
| `arp` | IPv4 ARP | Mangle ARP for clustering. |
| `bridge` | Ethernet via bridge devices | Different priority constants. |
| `netdev` | Any ethertype on a device | Per-interface ingress/egress. |

## Chain

A chain is an ordered list of rules within a table. Two kinds exist.

| Kind | Created with | Purpose |
|---|---|---|
| **Base chain** | `type`, `hook`, `priority` clauses | Entry point from a hook. |
| **Regular chain** | No hook clauses | Jump or goto target for organization. |

Anonymous regular chains are also allowed, defined inline within a verdict statement.

### Base chain types

| Type | Families | Hooks | Purpose |
|---|---|---|---|
| `filter` | all | all valid for the family | Default; standard packet filtering. |
| `nat` | `ip`, `ip6`, `inet` | `prerouting`, `input`, `output`, `postrouting` | NAT via conntrack. First packet of a flow only. |
| `route` | `ip`, `ip6`, `inet` | `output` | Trigger a re-route lookup if header fields changed. |

Restrictions:

- `netdev` only supports `filter` with `ingress` or `egress`, and requires a `device`.
- `arp` only supports `filter` with `input` or `output`.
- `nat` priority must be greater than `-200` (conntrack runs there).

### Priority

Priority is a signed integer that orders chains attached to the same hook. Lower runs first; equal priorities have undefined order. Standard names map to integers and may be combined arithmetically (`mangle - 5`).

| Name | Value | Families | Hooks |
|---|---|---|---|
| `raw` | `-300` | `ip`, `ip6`, `inet` | all |
| `mangle` | `-150` | `ip`, `ip6`, `inet` | all |
| `dstnat` | `-100` | `ip`, `ip6`, `inet` | `prerouting` |
| `filter` | `0` | `ip`, `ip6`, `inet`, `arp`, `netdev` | all |
| `security` | `50` | `ip`, `ip6`, `inet` | all |
| `srcnat` | `100` | `ip`, `ip6`, `inet` | `postrouting` |

The `bridge` family uses different values:

| Name | Value | Hooks |
|---|---|---|
| `dstnat` | `-300` | `prerouting` |
| `filter` | `-200` | all |
| `out` | `100` | `output` |
| `srcnat` | `300` | `postrouting` |

### Policy

Base chains carry a default verdict applied when no rule matches. Allowed values: `accept` (default) and `drop`.

```
table inet filter {
    chain input {
        type filter hook input priority filter
        policy drop
    }
}
```

### Devices

`netdev` and `inet` `ingress` chains are bound to one or more interfaces:

```
table netdev guard {
    chain rx {
        type filter hook ingress device eth0 priority 0
    }

    chain rx_multi {
        type filter hook ingress devices = { eth0, eth1, "wlan*" } priority 0
    }
}
```

A trailing `*` is a kernel-supported wildcard, resolved against currently registered interfaces.

## Hook

A hook is a kernel attachment point in the packet path. Base chains register on a hook with a priority; packets traversing that hook are evaluated by every base chain attached to it, in priority order.

| Family | Hooks |
|---|---|
| `ip`, `ip6`, `inet` | `prerouting`, `input`, `forward`, `output`, `postrouting` |
| `inet` (kernel ≥ 5.10) | also `ingress` |
| `arp` | `input`, `output` |
| `bridge` | same five as IPv4/IPv6 |
| `netdev` | `ingress`, `egress` (per device) |

Packet flow for the IP families:

```
   wire ──▶ ingress ──▶ prerouting ──▶ routing ──┬──▶ input ──▶ local
                                                  └──▶ forward ──▶ postrouting ──▶ wire
                                  local ──▶ output ──▶ routing ──▶ postrouting ──▶ wire
```

`netdev` `ingress` runs after `tc` ingress and before layer-3 demux; `netdev` `egress` runs after layer-3 and before `tc` egress. Tunneled packets (e.g. VXLAN) traverse `netdev` hooks both encapsulated and decapsulated.

## Rule

A rule is an ordered list of statements with an optional comment. Rules live in chains and are identified by a kernel-assigned `handle`.

```
table inet filter {
    chain input {
        type filter hook input priority filter
        policy drop

        ct state established,related accept
        iif lo accept
        tcp dport 22 accept comment "ssh"
    }
}
```

A rule is built from two grammatical pieces:

- **Expressions** — primary, payload, meta, set, prefix, range, binop, etc. — produce or test values.
- **Statements** — wrap expressions and actions; each rule is a sequence of statements.

Statements appear in two roles:

- **Matches** (predicate expressions): a relational/expression statement such as `tcp dport 22`, `ip saddr 10.0.0.0/8`, or `ct state established`. If the predicate is false, the rule is skipped and evaluation moves to the next rule.
- **Actions**: verdicts (`accept`, `drop`, `jump`, ...), mangling (`meta mark set ...`, `snat ...`), logging (`log`), counting (`counter`), set updates (`add @set { ... }`), and so on.

A rule has at most one **terminal** statement (`accept`, `drop`, `reject`, `jump`, `goto`, `return`, NAT statements). Non-terminal statements (`counter`, `log`, `meta`, `ct`, ...) may appear freely. Anything after a terminal statement is unreachable and rejected at load time.

## Verdicts and Evaluation

Verdicts steer control flow.

| Verdict | Effect |
|---|---|
| `accept` | End current base chain. Packet continues to the next base chain on the hook. |
| `drop` | End evaluation entirely. Packet is discarded. |
| `continue` | Fall through to the next rule (default). |
| `return` | Pop the call stack; resume after the calling `jump`. |
| `jump` *chain* | Push position, evaluate *chain*, return on `return` or end-of-chain. |
| `goto` *chain* | Like `jump` but does not push; `return` from *chain* exits to the base chain's policy. |

Evaluation rules:

- For each hook, base chains run in priority order.
- `accept` from any chain ends the current base chain only.
- `drop` short-circuits the entire ruleset across all hooks.
- A packet is accepted iff no matching rule or policy issues `drop`.
- `jump` and `goto` may only target regular chains in the same table.

Anonymous regular chains let a verdict carry inline rules:

```
chain input {
    type filter hook input priority filter
    tcp dport 22 jump {
        ip saddr 10.0.0.0/8 accept
        counter drop
    }
}
```

## Sets

Sets are typed collections referenced by rules.

| Form | Lifetime | Mutable |
|---|---|---|
| **Anonymous** | Tied to the rule that uses it | No |
| **Named** | Independent of any rule | Yes |

```
table inet filter {
    set blocked {
        type ipv4_addr
        flags interval
        elements = { 203.0.113.0/24 }
    }

    chain input {
        type filter hook input priority filter

        # anonymous set, inline
        ip saddr { 10.0.0.0/8, 192.168.0.0/16 } accept

        # reference to the named set
        ip saddr @blocked drop
    }
}
```

| Specification | Meaning |
|---|---|
| `type` | Element data type (`ipv4_addr`, `inet_service`, `ether_addr`, ...). |
| `typeof` | Derive the type from an expression (e.g. `typeof ip saddr . tcp dport`). |
| `flags` | Behavioral flags. |
| `timeout` | Default per-element TTL. Required if rules add elements at runtime. |
| `gc-interval` | Garbage collection cadence for timed entries. |
| `size` | Maximum element count. Required if rules add elements at runtime. |
| `policy` | `performance` (default) or `memory`. |
| `auto-merge` | Coalesce overlapping intervals automatically. |

| Flag | Meaning |
|---|---|
| `constant` | Contents fixed at creation. |
| `dynamic` | Allow updates from the packet path. |
| `interval` | Store ranges. Mutually exclusive with `dynamic`. |
| `timeout` | Allow per-element timeouts. |

## Maps

A map is a set with a value attached to each key. Used for table lookups inside rules.

```
table inet filter {
    map port_to_iface {
        type inet_service : ifname
        elements = { 80 : "eth0", 443 : "eth1" }
    }
}
```

Most set specifications apply. The element syntax is `key : value`; counter and quota types may appear as values but not keys.

`vmap` is the verdict-map variant: the value is a verdict, allowing dispatch tables.

```
chain input {
    type filter hook input priority filter
    iif vmap { "lo" : accept, "eth0" : jump from_eth0 }
}
```

## Flowtables

A flowtable offloads packet forwarding by caching tuples (`iif`, `saddr`, `daddr`, `sport`, `dport`, L3/L4 proto) and rewriting `ttl`/`hoplimit` and link-layer addresses inline.

```
table inet filter {
    flowtable ft {
        hook ingress priority filter
        devices = { eth0, eth1 }
    }

    chain forward {
        type filter hook forward priority filter
        ip protocol { tcp, udp } flow add @ft
    }
}
```

Flowtables attach to the `ingress` hook before `prerouting`. The `flow add @ft` statement in a `forward` chain decides which flows are offloaded. Families: `ip`, `ip6`, `inet`.

## Stateful Objects

Stateful objects are named containers attached to a table. Rules reference them by `<type> name <name>`.

| Type | Purpose |
|---|---|
| `counter` | Packet/byte counts. |
| `quota` | Cap on bytes; matches until exceeded. |
| `limit` | Token-bucket rate limit. |
| `ct helper` | Conntrack helper bindings (FTP, SIP, ...). |
| `ct timeout` | Per-flow conntrack timeouts. |
| `ct expectation` | Programmable conntrack expectations. |
| `secmark` | SELinux secmark labels. |
| `synproxy` | SYN-proxy parameters. |

```
table inet filter {
    counter http_hits {}

    chain input {
        type filter hook input priority filter
        tcp dport 80 counter name "http_hits" accept
    }
}
```

## Elements

Elements are entries inside sets and maps. They can be declared statically as part of a set or map definition, or added and removed dynamically at runtime.

```
set blocked {
    type ipv4_addr
    flags timeout
    elements = {
        203.0.113.5 timeout 1h comment "abuse report",
        203.0.113.7,
    }
}

map port_to_iface {
    type inet_service : ifname
    elements = { 8080 : "eth2" }
}
```

| Option | Meaning |
|---|---|
| `timeout` | Override the set's default TTL. |
| `expires` | Remaining lifetime; primarily for replication. |
| `comment` | Per-element annotation. |

## Handles, Identifiers, and Comments

- **Handle** — kernel-assigned 64-bit identifier, stable for the lifetime of the object. Used to refer unambiguously to a specific table, chain, rule, or set when removing or replacing it.
- **Identifier** — alphanumeric plus `/`, `\`, `_`, `.`. Identifiers clashing with keywords or using other characters must be quoted (`"my-table"`).
- **Comment** — single word or double-quoted string attached to tables, chains, rules, sets, maps, or elements. Decorative; not used for matching.

## Variables and Includes

Ruleset scripts support symbolic variables and includes.

```
define wan = eth0
define lan_nets = { 10.0.0.0/8, 192.168.0.0/16 }

include "/etc/nftables.d/*.conf"

table inet filter {
    chain input {
        type filter hook input priority filter
        policy drop

        iif $wan ip saddr $lan_nets drop
    }
}
```

Variables are lexically scoped to the enclosing block. `redefine` replaces; `undefine` removes.

## Atomicity

A ruleset script is applied to the kernel as a single transaction. The kernel either commits every change in the batch or rejects the whole batch; partial application is not possible. This is what allows safely swapping a complete ruleset without leaving the system unprotected in between.

## See Also

- Upstream wiki: <https://wiki.nftables.org>.
