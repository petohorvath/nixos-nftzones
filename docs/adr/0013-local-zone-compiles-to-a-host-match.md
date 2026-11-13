# The local zone compiles to a host match at every hook

The local zone stands for the firewall host: as a source, packets the host generates; as a destination, packets addressed to the host. A `local` direction compiles to no match only where the hook already implies it: `to` at input and `from` at output. At every other hook it compiles to a match that selects only the host's traffic, and where no packet of the host can pass the hook, Phase 1 rejects the reference with a `localZoneNotMatchable` error at the offending direction. Before this, a `local` direction compiled to no match at every hook, so a `local` source at input, postrouting or prerouting matched every packet there ([#54](https://github.com/petohorvath/nixos-nftzones/issues/54)).

| Hook        | `from` names `local` | `to` names `local`     |
| ----------- | -------------------- | ---------------------- |
| prerouting  | rejected             | `fib daddr type local` |
| input       | `meta iif "lo"`      | no match               |
| forward     | rejected             | rejected               |
| output      | no match             | `fib daddr type local` |
| postrouting | `meta iif 0`         | `fib daddr type local` |

A bridge table keeps only the two placements its hook implies and rejects every other one: nftables has no `fib` in the bridge family, and its hooks see bridged frames, where `meta iif 0` and `meta iif "lo"` are not known to select the host's own traffic.

A filter or policy cell from `local` to `local` stays at input, where `to` takes precedence, and matches `meta iif "lo"`. While `settings.loopback` is on (the default), the loopback rule accepts that traffic before any sub-chain jump, so the cell never fires; Phase 1 warns with `localToLocalShadowed` when an entry names `local` explicitly in both `from` and `to`. To filter the host's traffic to itself, an entry sets `chain` to output, where the source needs no match and the destination matches `fib daddr type local`.

## Considered options

- **Allow `local` only where the hook implies it**, and reject it everywhere else. Rejected: it rules out an snat from `local`, which masquerades the host's own traffic, and a filter from `local` to `local`.
- **`fib saddr type local` for a `local` source.** Rejected: with `settings.rpfilter` off (the default), a packet from outside that forges one of the host's addresses matches it, and host traffic sent from an address the host doesn't own does not. A packet the host generates has no input device at postrouting and arrives on `lo` at input, which is what the chosen matches test. `meta iif 0` reads "no input device"; `meta iifname ""` says the same, but nftypes refuses to render an empty interface name.
- **Place `local` to `local` at output**, where the loopback rule cannot shadow it. Rejected: a wildcard source expands to the local zone, so an everyday `from = [ "all" ]; to = [ "local" ]` entry would create an output chain, and with the default `chainPolicy = "drop"` every packet the host sends would be dropped.

## Consequences

- A cell that a wildcard produced is dropped where its local-zone direction is rejected, rather than failing Phase 1, so `dnats.<name>.from = [ "all" ]` still compiles (see the amendment to ADR-0007). Only cells built from names the entry spells out are reported.
- A `local` to `local` entry at its default placement does nothing under the default settings, which the warning makes visible.
