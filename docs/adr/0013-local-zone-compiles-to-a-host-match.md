# The local zone compiles to a host match at every hook

The local zone stands for the firewall host: as a source, packets the host generates; as a destination, packets addressed to the host. A `local` direction compiles to no match only where the hook already implies it: the `to` side at input and the `from` side at output. At every other hook it compiles to a match that selects only the host's traffic, and where no packet of the host can pass the hook, Phase 1 rejects the reference with a `localZoneUnmatchable` error at the offending direction. Before this, a `local` direction compiled to no match at every hook, so a `local` source at input, postrouting or prerouting matched every packet there ([#54](https://github.com/petohorvath/nixos-nftzones/issues/54)).

| Hook        | `from` names `local` | `to` names `local`     |
| ----------- | -------------------- | ---------------------- |
| prerouting  | rejected             | `fib daddr type local` |
| input       | `meta iif "lo"`      | no match               |
| forward     | rejected             | rejected               |
| output      | no match             | `fib daddr type local` |
| postrouting | `meta iifname ""`    | `fib daddr type local` |

A filter or policy cell from `local` to `local` goes to output, not input: `from` naming `local` always places the cell at output. At input, the loopback rule that `settings.loopback` emits (on by default) accepts the host's own traffic before any sub-chain jump, so the cell could never take effect there.

## Considered options

- **Allow `local` only where the hook implies it**, and reject it everywhere else. Rejected: it rules out an snat from `local`, which masquerades the host's own traffic, and a filter from `local` to `local`.
- **`fib saddr type local` for a `local` source.** Rejected: with `settings.rpfilter` off (the default), a packet from outside that forges one of the host's addresses matches it, and host traffic sent from an address the host doesn't own does not. A packet the host generates has no input device at postrouting and arrives on `lo` at input, which is what the chosen matches test.
- **Keep `local` to `local` at input**, matched by `meta iif "lo"`, and warn when `settings.loopback` is on. Rejected: under the defaults the rule would never run.

## Consequences

- A wildcard direction leaves the local zone out at a hook where the local zone is rejected, rather than failing Phase 1, so `dnats.<name>.from = [ "all" ]` still compiles (see the amendment to ADR-0007).
- `to` no longer takes precedence over `from` when both name `local`, which changes where existing `local` to `local` entries compile.
