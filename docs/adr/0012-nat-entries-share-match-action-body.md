# NAT entries share a `{ match; action; }` body

The body of an snat and a dnat is `rule = { match; action; }`: `match` is a list of match statements, and `action` holds exactly one tagged rewrite, `snat` or `masquerade` for snats, and `dnat` or `redirect` for dnats. Before this, an snat's body was the bare tag (`rule.masquerade`), so an snat could not be limited to particular ports or protocols, and the two NAT groups read differently. The `action` wrapper exists because `lib.types.attrTag` accepts exactly one key from its tag set, so `match` cannot sit beside the tag. The tags keep the names of the nftables statements they compile to.

## Considered options

- **Lift `match` onto the entry** (`snats.x = { from; to; match; rule.masquerade = { }; }`). It drops the `action` wrapper, but `rule` would then hold only the rewrite, while a filter's `rule` holds its matches and verdict, and an entry's body would no longer be its rule.
- **Keep the snat body as the bare tag** and document that an snat cannot take a match. Rejected: limiting masquerade or source translation to some traffic is a common need, and the two NAT groups would stay inconsistent.
