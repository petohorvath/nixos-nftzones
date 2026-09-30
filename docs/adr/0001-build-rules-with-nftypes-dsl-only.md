# Build rules with nftypes DSL helpers only

All rule-body and statement construction goes through `nftypes.dsl.*`
builders. Hand-rolled libnftables-json shapes such as `{ match = …; }`
or `{ accept = null; }` are forbidden. Hand-rolling would give more
control, but the DSL validates its markers and keeps the emitted shapes
in step with the nftypes schema.
