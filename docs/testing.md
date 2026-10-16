# Testing

`nix flake check` runs every check below, including the VM tests, so it needs KVM.

## Checks

The tests follow the devnix-labs test standard: each kind has one directory under [`tests/`](../tests/), one entry point that lists its tests by hand, and one shared runner in [`tests/runners/`](../tests/runners/). Shared test data lives in [`tests/fixtures/`](../tests/fixtures/) and helpers in [`tests/helpers/`](../tests/helpers/).

- **`unit`** ([`tests/unit/`](../tests/unit/)): nix-unit suites on the library, imported from source. Each suite has the path of the source file it tests, so `tests/unit/internal/compile.nix` (attribute `internal.compile`) tests `lib/internal/compile.nix`, and the suites of `lib/internal/normalize.nix` live in `tests/unit/internal/normalize/`. The root also holds suites that span several files: `scenarios` checks the [Phase 1](compile-pipeline.md#phase-1-normalize) warnings and structured assertions of each scenario fixture, `rejections` confirms that `mkRuleset` rejects each known-bad fixture with the expected errors, `examples` compiles every `examples/*.nix`, and `name-key` checks the `name` invariant across the object types.
- **`integration`** ([`tests/integration/`](../tests/integration/)): nix-unit suites that evaluate nftzones inside a host. `nixos-module` evaluates the NixOS module with `pkgs.nixos`.
- **`build-scenarios`** ([`tests/build/`](../tests/build/)): runs `nft -j --check` on the rendered JSON of every scenario fixture, through the LKL and libredirect shim in [`tests/helpers/nft-check.nix`](../tests/helpers/nft-check.nix), since the build sandbox has no netlink socket.
- **`formatting`** and **`lint`** ([`dev/checks.nix`](../dev/checks.nix)): `nix fmt` must leave the tree unchanged, and statix, deadnix, and actionlint must report nothing.

Inside `nix develop`, run the nix-unit suites directly, optionally selecting one suite:

```bash
nix-unit tests/unit
nix-unit tests/unit --attr internal.compile
nix-unit tests/integration --attr nixos-module
```

Pass `--arg nixpkgs …` to run the suites against another nixpkgs. Build one entry with `nix build .#checks.<system>.<entry>`, for example `nix build .#checks.x86_64-linux.build-scenarios`.

## VM tests

The VM tests in [`tests/vm/`](../tests/vm/) are checks named `vm-<name>`. They are NixOS test modules that the VM runner passes to `pkgs.testers.runNixOSTest`, and they check traffic against a real kernel, one topology per feature. NAT and deny-path tests verify through conntrack on the router; the others verify packet contents. Build one with `nix build .#checks.<system>.vm-<name>`, for example `nix build .#checks.x86_64-linux.vm-atomic-reload`.

| Test               | VMs                                                                  | Coverage                                                                                                                                                                                          |
| ------------------ | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `vm-forward`       | client + router + server + external                                  | L3 forwarding, ICMP, SSH, SNAT masquerade, DNAT port-forward, DNS redirect, default-deny wan→lan, non-DNAT'd port, stateful prelude `[ASSURED]` + INVALID drop, `reject` verdict, `log` statement |
| `vm-vlan`          | router + vlan-iot + vlan-admin (single 802.1Q trunk)                 | inter-VLAN allow, inter-VLAN default-deny                                                                                                                                                         |
| `vm-rpfilter`      | client + router + spoofer (wan-side host with a lan-range /32 alias) | `settings.rpfilter = true` accepts legit src, drops spoofed                                                                                                                                       |
| `vm-marks`         | client + router + server (with `ip rule fwmark X table Y`)           | `sroutes` mark steers forwarded traffic to an alternate routing table                                                                                                                             |
| `vm-droutes`       | router + target                                                      | `droutes` mark steers router-originated traffic (OUTPUT hook)                                                                                                                                     |
| `vm-dualstack`     | client + router + server, IPv4 + IPv6                                | dual-stack forwarding on an `inet` table, v6 conntrack tracking                                                                                                                                   |
| `vm-bridge`        | vmA + bridge + vmB                                                   | `family = "bridge"` L2 filter across a Linux bridge                                                                                                                                               |
| `vm-atomic-reload` | client + router + server                                             | mid-flight `nft -f` ruleset swap preserves established connections                                                                                                                                |
| `vm-activation`    | client + router + server                                             | real NixOS activation removes the SSH allow rule while preserving an established connection                                                                                                       |

The two reload tests use [`reload-verification.py`](../tests/vm/reload-verification.py) to establish SSH, run the test's reload, verify that the same session survives and fresh connections fail, and collect diagnostics on failure. Each test keeps its reload command and ruleset assertions inside the `verify_reload` context.

## CI and other nixpkgs revisions

CI calls the shared [project policy](https://github.com/petohorvath/nixos-project-policy) workflow. It builds the checks against the locked nixpkgs revision and against the policy's stable and unstable revisions, so upstream regressions surface alongside changes here. The VM tests run in the policy's separate `VM tests` jobs with all three revisions; a runner without KVM reports them as skipped.

To check another nixpkgs revision locally, override the input:

```bash
nix flake check --override-input nixpkgs "github:NixOS/nixpkgs/$NIXPKGS_REV" \
  --no-write-lock-file --print-build-logs
```
