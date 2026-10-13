# Testing

`nix flake check` runs five checks. The VM tests need KVM, so they live outside `checks` as `legacyPackages.<system>.vmTests.<name>`.

## Checks

- **`unit`** ([`tests/unit/`](../tests/unit/)): per-module tests of the compile pipeline's helpers and validators, run by [nix-unit](https://github.com/nix-community/nix-unit). For a focused run inside `nix develop`, select one test file or case, for example `nix-unit tests/entrypoint.nix --attr internal.compile`.
- **`integration`** ([`tests/integration/`](../tests/integration/)): assertions on the rendered nftables JSON for representative scenarios, plus rejection tests that confirm the Phase 1 validators reject known-bad inputs in the live `mkRuleset` pipeline.
- **`examples`** ([`tests/examples.nix`](../tests/examples.nix)): compiles every `examples/*.nix` through `mkRuleset`, so the shipped examples stay in sync with the types and the compiler.
- **`formatting`** and **`lint`**: `nix fmt` must leave the tree unchanged, and statix, deadnix, and actionlint must report nothing.

## VM tests

The VM tests in [`tests/vm/`](../tests/vm/) boot NixOS machines with `pkgs.testers.nixosTest` and check traffic against a real kernel, one topology per feature. NAT and deny-path tests verify through conntrack on the router; the others verify packet contents. Build one with `nix build .#vmTests.<name>`, for example `nix build .#vmTests.atomic-reload`.

| Test            | VMs                                                                  | Coverage                                                                                                                                                                                          |
| --------------- | -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `forward`       | client + router + server + external                                  | L3 forwarding, ICMP, SSH, SNAT masquerade, DNAT port-forward, DNS redirect, default-deny wan→lan, non-DNAT'd port, stateful prelude `[ASSURED]` + INVALID drop, `reject` verdict, `log` statement |
| `vlan`          | router + vlan-iot + vlan-admin (single 802.1Q trunk)                 | inter-VLAN allow, inter-VLAN default-deny                                                                                                                                                         |
| `rpfilter`      | client + router + spoofer (wan-side host with a lan-range /32 alias) | `settings.rpfilter = true` accepts legit src, drops spoofed                                                                                                                                       |
| `marks`         | client + router + server (with `ip rule fwmark X table Y`)           | `sroutes` mark steers forwarded traffic to an alternate routing table                                                                                                                             |
| `droutes`       | router + target                                                      | `droutes` mark steers router-originated traffic (OUTPUT hook)                                                                                                                                     |
| `dualstack`     | client + router + server, IPv4 + IPv6                                | dual-stack forwarding on an `inet` table, v6 conntrack tracking                                                                                                                                   |
| `bridge`        | vmA + bridge + vmB                                                   | `family = "bridge"` L2 filter across a Linux bridge                                                                                                                                               |
| `atomic-reload` | client + router + server                                             | mid-flight `nft -f` ruleset swap preserves established connections                                                                                                                                |
| `activation`    | client + router + server                                             | real NixOS activation removes the SSH allow rule while preserving an established connection                                                                                                       |

The two reload tests use [`reload-verification.py`](../tests/vm/reload-verification.py) to establish SSH, run the test's reload, verify that the same session survives and fresh connections fail, and collect diagnostics on failure. Each test keeps its reload command and ruleset assertions inside the `verify_reload` context.

## CI and other nixpkgs revisions

CI calls the shared [project policy](https://github.com/petohorvath/nixos-project-policy) workflow. It runs `nix flake check` against the locked nixpkgs revision and against the policy's stable and unstable revisions, so upstream regressions surface alongside changes here. The VM tests run once, against the locked revision, on a KVM-enabled `x86_64-linux` runner.

To check another nixpkgs revision locally, override the input:

```bash
nix flake check --override-input nixpkgs "github:NixOS/nixpkgs/$NIXPKGS_REV" \
  --no-write-lock-file --print-build-logs
```
