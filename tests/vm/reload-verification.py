"""Verify a reload from allowing SSH to dropping fresh connections.

Included in the NixOS test script with builtins.readFile. The caller starts
the VMs and supplies the reload action (and its ruleset assertions) as the
body of verify_reload; all SSH lifecycle and flow checks live here.
"""

from contextlib import contextmanager
from shlex import quote
import typing


class _Machine(typing.Protocol):
    # The pinned channels use different test-driver machine classes.
    # Describe only the operations this helper needs from either one.
    def execute(
        self, command: str, /, *, timeout: int = 900
    ) -> tuple[int, str]: ...

    def succeed(self, command: str, /) -> str: ...

    def wait_for_unit(self, unit: str, /) -> None: ...

    def wait_for_open_port(self, port: int, /) -> None: ...

    def wait_until_succeeds(self, command: str, /, *, timeout: int) -> str: ...


@contextmanager
def verify_reload(
    *,
    client: _Machine,
    router: _Machine,
    server: _Machine,
    server_ip: str,
    subtest: typing.Callable[[str], typing.ContextManager[None]],
) -> typing.Iterator[None]:
    """Require one established SSH session to survive while fresh SSH fails."""
    target = quote(f"root@{server_ip}")
    socket = "/tmp/nftzones-reload-ssh"
    unit = "nft-ssh-master.service"
    ssh_base_opts = (
        "-F /dev/null -o BatchMode=yes "
        "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        "-o ConnectTimeout=5"
    )
    # ProxyCommand=false prevents ssh from opening a replacement TCP
    # connection if the control socket disappears. ControlMaster=no still
    # reuses the existing master, but cannot create a new one.
    session_opts = (
        f"{ssh_base_opts} -S {socket} "
        "-o ControlMaster=no -o ProxyCommand=false"
    )

    def capture(machine: _Machine, command: str) -> str:
        try:
            status, output = machine.execute(command, timeout=10)
            return f"(exit {status})\n{output}"
        except Exception as error:
            return f"(failed to capture: {error})"

    @contextmanager
    def diagnostic_subtest(name: str) -> typing.Iterator[None]:
        with subtest(name):
            try:
                yield
            except Exception:
                print(f"\n=== state at failure of {name!r} ===", flush=True)
                # Capture independently: an unavailable router must not
                # hide evidence of a dead SSH master, or vice versa.
                for label, machine, command in (
                    ("ruleset (router)", router, "nft list ruleset"),
                    ("conntrack (router)", router, "conntrack -L"),
                    (
                        "nftables.service (router)",
                        router,
                        "systemctl status nftables.service --no-pager",
                    ),
                    (
                        "SSH master (client)",
                        client,
                        f"systemctl status {unit} --no-pager",
                    ),
                    (
                        "SSH master journal (client)",
                        client,
                        f"journalctl -u {unit} -n 30 --no-pager",
                    ),
                ):
                    print(f"--- {label} ---\n{capture(machine, command)}", flush=True)
                print("=== end state ===\n", flush=True)
                raise

    def echo_over_session(marker: str) -> None:
        client.succeed(f"ssh {session_opts} -O check {target}")
        # Forwarded mux requests need 30s when several VM tests boot
        # together on CI (the same budget before and after the reload).
        output = client.succeed(
            f"timeout 30 ssh {session_opts} {target} 'echo {marker}'"
        )
        assert marker in output, f"established SSH did not echo {marker}: {output!r}"

    try:
        with diagnostic_subtest("v1: establish SSH through the allow policy"):
            for machine in (client, router, server):
                machine.wait_for_unit("network-online.target")
            server.wait_for_unit("sshd.service")
            server.wait_for_open_port(22)

            client.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
            client.succeed('ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519')
            pubkey = client.succeed("cat /root/.ssh/id_ed25519.pub").strip()
            server.succeed("mkdir -p /root/.ssh && chmod 700 /root/.ssh")
            server.succeed(f"echo {quote(pubkey)} > /root/.ssh/authorized_keys")
            server.succeed("chmod 600 /root/.ssh/authorized_keys")

            # systemd detaches stdio from the test driver's per-command
            # shell; ssh -f (even with setsid) inherited pipes and died on
            # SIGPIPE. No ServerAlive: a brief reload hiccup must not make
            # the master close the very connection being tested.
            client.succeed(
                f"systemd-run --quiet --collect --unit {unit} "
                f"-- ssh {ssh_base_opts} -o ServerAliveInterval=0 "
                f"-o ControlMaster=yes -S {socket} -N {target}"
            )
            client.wait_until_succeeds(
                f"ssh {session_opts} -O check {target}", timeout=15
            )
            echo_over_session("hello-1")

        with diagnostic_subtest("reload: apply v2 and check its ruleset"):
            yield

        with diagnostic_subtest("v2: established SSH survives the reload"):
            echo_over_session("hello-2")

        with diagnostic_subtest("v2: fresh SSH is blocked by the new policy"):
            # Explicitly disable multiplexing, including any default
            # control path, so this probe must send a new SYN.
            status, output = client.execute(
                f"timeout 8 ssh {ssh_base_opts} -S none -o ControlMaster=no "
                "-o ServerAliveInterval=3 -o ServerAliveCountMax=2 "
                f"{target} 'echo should-not-arrive'"
            )
            assert status != 0, (
                f"expected fresh SSH to fail after reload, but it succeeded: {output!r}"
            )
            assert "should-not-arrive" not in output, (
                f"fresh SSH leaked an echo through the new policy: {output!r}"
            )
    finally:
        # Also runs on setup, reload, and assertion failures. Cleanup
        # must not replace the original failure if the client is down.
        try:
            client.execute(f"systemctl stop {unit}", timeout=10)
        except Exception as error:
            print(f"Failed to stop SSH master: {error}", flush=True)
