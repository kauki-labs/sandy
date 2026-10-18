# Hermetic VM test for the sandy-executor module (#287): proves the
# containment design point in the module's own doc comment — that a
# persistent system user + `PAMName = "login"` + the lingering marker
# actually gives `systemd-run --user --scope` a reachable user systemd
# instance, so `SystemdRunContainment::detect` reports `Available`, not
# `Unavailable`. Without this, capability detection would fail and the
# service would never even attempt to register — the same functional-but-
# dead shape #284 exists to prevent at the wire-population layer, just one
# layer further out (the OS wiring around the binary, not the binary's own
# logic). A manual first-boot log-watch (see nix/modules/README.md) is the
# belt-and-suspenders fallback; this test is what actually gates it in CI,
# before any ws01 apply.
#
# `main` (#288/#294) detects capabilities, then unconditionally dials
# `SANDY_HOST_CLIENT_ORCHESTRATOR` before ever logging anything about the
# detected capabilities themselves — there is no real orchestrator in this
# VM to dial, so the signal this test reads is which failure happens first:
# "cannot declare any capability" (containment broken) vs. "could not dial
# the orchestrator" (containment fine, it got past detection to the dial
# attempt that was always going to fail in this sandbox). Reaching the dial
# attempt at all proves containment succeeded.
{ pkgs }:
let
  # runNixOSTest pins `nixpkgs.pkgs` to whatever `pkgs` it's called on (the
  # node's `nixpkgs.overlays` is read-only there), so the overlay has to be
  # applied to THIS `pkgs` before calling it, not set inside the node module.
  testPkgs = pkgs.extend (import ../overlays/sandy-executor.nix);
in
testPkgs.testers.runNixOSTest {
  name = "sandy-executor-containment";

  nodes.machine =
    { ... }:
    {
      imports = [ (import ../modules/sandy-executor.nix) ];
      services.sandy-executor = {
        enable = true;
        # No real orchestrator in this VM — 127.0.0.1:1 is a loopback address
        # nothing will ever listen on, so the dial after capability detection
        # always fails fast (ECONNREFUSED), which is exactly the signal this
        # test reads (see the file's top comment).
        orchestrator = "127.0.0.1:1";
        hostId = "test-host";
      };

      # #300(b) proof: a short StopIdleSessionSec (set here, NOT in the
      # module — that's ws01-specific risk, not something this module
      # should impose on a consuming host) would tear down an idle,
      # TTY-less logind session well within this test's runtime if the
      # module's KillExcludeUsers drop-in didn't protect it.
      services.logind.settings.Login.StopIdleSessionSec = 2;
    };

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # Not `journalctl -u sandy-executor`: `PAMName = "login"` makes
    # systemd-logind open a real session for the process (that's the whole
    # point — it's what gives systemd-run --user a reachable user instance),
    # and logind re-parents the process into that session's own scope unit
    # (`session-N.scope`) rather than leaving it attached to
    # `sandy-executor.service`'s cgroup. journald tags log entries by the
    # cgroup a process is actually in, so the process's own output lands
    # under the session scope, not the service unit — confirmed against a
    # real boot (`journalctl -u sandy-executor` never saw it; this query,
    # unfiltered, does). The module's own doc comment and
    # nix/modules/README.md's log-watch note both reflect this.
    #
    # `Restart = on-failure` means this cycles every `RestartSec` forever in
    # this VM (nothing ever answers the dial) — wait for the first occurrence
    # of either outcome rather than a one-shot exit status.
    machine.wait_until_succeeds(
        "journalctl -b -o cat --no-pager | "
        + "grep -qE 'cannot declare any capability|could not dial the orchestrator'"
    )

    full_journal = machine.succeed("journalctl -b -o cat --no-pager")

    assert "cannot declare any capability" not in full_journal, (
        f"the host-client refused to declare any capability in the test VM "
        f"(the PAMName/linger wiring did not give it a usable user systemd "
        f"instance) — journal:\n{full_journal}"
    )
    assert "could not dial the orchestrator" in full_journal, (
        f"expected the process to get past capability detection and fail "
        f"only at the (expected, nothing listens here) dial step — got:\n"
        f"{full_journal}"
    )

    # Gates the unit's hardening score (sandy-73's suggestion, #299 security
    # review). `--threshold=` is on its OWN 0-100 scale, not the displayed
    # 0.0-10.0 exposure level (its default is 100, which would never fail
    # against a max displayed score of 10.0 — confirmed by testing: 70 passed
    # against an early 6.6 MEDIUM score, 7 failed against that same 6.6).
    # After fixing CapabilityBoundingSet (an empty NIX LIST serializes to
    # zero lines, silently keeping the full default capset — the empty
    # STRING is what actually emits the reset-to-empty line) and applying
    # the rest of the hardening set, this unit scores 2.5 OK; the remaining
    # ✗ lines are deliberate (the address families and bwrap-needed
    # namespaces/syscalls this unit actually needs; no PrivateNetwork/
    # PrivateUsers, which would break the orchestrator dial and the user
    # manager's D-Bus credentials respectively). 27 leaves a little headroom
    # for incidental score drift across nixpkgs/systemd versions while still
    # failing on an actual regression (a hardening option dropped, a new
    # capability granted, etc). Tighten this if the module gets hardened
    # further.
    print(machine.succeed("systemd-analyze security sandy-executor.service --no-pager --threshold=27"))

    # The inference chain this assertion pair relies on, spelled out since
    # it's indirect: reaching the dial step ⟹ `detect_register_capabilities`
    # returned `Ok` (main.rs hard-exits on `Err`, no fallthrough to the dial
    # call) ⟹ `capabilities_from` found `status.is_available()` (its only
    # `Ok` path) ⟹ `detected_isolation_classes(status)` returned at least
    # `[Trusted]` (capability.rs: it only returns empty when NOT available,
    # which `capabilities_from` already excludes) ⟹ the Register this host
    # would send declares `[Trusted]`, never an empty or hardcoded value.

    # Beyond declaring the capability: prove a REAL job actually runs through
    # the exact mechanism a dispatched job would use (`systemd-run --user
    # --scope`), under this unit's own hardening — not just the trivial
    # probe `SystemdRunContainment::detect` itself runs. The service's own
    # lingering user instance is already up (proven above), so this reuses
    # it rather than starting a second one.
    # `--scope` wraps the *existing* process in place (no transient service
    # unit forked to track separately), so `--wait`/`--pipe` don't apply —
    # the command's own stdout is already this invocation's stdout.
    job_output = machine.succeed(
        "runuser -u sandy-executor -- "
        + "env XDG_RUNTIME_DIR=/run/user/$(id -u sandy-executor) "
        + "systemd-run --user --scope -p Delegate=yes -- "
        + "/run/current-system/sw/bin/echo integration-proof"
    )
    assert "integration-proof" in job_output, (
        f"a real command failed to run through systemd-run --user --scope "
        f"under the hardened unit — got:\n{job_output}"
    )

    # #300(b) proof: with StopIdleSessionSec=2 set on this node and no
    # KillExcludeUsers protection, logind would tear the executor's idle,
    # TTY-less session down well within this sleep — re-checking containment
    # afterward (not just the unit's transient active/activating state,
    # which legitimately cycles every RestartSec against the unreachable
    # orchestrator) is what actually proves the session, not just the
    # process, survived: a killed session makes systemd-run --user
    # unreachable again, which would show up as a FRESH "cannot declare any
    # capability" line the module's drop-in is meant to prevent.
    machine.sleep(5)
    journal_after_idle_window = machine.succeed("journalctl -b -o cat --no-pager")
    assert "cannot declare any capability" not in journal_after_idle_window, (
        f"containment broke after the StopIdleSessionSec window — the "
        f"KillExcludeUsers drop-in did not protect the session — journal:\n"
        f"{journal_after_idle_window}"
    )
  '';
}
