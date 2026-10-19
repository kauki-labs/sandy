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
# `SANDY_HOST_EXECUTOR_ORCHESTRATOR` before ever logging anything about the
# detected capabilities themselves — there is no real orchestrator in this
# VM to dial, so the signal this test reads is which failure happens first:
# "cannot declare any capability" (containment broken) vs. "could not dial
# the orchestrator" (containment fine, it got past detection to the dial
# attempt that was always going to fail in this sandbox). Reaching the dial
# attempt at all proves containment succeeded.
{ pkgs }:
let
  # runNixOSTest pins `nixpkgs.pkgs` to whatever `pkgs` it's called on (the
  # node's `nixpkgs.overlays` is read-only there), so the overlays have to be
  # applied to THIS `pkgs` before calling it, not set inside the node module.
  # Both overlays (#287 split): the module's `agentPackage` option defaults
  # to `pkgs.sandy-agent`, which only the agent overlay provides.
  testPkgs = pkgs.extend (
    final: prev:
    (import ../overlays/sandy-agent.nix final prev)
    // (import ../overlays/sandy-host-executor.nix final prev)
  );
in
testPkgs.testers.runNixOSTest {
  name = "sandy-executor-containment";

  nodes.machine =
    {
      config,
      lib,
      pkgs,
      ...
    }:
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

      # #300(b): a short StopIdleSessionSec, set here (NOT in the module —
      # that's ws01-specific risk, not something this module should impose
      # on a consuming host). NOTE this does not actually exercise
      # KillExcludeUsers: confirmed (sandy-73, #299) that `StopIdleSessionSec`
      # never fires against a TTY-less/no-display session in the first
      # place, and `KillUserProcesses` defaults to `false` on NixOS, under
      # which logind kills nothing on session end regardless of the exclude
      # list. What actually keeps a dispatched job alive is lingering
      # (`users.users.${username}.linger`, written as a tmpfiles marker
      # below) keeping `user@<uid>.service` running independent of any
      # login session — jobs run under `user@.service`'s own cgroup via
      # `systemd-run --user`, never under `session-N.scope`. Kept here as a
      # smoke check (it still shouldn't regress); a real session-survival
      # assertion is tracked separately, #302.
      services.logind.settings.Login.StopIdleSessionSec = 2;

      # A probe unit that reuses `sandy-executor.service`'s EXACT
      # `serviceConfig` (not a re-typed copy that could silently drift from
      # it) to run a real `bwrap`-confined command under the full hardened
      # unit — not from the test driver's unconfined root shell, which the
      # job-runs assertion below used to do and which exercised none of
      # ProtectSystem/SystemCallFilter/PrivateDevices/ProtectProc at all
      # (security review, #299/sandy-73). This is the test that would catch
      # the hardening silently breaking `confines_filesystem` (bwrap) while
      # `is_available()` (the plain reaping probe) stays true — a job would
      # keep running, just without the mount-namespace confinement, with
      # every existing assertion here staying green.
      #
      # Red/green proof this assertion actually catches that (#299 review,
      # infra-f3 + sandy-73): temporarily adding `RestrictNamespaces = true;`
      # to this unit's override made the test fail for the right reason —
      # `bwrap: No permissions to create a new namespace, likely because the
      # kernel does not allow non-privileged user namespaces`, the probe
      # service exiting 1, and `machine.succeed` failing on it. Reverted
      # before merge; the real unit's own `RestrictNamespaces` stays
      # deliberately unset (the module's own comment explains why).
      systemd.services.sandy-executor-probe = {
        serviceConfig =
          (builtins.removeAttrs config.systemd.services.sandy-executor.serviceConfig [
            "RuntimeDirectory"
            "RuntimeDirectoryMode"
            "StateDirectory"
            "StateDirectoryMode"
            "Restart"
            "RestartSec"
          ])
          // {
            Type = "oneshot";
            RemainAfterExit = false;
            ExecStart = lib.getExe' (pkgs.writeShellApplication {
              name = "sandy-executor-probe-run";
              runtimeInputs = [
                pkgs.systemd
                pkgs.bubblewrap
              ];
              # No `|| true`/fallback anywhere here: a `bwrap` that can't
              # create its own namespaces under this unit's hardening must
              # make this whole script fail, not silently run the job
              # unwrapped — that failure is exactly the signal this test
              # needs to be able to observe (security review, #299/
              # sandy-73 + infra-f3: a silent confines_filesystem=false
              # flip must not stay green).
              text = ''
                # shellcheck disable=SC2016 # the $(...) is meant for the nested `sh -c`, not this script
                systemd-run --user --scope -p Delegate=yes -- \
                  sh -c 'echo "job-cgroup: $(cat /proc/self/cgroup)"; exec bwrap --ro-bind / / --dev /dev --tmpfs /tmp --unshare-all --share-net -- /run/current-system/sw/bin/echo confined-ok'
              '';
            }) "sandy-executor-probe-run";
          };
      };
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
        f"the host-executor refused to declare any capability in the test VM "
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

    # A basic liveness check that `systemd-run --user --scope` itself works
    # for this user at all. NOTE what this does NOT prove: `runuser` here
    # starts from the test driver's unconfined root shell, outside
    # `sandy-executor.service` entirely — none of ProtectSystem,
    # SystemCallFilter, PrivateDevices, or ProtectProc apply to it, and it
    # never runs `bwrap`. The in-unit probe below is what actually exercises
    # the hardening (security review, #299/sandy-73 + infra-f3).
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

    # The load-bearing proof: `sandy-executor-probe` reuses
    # `sandy-executor.service`'s EXACT `serviceConfig` (read live from
    # `config`, not a hand-copied duplicate that could drift from it) to run
    # `systemd-run --user --scope` -> `bwrap` -> a marker command FROM INSIDE
    # the fully hardened unit. `confines_filesystem()`
    # (`impls/local/src/containment.rs`) is what decides whether a dispatched
    # job gets bwrap's mount-namespace confinement at all; if any hardening
    # directive silently broke bwrap under this exact unit, `machine.succeed`
    # here would fail loudly (the probe script has no `|| true`/fallback path
    # — a `bwrap` that can't create its namespaces fails the whole script,
    # never falls back to running the job unwrapped), rather than the
    # declared capability staying `[Trusted]` while jobs silently lost their
    # filesystem confinement.
    probe_output = machine.succeed("systemctl start sandy-executor-probe && journalctl -b -o cat --no-pager")
    assert "confined-ok" in probe_output, (
        f"bwrap did not complete inside the hardened unit — a hardening "
        f"directive may have silently broken containment's confines_filesystem "
        f"path — journal:\n{probe_output}"
    )
    # Names the real survival mechanism directly (sandy-73, #299): a
    # dispatched job's cgroup must be under user@<uid>.service, not
    # session-N.scope — that's what lingering actually keeps alive
    # independent of any login session, not KillExcludeUsers. Read BEFORE
    # bwrap, inside the systemd-run --user scope: bwrap's --unshare-all
    # includes --unshare-cgroup, which would make /proc/self/cgroup read
    # "0::/" from inside the new namespace and wrongly fail this check
    # even when the real cgroup placement is correct (sandy-73, #299).
    cgroup_line = next(line for line in probe_output.splitlines() if line.startswith("job-cgroup: "))
    assert "user@" in cgroup_line and "session-" not in cgroup_line, (
        f"the probed job did not run under user@.service's cgroup as "
        f"expected: {cgroup_line}"
    )

    # #300(b) smoke check: with StopIdleSessionSec=2 set on this node, wait
    # past it and re-check containment. This does NOT prove KillExcludeUsers
    # is doing anything (confirmed, sandy-73, #299: StopIdleSessionSec never
    # fires on this TTY-less session, and KillUserProcesses defaults to
    # `false` anyway, so the exclude list is inert defense-in-depth here,
    # not active protection). What actually keeps a dispatched job alive
    # past this window is lingering keeping `user@<uid>.service` running
    # independent of any login session. A real assertion of that survival
    # path is tracked separately, #302; this block stays as a basic
    # "nothing regressed" check.
    machine.sleep(5)
    journal_after_idle_window = machine.succeed("journalctl -b -o cat --no-pager")
    assert "cannot declare any capability" not in journal_after_idle_window, (
        f"containment broke after the StopIdleSessionSec window — "
        f"journal:\n{journal_after_idle_window}"
    )
  '';
}
