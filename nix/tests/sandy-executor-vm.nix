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
# before any remote-host apply.
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
      # that's remote-host-specific risk, not something this module should impose
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

      # #302: the direct test. `KillUserProcesses` is boolean-valued (unlike
      # `KillExcludeUsers`, a list-valued key that accumulates across
      # conf.d files — see the module's own comment on why that one isn't
      # set here), so turning it on via `services.logind.settings` carries
      # no risk of silently replacing an accumulated list.
      services.logind.settings.Login.KillUserProcesses = true;

      # A throwaway control user, NOT in the module's `KillExcludeUsers`
      # list, with the same PAMName-session shape as `sandy-executor`
      # itself. Without this negative control, the #302 test could pass
      # vacuously: if `KillUserProcesses` silently had no effect at all (a
      # NixOS version regression, a logind reload that never took),
      # sandy-executor's job would "survive" for a reason that has nothing
      # to do with the exclude list actually working.
      #
      # `class=user` turned out to be required (confirmed by interactively
      # inspecting `loginctl session-status` on both users while writing
      # this test): a PAMName-opened session with no TTY defaults to class
      # `background-light`, under which logind starts the runtime directory
      # but NOT the full `user@<uid>.service` manager + bus — `systemd-run
      # --user` has nothing to connect to without it. Giving it `Linger`
      # instead (what sandy-executor relies on, and what starts
      # `user@<uid>.service` regardless of session class) does make the bus
      # appear, but it ALSO turned out to exempt the user from
      # `KillUserProcesses` on its own, independent of `KillExcludeUsers` —
      # defeating the negative control the same way omitting it entirely
      # would. Forcing class `user` gets a real, excludable session instead.
      users.users.kill-control = {
        isSystemUser = true;
        group = "kill-control";
        createHome = true;
        shell = pkgs.shadow;
      };
      users.groups.kill-control = { };
      security.pam.services.kill-control = {
        startSession = true;
        rules.session.systemd.args = [ "class=user" ];
      };
      systemd.services.kill-control-session = {
        description = "#302 control: a logind session the KillExcludeUsers list does not cover";
        # Not `wantedBy multi-user.target` — the test starts this itself, at
        # the point it actually wants the control session open.
        serviceConfig = {
          ExecStart = "${pkgs.coreutils}/bin/sleep infinity";
          User = "kill-control";
          Group = "kill-control";
          PAMName = "kill-control";
          Restart = "no";
        };
      };

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

    # #300: the unit actually carries the configured `TimeoutStopSec`, so a
    # `systemctl stop` gives an in-flight job's own shutdown fail-safe
    # (crates/sandy-host-executor/src/run.rs) the full window it's sized for
    # before systemd SIGKILLs the process — not the default ~90s, shorter
    # than a job's own STAGE1_TIMEOUT_SECS budget. This proves the unit's
    # wiring only; it does NOT exercise a real dispatched job surviving a
    # stop (that needs a fake orchestrator driving an actual `Dispatch` into
    # this VM, a bigger harness not built here — see docs/decisions/
    # sandyd.md §14's "Follow-up (#300)").
    unit_file = machine.succeed("systemctl cat sandy-executor.service")
    assert "TimeoutStopSec=330s" in unit_file, (
        f"expected the unit file to carry TimeoutStopSec=330s — got:\n{unit_file}"
    )

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
    # fires on this TTY-less session) — what actually keeps a dispatched job
    # alive past this window is lingering keeping `user@<uid>.service`
    # running independent of any login session. A real test of the exclude
    # list follows below (#302); this block stays as a basic "nothing
    # regressed" check.
    machine.sleep(5)
    journal_after_idle_window = machine.succeed("journalctl -b -o cat --no-pager")
    assert "cannot declare any capability" not in journal_after_idle_window, (
        f"containment broke after the StopIdleSessionSec window — "
        f"journal:\n{journal_after_idle_window}"
    )

    # #302: exercise KillUserProcesses=yes directly rather than the inert
    # StopIdleSessionSec proxy above. The node sets KillUserProcesses=true
    # and a throwaway `kill-control` user, run WITHOUT lingering and in a
    # real "user"-class session (negative control — without it, a
    # vacuously-passing test couldn't be told apart from sandy-executor's
    # own setup actually protecting its job). A dispatched job lives under
    # its user's OWN `user@<uid>.service`, not the login session scope (the
    # job-cgroup assertion above), so the question this proves is whether
    # ending a user's session reaches into THAT and kills it too.
    #
    # This isolates sandy-executor's WHOLE setup (lingering + the
    # KillExcludeUsers drop-in, exactly as deployed), not KillExcludeUsers
    # alone: confirmed interactively while writing this test that removing
    # sandy-executor from KillExcludeUsers changes nothing here, because
    # lingering already keeps `user@<uid>.service` alive regardless of that
    # list (see the module's own comment on the drop-in). Isolating
    # KillExcludeUsers the other way —
    # disabling lingering to see the list's effect on its own — breaks
    # `SystemdRunContainment::detect` itself before KillUserProcesses ever
    # enters the picture, so there's no config under which that isolation
    # is actually meaningful to test.
    sandy_uid = machine.succeed("id -u sandy-executor").strip()
    machine.succeed("systemctl start kill-control-session")
    machine.wait_for_unit("kill-control-session.service")
    control_uid = machine.succeed("id -u kill-control").strip()
    # `kill-control-session.service` becoming active only means its OWN PAM
    # session opened — not that the bus `systemd-run --user` connects to has
    # finished starting behind it. Without this wait the very next command
    # below raced it and failed ("Failed to connect to user scope bus via
    # local transport: No such file or directory"); sandy-executor's own
    # user bus doesn't need the same wait since its session has been open
    # since early boot. `wait_for_unit(f"user@{uid}.service")` isn't the
    # right check here: that unit is bus/socket-activated, not eagerly
    # started by opening a PAM session, so it can read "inactive, no
    # pending jobs" right up until something first dials the bus — a state
    # `wait_for_unit` treats as a hard failure rather than something to poll
    # past. Wait on the actual socket the bus listens on instead.
    machine.wait_until_succeeds(f"test -S /run/user/{control_uid}/bus")

    # A long-lived job under each user's own user manager — the same shape
    # a real dispatched job runs under, reusing the session each of their
    # services/units already holds open (sandy-executor.service's own
    # PAMName session; kill-control-session.service's, just started).
    machine.succeed(
        f"runuser -u sandy-executor -- env XDG_RUNTIME_DIR=/run/user/{sandy_uid} "
        "systemd-run --user --unit=kill-test-job -- sleep 300"
    )
    machine.succeed(
        f"runuser -u kill-control -- env XDG_RUNTIME_DIR=/run/user/{control_uid} "
        "systemd-run --user --unit=kill-test-job -- sleep 300"
    )

    # End each user's session the way a real idle/session timeout would, not
    # `loginctl terminate-user`: that command is a blunt administrator
    # override ("terminate this user NOW") which killed sandy-executor's job
    # too on an earlier draft of this test — it does not appear to consult
    # KillExcludeUsers at all, unlike a session ending on its own.
    #
    # sandy-executor.service restarts on its own every few seconds for the
    # whole test (Restart=on-failure against the always-refused orchestrator
    # dial) — that natural cycle is what ends ITS session here, not an
    # explicit restart issued by this block: an earlier draft called
    # `systemctl restart sandy-executor.service` directly and raced the
    # self-triggered cycle already in flight, producing a flaky false
    # failure (the job briefly read as killed, then came back). Sleeping
    # past one full cycle is simpler and doesn't fight that loop.
    machine.sleep(7)
    machine.succeed("systemctl stop kill-control-session")

    # KillUserProcesses's sweep is not instantaneous (confirmed interactively
    # while writing this test: a single fixed sleep before checking was
    # sometimes too short and caught the control job still alive). Poll for
    # each side's terminal state rather than sleeping a fixed amount then
    # checking once.
    #
    # Check `user@<uid>.service` itself from the SYSTEM manager
    # (`systemctl is-active`), not `kill-test-job` through
    # `--machine=<user>@ --user` (a bridge into that user's OWN bus): the
    # bridge doesn't just read state, it actively establishes a fresh
    # session to reach it — repeatedly polling it was itself re-opening a
    # session for the user on every single attempt, a classic observer
    # effect that made the control job look alive indefinitely regardless
    # of whether KillUserProcesses had already reaped it. `user@.service`'s
    # own state is a valid proxy for the job under it either way: the sweep
    # acts on the user's whole slice as one unit, so the manager and
    # everything beneath it live or die together.
    machine.wait_until_succeeds(f"systemctl --no-pager is-active user@{sandy_uid}.service", timeout=30)
    machine.wait_until_succeeds(
        f'test "$(systemctl --no-pager is-active user@{control_uid}.service 2>&1)" != active', timeout=30
    )

    sandy_manager_status = machine.succeed(
        f"systemctl --no-pager is-active user@{sandy_uid}.service 2>&1 || true"
    ).strip()
    control_manager_status = machine.succeed(
        f"systemctl --no-pager is-active user@{control_uid}.service 2>&1 || true"
    ).strip()
    assert sandy_manager_status == "active", (
        f"sandy-executor's user@.service (and the dispatched-job stand-in under it) was "
        f"killed when its session ended (is-active: {sandy_manager_status!r}), even "
        f"though sandy-executor is in the KillExcludeUsers list — the exclude list is "
        f"not actually protecting it"
    )
    assert control_manager_status != "active", (
        f"the unprotected control user's user@.service survived session end under "
        f"KillUserProcesses=true (is-active: {control_manager_status!r}) — this test's "
        f"negative control did not fire, so the sandy-executor survival above would "
        f"prove nothing even if it passed"
    )
  '';
}
