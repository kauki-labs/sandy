# The ws01 host-executor service (#287, M2 stage 1: trusted-process only, no
# VM/agent-image). ADDITIVE ONLY — this module must never touch
# `nix.buildMachines`, the nix daemon, or build users: ws01 is the sandy
# swarm's x86_64 remote build backend, and this service is layered alongside
# that role, never inside it. It only adds a user, a group, a service, and
# whatever packages the service's own PATH needs.
#
# `sandy-host-executor`'s trusted-process containment is
# `systemd-run --user --scope` over cgroup v2 (`impls/local/src/containment.rs`),
# which needs a real user `systemd --user` instance reachable over the session
# bus. A `DynamicUser` service has no such instance (no logind session, no
# `XDG_RUNTIME_DIR`), which would make `SystemdRunContainment::detect` report
# `Unavailable` and the service would never declare any capability at all —
# running, but silently incapable of everything, the same failure shape #284
# existed to prevent at the wire-population layer. So this uses a persistent
# system user instead, a minimal PAM service (`startSession = true`, not the
# full interactive "login" stack — no auth/account/password modules this
# service account never needs) so starting the service opens a real logind
# session for it, and a lingering marker
# (`/var/lib/systemd/linger/<user>`, what `loginctl enable-linger` itself
# writes) so that user's systemd instance survives independent of any
# interactive session. Confirmed against a real boot (nixosTest, see
# `nix/tests/sandy-executor-vm.nix`): `systemd-run --user`'s own probe
# succeeds and the binary declares `supported_isolation_classes: [Trusted]`.
#
# Side effect of `PAMName`: logind re-parents the process into its own
# session scope (`session-N.scope`), not `sandy-executor.service`'s cgroup —
# so the process's own stdout/stderr never shows up under a unit-scoped
# `journalctl -u sandy-executor` query (confirmed in the same test). An
# operator watching the log needs `journalctl -b -f`, not `-u`; see
# `nix/modules/README.md`'s log-watch note.
#
# The host-executor only DIALS the orchestrator (#288's main loop) — it never
# binds a mesh listener itself, so there is no "bind to the mesh interface
# only" restriction to apply here (unlike sandyd's `SANDY_MESH_LISTEN`, which
# is out of #287's scope per the issue's own comment thread). Least privilege
# here means systemd hardening around the process and 0700 runtime/state
# dirs, not a firewall rule for a socket this binary never opens.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.sandy-executor;
  username = "sandy-executor";
in
{
  options.services.sandy-executor = {
    enable = lib.mkEnableOption "the sandy-host-executor service (#287, M2 stage 1)";

    orchestrator = lib.mkOption {
      type = lib.types.str;
      example = "100.64.0.2:7420";
      description = ''
        The macOS orchestrator's mesh management address to dial
        (`SANDY_HOST_EXECUTOR_ORCHESTRATOR`). Required, no default — an unset
        orchestrator address is a configuration error, never a guessed host.
      '';
    };

    hostId = lib.mkOption {
      type = lib.types.str;
      description = ''
        The self-reported host_id this host registers under
        (`SANDY_HOST_EXECUTOR_ID`). Bookkeeping and placement only — the
        orchestrator authorizes by mesh peer identity, never by this value
        (decision 12).
      '';
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.sandy-host-executor;
      defaultText = lib.literalExpression "pkgs.sandy-host-executor";
      description = "The sandy-host-executor package to run.";
    };

    agentPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.sandy-agent;
      defaultText = lib.literalExpression "pkgs.sandy-agent";
      description = "The sandy-agent package a dispatched job's sandbox launches (SANDY_AGENT_PATH).";
    };

    guestWrapperPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.sandy-guest-wrapper;
      defaultText = lib.literalExpression "pkgs.sandy-guest-wrapper";
      description = ''
        The packaged guest-wrapper source tree (SANDY_GUEST_WRAPPER, #332):
        resolves+builds a `flake/v1` dispatch's guest topology, the same
        `nix/guest-wrapper` logic `sandy run --flake` runs locally, against
        THIS host. Declaring `SandboxKind::Vm` capability also requires this
        to actually be present and KVM/vhost-vsock to be reachable by
        `${username}` — none of which this module enables yet (#287 is
        trusted-process-only stage 1); setting this option alone does not
        make a host VM-capable.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${username} = {
      isSystemUser = true;
      group = username;
      home = "/var/lib/sandy-executor";
      createHome = true;
      # No interactive shell: this account only ever runs as the service's
      # User=, never an operator login.
      shell = pkgs.shadow;
    };
    users.groups.${username} = { };

    # A minimal PAM service — just enough to register a logind session
    # (pam_systemd, via `startSession`) — instead of inheriting the full
    # "login" stack's auth/account/password modules this non-interactive
    # service account never exercises (security review, #299/sandy-73).
    security.pam.services.${username} = {
      startSession = true;
    };

    # #300(b): defense-in-depth, inert under the default
    # `KillUserProcesses=false` (confirmed, sandy-73/#299 — NixOS defaults it
    # to `false`, under which logind kills nothing on session end regardless
    # of this list, and `StopIdleSessionSec` doesn't fire on this TTY-less
    # session anyway). What actually keeps a dispatched job alive is
    # lingering keeping `user@<uid>.service` running independent of any
    # login session (see nix/tests/sandy-executor-vm.nix's job-cgroup
    # assertion, and tracking issue #302 for the one open gap: if ws01 ever
    # sets `StopIdleSessionSec` itself, protection is logind's no-TTY idle
    # model, not this drop-in). Kept anyway in case ws01's own config ever
    # turns `KillUserProcesses` on for other accounts — a drop-in, not
    # `services.logind.settings`, because `KillExcludeUsers` is a
    # list-valued logind.conf key that ACCUMULATES across drop-in files
    # (systemd's own conf.d semantics) — this adds `sandy-executor` to
    # whatever ws01's own logind.conf.d already excludes, rather than
    # risking the `services.logind.settings` module's single merged value
    # silently replacing it (security review, #299/sandy-73). Never assign
    # an empty value here: that RESETS the accumulated list.
    #
    # `root` is included explicitly: an unset `KillExcludeUsers` implicitly
    # excludes root, but this drop-in's own assignment overrides that
    # default rather than adding to it (CodeRabbit, #299) — dropping `root`
    # here would let `KillUserProcesses=yes` kill root's session processes
    # on logout where it previously didn't.
    environment.etc."systemd/logind.conf.d/50-sandy-executor.conf".text = ''
      [Login]
      KillExcludeUsers=root ${username}
    '';

    # What `loginctl enable-linger sandy-executor` itself writes: keeps this
    # user's `systemd --user` instance running independent of any login
    # session, which `systemd-run --user --scope` needs to be reachable at
    # all times the service is up, not only while a session happens to be open.
    systemd.tmpfiles.rules = [
      "f /var/lib/systemd/linger/${username} 0644 root root -"
    ];

    systemd.services.sandy-executor = {
      description = "sandy host-executor (#287, M2 stage 1, trusted-process)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      # bwrap is the mount-namespace confinement layer SystemdRunContainment
      # probes for (#142); scoped to this service's own PATH, not installed
      # system-wide, so the only visible change to ws01's environment is this
      # service's own process tree.
      path = [ pkgs.bubblewrap ];

      environment = {
        SANDY_HOST_EXECUTOR_ORCHESTRATOR = cfg.orchestrator;
        SANDY_HOST_EXECUTOR_ID = cfg.hostId;
        SANDY_AGENT_PATH = "${cfg.agentPackage}/bin/sandy-agent";
        SANDY_GUEST_WRAPPER = "${cfg.guestWrapperPackage}";
      };

      serviceConfig = {
        ExecStart = "${cfg.package}/bin/sandy-host-executor";
        User = username;
        Group = username;
        # Registers a real logind session for this user on start, so a user
        # systemd instance + session bus exist for systemd-run --user to
        # reach — see the module-level doc comment above. Points at the
        # minimal PAM service defined above, not the interactive "login" one.
        PAMName = username;

        RuntimeDirectory = "sandy-executor";
        RuntimeDirectoryMode = "0700";
        StateDirectory = "sandy-executor";
        StateDirectoryMode = "0700";

        Restart = "on-failure";
        RestartSec = "5s";

        # Least privilege around the host-executor process itself; the
        # sandboxed job it dispatches is bwrap/cgroup-confined separately
        # (security review, #299/sandy-73: since `systemd-run --user --scope`
        # execs the job in this unit's own context, this hardening is the
        # outer boundary for dispatched jobs too, not just this process).
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        ProtectHostname = true;
        # `containment.rs` never writes cgroupfs itself — `systemd-run --user`
        # asks the user's systemd instance to create/manage the delegated
        # scope, over its own socket, not this process touching
        # /sys/fs/cgroup directly, so this needs no exemption (sandy-73).
        ProtectControlGroups = true;
        # NOT `[ ]`: NixOS's unit-option serializer emits one line per list
        # element, so an empty LIST writes no `CapabilityBoundingSet=` line
        # at all — leaving the default (full) set in place, silently. The
        # empty STRING is what actually emits `CapabilityBoundingSet=` with
        # no value, which systemd defines as resetting the bounding set to
        # empty (caught by `systemd-analyze security` itself still showing
        # every `CapabilityBoundingSet=~CAP_*` check failing against `[ ]`;
        # #299/sandy-73 review).
        CapabilityBoundingSet = "";
        RestrictSUIDSGID = true;
        RestrictRealtime = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        RestrictAddressFamilies = [
          "AF_UNIX" # the user systemd/D-Bus session bus
          "AF_INET"
          "AF_INET6" # the orchestrator dial + each dispatch's forward_back
          "AF_NETLINK" # dhcpcd/udev-adjacent; harmless to allow, costly to chase down
        ];
        ProtectProc = "invisible";
        PrivateDevices = true; # bwrap builds its own /dev inside its own mount ns regardless
        UMask = "0077";
        RemoveIPC = true;
        SystemCallFilter = [
          "@system-service"
          # bwrap's own confinement needs these (#142); none are in
          # @system-service, and none are a privilege sandy-host-executor
          # itself exercises outside of spawning bwrap.
          "@mount"
          "unshare"
          "pivot_root"
          "setns"
        ];
        # Left open (not hardened): `bwrap` needs to create its own mount/PID
        # namespaces for the confinement layer SystemdRunContainment probes
        # for (#142); restricting namespaces here would break that.
      };
    };
  };
}
