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
        THIS host. Always set, regardless of `vm.enable`: it costs nothing to
        build and `detect_vm_capability`'s `guest_wrapper_present` check
        reads it unconditionally. `vm.enable` is what actually grants
        `${username}` the qemu/kvm/vhost-vsock access this needs to make the
        host declare `SandboxKind::Vm`.
      '';
    };

    vm = {
      enable = lib.mkEnableOption ''
        Vm-capable dispatch on top of #287's trusted-process stage 1:
        qemu/nix/virtiofsd/git on PATH, `kvm` group membership, and
        `/dev/kvm`/`/dev/vhost-vsock` bound into the service's private
        `/dev`. Off by default — real extra attack surface, not just a flag
      '';

      qemuPackage = lib.mkOption {
        type = lib.types.package;
        default = pkgs.qemu;
        defaultText = lib.literalExpression "pkgs.qemu";
        description = "The qemu providing `qemu-system-x86_64` on the service's PATH.";
      };

      nixPackage = lib.mkOption {
        type = lib.types.package;
        default = config.nix.package;
        defaultText = lib.literalExpression "config.nix.package";
        description = ''
          The `nix` the service's PATH uses to resolve+build a `flake/v1`
          dispatch's guest. Defaults to the same `nix` the rest of this host
          already runs, not a second pinned copy.
        '';
      };

      virtiofsdPackage = lib.mkOption {
        type = lib.types.package;
        default = pkgs.virtiofsd;
        defaultText = lib.literalExpression "pkgs.virtiofsd";
        description = "The `virtiofsd` `QemuBackend` launches per guest share.";
      };

      gitPackage = lib.mkOption {
        type = lib.types.package;
        default = pkgs.git;
        defaultText = lib.literalExpression "pkgs.git";
        description = "`git`, on PATH for resolving a `git+https://…` flake ref.";
      };
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
      # service's own process tree. `vm.enable` adds what a `flake/v1`
      # dispatch resolves+boots with: qemu, this host's own nix, virtiofsd
      # per guest share, and git for a `git+https://…` flake ref.
      path = [
        pkgs.bubblewrap
      ]
      ++ lib.optionals cfg.vm.enable [
        cfg.vm.qemuPackage
        cfg.vm.nixPackage
        cfg.vm.virtiofsdPackage
        cfg.vm.gitPackage
      ];

      environment = {
        SANDY_HOST_EXECUTOR_ORCHESTRATOR = cfg.orchestrator;
        SANDY_HOST_EXECUTOR_ID = cfg.hostId;
        SANDY_AGENT_PATH = "${cfg.agentPackage}/bin/sandy-agent";
        SANDY_GUEST_WRAPPER = "${cfg.guestWrapperPackage}";
      }
      # Absolute-path overrides, bypassing a PATH lookup entirely (#335
      # follow-up): confirmed live on ws01 that this unit's own `path =`
      # correctly lists qemu/nix/virtiofsd/git, yet the ACTUAL resolved PATH
      # the running process sees reverts to a stock per-user NixOS profile
      # path with none of them — PAMName's session establishment appears to
      # reset it (root cause not fully chased down; this sidesteps it rather
      # than depends on understanding/fighting NixOS's PAM internals). Each
      # of `capability.rs`'s probe and the real spawn (`impls/vm`'s
      # `QemuBackend`/`VirtiofsdTransport`, `sandy-guest-template`'s
      # `run_nix`) reads the exact same override, so they can never drift
      # onto different binaries.
      // lib.optionalAttrs cfg.vm.enable {
        SANDY_QEMU_BIN = "${cfg.vm.qemuPackage}/bin/qemu-system-x86_64";
        SANDY_NIX_BIN = "${cfg.vm.nixPackage}/bin/nix";
        SANDY_VIRTIOFSD_BIN = "${cfg.vm.virtiofsdPackage}/bin/virtiofsd";
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
        ]
        ++ lib.optionals cfg.vm.enable [
          "AF_VSOCK" # the agent-link's host<->guest transport over vhost-vsock (#238)
        ];
        ProtectProc = "invisible";
        # Still true with `vm.enable`: PrivateDevices builds a private /dev
        # with only the safe pseudo-devices (null/zero/random/tty/…) AND
        # implicitly sets DevicePolicy=closed (systemd.exec(5)) — a physical
        # device node never just reappears because something elsewhere in
        # this config references it, and neither BindPaths nor group
        # membership alone grants cgroup-level device access under a closed
        # policy. Three things have to agree for `${username}` to actually
        # open /dev/kvm or /dev/vhost-vsock: BindPaths (the path exists in
        # this unit's mount namespace), DeviceAllow (the cgroup eBPF device
        # program permits it despite DevicePolicy=closed), and
        # SupplementaryGroups (the device node's own root:kvm 0660
        # permission bits). bwrap's own /dev (built inside its own mount ns
        # for the trusted-process path, #142) is unaffected either way.
        PrivateDevices = true;
        BindPaths = lib.optionals cfg.vm.enable [
          "/dev/kvm"
          # Dash-prefixed: tolerate a host without vhost_vsock loaded rather
          # than failing this unit's start outright (which would also take
          # down the trusted-process capability that works today).
          "-/dev/vhost-vsock"
        ];
        DeviceAllow = lib.optionals cfg.vm.enable [
          "/dev/kvm rw"
          "/dev/vhost-vsock rw"
        ];
        SupplementaryGroups = lib.optionals cfg.vm.enable [ "kvm" ];
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
