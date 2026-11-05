# The guest setup sequence (#670): `sandy.setup.<name>` declares a step that runs inside the guest before the
# SANDY-READY marker. A failed step blocks the marker by design; this is eval-checked only, not live-verified.
#
# Mechanism: each step is a systemd oneshot ordered `Before=` and `RequiredBy=` `sandy-ready.target`. The serial
# getty that autologins root and prints the marker (via bash `loginShellInit`, see guest.nix) `Requires=` and
# `After=` that target, so it does not start when a step fails. `after` orders one step behind another; steps
# without it run in parallel. A cycle in `after` is not detected: it fails closed as a boot timeout.
#
# What a step does NOT get:
#   - the staged secrets as env vars, or the input symlinks: both are made in bash `loginShellInit`, after setup.
#     A step may read /run/sandy/secrets and /run/sandy/inputs directly (ordered after those mounts, see below).
#   - a network in default/proxy mode (the guest has no NIC; the egress relay wraps only the injected job), and no
#     ordering after network-online in NIC mode.
# Setup counts against the host's `timeout_secs` boot budget, and a failed step shows as a boot timeout: there is
# no separate signal. `timeoutSecs` bounds one step so a hung step cannot eat the whole budget unnoticed.
#
# The share mounts are `nofail`, so `local-fs.target` does not wait for them. A step is ordered `After=` and
# `Wants=` them (not `Requires=`, not RequiresMountsFor): a run without inputs has no `sandy-inputs` share, that
# mount fails, and it must not fail the step.
#
# Setup runs inside the guest only: the steps are guest code, never run on the host.
{ lib, config, ... }:
let
  unitOf = name: "sandy-setup-${name}.service";
  shareMounts = [
    "run-sandy-secrets.mount"
    "run-sandy-inputs.mount"
    "run-sandy-outputs.mount"
  ];
in
{
  options.sandy.setup = lib.mkOption {
    default = { };
    description = "Guest setup steps that must succeed before the SANDY-READY marker is printed.";
    type = lib.types.attrsOf (
      lib.types.submodule {
        options = {
          script = lib.mkOption {
            type = lib.types.lines;
            description = "The shell script the step runs. A non-zero exit fails the step and blocks READY.";
          };
          user = lib.mkOption {
            type = lib.types.str;
            default = "root";
            description = "The account the step runs as.";
          };
          description = lib.mkOption {
            type = lib.types.str;
            default = "";
            description = "What the step does; shown in the unit's description and in systemd's failure message.";
          };
          timeoutSecs = lib.mkOption {
            type = lib.types.ints.positive;
            default = 120;
            description = "Seconds the step may run before systemd fails it (a oneshot has no start timeout otherwise).";
          };
          after = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [ ];
            description = "Names of other `sandy.setup` steps that must finish first.";
          };
        };
      }
    );
  };

  config = {
    assertions = lib.concatLists (
      lib.mapAttrsToList (
        name: step:
        [
          {
            assertion = builtins.match "[a-zA-Z0-9_-]+" name != null;
            message = "sandy.setup step name \"${name}\" must match [a-zA-Z0-9_-]+ (it becomes a systemd unit name)";
          }
          {
            assertion = !(builtins.elem name step.after);
            message = "sandy.setup.${name}.after lists the step itself";
          }
        ]
        ++ map (dep: {
          assertion = config.sandy.setup ? ${dep};
          message = "sandy.setup.${name}.after names \"${dep}\", which is not a sandy.setup step";
        }) step.after
      ) config.sandy.setup
    );

    systemd.targets.sandy-ready = {
      description = "Every sandy guest setup step has succeeded";
      wantedBy = [ "multi-user.target" ];
    };

    systemd.services =
      lib.mapAttrs' (
        name: step:
        lib.nameValuePair "sandy-setup-${name}" {
          description = "sandy setup: ${if step.description == "" then name else step.description}";
          before = [ "sandy-ready.target" ];
          requiredBy = [ "sandy-ready.target" ];
          after = [ "local-fs.target" ] ++ shareMounts ++ map unitOf step.after;
          wants = shareMounts;
          requires = map unitOf step.after;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            User = step.user;
            TimeoutStartSec = step.timeoutSecs;
          };
          inherit (step) script;
        }
      ) config.sandy.setup
      // {
        # The gate: no getty, so no autologin shell and no marker, until the target is up. A drop-in on the
        # upstream template, so every instance (ttyS0 on qemu, hvc0 on vfkit) gets it.
        "serial-getty@" = {
          requires = [ "sandy-ready.target" ];
          after = [ "sandy-ready.target" ];
        };
      };
  };
}
