# The guest setup sequence (#670): `sandy.setup.<name>` declares a step that runs inside the guest before the
# SANDY-READY marker, so a failed step means no marker and the run fails.
#
# Mechanism: each step is a systemd oneshot ordered `Before=` and `RequiredBy=` `sandy-ready.target`. The serial
# getty that autologins root and prints the marker (via bash `loginShellInit`, see guest.nix) `Requires=` and
# `After=` that target, so it does not start when a step fails. `after` orders one step behind another; steps
# without it run in parallel.
#
# Setup runs inside the guest only: the steps are guest code, never run on the host.
{ lib, config, ... }:
let
  unitOf = name: "sandy-setup-${name}.service";
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
        map (dep: {
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
          after = [ "local-fs.target" ] ++ map unitOf step.after;
          requires = map unitOf step.after;
          serviceConfig = {
            Type = "oneshot";
            RemainAfterExit = true;
            User = step.user;
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
