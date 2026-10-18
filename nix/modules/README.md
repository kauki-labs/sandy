# sandy-executor: importing into a host's own NixOS config

`sandy-executor.nix` is a standalone NixOS module (#287, M2 spec #269 D3). It
is delivered as a flake output (`nixosModules.sandy-executor`) so a host's own
config — wherever that config lives, outside this repo — imports it directly;
nothing here assumes where or how that host is otherwise managed.

**Additive-only.** The module adds exactly one system user/group
(`sandy-executor`), one systemd service, and one tmpfiles rule (the lingering
marker the service's containment needs — see the module's own doc comment).
It sets nothing under `nix.*`, touches no existing service, and installs no
package system-wide (`bubblewrap` is scoped to the service's own `PATH`, via
`systemd.services.sandy-executor.path`, not `environment.systemPackages`). On
a host that already serves another role (a nix remote-build backend, for
example), this must be the only diff a `nixos-rebuild build` produces.

## Import

In the host's flake, add this repo as an input and import the module:

```nix
{
  inputs.sandy.url = "github:kauki-labs/sandy";

  outputs = { self, nixpkgs, sandy, ... }: {
    nixosConfigurations.<host> = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        { nixpkgs.overlays = [ sandy.overlays.default ]; }
        sandy.nixosModules.sandy-executor
        {
          services.sandy-executor = {
            enable = true;
            orchestrator = "<macos orchestrator mesh host>:<port>";
            hostId = "<this host's self-reported id>";
          };
        }
        # ... the host's existing modules, untouched
      ];
    };
  };
}
```

`orchestrator` and `hostId` are required, with no defaults — an unset value
is a configuration error, not a guessed host (see `services.sandy-executor`'s
option docs in `sandy-executor.nix` for what each one means and why). The
`package`/`agentPackage` options default to the overlay's own
`sandy-host-client`/`sandy-agent`; override only to pin a different build.

## Apply

Never a blind switch on a host this important to verify first:

```bash
nixos-rebuild build --flake .#<host>
# Inspect the closure diff against the current generation — it must touch
# ONLY the sandy-executor user/group/service/tmpfiles rule, nothing else
# (in particular: no change under nix.buildMachines, the nix daemon config,
# or build users, if this host serves that role too).
nixos-rebuild switch --flake .#<host>
```

Keep the prior generation's number handy (`nixos-rebuild list-generations`)
to roll back (`nixos-rebuild switch --rollback`, or
`--switch-generation <n>`) if anything looks wrong post-switch.

## After switch

- `systemctl status sandy-executor` — the service should be `active` and
  stay that way (it holds one persistent connection to the orchestrator for
  as long as it's registered). A real orchestrator must be reachable at
  `orchestrator` for this to succeed; against an unreachable one it exits
  non-zero and `Restart = on-failure` cycles it every 5s.
- `journalctl -b -f` on first start, NOT `journalctl -u sandy-executor -f`:
  `PAMName = "login"` makes logind open a real session for the process (the
  wiring that gives `systemd-run --user` a reachable user instance), and
  logind re-parents the process into that session's own scope unit rather
  than `sandy-executor.service`'s cgroup — so the process's own stdout never
  shows up under a unit-scoped `journalctl -u` query (confirmed against a
  real boot; see `nix/tests/sandy-executor-vm.nix`'s own doc comment for the
  detail). Watch for a containment refusal (`cannot declare any capability:
trusted-process containment is not available: ...`); if that appears, the
  service's user has no reachable `systemd --user` instance after all — see
  the design note in `sandy-executor.nix`'s top comment.
- If this host also serves as an x86_64 remote nix-build backend: run one
  hermetic build through it as before, to confirm that role is unaffected.
