---
title: "Decisions: the T3 guest image"
status: accepted
project: sandy
updated: 2026-11-03
---

# Decisions: the T3 guest image

The guest an on-demand T3 environment boots (epic #597, #608): the t3 server and the harness binaries it launches,
and nothing else. Starting the server is the service workload kind's job (#589), and the provider config comes from
the identity profile (#592).

## 1. A separate image with its own nixpkgs pin

**Status:** accepted.

**Context.** The base guest in `nix/guest` has no t3 and no harness, so a booted environment could do no work. Its
nixpkgs pin carries t3code 0.0.44, which lacks `t3 pair --scope`. The owner exercised 0.1.2.

**Decision.** `nix/guest/flake.nix` adds two guests, `qemu-t3` and `vfkit-t3` (topologies, `nixosConfigurations` and
`guest-runner-t3` packages), that add a `t3Module` to the base modules. t3 comes from a second input, `nixpkgs-t3`,
pinned to the root flake's nixpkgs revision as of 2026-11-03, where it is 0.1.2. The pin does not follow later
root bumps (#631). Only that package uses the second pin, so the base
guest's kernel, agent and topology do not change (the base `qemu` topology is byte-identical to `main`).

The module installs `t3code` built with `enableClaude` and `enableCodex`, so `claude` and `codex` sit on t3's own
PATH, and `sandy-t3-ready`, a probe that succeeds when `127.0.0.1:<port>` answers HTTP with a status below 500. t3 answers
503 while it starts and 401 once auth is on, so readiness never rests on console text. It proves an HTTP listener, not
that t3's API or websocket is up. It refuses a port argument that is not digits and bypasses any proxy variable. claude-code is unfree, so the module allows that one package.

**Consequences.**

- The guest has 2 GiB (`microvm.mem`, forced over the base guest's 512 MiB), because the topology's value is what a
  caller that omits `--mem` boots with.
- The image holds no key, token or config. The credential module exports every staged secret into the login shell,
  so `t3 serve` and the harnesses it launches inherit them: #589 and #592 own that threat model. Provider config dirs and the pairing scope come at run time.
- The closure is about 3.7 GB: nixpkgs builds t3code with electron (1.4 GB, plus gtk and gstreamer) and codex is
  1 GB. The image is built once and shared read-only. A server-only build is a follow-up.
- A bump of the t3 version is a change to the `nixpkgs-t3` pin, independent of the base guest.
- `sandy run` evaluates a topology and does not build its artifacts, so a caller builds `guest-runner-t3` first, as
  the live tests do for the base guest.

**Set aside.**

- Bumping the base guest's nixpkgs to get 0.1.2: it moves the kernel and every live test's baseline for one package.
- A server-only t3 build now: it means rebuilding upstream's bundle without electron, which is a separate item.

## Live evidence (2026-11-03, x86_64 KVM host, qemu, 2 GiB)

`t3 v0.1.2` is on PATH, t3's wrapper carries `claude-code-2.1.311` and `codex-0.164.0`, `sandy-t3-ready` fails with
rc 7 (connection refused) before `t3 serve` starts and succeeds 6 s after it, and `t3 pair` prints
`Pairing with sandy (http://127.0.0.1:3773)` and a QR code. Not yet tested: the vfkit guest, the stdio harness
protocols through the guest console, a primary T3 linking to the guest, and a harness reaching its provider (#609).

## Live evidence (2026-11-07, link from a delegator app)

A Mac delegator app (T3 Code 0.1.7) linked a `qemu-t3` guest on a Linux/KVM host through `scripts/dev/t3-env/`, used
the environment, and unlinked it when the job ended. The run found these constraints:

- The guest needs t3code 0.1.6 or newer. The app links only a server that reports `mcpModeLimitHeader` and
  `linkFence`; 0.1.2 reports neither and the link fails with `PeerLinkError`.
- `--env` does not reach the job command. Secrets do, as login-shell exports of `/run/sandy/secrets/<NAME>`. The
  start script passes the pairing nonce as an argument.
- `systemd-run` looks the command up in sudo's `secure_path`, and does not set `SUDO_UID`. Call sandy by absolute
  path and set `SUDO_UID`, or `nix eval` refuses the checkout (libgit2 owner check).
- A sandy that runs as root reads trust roots only when the directory and files are root-owned (`cred.rs`).
- `install -d -o t3` gives the owner to the leaf only. Create `$base` and `$base/userdata` in one call.
- A `SIGTERM` to `sandy run` leaves the record at `running` and the credential unrevoked (#687).

The pairing code leaves the guest over plain http on a nonce path, because the guest has no ssh and the console is
unreadable before the job ends. Not tested: a harness thread (no provider credential staged), the app closed during
unlink, and a killed wrapper or an unreachable host.
