---
name: sandy
description: Run an untrusted or isolated job in sandy's ephemeral NixOS microVM/process sandbox (kauki-labs/sandy's `sandy` CLI) instead of running it directly on the host. Use this whenever you (the agent) need to execute code you don't fully trust, a job that could touch the network or write files you don't want to risk on the host, or anything that wants CPU/memory/timeout/egress bounds and a locked result envelope you can inspect afterward. Trigger on "run this in a sandbox", "box this up", "run via sandy", "isolate this job", "spin up a microVM for this", or whenever a task calls for running arbitrary/untrusted code or commands with resource or network limits. Not for developing or modifying the sandy codebase itself (that's the repo's own AGENTS.md) — this skill is about USING the already-built `sandy` CLI as a tool from inside an agent session.
---

# sandy: run a job in an isolated microVM/process sandbox

`sandy` boots an ephemeral NixOS microVM (or a contained process, for trusted
jobs) to run one job and hand back a locked result envelope — a status, an
exit code, and whatever outputs/logs you asked to collect. Use it whenever a
job shouldn't run with the full trust and access of the current host:
untrusted code, something that writes files you don't want to risk directly,
or anything that benefits from a declared CPU/memory/timeout/egress bound.

Always pass `-o json` (or the global `--output json`) when you intend to
parse the result programmatically. Every subcommand supports it, and the
result shape is stable — don't scrape the plain-text output.

## Before the first run: `sandy doctor`

Run `sandy doctor -o json` once before using sandy in a new environment. It
checks the real preconditions (nix with flakes enabled, and on macOS, a
working `aarch64-linux` remote builder for vfkit), then that `sandyd` answers
on its control socket (`$SANDY_SOCK`) and at least one executor is registered. It
names exactly what's missing (exit `2`) rather than failing deep inside a boot or
a submit. On macOS specifically, vfkit
needs a matching-arch Linux guest built remotely (nix-darwin's
`nix.linux-builder`) — `doctor` is what catches a missing or misconfigured
builder before you waste time on a `run` that fails mid-boot.

## Running one job: `sandy run`

```
sandy run [TEMPLATE] [OPTIONS] [-- CMD ARGS...]
```

- `TEMPLATE` (positional) names a built-in sandy template/flake attr. For an
  arbitrary flake with no sandy-awareness, use `--flake <ref>` instead
  (mutually exclusive with `TEMPLATE`) — sandy auto-detects whether it's a
  `topology`, `nixos-module`, or `nixos-configuration` and wraps it; force
  one with `--kind`, or override the resolved attr with `--attr`.
  `--from-devshell` is a best-effort fourth kind that synthesizes a
  throwaway module from a flake's `devShells.<system>.default` — always
  opt-in, never auto-detected, and it prints a warning about what doesn't
  carry over (interactive shell assumptions, host env, cwd).
- `sandy run` submits to `sandyd` and waits (an untrusted VM job), so `sandyd` and
  a VM-capable `sandy-host-executor` must be running; `sandy doctor` reports
  whether they are. `TEMPLATE` is `topologies.<system>.<hypervisor>` of sandy's
  bundled guest flake or `REF#topologies.<system>.<hypervisor>`. The executor
  evaluates it but does not build it: on a cold executor, build the guest runner
  of the topology you submit first (for sandy's own:
  `nix build ./nix/guest#packages.<system>.guest-runner`).
- No trailing `-- CMD` means "boot the template's default command."
- **Resource/time bounds**: `--cpu N`, `--mem MiB`, `--timeout SECS`
  (defaults to 5 minutes if omitted). These are requests the host may clamp,
  not guarantees of exactly that much.
- **Moving data in and out**, all repeatable:
  - `--input HOST:NAME` — a host file/dir appears read-only at
    `/run/sandy/inputs/NAME` inside the guest.
  - `--out DEST` collects everything under `/run/sandy/outputs` back to the
    host path `DEST` at teardown; `--out NAME:DEST` collects just
    `/run/sandy/outputs/NAME`.
  - `--secret NAME=@PATH` stages a host file's bytes as a secret, exposed
    in-guest via a dedicated read-only share — never as an env var, never on
    argv, never in the manifest or any log. The leading `@` is required and
    marks "read from this file," not an inline value.
  - `--env KEY=VALUE` for a plain (non-secret) environment variable.
- **Network**: jobs have no egress by default. `--allow HOST:PORT`
  (repeatable) opens exactly those destinations; anything else is refused by
  the enforced allow-list around the boot.
- **A scoped credential for the job**: `--credential <name>` mints a
  short-lived, scoped forge token from a trust root you've already
  registered (see `sandy cred github register` below), injects it as
  `GITHUB_TOKEN`, and revokes it at teardown. `--cred-capability` narrows
  what it can do (`read-code` | `write-code` | `read-pr` | `write-pr`,
  repeatable; defaults to `read-code`).
- `--digests` records a sha256 content digest of every input/output in the
  result receipt — off by default since hashing large outputs costs time.

Read the result's `status`/`classification` field, not just the process exit
code: sandy distinguishes a job that ran and failed from one that was
refused outright (a bad flag, a disallowed path, a missing capability)
before anything ever booted — those are different failure shapes and you
should branch on which one you got, not just "exit != 0."

## Checking in on and managing jobs

`sandy run` blocks in the foreground until the job finishes. For a job that
keeps running without this CLI, use `sandy daemon submit` (below). Either way:

- `sandy ls -o json` — every job `sandyd` knows.
- `sandy status <job-id> -o json` — one job's current state.
- `sandy wait <job-id> -o json` — block until that job reaches a terminal
  state, then print it; exit `0` succeeded, `1` failed or cancelled, `3` an
  infrastructure fault or timeout. Prefer this over polling `status` in a loop.
- `sandy kill <job-id>` — cancel a job and tear its sandbox down.
- `sandy gc --keep-last N` — delete old terminal jobs and sweep stale
  credential staging dirs (defaults to keeping the newest 20).

## Dispatching through `sandyd` (the daemon path)

`sandy daemon submit` makes the same call `sandy run` does, without waiting by
default and with the manifest and isolation-class flags — use it when you want
the job to keep running independent of this CLI invocation, or to run a
trusted argv job.

```
sandy daemon submit --isolation-class <trusted|untrusted> --flake <ref> [OPTIONS] [-- CMD ARGS...]
```

- `--isolation-class` is **required**, no default: `trusted` (a shared-kernel
  backend may run it) or `untrusted` (only a full VM boundary may). Decide
  this honestly — sandy refuses to guess, because guessing wrong here is a
  security decision, not a convenience default.
- `--flake`/`--attr`/`--kind`/`--env`/`--cpu`/`--mem`/`--timeout` mirror
  `sandy run`'s own flags of the same name.
- `--input`/`--out`/`--secret` use the same grammar as `sandy run`, but
  today only work if the host `sandyd` picks for this job actually declares
  it can serve them (`shares_submitter_filesystem`, or — for inputs/outputs
  only — `transfer`). If it doesn't, the whole Submit is refused by name,
  not silently dropped — if you hit that refusal, it means the available
  host doesn't support remote path fields yet, not that you did something
  wrong.
- `--history-lines` (default 10,000) bounds both the live attach scrollback
  and the archived transcript delivered once the job ends.
- `sandy daemon attach <job-id>` attaches to a running (or recently
  finished) job, interactively or for its printed data-plane channel/cap.
  Detaching never ends the job.
- `sandy daemon cancel <job-id>` / `status <job-id>` / `list` round out the
  set, the same calls as `sandy kill`, `status` and `ls` above.

## Managing forge credentials: `sandy cred`

Before `--credential <name>` works on a job, register a trust root once:

```
sandy cred github register <name> --capability read-code [--capability write-pr ...] [--org ORG] [--repo owner/repo ...]
```

This drives the actual GitHub App creation flow, captures the key and ids,
and writes the local config — there's no hand-copying step. It verifies live
scope by default; pass `--skip-verify` only for a deliberate key-only
bootstrap. `sandy cred github verify|import|deregister <name>` round out the
lifecycle. GitLab support is planned but not yet implemented — only
`cred github` exists today.

## Things that bite if you don't know them going in

- **A secret is a file, never an inline value, everywhere in this CLI.**
  `--secret NAME=@PATH` and `daemon submit --cap-file PATH` both read from a
  file, deliberately — an inline secret on argv is visible to anyone who can
  read `ps` or this shell's history.
- **`--flake` always resolves against the EXECUTING host**, never a
  prebuilt artifact from wherever you ran the CLI — for a remote dispatch,
  that's the remote host-executor's own nix evaluation, not yours.
- **Egress is deny-by-default.** A job with no `--allow` entries has no
  network access at all; this is usually what you want for an untrusted job,
  but it surprises people the first time a job needs to reach anything.
  `--allow` the specific `HOST:PORT`s you actually need.
  Likewise a remote job's path fields (`--input`/`--out`/`--secret`) are
  flag-valid even when the placement can't serve them — the refusal lands
  at Submit time with the field named, not as a confusing runtime error.
