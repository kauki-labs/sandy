//! The `sandy` command-line interface.
//!
//! A thin argv shell over the `sandy-cli` library: `doctor` (Block 0) and the
//! Block 6 job ops `run`/`ls`/`status`/`wait`/`kill`/`gc`. All orchestration lives
//! in the library modules; `main` only parses argv, selects the host backend, and
//! maps results to process exit bands (INV-11).
//!
//! A separate crate root from `lib.rs`, so it repeats that file's
//! `clippy::print_stdout` deny (#512): [`sandy_cli::output::emit`] is
//! this binary's only sanctioned stdout sink.
#![deny(clippy::print_stdout)]

use base64::Engine as _;
use clap::{Parser, Subcommand};
use sandy::{CoreError, GithubAdapter, Journal, ProcessExit, Scope};
use sandy_cli::{
    app_register::{self, Owner},
    doctor,
    output::{
        AttachEvent, AttachedChannel, CancelledJob, JobRecords, JobStatusReport, JobSummaries, MeshFingerprint,
        OutputFormat, Render, SubmittedJob, emit,
    },
    plan::{JobPlan, RunArgs, parse_run},
    supervisor,
};
use sandy_control_proto::{
    AttachRequest, CancelRequest, ListRequest, PruneRequest, StatusRequest, SubmitRequest, control_request,
    control_response,
};

/// Command-line surface for `sandy`.
#[derive(Debug, Parser)]
#[command(name = "sandy", about = "Sandboxed job runner")]
struct Cli {
    /// The subcommand to run.
    #[command(subcommand)]
    command: Command,
    /// Output format: `plain` (human, default) or `json` (for agents/automation).
    #[arg(long = "output", short = 'o', value_enum, default_value = "plain", global = true)]
    output: OutputFormat,
}

/// Top-level `sandy` subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Verify environment preconditions before any job runs (Block 0, REQ-12).
    Doctor,
    /// Boot a template and run a job to completion in the foreground.
    Run {
        /// The template (flake attr / image) to boot. Mutually exclusive with `--flake`.
        #[arg(required_unless_present = "flake", conflicts_with = "flake")]
        template: Option<String>,
        /// Boot an arbitrary flake with no sandy awareness at all (#325): sandy
        /// detects which of three template kinds it exposes (`topology` |
        /// `nixos-module` | `nixos-configuration`, see `--kind`) and wraps it
        /// through its own guest-wrapper flake, always printing which kind it
        /// picked. `--from-devshell` adds a fourth, always-explicit kind.
        #[arg(long, conflicts_with = "template")]
        flake: Option<String>,
        /// Override the attr name `--flake` resolves within its kind (the
        /// `nixosModules`/`nixosConfigurations`/`devShells` entry; default
        /// `"default"`, ignored for kind `topology`).
        #[arg(long, requires = "flake")]
        attr: Option<String>,
        /// Force the `--flake` template kind instead of auto-detecting it:
        /// `topology` | `nixos-module` | `nixos-configuration`.
        #[arg(long, requires = "flake")]
        kind: Option<String>,
        /// Best-effort (#326): synthesize a throwaway nixos-module from
        /// `devShells.<system>.default` (or `--attr`) instead of requiring
        /// `nixosModules`/`nixosConfigurations`. Always opt-in — never
        /// auto-detected — and always prints a best-effort warning: a
        /// devShell's `shellHook` assumes an interactive shell, the dev's own
        /// checkout as `cwd`, and inherited host env, none of which carry
        /// over identically into the guest.
        // `conflicts_with = "template"` is explicit here, not left to
        // `requires = "flake"` (which already conflicts with `template`
        // itself): with both `template` and `--from-devshell` given and no
        // `--flake`, clap's required-args resolution is satisfied by
        // `template` alone and never separately enforces `from_devshell`'s
        // own `requires`, so `--from-devshell` would otherwise be silently
        // ignored rather than refused — never acceptable for a flag whose
        // whole contract is "never silent" (#326).
        #[arg(long, requires = "flake", conflicts_with_all = ["kind", "template"])]
        from_devshell: bool,
        /// `--input HOST:NAME` read-only input at `/run/sandy/inputs/NAME` (repeatable).
        #[arg(long = "input")]
        inputs: Vec<String>,
        /// `--out DEST` collect everything under `/run/sandy/outputs` to host DEST, or `--out NAME:DEST` just
        /// `/run/sandy/outputs/NAME`, at teardown (repeatable).
        #[arg(long = "out")]
        outputs: Vec<String>,
        /// `--secret NAME=@PATH` (repeatable).
        #[arg(long = "secret")]
        secrets: Vec<String>,
        /// `--env KEY=VALUE` (repeatable).
        #[arg(long = "env")]
        env: Vec<String>,
        /// `--allow HOST:PORT` egress allow-list entry (repeatable).
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// Optional vCPU count.
        #[arg(long)]
        cpu: Option<u32>,
        /// Optional memory budget in MiB.
        #[arg(long)]
        mem: Option<u32>,
        /// Optional wall-clock timeout in seconds.
        #[arg(long)]
        timeout: Option<u32>,
        /// Record a sha256 content digest of each input (host-observed) and each
        /// collected output (guest-reported) in the receipt. Off by default:
        /// hashing large outputs costs time on every run that asks for it.
        #[arg(long)]
        digests: bool,
        /// Mint a scoped forge token for the job from the named trust root (a
        /// `sandy cred github` name); the token is injected as `GITHUB_TOKEN` and
        /// revoked at teardown.
        #[arg(long = "credential")]
        credential: Option<String>,
        /// Capability for the minted credential: `read-code` | `write-code` |
        /// `read-pr` | `write-pr` (repeatable; default `read-code`).
        #[arg(long = "cred-capability")]
        cred_capability: Vec<String>,
        /// The trailing `-- CMD ARGS...` guest command.
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// List every job record.
    Ls,
    /// Reconcile and print one job's current state.
    Status {
        /// The job id to inspect.
        job_id: String,
    },
    /// Wait for one job to reach a terminal state, then print it.
    Wait {
        /// The job id to wait on.
        job_id: String,
    },
    /// Cancel a running job and tear its box down.
    Kill {
        /// The job id to cancel.
        job_id: String,
    },
    /// Garbage-collect terminal job records (keeping the newest N) and sweep
    /// stale credential staging dirs past their mint TTL.
    Gc {
        /// How many terminal records to keep (newest first).
        #[arg(long, default_value_t = 20)]
        keep_last: usize,
    },
    /// Manage the forge credential trust roots the credential seam mints from.
    Cred {
        /// The forge provider the trust root belongs to.
        #[command(subcommand)]
        provider: CredProvider,
    },
    /// Manage a node's mesh mutual-TLS identity (decision 20): the pinned
    /// keypair `sandyd`/`sandy-host-executor` each load at startup for
    /// `listen_tls`/`connect_tls`.
    Mesh {
        /// The operation on this node's mesh TLS identity.
        #[command(subcommand)]
        op: MeshOp,
    },
    /// Drive `sandyd`, the control-plane daemon, over its control RPC (#205,
    /// B4). A separate job model from `run`/`status`/…, which execute
    /// directly with no daemon involved — see #221 for the planned
    /// convergence once `sandy submit`'s manifest reaches parity with `run`'s
    /// flag set.
    Daemon {
        /// The daemon operation to perform.
        #[command(subcommand)]
        op: DaemonOp,
    },
}

/// `sandy daemon submit --isolation-class`'s value: mirrors
/// `sandy_control_proto::IsolationClass` minus `Unspecified`, which Submit
/// always refuses (#381) — clap requires one of these, so the wire request
/// never carries an unstated class.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum IsolationClassArg {
    /// A shared-kernel backend may run this job.
    Trusted,
    /// Only a full hypervisor boundary (`SandboxKind::Vm`) may run this job.
    Untrusted,
}

impl From<IsolationClassArg> for sandy_control_proto::IsolationClass {
    fn from(value: IsolationClassArg) -> Self {
        match value {
            IsolationClassArg::Trusted => sandy_control_proto::IsolationClass::Trusted,
            IsolationClassArg::Untrusted => sandy_control_proto::IsolationClass::Untrusted,
        }
    }
}

/// `sandy daemon <op>`: one control-RPC call to `sandyd` per invocation.
#[derive(Debug, Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "Submit carries every daemon-submit flag (manifest-parity #480/#496); the other variants are each one \
              job id. clap's derive needs a plain struct variant per subcommand, not a boxed indirection, to parse \
              args directly into it."
)]
enum DaemonOp {
    /// Submit a job manifest to `sandyd`, printing the assigned job id.
    Submit {
        /// Path to the manifest file or `-` for stdin (with `--manifest-encoding`), or a TEMPLATE: a flake reference
        /// booted as `--flake REF --kind topology` (without it). Mutually exclusive with `--flake`.
        #[arg(required_unless_present = "flake", conflicts_with = "flake")]
        manifest: Option<String>,
        /// This job's required isolation class (#381). Required — `sandyd`
        /// refuses a Submit with no stated class rather than defaulting one.
        #[arg(long, value_enum)]
        isolation_class: IsolationClassArg,
        /// Names the encoding of `manifest`'s bytes (e.g. a future
        /// `sandy.orchestrator.v1.JobManifest`). It marks the positional as a manifest file, never a
        /// silent default interpretation of unknown bytes; without it the positional is a TEMPLATE. Refused with
        /// `--flake`, which encodes its own `flake/v1` tag.
        #[arg(long, conflicts_with = "flake")]
        manifest_encoding: Option<String>,
        /// Dispatch an arbitrary flake with no sandy awareness at all as a
        /// VM job (#332), mirroring `sandy run --flake`'s own shape: encodes
        /// a `flake/v1` manifest the remote host-executor resolves against
        /// ITS OWN host (never a prebuilt artifact built here) and runs via
        /// `SandboxKind::Vm`.
        #[arg(long, conflicts_with = "manifest")]
        flake: Option<String>,
        /// Override the attr name `--flake` resolves within its kind (see
        /// `sandy run --flake`'s own flag of the same name).
        #[arg(long, requires = "flake")]
        attr: Option<String>,
        /// Force the `--flake` template kind instead of auto-detecting it:
        /// `topology` | `nixos-module` | `nixos-configuration`.
        #[arg(long, requires = "flake")]
        kind: Option<String>,
        /// Best-effort (#326): synthesize the guest from `devShells.<system>.default` (or `--attr`), as `sandy run
        /// --flake REF --from-devshell`. Always opt-in; needs `--flake`.
        #[arg(long, requires = "flake", conflicts_with_all = ["kind", "manifest"])]
        from_devshell: bool,
        /// The scrollback/transcript line bound for the job's interactive
        /// session (epic #340): both the live reattach history and the
        /// archived transcript delivered back once the job ends are capped
        /// to this many lines.
        #[arg(long)]
        history_lines: Option<u32>,
        /// `--env KEY=VALUE` for the job (repeatable, only with a TEMPLATE
        /// or `--flake`; manifest-parity #480).
        #[arg(long = "env")]
        env: Vec<String>,
        /// Optional vCPU count (only with a TEMPLATE or `--flake`;
        /// manifest-parity #480).
        #[arg(long)]
        cpu: Option<u32>,
        /// Optional memory budget in MiB (only with a TEMPLATE or `--flake`;
        /// manifest-parity #480).
        #[arg(long)]
        mem: Option<u32>,
        /// Optional wall-clock timeout in seconds, clamped to the executing
        /// host's own ceiling (only with a TEMPLATE or `--flake`;
        /// manifest-parity #480).
        #[arg(long)]
        timeout: Option<u32>,
        /// The trailing `-- CMD ARGS...` guest command (only with a TEMPLATE
        /// or `--flake`; empty means "boot the template's default command").
        #[arg(last = true)]
        command: Vec<String>,
        /// Path to a file holding a capability this submitter already holds
        /// (decision C-at-Submit, #226), as base64 text — the exact encoding
        /// `sandy daemon attach -o json`'s own `cap` field already prints, so
        /// a cap handed back by an earlier `attach` can be saved to a file
        /// and referenced here. A FILE, never an inline value (CodeRabbit on
        /// this PR): a bearer credential given directly on the command line
        /// is visible to anyone who can read `ps`/`/proc/<pid>/cmdline` or
        /// this shell's history, the same reason `sandy run --secret
        /// NAME=@PATH` already reads its secret from a file rather than
        /// taking it inline. Repeatable: each occurrence becomes one entry of
        /// `SubmitRequest.submitter_caps`. #232's "where does a submitter's
        /// own cap come from" is answered by this round trip for now — there
        /// is no separate local cap store or issuance flow yet, only a way to
        /// re-present a cap the operator already has in hand. Refused with
        /// `--flake`: a `flake/v1` manifest is never the
        /// `sandy.orchestrator.v1.JobManifest+json` encoding
        /// `resolve_granted_caps` requires to bound a presented cap, so the
        /// daemon would refuse the whole submit anyway — better to say so
        /// here than let the combination reach the wire first.
        #[arg(long = "cap-file", conflicts_with = "flake")]
        cap_files: Vec<String>,
        /// `--input HOST:NAME` (repeatable; manifest-parity #496). Same
        /// grammar as `sandy run`'s own `--input`. Valid with either
        /// `manifest` or `--flake`: the path is carried in `SubmitRequest`,
        /// never inside the manifest (decision 21) — `sandyd` refuses the
        /// whole Submit unless a registered host declared
        /// `shares_submitter_filesystem`.
        #[arg(long = "input")]
        inputs: Vec<String>,
        /// `--out [NAME:]DEST` (repeatable; manifest-parity #496). Same
        /// grammar as `sandy run`'s own `--out`.
        #[arg(long = "out")]
        outputs: Vec<String>,
        /// `--secret NAME=@PATH` (repeatable; manifest-parity #496). Same
        /// grammar as `sandy run`'s own `--secret`.
        #[arg(long = "secret")]
        secrets: Vec<String>,
        /// Have `sandyd` mint a scoped forge token for the job from the named
        /// trust root on the daemon's host (a `sandy cred github` name, #481).
        /// The token is injected as `GITHUB_TOKEN` and revoked when the job
        /// ends. `sandyd` mints it once, at submit, and does not refresh it:
        /// forge access ends with the token's native life (about 1 hour from
        /// the mint, time queued on the executor included). Needs a
        /// host-executor that declared `shares_submitter_filesystem`; `sandyd`
        /// refuses the Submit otherwise.
        #[arg(long = "credential")]
        credential: Option<String>,
        /// Capability for the minted credential: `read-code` | `write-code` |
        /// `read-pr` | `write-pr` (repeatable; default `read-code`).
        #[arg(long = "cred-capability", requires = "credential")]
        cred_capability: Vec<String>,
        /// `--allow HOST:PORT` egress allow-list entry (repeatable), as `sandy run --allow` (A1 of #483). Any
        /// entry runs the job's guest behind the host's egress proxy with exactly these destinations. Needs a
        /// host-executor that declared `egress_proxy`; `sandyd` refuses the Submit otherwise. No entry means no
        /// policy.
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// Record a sha256 of each staged input and each collected output in the result envelope, as `sandy run
        /// --digests` (#373, A2c of #483). Needs a host-executor that declared `digests`; `sandyd` refuses the Submit
        /// otherwise.
        #[arg(long)]
        digests: bool,
        /// Block until the job ends, print its status with the result envelope and exit by band (`0` succeeded, `1`
        /// failed or cancelled, `3` an infrastructure fault), as `sandy run` does. Ctrl-C (or SIGTERM) cancels the
        /// job.
        #[arg(long)]
        wait: bool,
        /// With `--wait`: give up after this many seconds, naming the state the job was in (exit `3`).
        #[arg(long, requires = "wait", default_value_t = DEFAULT_WAIT_TIMEOUT_SECS)]
        wait_timeout: u64,
    },
    /// Block until a job ends, then print it with its result envelope; exit `0` succeeded, `1` failed or cancelled, `3`
    /// an infrastructure fault or a timeout. Ctrl-C stops the wait only: the job keeps running and the exit is `1`.
    Wait {
        /// The job id to wait on.
        job_id: String,
        /// Give up after this many seconds, naming the state the job was in (exit `3`).
        #[arg(long, default_value_t = DEFAULT_WAIT_TIMEOUT_SECS)]
        wait_timeout: u64,
    },
    /// Cancel a submitted job.
    Cancel {
        /// The job id to cancel.
        job_id: String,
    },
    /// Attach to a running (or recently finished) job, printing the
    /// data-plane channel id and cap `sandyd` hands back.
    Attach {
        /// The job id to attach to.
        job_id: String,
    },
    /// Query one job's current status.
    Status {
        /// The job id to query.
        job_id: String,
    },
    /// List every job `sandyd` knows about.
    List,
    /// Delete terminal jobs from `sandyd`'s store (keeping the newest N) and sweep stale credential staging dirs
    /// past their mint TTL: `sandy gc` for the daemon. A running or pending job is never deleted.
    Prune {
        /// How many terminal jobs to keep (newest first).
        #[arg(long, default_value_t = 20)]
        keep_last: usize,
    },
}

/// `sandy mesh <op>`: today, only a node's TLS identity key (decision 20).
/// Nested like `cred <provider>` so a future mesh-wide operation (e.g.
/// rotating the allowlist format) has a natural home alongside `key`.
#[derive(Debug, Subcommand)]
enum MeshOp {
    /// Operations on this node's persisted mesh mutual-TLS identity.
    Key {
        /// The operation on the identity.
        #[command(subcommand)]
        op: MeshKeyOp,
    },
}

/// `sandy mesh key <op>`: mint/load, or just print the fingerprint of, a
/// node's persisted mesh TLS identity (`identity.cert.der`/`identity.key.der`
/// under `dir`) — the operator-facing side of decision 20's pinned-key
/// provisioning. The same directory is what `$SANDY_MESH_TLS_IDENTITY_DIR`/
/// `$SANDY_HOST_EXECUTOR_TLS_IDENTITY_DIR` point sandyd/sandy-host-executor
/// at.
#[derive(Debug, Subcommand)]
enum MeshKeyOp {
    /// Mint a fresh identity if `dir` holds none yet (idempotent: reloads
    /// an existing one unchanged, never rotates it), then print its
    /// fingerprint — the value to hand the peer operator to pin in their
    /// own `SANDY_MESH_ALLOWLIST`/`SANDY_HOST_EXECUTOR_ORCHESTRATOR_FINGERPRINT`.
    Generate {
        /// Directory to hold `identity.cert.der`/`identity.key.der`.
        dir: std::path::PathBuf,
    },
    /// Print the fingerprint of an identity already generated at `dir` —
    /// refuses outright (never mints one) if `dir` holds none yet, so a
    /// typo'd path can't be mistaken for "no identity needed here."
    Fingerprint {
        /// Directory already holding `identity.cert.der`/`identity.key.der`.
        dir: std::path::PathBuf,
    },
}

/// `sandy cred <provider>`: the forge a trust root belongs to. Operations are
/// provider-specific, so each forge is its own subcommand group.
#[derive(Debug, Subcommand)]
enum CredProvider {
    /// GitHub App trust roots.
    Github {
        /// The operation on a GitHub trust root.
        #[command(subcommand)]
        op: GithubOp,
    },
}

/// `sandy cred github <op>`: register / verify / import / deregister a GitHub App
/// trust root.
#[derive(Debug, Subcommand)]
enum GithubOp {
    /// Register a GitHub App trust root in-code (drives the Create + Install
    /// clicks, captures the key and ids, writes the config — no hand-copying).
    Register {
        /// The local handle (the `<name>.json` / `<name>.pem` file stem). The
        /// GitHub App name is deterministic — `<name>-<org>` (or `<name>` for a
        /// user account) — so the whole org shares one App and the duplicate
        /// check can find it.
        name: String,
        /// Use this exact GitHub App name instead of the default `<name>-<org>`.
        #[arg(long)]
        name_override: Option<String>,
        /// Register under this organization instead of your user account.
        #[arg(long)]
        org: Option<String>,
        /// Web base for GitHub Enterprise Server.
        #[arg(long, default_value = "https://github.com")]
        base_url: String,
        /// The App homepage URL.
        #[arg(long, default_value = "https://github.com/kauki-labs/sandy")]
        homepage: String,
        /// A capability a minted token may need: read-code | write-code | read-pr
        /// | write-pr (repeatable, at least one).
        #[arg(long = "capability", required = true)]
        capabilities: Vec<String>,
        /// A repository the credential may be scoped to, as owner/repo (repeatable).
        #[arg(long = "repo")]
        repos: Vec<String>,
        /// Write the trust root WITHOUT the live scope-check probe (register
        /// verifies by default). An explicit key-only bootstrap escape.
        #[arg(long)]
        skip_verify: bool,
        /// Create the App even if one already exists on the owner (overrides the
        /// one-shared-org-App duplicate check).
        #[arg(long)]
        force: bool,
    },
    /// Import an existing shared GitHub App trust root from its credentials (no
    /// browser) — for members reusing the org's one shared App.
    Import {
        /// The local handle (the `<name>.json` / `<name>.pem` file stem).
        name: String,
        /// The GitHub App id.
        #[arg(long)]
        app_id: String,
        /// The installation id the token is minted for.
        #[arg(long)]
        installation_id: u64,
        /// Path to the shared App private key (obtained from the secret store).
        #[arg(long)]
        pem: std::path::PathBuf,
        /// API base for GitHub Enterprise Server (default github.com).
        #[arg(long)]
        base_url: Option<String>,
        /// A repository the credential may be scoped to, as owner/repo (repeatable).
        #[arg(long = "repo")]
        repos: Vec<String>,
    },
    /// Verify an existing trust root: dry-run mint a scoped token and check the
    /// installation grants the requested capabilities.
    Verify {
        /// The trust-root name (its config file stem).
        name: String,
        /// A capability to verify the installation grants: read-code | write-code
        /// | read-pr | write-pr (repeatable, at least one).
        #[arg(long = "capability", required = true)]
        capabilities: Vec<String>,
    },
    /// Remove a trust root: uninstall the App at the forge, then shred the local
    /// key and config.
    Deregister {
        /// The trust-root name (its config file stem).
        name: String,
        /// Shred locally only; uninstall the App yourself in the GitHub UI.
        #[arg(long)]
        keep_remote: bool,
    },
}

/// The macOS host backend: vfkit. The live boot is the #26 seam — the sandbox
/// gate exercises the generic `run_job` with a `FakeBackend`, never this path.
#[cfg(target_os = "macos")]
fn host_backend() -> sandy_backend::VfkitBackend {
    // Resolve the vfkit binary from $SANDY_VFKIT_BIN, else let PATH resolve it at
    // spawn time. Construction is lazy enough to stay off the sandbox path (#26).
    let vfkit_bin = std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string());
    sandy_backend::VfkitBackend::new(vfkit_bin)
}

/// The Linux host backend: qemu/KVM. See [`host_backend`] above for the #26 seam.
#[cfg(not(target_os = "macos"))]
fn host_backend() -> sandy_backend::QemuBackend {
    sandy_backend::QemuBackend::new()
}

/// The Linux egress applier: `nft`-backed default-deny enforcement. The live load
/// whose boundary an in-guest root flush cannot bypass is tier-3 (#29).
#[cfg(target_os = "linux")]
fn egress_applier() -> sandy::NftablesApplier {
    sandy::NftablesApplier::default()
}

/// The non-Linux egress applier: the local no-op ([`sandy_backend::NoEgress`]),
/// because `plan_egress` yields `NoBoundary` off Linux and nothing is applied.
#[cfg(not(target_os = "linux"))]
fn egress_applier() -> sandy_backend::NoEgress {
    sandy_backend::NoEgress
}

/// Load the named trust root from `dir` and build the live [`GithubAdapter`] plus
/// the [`Scope`] to mint for. Delegates to [`sandy::resolve_provider`], the one
/// resolution `sandy run` and sandyd's job credential (#481) share.
fn credential_setup(
    dir: &std::path::Path,
    name: &str,
    capabilities: &[String],
) -> Result<(GithubAdapter, Scope), String> {
    sandy::resolve_provider(dir, name, capabilities)
}

/// The host credential source: load the named trust root and build the live GitHub
/// adapter ([`credential_setup`]), boxed behind the [`sandy::CredentialSource`] seam
/// so the credentialed run path composes through the profile like the backend and
/// egress seams. The provider is built per run (it needs `--credential` + the trust
/// root), so the profile carries the construction, not a prebuilt provider.
struct HostCredentialSource;

impl sandy::CredentialSource for HostCredentialSource {
    fn provider(
        &self,
        dir: &std::path::Path,
        name: &str,
        capabilities: &[String],
    ) -> Result<(Box<dyn sandy::CredentialProvider + Sync>, sandy::Scope), String> {
        let (adapter, scope) = credential_setup(dir, name, capabilities)?;
        Ok((Box::new(adapter), scope))
    }
}

/// The host run profile: today's sandbox backend, egress applier, and GitHub
/// credential source, bundled as the composition root `dispatch_run` threads. The
/// egress OS model is the platform's (Linux enforces the nftables boundary, macOS
/// is honestly unenforced). This is the one concrete profile today; a different
/// profile (all-local) swaps the impls without touching dispatch.
fn host_profile() -> sandy::Profile {
    let egress_os = if cfg!(target_os = "macos") {
        sandy::EgressOs::MacOs
    } else {
        sandy::EgressOs::Linux
    };
    sandy::Profile::new(
        Box::new(host_backend()),
        Box::new(egress_applier()),
        egress_os,
        Box::new(HostCredentialSource),
    )
}

fn main() {
    let cli = Cli::parse();
    std::process::exit(dispatch(cli.command, cli.output));
}

/// Dispatch a `sandy mesh <op>` command.
fn dispatch_mesh(op: MeshOp, output: OutputFormat) -> i32 {
    match op {
        MeshOp::Key { op } => dispatch_mesh_key(op, output),
    }
}

/// Dispatch a `sandy mesh key <op>` command: mint/load or print a node's
/// persisted mesh TLS identity fingerprint (decision 20).
fn dispatch_mesh_key(op: MeshKeyOp, output: OutputFormat) -> i32 {
    match op {
        MeshKeyOp::Generate { dir } => match sandy_conn::TlsIdentity::load_or_generate(&dir) {
            Ok(identity) => succeed_or(emit(
                &MeshFingerprint {
                    fingerprint: identity.fingerprint().to_hex(),
                },
                output,
            )),
            Err(e) => {
                eprintln!("sandy: {e}");
                ProcessExit::InvalidPlan.code()
            }
        },
        MeshKeyOp::Fingerprint { dir } => {
            let cert_path = dir.join("identity.cert.der");
            let key_path = dir.join("identity.key.der");
            if !cert_path.exists() || !key_path.exists() {
                eprintln!(
                    "sandy: no mesh TLS identity at {}; run `sandy mesh key generate {}` first",
                    dir.display(),
                    dir.display()
                );
                return ProcessExit::InvalidPlan.code();
            }
            // Both files already confirmed present, so `load_or_generate`
            // only ever takes its load path here — never mints a fresh one.
            match sandy_conn::TlsIdentity::load_or_generate(&dir) {
                Ok(identity) => succeed_or(emit(
                    &MeshFingerprint {
                        fingerprint: identity.fingerprint().to_hex(),
                    },
                    output,
                )),
                Err(e) => {
                    eprintln!("sandy: {e}");
                    ProcessExit::InvalidPlan.code()
                }
            }
        }
    }
}

/// Dispatch a `sandy cred <provider>` command to the provider's handler.
fn dispatch_cred(provider: CredProvider, output: OutputFormat) -> i32 {
    match provider {
        CredProvider::Github { op } => dispatch_github(op, output),
    }
}

/// Emit a cred command's typed result, or map its [`sandy::InstallError`] to a
/// nonzero exit.
fn finish_cred<T: Render + serde::Serialize>(result: Result<T, sandy::InstallError>, output: OutputFormat) -> i32 {
    match result {
        Ok(value) => succeed_or(emit(&value, output)),
        Err(e) => {
            eprintln!("sandy: {e}");
            ProcessExit::InvalidPlan.code()
        }
    }
}

/// Dispatch a `sandy cred github <op>`. These touch only the user config dir.
fn dispatch_github(op: GithubOp, output: OutputFormat) -> i32 {
    match op {
        GithubOp::Register {
            name,
            name_override,
            org,
            base_url,
            homepage,
            capabilities,
            repos,
            skip_verify,
            force,
        } => {
            let caps = match parse_caps(&capabilities) {
                Ok(caps) => caps,
                Err(bad) => {
                    eprintln!("sandy: unknown capability '{bad}' (use read-code | write-code | read-pr | write-pr)");
                    return ProcessExit::InvalidPlan.code();
                }
            };
            let owner = org.map_or(Owner::User, Owner::Org);
            let targets = repos.into_iter().map(sandy::Target).collect();
            let github_name = app_register::github_app_name(&name, &owner, name_override.as_deref());
            finish_cred(
                app_register::run_register(
                    &name,
                    &github_name,
                    &homepage,
                    owner,
                    &base_url,
                    &caps,
                    targets,
                    skip_verify,
                    force,
                ),
                output,
            )
        }
        GithubOp::Import {
            name,
            app_id,
            installation_id,
            pem,
            base_url,
            repos,
        } => {
            let targets = repos.into_iter().map(sandy::Target).collect();
            finish_cred(
                app_register::run_import(&name, &app_id, installation_id, &pem, base_url, targets),
                output,
            )
        }
        GithubOp::Verify { name, capabilities } => match parse_caps(&capabilities) {
            Ok(caps) => finish_cred(app_register::run_verify(&name, &caps), output),
            Err(bad) => {
                eprintln!("sandy: unknown capability '{bad}' (use read-code | write-code | read-pr | write-pr)");
                ProcessExit::InvalidPlan.code()
            }
        },
        GithubOp::Deregister { name, keep_remote } => {
            finish_cred(app_register::run_deregister(&name, keep_remote), output)
        }
    }
}

/// Parse each `--capability` token into a [`sandy::Capability`], returning the
/// first unrecognized token as the error.
fn parse_caps(tokens: &[String]) -> Result<Vec<sandy::Capability>, String> {
    tokens.iter().map(|t| sandy::parse_capability(t)).collect()
}

/// The control socket `sandyd` listens on: `$SANDY_SOCK` if set (trusted as
/// given), else `sandyd.sock` under the same sandy-owned, `0700` runtime
/// directory `sandyd` itself defaults into (mirrors
/// `crates/sandyd/src/main.rs`'s `ensure_runtime_dir`), so a bare `sandy
/// daemon` invocation talks to a bare `sandyd` invocation without either side
/// setting the var. Never falls back to a predictable name directly under the
/// shared OS temp dir (CWE-923): a local attacker who pre-binds that path
/// before `sandyd` starts could read a submitted manifest and answer in its
/// place, and the sandy-owned base is validated fail-closed against exactly
/// that kind of pre-creation or symlink (`ensure_sandy_staging_base`).
fn daemon_socket_path() -> std::io::Result<std::path::PathBuf> {
    match std::env::var_os("SANDY_SOCK") {
        Some(path) => Ok(std::path::PathBuf::from(path)),
        None => {
            let base = sandy_fsutil::ensure_sandy_staging_base().map_err(std::io::Error::other)?;
            let owned = sandy_fsutil::OwnedDir::open_or_create(&base.join("sandyd")).map_err(std::io::Error::other)?;
            Ok(owned.path().join("sandyd.sock"))
        }
    }
}

/// The largest manifest `read_manifest` will load: the protocol's
/// [`sandy_control_proto::MAX_FRAME_LEN`], less headroom for the rest of the
/// `SubmitRequest` frame (the request id, the encoding tag, protobuf field
/// overhead) so a manifest that itself fits under the raw frame limit still
/// fits once wrapped.
const MAX_MANIFEST_LEN: u64 = sandy_control_proto::MAX_FRAME_LEN as u64 - 4096;

/// How often an interactive `sandy daemon attach` polls the job's status on
/// its own side connection (#327), to detect the job reaching a terminal
/// state and end the bridge. Frequent enough to feel immediate to an
/// attached operator, far below the cost of a real job run.
const ATTACH_STATUS_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// Read a job manifest from `path`, or from stdin when `path` is `-`, refusing
/// one that exceeds [`MAX_MANIFEST_LEN`] without loading it fully first: an
/// unbounded read of an oversized file or stdin stream would exhaust the
/// CLI's memory before the daemon ever gets a chance to reject the frame.
fn read_manifest(path: &str) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut reader: Box<dyn Read> = if path == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(std::fs::File::open(path)?)
    };
    let mut buf = Vec::new();
    let read = reader.by_ref().take(MAX_MANIFEST_LEN + 1).read_to_end(&mut buf)?;
    if read as u64 > MAX_MANIFEST_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("manifest exceeds the {MAX_MANIFEST_LEN}-byte limit"),
        ));
    }
    Ok(buf)
}

/// Bound on `--cap-file`'s own size, before base64 decoding (CodeRabbit on
/// this PR). A real encoded `Cap` is a few hundred bytes at most; anything
/// past this is either misconfiguration (the wrong file) or a way to make
/// this read unbounded — the same discipline [`MAX_MANIFEST_LEN`] already
/// enforces for the job manifest via [`read_manifest`].
const MAX_CAP_FILE_LEN: u64 = 64 * 1024;

/// Read `path` fully as UTF-8 text from a SINGLE already-open handle,
/// refusing one that exceeds `limit` bytes or is group/world-readable
/// (CodeRabbit on this PR, INV-1 — the same discipline
/// [`sandy::cred::read_secret_0600`] already applies to the forge App key /
/// service PAT: a bearer cap is exactly as sensitive). The mode check reads
/// the OPEN FILE's own metadata (fstat), not a separate stat-then-open by
/// path: checking permissions on the path and then reopening it to read
/// would leave a TOCTOU window where a symlink swap or `chmod` between the
/// two calls slips a now-wide-open file past the check.
fn read_bounded_private_file(path: &str, limit: u64) -> std::io::Result<String> {
    use std::{io::Read, os::unix::fs::PermissionsExt};
    let mut file = std::fs::File::open(path)?;
    let mode = file.metadata()?.permissions().mode() & 0o777;
    if mode & 0o044 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("is group/world-readable (mode {mode:#o}); refusing to read it (INV-1)"),
        ));
    }
    let mut buf = Vec::new();
    let read = file.by_ref().take(limit + 1).read_to_end(&mut buf)?;
    if read as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("exceeds the {limit}-byte limit"),
        ));
    }
    String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Read and decode each `--cap-file` path into the raw bytes
/// `SubmitRequest.submitter_caps` carries (#232). Each file holds exactly the
/// base64 text `sandy daemon attach -o json`'s own `cap` field already
/// prints, trimmed of surrounding whitespace — a cap handed back by an
/// earlier `attach` round-trips straight into this flag once saved to a file.
/// Make a `--input`/`--out`/`--secret` host path absolute before it crosses
/// the wire (#496, CodeRabbit on #508): a relative path means something on
/// THIS process's own working directory, which the host-executor that
/// actually reads/writes it does not share — its own working directory is
/// the mesh service's own (`/` under the default systemd unit), not the
/// submitter's shell. Lexical only ([`std::path::absolute`]): it never
/// touches the filesystem or requires the path to exist, so an `--out` dest
/// that doesn't exist yet still resolves.
///
/// # Errors
/// Whatever [`std::path::absolute`] returns (rare: it fails only when the
/// current directory can't be determined).
fn absolutize_host_path(path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
    std::path::absolute(path)
}

/// A malformed or unreadable path refuses the whole submit outright, naming
/// it, never silently dropping it and falling back to a direct-mint submit
/// the caller didn't ask for.
///
/// # Errors
/// Names the path that failed to read (including one over
/// [`MAX_CAP_FILE_LEN`] or group/world-readable), or whose contents aren't
/// valid base64.
fn read_submitter_caps(paths: &[String]) -> Result<Vec<Vec<u8>>, String> {
    paths
        .iter()
        .map(|path| {
            let contents = read_bounded_private_file(path, MAX_CAP_FILE_LEN)
                .map_err(|e| format!("--cap-file {path:?} could not be read: {e}"))?;
            base64::engine::general_purpose::STANDARD
                .decode(contents.trim())
                .map_err(|e| format!("--cap-file {path:?} does not contain valid base64: {e}"))
        })
        .collect()
}

/// Dispatch `sandy daemon <op>`: drives its own async connection, since `main`
/// is synchronous like the rest of the CLI (`app_register`'s octocrab calls
/// use the same build-a-runtime-and-block-on pattern for the same reason).
fn dispatch_daemon(op: DaemonOp, output: OutputFormat) -> i32 {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("sandy: could not start the async runtime: {e}");
            return ProcessExit::InfraFault.code();
        }
    };
    runtime.block_on(dispatch_daemon_async(op, output))
}

/// How long `daemon wait` and `daemon submit --wait` wait by default: an hour, longer than the host ceiling on a job's
/// own timeout. The daemon has no wait call, so the client polls `Status` within this bound.
const DEFAULT_WAIT_TIMEOUT_SECS: u64 = 3600;

/// How often a waiting client asks the daemon for the job's status.
const WAIT_POLL: std::time::Duration = std::time::Duration::from_millis(500);

/// How long a client waits for the job to end after it cancelled it on Ctrl-C.
const CANCEL_SETTLE: std::time::Duration = std::time::Duration::from_secs(15);

/// One `Status` call on `stream`, as the wait loop's fetch: the daemon's answer, or a message naming what went wrong.
async fn status_call(
    stream: &mut tokio::net::UnixStream,
    request_id: u64,
    job_id: &str,
) -> Result<sandy_control_proto::StatusResponse, String> {
    let op = control_request::Op::Status(StatusRequest {
        job_id: job_id.to_owned(),
    });
    match sandy_control_proto::client::call(stream, request_id, op).await {
        Ok(response) => match response.result {
            Some(control_response::Result::Status(status)) => Ok(status),
            Some(control_response::Result::Error(e)) => Err(e.message),
            other => Err(format!("the daemon answered a status request with {other:?}")),
        },
        Err(e) => Err(format!("the daemon call failed: {e}")),
    }
}

/// Print `status` as `daemon status` does and return the exit band it gives. A job still not terminal here is an
/// infrastructure fault (the wait gave up).
fn report_and_band(status: &sandy_control_proto::StatusResponse, output: OutputFormat) -> i32 {
    let band = sandy_cli::wait::exit_band(status).unwrap_or(ProcessExit::InfraFault);
    match JobStatusReport::from_response(status) {
        Ok(report) => {
            if emit(&report, output).is_err() {
                return ProcessExit::InfraFault.code();
            }
            band.code()
        }
        Err(e) => {
            eprintln!("sandy: sandyd sent a status reply with a result envelope that does not decode: {e}");
            ProcessExit::InfraFault.code()
        }
    }
}

/// The bound a waiting op (`daemon wait`, `daemon submit --wait`) gives its poll; `None` for every other op.
fn wait_bound_of(op: &DaemonOp) -> Option<std::time::Duration> {
    match op {
        DaemonOp::Wait { wait_timeout, .. }
        | DaemonOp::Submit {
            wait: true,
            wait_timeout,
            ..
        } => Some(std::time::Duration::from_secs(*wait_timeout)),
        _ => None,
    }
}

/// The interrupt (SIGINT, SIGTERM) streams of a waiting client. Installed before the Submit is sent, so an interrupt
/// that lands before the job id is known is held, not fatal, and cancels the job as soon as the reply arrives.
struct Interrupts {
    sigint: tokio::signal::unix::Signal,
    sigterm: tokio::signal::unix::Signal,
}

impl Interrupts {
    fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            sigint: signal(SignalKind::interrupt())?,
            sigterm: signal(SignalKind::terminate())?,
        })
    }
}

/// Wait on `stream` for `job_id` to end, within `bound`, and report it. With `cancel_token` set (a job this client
/// submitted) an interrupt (SIGINT or SIGTERM) cancels the job on the daemon through a fresh connection, because the
/// interrupted poll leaves `stream` mid-conversation, and then waits a short while for it to end.
async fn wait_and_report(
    mut stream: tokio::net::UnixStream,
    socket: &std::path::Path,
    job_id: &str,
    cancel_token: Option<Vec<u8>>,
    bound: std::time::Duration,
    output: OutputFormat,
    interrupts: Interrupts,
) -> i32 {
    let Interrupts {
        mut sigint,
        mut sigterm,
    } = interrupts;
    let ids = std::sync::atomic::AtomicU64::new(2);
    let cell = tokio::sync::Mutex::new(&mut stream);
    let mut waiting = Box::pin(sandy_cli::wait::wait_until_terminal(
        || {
            let id = ids.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let cell = &cell;
            async move {
                let mut stream = cell.lock().await;
                status_call(&mut stream, id, job_id).await
            }
        },
        WAIT_POLL,
        bound,
    ));
    let interrupted = tokio::select! {
        done = &mut waiting => Err(done),
        _ = sigint.recv() => Ok(()),
        _ = sigterm.recv() => Ok(()),
    };
    drop(waiting);
    let done = match interrupted {
        Err(done) => done,
        Ok(()) => {
            let Some(token) = cancel_token else {
                eprintln!("sandy: interrupted; the job was not submitted by this client and keeps running");
                return ProcessExit::TaskFailure.code();
            };
            eprintln!("sandy: interrupted; cancelling job {job_id}");
            let Ok(mut fresh) = tokio::net::UnixStream::connect(socket).await else {
                eprintln!("sandy: could not reconnect to sandyd to cancel the job");
                return ProcessExit::InfraFault.code();
            };
            let cancel = control_request::Op::Cancel(CancelRequest {
                job_id: job_id.to_owned(),
                attach_token: Some(token),
            });
            if let Err(e) = sandy_control_proto::client::call(&mut fresh, 1, cancel).await {
                eprintln!("sandy: the cancel call failed: {e}");
            }
            let fresh = tokio::sync::Mutex::new(fresh);
            sandy_cli::wait::wait_until_terminal(
                || {
                    let fresh = &fresh;
                    async move {
                        let mut stream = fresh.lock().await;
                        status_call(&mut stream, 2, job_id).await
                    }
                },
                WAIT_POLL,
                CANCEL_SETTLE,
            )
            .await
        }
    };
    match done {
        Ok(status) => report_and_band(&status, output),
        Err(e) => {
            eprintln!("sandy: {e}");
            ProcessExit::InfraFault.code()
        }
    }
}

/// Connect to `sandyd`, make the one matching control-RPC call, print the
/// result, and map it to a process exit band (INV-11). A fresh connection per
/// invocation: the control RPC is strictly one-request-one-response with no
/// pipelining (#211 §1), so there is nothing to pool across a single CLI run.
async fn dispatch_daemon_async(op: DaemonOp, output: OutputFormat) -> i32 {
    // #232 (CodeRabbit on this PR): validate `--cap-file` before opening any
    // connection — a malformed or unreadable path is a pure client-side
    // input error, and refusing it must never depend on a live daemon being
    // reachable.
    let submitter_caps = if let DaemonOp::Submit { cap_files, .. } = &op {
        match read_submitter_caps(cap_files) {
            Ok(caps) => caps,
            Err(e) => {
                eprintln!("sandy: {e}");
                return ProcessExit::InvalidPlan.code();
            }
        }
    } else {
        Vec::new()
    };

    // A TEMPLATE or `--flake` becomes a `flake/v1` manifest here, before any connection (CodeRabbit on this PR, same
    // bar as `--cap-file` above): a malformed `--env` value, a positional that is a forgotten manifest, or a plain flag
    // given with a manifest file is a pure client-side input error and must be refused the same way whether or not
    // sandyd is reachable, not get a different exit band (`InfraFault` vs `InvalidPlan`) depending on daemon state.
    let flake_submit = if let DaemonOp::Submit {
        manifest,
        manifest_encoding,
        flake,
        attr,
        kind,
        from_devshell,
        history_lines,
        env,
        cpu,
        mem,
        timeout,
        command,
        ..
    } = &op
    {
        let template = match (flake, manifest) {
            (None, Some(positional)) => {
                match sandy_cli::submit::classify_positional(positional, manifest_encoding.as_deref(), |p| {
                    std::path::Path::new(p).is_file()
                }) {
                    Ok(sandy_cli::submit::Positional::Template(t)) => Some(t.to_owned()),
                    Ok(sandy_cli::submit::Positional::Manifest(_)) => None,
                    Err(e) => {
                        eprintln!("sandy: {e}");
                        return ProcessExit::InvalidPlan.code();
                    }
                }
            }
            _ => None,
        };
        let plain = sandy_cli::submit::PlainFlags {
            history_lines: history_lines.unwrap_or_else(sandy_guest_template::manifest::default_history_lines),
            env: env.clone(),
            cpu: *cpu,
            mem: *mem,
            timeout: *timeout,
            command: command.clone(),
        };
        let built = match (flake, template) {
            (Some(flake), _) => Some(sandy_cli::submit::flake_manifest(
                flake.clone(),
                kind.clone(),
                attr.clone(),
                *from_devshell,
                plain,
            )),
            (None, Some(template)) => Some(sandy_cli::submit::template_manifest(&template, plain)),
            (None, None) => None,
        };
        match built {
            Some(Ok(manifest)) => Some(manifest),
            Some(Err(e)) => {
                eprintln!("sandy: {e}");
                return ProcessExit::InvalidPlan.code();
            }
            None => {
                if history_lines.is_some()
                    || !env.is_empty()
                    || cpu.is_some()
                    || mem.is_some()
                    || timeout.is_some()
                    || !command.is_empty()
                {
                    eprintln!(
                        "sandy: --history-lines, --env, --cpu, --mem, --timeout and a trailing command only apply to \
                         a template or --flake, not to a manifest file"
                    );
                    return ProcessExit::InvalidPlan.code();
                }
                None
            }
        }
    } else {
        None
    };

    // A bad `--cred-capability` is the caller's input error (exit 2), not a
    // retryable infrastructure failure because the daemon happens to be down.
    if let DaemonOp::Submit { cred_capability, .. } = &op
        && let Err(bad) = parse_caps(cred_capability)
    {
        eprintln!("sandy: --cred-capability: {bad}");
        return ProcessExit::InvalidPlan.code();
    }

    // A malformed `--allow` is the caller's input error too, refused the same way whether or not sandyd is up.
    let submit_egress = if let DaemonOp::Submit { allow, .. } = &op {
        match sandy_cli::plan::egress_policy(allow) {
            Ok(egress) => egress,
            Err(e) => {
                eprintln!("sandy: {e}");
                return ProcessExit::InvalidPlan.code();
            }
        }
    } else {
        None
    };

    // Same pre-connection bar as `--cap-file`/`--env` above (manifest-parity
    // #496): a malformed `--input`/`--out`/`--secret` value, or two inputs
    // colliding on the same staged name, is a pure client-side input error.
    let (submit_inputs, submit_outputs, submit_secrets) = if let DaemonOp::Submit {
        inputs,
        outputs,
        secrets,
        ..
    } = &op
    {
        let parsed_inputs = match inputs
            .iter()
            .enumerate()
            .map(|(i, raw)| sandy_cli::plan::parse_input(raw, i))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|parsed| {
                sandy_cli::plan::reject_duplicate_input_names(&parsed)?;
                Ok(parsed)
            }) {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!("sandy: {e}");
                return ProcessExit::InvalidPlan.code();
            }
        };
        let parsed_outputs = match outputs
            .iter()
            .map(|raw| sandy_cli::plan::parse_output(raw))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!("sandy: {e}");
                return ProcessExit::InvalidPlan.code();
            }
        };
        let parsed_secrets = match secrets
            .iter()
            .map(|raw| sandy_cli::plan::parse_secret(raw))
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(parsed) => parsed,
            Err(e) => {
                eprintln!("sandy: {e}");
                return ProcessExit::InvalidPlan.code();
            }
        };
        let mut inputs = Vec::with_capacity(parsed_inputs.len());
        for i in parsed_inputs {
            let host = match absolutize_host_path(&i.host) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("sandy: --input {:?}: {e}", i.host);
                    return ProcessExit::InvalidPlan.code();
                }
            };
            inputs.push(sandy_control_proto::Input {
                host: host.display().to_string(),
                name: i.name,
                guest_path: i.guest_path.map(|p| p.display().to_string()),
            });
        }
        let mut outputs = Vec::with_capacity(parsed_outputs.len());
        for o in parsed_outputs {
            let dest = match absolutize_host_path(&o.dest) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("sandy: --out {:?}: {e}", o.dest);
                    return ProcessExit::InvalidPlan.code();
                }
            };
            outputs.push(sandy_control_proto::Output {
                name: o.name,
                dest: dest.display().to_string(),
            });
        }
        let mut secrets = Vec::with_capacity(parsed_secrets.len());
        for s in parsed_secrets {
            let sandy::SecretSource::File(path) = s.source else {
                unreachable!("parse_secret only ever produces a File source")
            };
            let path = match absolutize_host_path(&path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("sandy: --secret {}: {e}", s.name);
                    return ProcessExit::InvalidPlan.code();
                }
            };
            secrets.push(sandy_control_proto::SecretRef {
                name: s.name,
                host_path: path.display().to_string(),
            });
        }
        (inputs, outputs, secrets)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    let socket = match daemon_socket_path() {
        Ok(socket) => socket,
        Err(e) => {
            eprintln!("sandy: could not resolve the control socket path: {e}");
            return ProcessExit::InfraFault.code();
        }
    };
    let mut stream = match tokio::net::UnixStream::connect(&socket).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("sandy: could not connect to sandyd at {}: {e}", socket.display());
            return ProcessExit::InfraFault.code();
        }
    };

    // `CancelResponse` carries no fields; keep the id the caller asked to
    // cancel so the result can still name it.
    let cancel_echo = if let DaemonOp::Cancel { job_id } = &op {
        Some(job_id.clone())
    } else {
        None
    };
    // Attach's job id, kept alongside the request for the same reason: once
    // `op` moves into `request_op` below, this is the only copy left to name
    // the interactive bridge's status-watch job and diagnostics with.
    let attach_job_id = if let DaemonOp::Attach { job_id } = &op {
        Some(job_id.clone())
    } else {
        None
    };

    // `daemon wait`, and `daemon submit --wait` after its Submit: poll Status to a terminal state within this bound.
    // The interrupt handlers go in first, so a Ctrl-C during the Submit still cancels the job it creates.
    let interrupts = if wait_bound_of(&op).is_some() {
        match Interrupts::install() {
            Ok(i) => Some(i),
            Err(e) => {
                eprintln!("sandy: could not install the interrupt handlers: {e}");
                return ProcessExit::InfraFault.code();
            }
        }
    } else {
        None
    };
    let wait_bound = wait_bound_of(&op);

    let request_op = match op {
        DaemonOp::Submit {
            manifest,
            isolation_class,
            manifest_encoding,
            credential,
            cred_capability,
            digests,
            ..
        } => {
            // clap's `required_unless_present = "flake"`/`conflicts_with`
            // pairs above guarantee exactly one of `manifest` or `flake` is
            // set here.
            let (bytes, encoding) = if let Some(manifest) = flake_submit {
                match sandy_guest_template::manifest::encode_flake_manifest(&manifest) {
                    Ok(bytes) => (
                        bytes,
                        sandy_guest_template::manifest::MANIFEST_ENCODING_FLAKE_V1.to_owned(),
                    ),
                    Err(e) => {
                        eprintln!("sandy: could not encode the flake manifest: {e}");
                        return ProcessExit::InfraFault.code();
                    }
                }
            } else {
                // `required_unless_present = "flake"` guarantees `manifest`
                // is `Some` whenever `flake` is `None`.
                let manifest = manifest.expect("manifest is required unless --flake is given");
                let encoding =
                    manifest_encoding.expect("a positional without a manifest encoding was classified as a template");
                let bytes = match read_manifest(&manifest) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("sandy: could not read manifest {manifest:?}: {e}");
                        return ProcessExit::InvalidPlan.code();
                    }
                };
                (bytes, encoding)
            };
            control_request::Op::Submit(SubmitRequest {
                digests,
                manifest: bytes,
                manifest_encoding: encoding,
                submitter_caps,
                required_isolation_class: sandy_control_proto::IsolationClass::from(isolation_class).into(),
                inputs: submit_inputs,
                outputs: submit_outputs,
                secrets: submit_secrets,
                credential,
                cred_capabilities: cred_capability,
                egress: submit_egress,
            })
        }
        DaemonOp::Cancel { job_id } => {
            // Cancel needs the job's attach token (#540), read back from where `submit` persisted it,
            // the same way `attach` does.
            let attach_token = sandy_cli::attach::read_attach_token(&job_id);
            control_request::Op::Cancel(CancelRequest { job_id, attach_token })
        }
        DaemonOp::Attach { job_id } => {
            // #327: present the durable token `daemon submit` persisted for
            // this job, if any — proves "I'm the submitter" even though this
            // is necessarily a fresh connection/session (a separate CLI
            // invocation). `None` (no file, or any read failure) just falls
            // back to `session_matches` server-side, same as before this
            // existed.
            let attach_token = sandy_cli::attach::read_attach_token(&job_id);
            control_request::Op::Attach(AttachRequest {
                job_id,
                attach_token,
                collector: false,
            })
        }
        DaemonOp::Status { job_id } | DaemonOp::Wait { job_id, .. } => {
            control_request::Op::Status(StatusRequest { job_id })
        }
        DaemonOp::List => control_request::Op::List(ListRequest {}),
        DaemonOp::Prune { keep_last } => control_request::Op::Prune(PruneRequest {
            keep_last: u32::try_from(keep_last).unwrap_or(u32::MAX),
        }),
    };

    let response = match sandy_control_proto::client::call(&mut stream, 1, request_op).await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("sandy: daemon call failed: {e}");
            return ProcessExit::InfraFault.code();
        }
    };

    match response.result {
        Some(control_response::Result::Submit(r)) => {
            // #327: persisted so a LATER, separate `daemon attach`
            // invocation can present it and still get post rights — see
            // `attach::persist_attach_token`'s own doc for the fallback
            // behavior on any failure here.
            sandy_cli::attach::persist_attach_token(&r.job_id, &r.attach_token);
            match wait_bound {
                // `--wait`: the job is the client's own, so an interrupt cancels it; only the final report prints.
                Some(bound) => match interrupts {
                    Some(interrupts) => {
                        wait_and_report(
                            stream,
                            &socket,
                            &r.job_id,
                            Some(r.attach_token.clone()),
                            bound,
                            output,
                            interrupts,
                        )
                        .await
                    }
                    None => ProcessExit::InfraFault.code(),
                },
                None => succeed_or(emit(&SubmittedJob::from(&r), output)),
            }
        }
        Some(control_response::Result::Cancel(_)) => {
            succeed_or(emit(&CancelledJob::new(cancel_echo.as_deref().unwrap_or("?")), output))
        }
        // Both formats redeem the cap on `sandyd`'s separate attach data-plane
        // socket (#327) and go interactive. `-o json` (#513, owner decision on
        // #564) wraps the console in an NDJSON stream whose first line is the
        // cap, written before the join so cap retrieval does not depend on the
        // job being joinable; every later failure still ends it with `exit`.
        Some(control_response::Result::Attach(r)) => {
            let json = output == OutputFormat::Json;
            if json && !emit_attach_line(&AttachEvent::Attached(AttachedChannel::from(&r))) {
                // The caller never got the cap, so joining the job would only strand it.
                eprintln!("sandy: could not write the attached line to stdout");
                return ProcessExit::InfraFault.code();
            }
            let fault = |message: String, code: ProcessExit| {
                eprintln!("sandy: {message}");
                if json {
                    // The write already failed if stdout is broken; the message is on stderr.
                    let _ = emit_attach_line(&AttachEvent::Exit {
                        reason: format!("fault:{message}"),
                    });
                }
                code.code()
            };
            let job_id = attach_job_id.unwrap_or_default();
            let attach_sock = sandy_control_proto::attach_socket_path(&socket);
            let data_stream = match tokio::net::UnixStream::connect(&attach_sock).await {
                Ok(data_stream) => data_stream,
                Err(e) => {
                    return fault(
                        format!(
                            "could not connect to the attach data plane at {}: {e}",
                            attach_sock.display()
                        ),
                        ProcessExit::InfraFault,
                    );
                }
            };
            let (mut data_rd, mut data_wr) = tokio::io::split(data_stream);
            let (cols, rows) = sandy_cli::attach::window_size().unzip();
            let join = sandy_fabric_local::link::LinkFrame::Join {
                cap: hex::encode(&r.cap),
                channel: None,
                cols,
                rows,
            };
            if let Err(e) = sandy_fabric_local::link::write_frame(&mut data_wr, &join).await {
                return fault(
                    format!("could not present the attach cap: {e}"),
                    ProcessExit::InfraFault,
                );
            }
            match sandy_fabric_local::link::read_frame(&mut data_rd).await {
                Ok(Some(sandy_fabric_local::link::LinkFrame::Joined { .. })) => {}
                Ok(Some(sandy_fabric_local::link::LinkFrame::Refused { reason })) => {
                    return fault(format!("attach refused: {reason}"), ProcessExit::InvalidPlan);
                }
                Ok(other) => {
                    return fault(
                        format!("attach: unexpected handshake response: {other:?}"),
                        ProcessExit::InfraFault,
                    );
                }
                Err(e) => {
                    return fault(format!("attach: handshake failed: {e}"), ProcessExit::InfraFault);
                }
            }

            // The control connection already answered Attach; it stays open,
            // otherwise idle, just to poll Status in the same session while
            // the data plane (above) carries the bridge.
            let status_watch =
                sandy_cli::attach::spawn_status_watch(stream, job_id.clone(), ATTACH_STATUS_POLL_INTERVAL);
            match sandy_cli::attach::run_interactive(data_rd, data_wr, Some(status_watch), output).await {
                Ok(archive) => {
                    if let Some(archive) = archive {
                        sandy_cli::attach::write_archive(&job_id, &archive, output);
                    }
                    ProcessExit::Succeeded.code()
                }
                Err(e) => {
                    eprintln!("sandy: attach bridge faulted: {e}");
                    ProcessExit::InfraFault.code()
                }
            }
        }
        // `daemon wait`: the first answer decides whether to keep polling; an unknown job is the `Error` arm below.
        Some(control_response::Result::Status(r)) if wait_bound.is_some() => match (wait_bound, interrupts) {
            (Some(bound), Some(interrupts)) if !sandy_cli::wait::is_terminal(&r) => {
                wait_and_report(stream, &socket, &r.job_id, None, bound, output, interrupts).await
            }
            _ => report_and_band(&r, output),
        },
        Some(control_response::Result::Status(r)) => match JobStatusReport::from_response(&r) {
            Ok(report) => succeed_or(emit(&report, output)),
            Err(e) => {
                eprintln!("sandy: sandyd sent a status reply with a result envelope that does not decode: {e}");
                ProcessExit::InfraFault.code()
            }
        },
        Some(control_response::Result::List(r)) => succeed_or(emit(&JobSummaries::from(&r), output)),
        // The same report and spelling `sandy gc` prints, so the promotion of `daemon prune` to `gc` changes no format.
        Some(control_response::Result::Prune(r)) => succeed_or(emit(
            &supervisor::GcReport {
                evicted: r.evicted,
                swept_staging_dirs: r.swept_staging_dirs,
            },
            output,
        )),
        // The daemon understood the request but could not honour it (unknown
        // job id, not yet dispatchable, …): the request itself is the fault,
        // the same InvalidPlan band `run` uses for an unbootable plan.
        Some(control_response::Result::Error(e)) => {
            eprintln!("sandy: {}", e.message);
            ProcessExit::InvalidPlan.code()
        }
        // `sandy daemon` sends no environment operation, so the daemon has no
        // reason to answer one here: an unexpected reply, not a result to show.
        Some(
            control_response::Result::Environment(_)
            | control_response::Result::Environments(_)
            | control_response::Result::EnvironmentError(_),
        ) => {
            eprintln!("sandy: daemon answered a job request with an environment response");
            ProcessExit::InfraFault.code()
        }
        None => {
            eprintln!("sandy: daemon sent a response with no result set");
            ProcessExit::InfraFault.code()
        }
    }
}

/// Dispatch `sandy doctor`: print the host-prerequisite verdict and return its
/// exit band. Needs no journal, so it runs before `$SANDY_HOME` is touched.
fn dispatch_doctor(output: OutputFormat) -> i32 {
    let result = doctor::run_doctor();
    if output == OutputFormat::Plain && result.exit_code != 0 {
        // Plain keeps the stream convention (ok→stdout, refusal→stderr): a
        // refusal explains itself, so it's a diagnostic like every other
        // eprintln! in this file, not routed through emit's one stdout sink.
        eprintln!("{}", result.message);
    } else if let Err(code) = emit(&result, output) {
        // JSON always goes to stdout (emit's only sink) regardless of
        // exit_code, so an agent reads the verdict from one channel.
        return code;
    }
    result.exit_code
}

/// Removes a directory when dropped: the credential staging dir must not
/// outlive the run, including on a panic.
struct RemoveDirOnDrop(std::path::PathBuf);

impl Drop for RemoveDirOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Mint a scoped forge token from the named trust root, stage it under a
/// per-process dir, and run the job bracketed by it (mint → inject → revoke at
/// teardown). Setup faults (bad trust-roots dir, unknown capability) map to an
/// exit band before any boot; the staging dir is always removed. The error arm
/// carries the process band so the caller returns it directly.
#[allow(
    clippy::too_many_arguments,
    reason = "forwards the run and credential inputs to run_job_with_credential"
)]
fn run_credentialed(
    profile: &sandy::Profile,
    journal: &Journal,
    plan: JobPlan,
    tap: Option<&str>,
    name: &str,
    cred_capability: &[String],
) -> Result<supervisor::RunReport, i32> {
    let dir = app_register::trust_roots_dir().map_err(|e| {
        eprintln!("sandy: trust-roots dir: {e}");
        ProcessExit::InfraFault.code()
    })?;
    let (provider, scope) = profile.cred().provider(&dir, name, cred_capability).map_err(|e| {
        eprintln!("sandy: {e}");
        ProcessExit::InvalidPlan.code()
    })?;
    // A fresh 0700 dir under the validated staging base, randomly named: a
    // predictable /tmp path could be pre-created by another user (#192).
    let cred_handle = sandy_fsutil::private_staging_dir("cred").map_err(|e| {
        eprintln!("sandy: create credential staging dir: {e}");
        ProcessExit::InfraFault.code()
    })?;
    // Captured here, not re-derived later: the fingerprint is this validation's
    // own binding to the directory it just created (#323), carried alongside the
    // bare path every downstream re-open (mint, refresh, the backend's guest-share
    // staging) is checked against, instead of trusting a same-uid, same-mode
    // directory swapped in at the path afterward.
    let (dev, ino) = cred_handle.dev_ino().map_err(|e| {
        eprintln!("sandy: fingerprint credential staging dir: {e}");
        ProcessExit::InfraFault.code()
    })?;
    let cred_fingerprint = sandy::DirFingerprint { dev, ino };
    let cred_dir = cred_handle.path().to_path_buf();
    drop(cred_handle);
    // Removed on every exit from here, a panic included, not only a normal return.
    let _cleanup = RemoveDirOnDrop(cred_dir.clone());
    let result = supervisor::run_job_with_credential(
        profile.backend(),
        journal,
        plan,
        profile.egress(),
        profile.egress_os(),
        tap,
        provider.as_ref(),
        &scope,
        "GITHUB_TOKEN",
        &cred_dir,
        cred_fingerprint,
        sandy::MAX_TTL_SECS,
    );
    result.map_err(|e| {
        eprintln!("sandy: run failed: {e}");
        ProcessExit::InfraFault.code()
    })
}

/// What `sandy run` says about the sweep it made, or nothing when it found nothing to do. A box left alone because
/// its owner is alive is not news.
fn sweep_notice(report: &sandy_backend::SweepReport) -> Option<String> {
    let left = report.undecided + report.unreadable;
    if report.killed + report.wiped + left == 0 {
        return None;
    }
    let mut notice = format!(
        "swept the VMs a killed host left behind: {} process(es) signalled, {} box(es) removed",
        report.killed, report.wiped
    );
    if left > 0 {
        notice.push_str(&format!(", {left} left for the next run"));
    }
    Some(notice)
}

/// Dispatch `sandy run`: parse the plan, bracket the boot with egress and an
/// optional credential, print the result envelope, and return the process exit
/// band (INV-11).
fn dispatch_run(
    profile: &sandy::Profile,
    args: RunArgs,
    credential: Option<String>,
    cred_capability: &[String],
    journal: &Journal,
    output: OutputFormat,
) -> i32 {
    let mut plan = match parse_run(args) {
        Ok(plan) => plan,
        Err(e) => {
            eprintln!("sandy: {e}");
            return ProcessExit::InvalidPlan.code();
        }
    };
    // `SANDY_EGRESS=proxy` runs the guest behind the backend's egress proxy instead of the nftables boundary (#360).
    // An unknown value is refused rather than ignored, so a typo never boots under the other model.
    match std::env::var("SANDY_EGRESS").ok().as_deref() {
        None | Some("") => {}
        Some("proxy") => plan.egress_proxy = true,
        Some(other) => {
            eprintln!("sandy: SANDY_EGRESS must be `proxy` or unset, got `{other}`");
            return ProcessExit::InvalidPlan.code();
        }
    }
    // `SANDY_NETWORK=nic` boots the guest with a NIC (#602). An unknown value is refused, never defaulted.
    match sandy::NetworkMode::from_env() {
        Ok(mode) => plan.network = mode,
        Err(e) => {
            eprintln!("sandy: {e}");
            return ProcessExit::InvalidPlan.code();
        }
    }
    // From here on the run owns a guest, a credential and an egress boundary: a termination signal must cancel the
    // run so the teardown runs, not end the process with the default action (#687). Fail closed when the handlers
    // cannot be installed.
    if let Err(e) = sandy_cli::signals::cancel_on_termination(plan.control.clone()) {
        eprintln!("sandy: cannot install the termination-signal handlers: {e}");
        return ProcessExit::InfraFault.code();
    }
    // The run seams come from the injected `profile` — the sandbox backend, the
    // egress applier (Linux enforces the nftables boundary, macOS has none), and the
    // credential source. The composition root selects the profile at the top
    // (`dispatch`) and threads it here, so this code never names a concrete impl and
    // a different profile swaps them without touching dispatch.
    // The guest's tap (if any) comes from $SANDY_TAP — the same interface the
    // backend attaches the NIC to. On Linux a bound tap selects the guest-scoped
    // forward ruleset (safe), never the host-OUTPUT drop-all (#29).
    let tap = std::env::var("SANDY_TAP").ok().filter(|t| !t.is_empty());

    // With `--credential`, mint a scoped forge token and bracket the run with it;
    // otherwise run with no credential. Both paths compose through the profile.
    let report = match credential {
        Some(name) => match run_credentialed(profile, journal, plan, tap.as_deref(), &name, cred_capability) {
            Ok(report) => report,
            Err(code) => return code,
        },
        None => match supervisor::run_with_profile(profile, journal, &plan, tap.as_deref()) {
            Ok(report) => report,
            Err(e) => {
                eprintln!("sandy: run failed: {e}");
                return ProcessExit::InfraFault.code();
            }
        },
    };
    // The envelope is the result, not a diagnostic — print it (the band, not
    // stdout, signals failure) and exit on the process band.
    if let Err(code) = emit(&report.envelope, output) {
        return code;
    }
    report.process_exit.code()
}

/// Dispatch one parsed command and return the process exit band (INV-11).
fn dispatch(command: Command, output: OutputFormat) -> i32 {
    // Doctor needs no journal; handle it before touching `$SANDY_HOME`.
    if let Command::Doctor = command {
        return dispatch_doctor(output);
    }

    // `cred` ops need only the user config dir, not $SANDY_HOME.
    if let Command::Cred { provider } = command {
        return dispatch_cred(provider, output);
    }

    // `mesh` ops touch only the caller-named identity dir, not $SANDY_HOME.
    if let Command::Mesh { op } = command {
        return dispatch_mesh(op, output);
    }

    // `daemon` ops talk to sandyd over its own socket, not $SANDY_HOME.
    if let Command::Daemon { op } = command {
        return dispatch_daemon(op, output);
    }

    let journal = Journal::new(doctor::sandy_home());
    if let Err(e) = journal.ensure_dirs() {
        eprintln!("sandy: cannot initialize $SANDY_HOME: {e}");
        return ProcessExit::InfraFault.code();
    }

    match command {
        Command::Doctor => unreachable!("doctor handled above"),
        Command::Cred { .. } => unreachable!("cred handled above"),
        Command::Mesh { .. } => unreachable!("mesh handled above"),
        Command::Daemon { .. } => unreachable!("daemon handled above"),
        Command::Run {
            template,
            flake,
            attr,
            kind,
            from_devshell,
            inputs,
            outputs,
            secrets,
            env,
            allow,
            cpu,
            mem,
            timeout,
            digests,
            credential,
            cred_capability,
            command,
        } => {
            // `--flake` resolves to either the user's own `topologies` attr
            // (kind `topology`, unchanged) or a prebuilt topology JSON file
            // (kinds `nixos-module`/`nixos-configuration`, #325) that
            // `JobPlan::template` becomes — `_kept_template_file` holds that
            // file open for exactly this call, dropped (and deleted) only
            // after `dispatch_run` returns.
            let (resolved_template, _kept_template_file) = match flake {
                Some(flake_ref) => {
                    match sandy_cli::flake_wrap::resolve_flake_template(
                        &flake_ref,
                        kind.as_deref(),
                        attr.as_deref(),
                        from_devshell,
                    ) {
                        Ok(sandy_cli::flake_wrap::ResolvedTemplate::Direct(t)) => (t, None),
                        Ok(sandy_cli::flake_wrap::ResolvedTemplate::Prebuilt { path, _kept }) => (path, Some(_kept)),
                        Err(e) => {
                            eprintln!("sandy: --flake {flake_ref}: {e}");
                            return ProcessExit::InvalidPlan.code();
                        }
                    }
                }
                // clap's `required_unless_present = "flake"` guarantees
                // `template` is set whenever `flake` is not; the `None` arm
                // is unreachable in practice but reported, not panicked, if
                // clap's own guarantee ever changes.
                None => match template {
                    Some(t) => (t, None),
                    None => {
                        eprintln!("sandy: neither a template nor --flake was given");
                        return ProcessExit::InvalidPlan.code();
                    }
                },
            };
            let args = RunArgs {
                template: resolved_template,
                inputs,
                outputs,
                secrets,
                env,
                allow,
                cpu,
                mem,
                timeout,
                digests,
                command,
            };
            // Stop the VMs a killed `sandy` or `sandyd` left behind before this run boots another (#666). It touches
            // only a box whose owner is verifiably gone, so a daemon or a CLI run that is alive is never hit. Here and
            // not in `host_backend()`, which read-only commands (`ls`, `status`) share. It sweeps by the records a run
            // writes, so it covers qemu on Linux and vfkit on macOS.
            if let Some(notice) = sweep_notice(&sandy_backend::sweep_orphaned_vms()) {
                eprintln!("sandy: {notice}");
            }
            // The composition root: select the run profile here and inject it. Today
            // only the host profile exists; a different profile (all-local) is a swap
            // at this one call site, not a change to dispatch_run.
            dispatch_run(&host_profile(), args, credential, &cred_capability, &journal, output)
        }
        Command::Ls => match supervisor::ls(&journal) {
            Ok(records) => succeed_or(emit(&JobRecords(records), output)),
            Err(e) => report_error(&e),
        },
        Command::Status { job_id } => {
            let backend = host_backend();
            match supervisor::status(&journal, &backend, &job_id) {
                Ok(record) => succeed_or(emit(&record, output)),
                Err(e) => report_error(&e),
            }
        }
        Command::Wait { job_id } => {
            let backend = host_backend();
            match supervisor::wait(&journal, &backend, &job_id) {
                Ok(record) => succeed_or(emit(&record, output)),
                Err(e) => report_error(&e),
            }
        }
        Command::Kill { job_id } => {
            let backend = host_backend();
            match supervisor::kill(&journal, &backend, &job_id) {
                Ok(record) => succeed_or(emit(&record, output)),
                Err(e) => report_error(&e),
            }
        }
        Command::Gc { keep_last } => match supervisor::gc(&journal, keep_last) {
            Ok(report) => succeed_or(emit(&report, output)),
            Err(e) => report_error(&e),
        },
    }
}

/// Writes one line of `daemon attach -o json`'s NDJSON stream (#513); `false`
/// when the write failed.
fn emit_attach_line(event: &AttachEvent) -> bool {
    sandy_cli::output::emit_stream_to([event.clone()], OutputFormat::Json, &mut std::io::stdout().lock()).is_ok()
}

/// Map an [`emit`] result to a process band: success (band 0) or
/// the serialization failure band it carries.
fn succeed_or(emitted: Result<(), i32>) -> i32 {
    match emitted {
        Ok(()) => ProcessExit::Succeeded.code(),
        Err(code) => code,
    }
}

/// Print a management-op error and map it to an exit band: an unknown job id is a
/// usage error (band 2); every other journal fault is an infra fault (band 3).
fn report_error(error: &CoreError) -> i32 {
    eprintln!("sandy: {error}");
    match error {
        CoreError::NotFound(_) => ProcessExit::InvalidPlan.code(),
        _ => ProcessExit::InfraFault.code(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Context;
    use sandy::{
        Capability, CredentialProvider, CredentialSource, EgressOs, Outcome, Profile, Target, TrustRoot, TrustRootIo,
    };
    use sandy_test_support::{FakeApplier, FakeBackend};

    use super::*;

    /// The non-credentialed dispatch path builds no provider, so a test profile
    /// carries this to satisfy the credential seam without a live backend.
    struct NoCred;
    impl CredentialSource for NoCred {
        fn provider(
            &self,
            _dir: &std::path::Path,
            _name: &str,
            _capabilities: &[String],
        ) -> Result<(Box<dyn CredentialProvider + Sync>, Scope), String> {
            unreachable!("the non-credentialed dispatch path never builds a credential provider")
        }
    }

    /// A minimal `run demo` request with no inputs, secrets, or command.
    fn demo_run_args() -> RunArgs {
        RunArgs {
            template: "demo".to_string(),
            inputs: vec![],
            outputs: vec![],
            secrets: vec![],
            env: vec![],
            allow: vec![],
            cpu: None,
            mem: None,
            timeout: None,
            digests: false,
            command: vec![],
        }
    }

    /// The composition root threads the INJECTED profile (#131 T1): `dispatch_run`,
    /// given a `Profile` whose `FakeBackend` is scripted to a clean success, exits on
    /// the band-0 success code — proving the dispatch SITE runs the injected backend,
    /// not `host_backend()`. A regression where `dispatch_run` bypassed the profile
    /// and reached a real host backend could not produce a band-0 success here.
    #[test]
    fn dispatch_run_threads_the_injected_profile() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir().context("temp SANDY_HOME")?;
        let journal = Journal::new(tmp.path());
        journal.ensure_dirs().context("ensure_dirs")?;
        let backend = FakeBackend::new().with_outcome(Outcome {
            digests: None,
            booted: true,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: String::new(),
        });
        let profile = Profile::new(
            Box::new(backend),
            Box::new(FakeApplier::new()),
            EgressOs::Linux,
            Box::new(NoCred),
        );
        let code = dispatch_run(&profile, demo_run_args(), None, &[], &journal, OutputFormat::Plain);
        assert_eq!(
            code,
            ProcessExit::Succeeded.code(),
            "dispatch_run must run the injected FakeBackend's clean-success outcome (band 0)"
        );
        Ok(())
    }

    /// Write a GitHub trust root (and a `0600` dummy key) under `dir`, so
    /// `credential_setup` has something to load without a live forge.
    fn write_trust_root(dir: &std::path::Path, name: &str, targets: &[&str]) -> anyhow::Result<()> {
        std::fs::create_dir_all(dir).context("mkdir")?;
        let pem = dir.join(format!("{name}.pem"));
        std::fs::write(&pem, b"-----dummy-----").context("write pem")?;
        std::fs::set_permissions(&pem, std::fs::Permissions::from_mode(0o600)).context("chmod pem")?;
        let root = TrustRoot::Github {
            base_url: None,
            app_id: "123".to_string(),
            private_key_path: pem,
            installation_id: 7,
            targets: targets.iter().map(|t| Target((*t).to_string())).collect(),
        };
        root.write(&dir.join(format!("{name}.json")))
            .context("write trust root")?;
        Ok(())
    }

    #[test]
    fn credential_setup_scopes_to_the_trust_root_targets_and_capabilities() -> anyhow::Result<()> {
        let tmp = tempfile::Builder::new()
            .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
                0o700,
            ))
            .tempdir()?;
        write_trust_root(tmp.path(), "runner", &["kauki-labs/sandy-pilot-test"])?;

        let (_adapter, scope) = credential_setup(
            tmp.path(),
            "runner",
            &["write-code".to_string(), "write-pr".to_string()],
        )
        .map_err(|e| anyhow::anyhow!(e))?;

        assert_eq!(scope.targets, vec![Target("kauki-labs/sandy-pilot-test".to_string())]);
        assert_eq!(scope.capabilities, vec![Capability::WriteCode, Capability::WritePr]);
        Ok(())
    }

    #[test]
    fn credential_setup_defaults_to_read_code_when_no_capability_is_given() -> anyhow::Result<()> {
        let tmp = tempfile::Builder::new()
            .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
                0o700,
            ))
            .tempdir()?;
        write_trust_root(tmp.path(), "runner", &["o/r"])?;

        let (_adapter, scope) = credential_setup(tmp.path(), "runner", &[]).map_err(|e| anyhow::anyhow!(e))?;

        assert_eq!(
            scope.capabilities,
            vec![Capability::ReadCode],
            "no capability flag defaults to read-code"
        );
        Ok(())
    }

    #[test]
    fn credential_setup_rejects_an_unknown_capability() -> anyhow::Result<()> {
        let tmp = tempfile::Builder::new()
            .permissions(<std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(
                0o700,
            ))
            .tempdir()?;
        write_trust_root(tmp.path(), "runner", &["o/r"])?;

        let err = credential_setup(tmp.path(), "runner", &["admin".to_string()])
            .map(|_| ())
            .expect_err("an unknown capability must be rejected");
        assert!(err.contains("unknown --cred-capability"), "got: {err}");
        Ok(())
    }

    fn write_cap_file(dir: &std::path::Path, name: &str, contents: &str) -> anyhow::Result<String> {
        let path = dir.join(name);
        std::fs::write(&path, contents)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(path.to_str().context("cap file path is utf8")?.to_owned())
    }

    #[test]
    fn read_submitter_caps_refuses_a_group_or_world_readable_file() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"a-real-cap-blob");
        let path = write_cap_file(tmp.path(), "cap-1", &encoded)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;

        let err = read_submitter_caps(&[path]).expect_err("a group/world-readable --cap-file must be refused");
        assert!(err.contains("group/world-readable"), "got: {err}");
        assert!(err.contains("INV-1"), "got: {err}");
        Ok(())
    }

    #[test]
    fn read_submitter_caps_round_trips_base64() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"a-real-cap-blob");
        let path = write_cap_file(tmp.path(), "cap-1", &encoded)?;
        let decoded = read_submitter_caps(&[path]).map_err(|e| anyhow::anyhow!(e))?;
        assert_eq!(decoded, vec![b"a-real-cap-blob".to_vec()]);
        Ok(())
    }

    #[test]
    fn read_submitter_caps_trims_surrounding_whitespace() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"a-real-cap-blob");
        let path = write_cap_file(tmp.path(), "cap-1", &format!("  {encoded}\n"))?;
        let decoded = read_submitter_caps(&[path]).map_err(|e| anyhow::anyhow!(e))?;
        assert_eq!(decoded, vec![b"a-real-cap-blob".to_vec()]);
        Ok(())
    }

    /// A2c (#483): `sandy daemon submit --digests` is a flag of the Submit, off by default.
    #[test]
    fn daemon_submit_takes_a_digests_flag() -> anyhow::Result<()> {
        use clap::Parser;
        let parse = |extra: &[&str]| -> anyhow::Result<bool> {
            let mut args = vec![
                "sandy",
                "daemon",
                "submit",
                "github:acme/guest",
                "--isolation-class",
                "trusted",
            ];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args)?.command {
                Command::Daemon {
                    op: DaemonOp::Submit { digests, .. },
                } => Ok(digests),
                _ => anyhow::bail!("not a daemon submit"),
            }
        };
        assert!(parse(&["--digests"])?);
        assert!(!parse(&[])?);
        Ok(())
    }

    #[test]
    fn read_submitter_caps_allows_no_caps_at_all() -> anyhow::Result<()> {
        let decoded = read_submitter_caps(&[]).map_err(|e| anyhow::anyhow!(e))?;
        assert!(decoded.is_empty());
        Ok(())
    }

    #[test]
    fn read_submitter_caps_refuses_a_file_over_the_size_limit() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let oversized = "A".repeat((MAX_CAP_FILE_LEN + 1) as usize);
        let path = write_cap_file(tmp.path(), "cap-huge", &oversized)?;

        let err = read_submitter_caps(&[path]).expect_err("an oversized --cap-file must be refused");
        assert!(err.contains("exceeds"), "got: {err}");
        Ok(())
    }

    #[test]
    fn read_submitter_caps_names_the_malformed_path() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let good = base64::engine::general_purpose::STANDARD.encode(b"fine");
        let good_path = write_cap_file(tmp.path(), "cap-good", &good)?;
        let bad_path = write_cap_file(tmp.path(), "cap-bad", "not valid base64!!")?;

        let err = read_submitter_caps(&[good_path, bad_path.clone()])
            .expect_err("a malformed second --cap-file must be refused");
        assert!(err.contains(&bad_path), "got: {err}");
        Ok(())
    }

    #[test]
    fn read_submitter_caps_names_an_unreadable_path() {
        let err = read_submitter_caps(&["/nonexistent/cap/path".to_owned()])
            .expect_err("a missing --cap-file must be refused");
        assert!(err.contains("/nonexistent/cap/path"), "got: {err}");
        assert!(err.contains("could not be read"), "got: {err}");
    }

    /// #666: a run that stopped a killed host's VMs says so, or the user never learns that it killed anything.
    #[test]
    fn a_sweep_that_did_something_is_reported() {
        let swept = sandy_backend::SweepReport {
            killed: 3,
            wiped: 1,
            ..sandy_backend::SweepReport::default()
        };
        assert_eq!(
            sweep_notice(&swept).as_deref(),
            Some("swept the VMs a killed host left behind: 3 process(es) signalled, 1 box(es) removed")
        );
    }

    #[test]
    fn a_box_that_could_not_be_swept_is_reported_as_left_for_the_next_run() {
        let swept = sandy_backend::SweepReport {
            killed: 1,
            undecided: 2,
            unreadable: 1,
            ..sandy_backend::SweepReport::default()
        };
        assert_eq!(
            sweep_notice(&swept).as_deref(),
            Some(
                "swept the VMs a killed host left behind: 1 process(es) signalled, 0 box(es) removed, 3 left for the \
                 next run"
            )
        );
    }

    #[test]
    fn a_sweep_that_found_nothing_to_do_says_nothing() {
        assert_eq!(sweep_notice(&sandy_backend::SweepReport::default()), None);
        // A live owner's box is left alone, and that is not news.
        let alive = sandy_backend::SweepReport {
            live_owner: 2,
            ..sandy_backend::SweepReport::default()
        };
        assert_eq!(sweep_notice(&alive), None);
    }
}
