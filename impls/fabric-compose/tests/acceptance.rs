//! The all-local MVP acceptance test (issue #115, increment 1: seam-level).
//!
//! Two things, both running and passing today, no `#[ignore]`: the gate
//! rejects a broken swap regardless of whether that seam's slot is real or
//! still a placeholder, and INV-1 holds through the real Executor dispatch
//! path. The full issue-#115 scenario (discover a sandbox, open an
//! orchestrator channel, the agent runs the job, a peer-group coordinates, an
//! escalation reaches a human backend) is `tests/scenario.rs` (#229).
//!
//! `sandy_fabric::contract::fakes` fills every seam this profile doesn't have
//! a real impl for yet (see [`PENDING_FAKED_SEAMS`]) plus `Transport`, which
//! stays fake by design (see [`DEFERRED_FAKE_SEAMS`]). A swap PR removes a
//! pending seam's entry in the same change that lands the real impl.
//!
//! Real does not mean isolating: this profile's `Process` executor is a
//! verification path for library composition on one machine, never an
//! untrusted-code boundary (#150). [`the_all_local_profile_provides_no_process_isolation`]
//! asserts that fact directly through `sandy::admits_untrusted` rather than
//! leaving it as an absence a reader could mistake for an oversight.
//!
//! `validate_profile` (the composition gate itself) lives here rather than in
//! `src/`: running full contract suites is test-time work (`executor_suite`
//! actually dispatches a real process), not something a real `sandyd` would
//! do at its own startup, and there's no concrete production consumer today.

use std::{
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::Context as _;
use sandy::{VmBackend as _, admits_untrusted};
use sandy_api::backend::{Grants, RunSpec, SandboxKind, SecretRef, SecretSource};
use sandy_backend::ProcessBackend;
use sandy_fabric::{
    capauth::CapAuthority,
    channel_backend::ChannelBackend,
    contract::{
        ContractViolation, capacity_suite, capauth_suite, channel_backend_suite, discovery_suite, executor_suite,
        fakes::{ConstantMinter, FakeTransport, SnapshotBackend},
        lifecycle_suite, minter_suite, telemetry_suite, transport_suite,
    },
    executor::{Arch, Capabilities, Executor},
    minter::Minter,
    placement::{Capacity, Discovery, Lifecycle},
    telemetry::TelemetrySink,
    transport::Transport,
    types::HostId,
};
use sandy_fabric_local::{
    LocalCapAuthority,
    executor::VmBackendExecutor,
    inmem::InMem,
    minter::LocalMinter,
    placement::{ExecutorCapacity, LeaseTable, StaticRegistry},
    telemetry::LocalLog,
};
use sha2::{Digest as _, Sha256};

/// Seams the all-local profile still composes with a placeholder fake,
/// pending that seam's block landing. A swap PR removes its entry in the
/// same change that lands the real impl; an empty list means every
/// block-pending seam is real (see [`DEFERRED_FAKE_SEAMS`] for the rest).
const PENDING_FAKED_SEAMS: &[&str] = &[];

/// Seams the all-local profile composes with a placeholder fake by design,
/// not pending any block. `Transport`'s local-process detail is deferred
/// (spec §3.9); nothing tracks a real impl as a dependency, so it stays here
/// even once [`PENDING_FAKED_SEAMS`] is empty.
const DEFERRED_FAKE_SEAMS: &[&str] = &["Transport"];

/// #115's real close signal for seam reality: every block-pending seam now
/// composes with its real impl. `DEFERRED_FAKE_SEAMS` stays non-empty by
/// design, so this only guards the pending list going stale (someone adding a
/// fake back without updating the const, or landing a real impl without
/// removing its entry).
#[test]
fn every_pending_seam_is_real() {
    assert!(
        PENDING_FAKED_SEAMS.is_empty(),
        "a seam still composes with a placeholder fake pending its own block: {PENDING_FAKED_SEAMS:?}"
    );
}

/// Guards the deliberate-fake list going stale the other way: a seam quietly
/// disappearing from here would read as "swapped to real" when it was
/// actually just dropped.
#[test]
fn deferred_fake_seams_are_tracked_not_silently_dropped() {
    assert_eq!(
        DEFERRED_FAKE_SEAMS,
        &["Transport"],
        "update this test alongside any change to the deliberate-fake list"
    );
}

/// The all-local profile's `CapAuthority` slot (real, #110). `capauth_suite`
/// always mints with an explicit `expires_at`, so `default_ttl` is never
/// actually exercised here — the value just has to be sane.
fn local_cap_authority() -> LocalCapAuthority {
    LocalCapAuthority::new(std::time::Duration::from_secs(300)).expect("rng available for a fresh authority")
}

/// A fresh timeout future for `channel_backend_suite`'s stream-wait steps (its
/// own runtime's sleep, per the suite's runtime-agnostic contract).
fn deadline() -> tokio::time::Sleep {
    tokio::time::sleep(std::time::Duration::from_secs(2))
}

/// The two factories `telemetry_suite` needs, as named fields rather than two
/// adjacent same-typed closure parameters — swapping enabled/disabled is then
/// a field-name mistake the type system would catch on a rename, not a silent
/// argument-order bug a reviewer has to catch by eye.
struct TelemetryFactories<E, D> {
    enabled: E,
    disabled: D,
}

/// A fresh `LocalLog`/`LocalLog::disabled` pair for one `validate_profile`
/// call: `enabled` opens a distinct file per call under `dir` (the suite
/// calls a seam's factory more than once), since two `LocalLog`s sharing a
/// path would serialize on the same `flock` for no reason here.
fn telemetry_factories(dir: &Path) -> TelemetryFactories<impl Fn() -> LocalLog + '_, impl Fn() -> LocalLog> {
    let next_file = AtomicU64::new(0);
    TelemetryFactories {
        enabled: move || {
            let i = next_file.fetch_add(1, Ordering::Relaxed);
            LocalLog::open(dir.join(format!("t{i}.jsonl")))
        },
        disabled: LocalLog::disabled,
    }
}

/// `telemetry_suite`'s `captured` probe for a [`LocalLog`]: the records it has
/// durably appended so far.
fn telemetry_captured(log: &LocalLog) -> usize {
    log.records().map_or(usize::MAX, |r| r.len())
}

/// Run every seam's own contract suite against the given per-seam factories.
/// Returns the first violation.
///
/// Generic rather than fixed to one profile: the all-local MVP's real choices
/// are one call site below, and a deliberately broken factory for a single
/// seam is another — both go through the same gate, so a broken swap is
/// caught the same way whether that seam's current slot is a real impl or
/// still a placeholder.
#[expect(
    clippy::too_many_arguments,
    reason = "one factory per seam (spec §6's nine), the gate for the whole profile in one call; splitting it would \
              just move the same nine-seam coupling into a builder with its own nine setters"
)]
async fn validate_profile<CA, M, CB, T, E, D, CP, L, TS>(
    cap_authority: impl Fn() -> CA,
    minter: impl Fn() -> M,
    channel_backend: impl Fn() -> CB,
    transport: impl Fn() -> T,
    executor: impl Fn() -> E,
    executor_capabilities: Capabilities,
    executor_template: &str,
    discovery: impl Fn() -> D,
    capacity_host: HostId,
    capacity: impl Fn() -> CP,
    lifecycle: impl Fn() -> L,
    telemetry: TelemetryFactories<impl Fn() -> TS, impl Fn() -> TS>,
    telemetry_captured: impl Fn(&TS) -> usize,
) -> Result<(), ContractViolation>
where
    CA: CapAuthority,
    M: Minter,
    CB: ChannelBackend,
    T: Transport,
    E: Executor,
    D: Discovery,
    CP: Capacity,
    L: Lifecycle,
    TS: TelemetrySink,
{
    capauth_suite(cap_authority)?;
    minter_suite(minter).await?;
    channel_backend_suite(channel_backend, deadline).await?;
    transport_suite(transport).await?;
    executor_suite(executor_capabilities, executor_template, executor).await?;
    discovery_suite(discovery).await?;
    capacity_suite(capacity_host, capacity).await?;
    lifecycle_suite(lifecycle).await?;
    telemetry_suite(telemetry.enabled, telemetry.disabled, telemetry_captured).await?;
    Ok(())
}

/// The compiled host architecture. The flake only ever builds `x86_64-linux`
/// or `aarch64-darwin` (see `AGENTS.md`).
fn host_arch() -> Arch {
    match std::env::consts::ARCH {
        "x86_64" => Arch::X86_64,
        "aarch64" => Arch::Aarch64,
        other => panic!("unsupported host architecture for this acceptance test: {other}"),
    }
}

fn process_capabilities() -> Capabilities {
    Capabilities {
        kind: SandboxKind::Process,
        arch: host_arch(),
        attestation: None,
    }
}

/// The all-local profile's `Capacity` slot (real, #112): a direct probe over
/// a second `Process` executor instance, since `validate_profile` takes an
/// independent factory per seam.
fn executor_capacity() -> ExecutorCapacity<VmBackendExecutor<ProcessBackend>> {
    ExecutorCapacity::new().with_host(
        HostId::from(StaticRegistry::LOCALHOST),
        VmBackendExecutor::new(ProcessBackend::new()),
        1,
    )
}

/// The all-local profile's `Lifecycle` slot (real, #112): lease soft-state on
/// a generous TTL, since `lifecycle_suite` drives registration/heartbeat
/// directly rather than waiting out a lease.
fn lease_table() -> LeaseTable {
    LeaseTable::new(std::time::Duration::from_secs(300))
}

/// The all-local profile's current real/fake mix (see [`PENDING_FAKED_SEAMS`]
/// and [`DEFERRED_FAKE_SEAMS`]).
async fn validate_all_local_profile(telemetry_dir: &Path) -> Result<(), ContractViolation> {
    validate_profile(
        local_cap_authority,
        || LocalMinter,
        InMem::default,
        FakeTransport::default,
        || VmBackendExecutor::new(ProcessBackend::new()),
        process_capabilities(),
        "contract",
        StaticRegistry::default,
        HostId::from(StaticRegistry::LOCALHOST),
        executor_capacity,
        lease_table,
        telemetry_factories(telemetry_dir),
        telemetry_captured,
    )
    .await
}

/// Positive: today's real/fake mix passes its own gate.
#[tokio::test(flavor = "multi_thread")]
async fn the_all_local_profile_passes_its_own_gate() -> anyhow::Result<()> {
    let telemetry_dir = tempfile::tempdir().context("telemetry dir")?;
    validate_all_local_profile(telemetry_dir.path())
        .await
        .context("today's real/fake mix")
}

/// Honest-gate (#150): the all-local profile's `Process` executor is NOT an
/// isolation boundary, asserted directly through the same fail-closed gate
/// (`sandy::admits_untrusted`) the real executor path is keyed off, rather
/// than leaving "no containment" as something a reader could mistake for an
/// oversight instead of the intended scope. This profile proves library
/// composition on one machine; untrusted code stays VM-only (process-containment.md).
#[test]
fn the_all_local_profile_provides_no_process_isolation() {
    let backend = ProcessBackend::new();
    assert!(
        !admits_untrusted(backend.kind(), &backend.containment_status()),
        "the all-local profile's Process executor must not admit untrusted jobs: it is a verification path, never an \
         isolation boundary"
    );
}

/// Adversarial: swapping the REAL ChannelBackend slot for a broken variant
/// fails the gate. `SnapshotBackend` is a `stream_from` that ends instead of
/// following live appends.
#[tokio::test(flavor = "multi_thread")]
async fn gate_rejects_a_broken_channel_backend_even_though_its_slot_is_real() -> anyhow::Result<()> {
    let telemetry_dir = tempfile::tempdir().context("telemetry dir")?;
    let result = validate_profile(
        local_cap_authority,
        || LocalMinter,
        SnapshotBackend::default,
        FakeTransport::default,
        || VmBackendExecutor::new(ProcessBackend::new()),
        process_capabilities(),
        "contract",
        StaticRegistry::default,
        HostId::from(StaticRegistry::LOCALHOST),
        executor_capacity,
        lease_table,
        telemetry_factories(telemetry_dir.path()),
        telemetry_captured,
    )
    .await;
    let violation = result
        .err()
        .context("a stream that ends instead of following must fail the gate")?;
    assert!(
        violation.rule.contains("the stream ended"),
        "violated `{}`, expected the live-follow rule",
        violation.rule
    );
    Ok(())
}

/// Adversarial: swapping the REAL Minter slot for a broken variant also fails
/// the gate — proving it's uniform across every seam now that none is a
/// placeholder (save `Transport`, deliberately out of scope). `ConstantMinter`
/// mints the same secret every call.
#[tokio::test(flavor = "multi_thread")]
async fn gate_rejects_a_broken_minter_even_though_its_slot_is_real() -> anyhow::Result<()> {
    let telemetry_dir = tempfile::tempdir().context("telemetry dir")?;
    let result = validate_profile(
        local_cap_authority,
        || ConstantMinter,
        InMem::default,
        FakeTransport::default,
        || VmBackendExecutor::new(ProcessBackend::new()),
        process_capabilities(),
        "contract",
        StaticRegistry::default,
        HostId::from(StaticRegistry::LOCALHOST),
        executor_capacity,
        lease_table,
        telemetry_factories(telemetry_dir.path()),
        telemetry_captured,
    )
    .await;
    let violation = result
        .err()
        .context("a minter with a constant secret must fail the gate")?;
    assert!(
        violation.rule.contains("two mints for one job differ"),
        "violated `{}`, expected the fresh-mint rule",
        violation.rule
    );
    Ok(())
}

/// INV-1 holds through the real Executor dispatch path: a secret referenced by
/// a `SecretRef` never reaches the spawned process's argv or env.
///
/// Deliberately decoupled from Minter (still a placeholder — see
/// `FAKED_SEAMS`): the `SecretRef` here is constructed directly, not minted.
/// This proves fabric's dispatch glue downstream of wherever a secret comes
/// from doesn't introduce a leak; it does not prove a real Minter's own output
/// is safe (that's #111's job when it lands). It also isn't re-deriving
/// `sandy-impls-local`'s own `a_secret_value_is_absent_from_the_process_env`
/// test (which already proves `ProcessBackend`'s env isolation directly) —
/// `VmBackendExecutor::run` is a zero-transformation passthrough
/// (`block_in_place(|| self.backend.run(spec))`), so this confirms the
/// fabric Executor adapter doesn't regress that guarantee, which is a real
/// but much thinner claim than "INV-1 end-to-end."
#[tokio::test(flavor = "multi_thread")]
async fn inv1_holds_through_the_real_executor_dispatch_path() -> anyhow::Result<()> {
    const MARKER: &str = "s3cr3t-marker-v1";
    let digest = hex::encode(Sha256::digest(MARKER));

    let secret_dir = tempfile::tempdir().context("secret_dir")?;
    let secret_file = secret_dir.path().join("tok");
    std::fs::write(&secret_file, MARKER).context("write secret file")?;
    std::fs::set_permissions(&secret_file, std::fs::Permissions::from_mode(0o600)).context("secret file perms")?;

    let executor = VmBackendExecutor::new(ProcessBackend::new());
    let secrets = [SecretRef {
        name: "TOKEN".to_owned(),
        source: SecretSource::File(secret_file),
    }];
    let grants = Grants {
        secrets: true,
        agent: false,
        shares: false,
    };
    // Prints the staged file's SHA-256 digest (never its content) plus an env
    // dump: the digest, checked against a Rust-computed digest of MARKER
    // below, proves the secret channel delivers exactly the right bytes (a
    // byte-length check alone would pass a same-length wrong-content bug
    // silently), while the comparison value itself never appears in the
    // script — embedding MARKER would put it on this process's own argv, the
    // exact leak INV-1 rules out, in the test meant to prove INV-1 holds.
    let command = [
        "sh".to_owned(),
        "-c".to_owned(),
        r#"echo "SECRET_DIGEST=$(sha256sum < "$SANDY_SECRETS_DIR/TOKEN" | cut -d' ' -f1)"; env"#.to_owned(),
    ];
    let spec = RunSpec {
        template: "contract",
        command: &command,
        inputs: &[],
        outputs: &[],
        secrets: &secrets,
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants: &grants,
        outcome_file: None,
        secret_dir: None,
    };

    let outcome = executor.run(&spec).await.context("dispatch through the real adapter")?;
    assert_eq!(outcome.guest_exit, Some(0), "the job ran: {:?}", outcome.console);
    assert!(
        outcome.console.contains(&format!("SECRET_DIGEST={digest}")),
        "the job must read exactly the staged secret's content via SANDY_SECRETS_DIR, got {:?}",
        outcome.console
    );
    assert!(
        !outcome.console.contains(MARKER),
        "INV-1: the secret bytes must never reach the job's env, got {:?}",
        outcome.console
    );
    assert!(
        outcome.console.contains("SANDY_SECRETS_DIR="),
        "the job should still see the secret's staging dir path, got {:?}",
        outcome.console
    );
    Ok(())
}
