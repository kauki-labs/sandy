//! The all-local MVP acceptance test (issue #115, increment 1: seam-level).
//!
//! Two things, both running and passing today, no `#[ignore]`: the gate
//! rejects a broken swap regardless of whether that seam's slot is real or
//! still a placeholder, and INV-1 holds through the real Executor dispatch
//! path. The full issue-#115 scenario (discover a sandbox, open an
//! orchestrator channel, the agent runs the job, a peer-group coordinates, an
//! escalation reaches a human backend) needs #106 (Channel) and #109 (the
//! sandbox agent) first — neither exists yet, so that scenario is a later
//! increment, not this one.
//!
//! `sandy_fabric::contract::fakes` fills every seam this profile doesn't have
//! a real impl for yet (see [`FAKED_SEAMS`]). A swap PR removes its entry in
//! the same change that lands the real impl.
//!
//! `validate_profile` (the composition gate itself) lives here rather than in
//! `src/`: running full contract suites is test-time work (`executor_suite`
//! actually dispatches a real process), not something a real `sandyd` would
//! do at its own startup, and there's no concrete production consumer today.

use std::os::unix::fs::PermissionsExt as _;

use anyhow::Context as _;
use sandy_api::backend::{Grants, RunSpec, SandboxKind, SecretRef, SecretSource};
use sandy_backend::ProcessBackend;
use sandy_fabric::{
    capauth::CapAuthority,
    channel_backend::ChannelBackend,
    contract::{
        ContractViolation, capacity_suite, capauth_suite, channel_backend_suite, discovery_suite, executor_suite,
        fakes::{
            FakeAuthority, FakeCapacity, FakeDiscovery, FakeLifecycle, FakeMinter, FakeSink, FakeTransport,
            NonAttenuatingAuthority, SnapshotBackend,
        },
        lifecycle_suite, minter_suite, telemetry_suite, transport_suite,
    },
    executor::{Arch, Capabilities, Executor},
    minter::Minter,
    placement::{Capacity, Discovery, Lifecycle},
    telemetry::TelemetrySink,
    transport::Transport,
    types::HostId,
};
use sandy_fabric_local::{executor::VmBackendExecutor, inmem::InMem};
use sha2::{Digest as _, Sha256};

/// Which seams the all-local profile still composes with a placeholder fake,
/// pending that seam's block landing. A swap PR removes its entry in the same
/// change that lands the real impl; an empty list is #115's real close signal.
const FAKED_SEAMS: &[&str] = &[
    "CapAuthority",  // pending #110
    "Minter",        // pending #111
    "Discovery",     // pending #112 (static registry)
    "Capacity",      // pending #112 (direct probe)
    "Lifecycle",     // pending #112 (lease soft-state)
    "Transport",     // deferred transport detail (spec §3.9); no block files it
    "TelemetrySink", // pending #114
];

/// Guards against the list silently going stale: an empty `FAKED_SEAMS` is
/// #115's real close signal (every seam real, the second acceptance test
/// becomes the issue's actual scenario), not something that should happen by
/// someone quietly forgetting to update a const.
#[test]
fn faked_seams_is_not_empty_yet() {
    assert!(
        !FAKED_SEAMS.is_empty(),
        "every seam is real: #115 can close for real, starting with the actual scenario test"
    );
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

/// The all-local profile's current real/fake mix (see [`FAKED_SEAMS`]).
async fn validate_all_local_profile() -> Result<(), ContractViolation> {
    validate_profile(
        FakeAuthority::new,
        FakeMinter::new,
        InMem::default,
        FakeTransport::default,
        || VmBackendExecutor::new(ProcessBackend::new()),
        process_capabilities(),
        "contract",
        FakeDiscovery::default,
        HostId::from("local"),
        || FakeCapacity::new(HostId::from("local"), 1),
        FakeLifecycle::default,
        TelemetryFactories {
            enabled: || FakeSink::new(true),
            disabled: || FakeSink::new(false),
        },
        FakeSink::captured,
    )
    .await
}

/// Positive: today's real/fake mix passes its own gate.
#[tokio::test(flavor = "multi_thread")]
async fn the_all_local_profile_passes_its_own_gate() -> anyhow::Result<()> {
    validate_all_local_profile().await.context("today's real/fake mix")
}

/// Adversarial: swapping the REAL ChannelBackend slot for a broken variant
/// fails the gate. `SnapshotBackend` is a `stream_from` that ends instead of
/// following live appends.
#[tokio::test(flavor = "multi_thread")]
async fn gate_rejects_a_broken_channel_backend_even_though_its_slot_is_real() -> anyhow::Result<()> {
    let result = validate_profile(
        FakeAuthority::new,
        FakeMinter::new,
        SnapshotBackend::default,
        FakeTransport::default,
        || VmBackendExecutor::new(ProcessBackend::new()),
        process_capabilities(),
        "contract",
        FakeDiscovery::default,
        HostId::from("local"),
        || FakeCapacity::new(HostId::from("local"), 1),
        FakeLifecycle::default,
        TelemetryFactories {
            enabled: || FakeSink::new(true),
            disabled: || FakeSink::new(false),
        },
        FakeSink::captured,
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

/// Adversarial: swapping a still-PLACEHOLDER seam (`CapAuthority`) for a
/// broken variant also fails the gate — proving it's uniform regardless of a
/// slot's current real/fake status, not just for seams that happen to be real
/// yet. `NonAttenuatingAuthority` hands back the parent cap unchanged instead
/// of narrowing it.
#[tokio::test(flavor = "multi_thread")]
async fn gate_rejects_a_broken_cap_authority_even_though_its_slot_is_a_placeholder() -> anyhow::Result<()> {
    let result = validate_profile(
        || NonAttenuatingAuthority(FakeAuthority::new()),
        FakeMinter::new,
        InMem::default,
        FakeTransport::default,
        || VmBackendExecutor::new(ProcessBackend::new()),
        process_capabilities(),
        "contract",
        FakeDiscovery::default,
        HostId::from("local"),
        || FakeCapacity::new(HostId::from("local"), 1),
        FakeLifecycle::default,
        TelemetryFactories {
            enabled: || FakeSink::new(true),
            disabled: || FakeSink::new(false),
        },
        FakeSink::captured,
    )
    .await;
    let violation = result
        .err()
        .context("attenuation that doesn't narrow rights must fail the gate")?;
    assert!(
        violation.rule.contains("narrowed rights"),
        "violated `{}`, expected the narrowed-rights rule",
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
