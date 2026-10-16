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

use std::os::unix::fs::PermissionsExt as _;

use anyhow::Context as _;
use sandy_api::backend::{Grants, RunSpec, SandboxKind, SecretRef, SecretSource};
use sandy_backend::ProcessBackend;
use sandy_fabric::{
    contract::{
        ContractViolation,
        fakes::{
            FakeAuthority, FakeCapacity, FakeDiscovery, FakeLifecycle, FakeMinter, FakeSink, FakeTransport,
            NonAttenuatingAuthority, SnapshotBackend,
        },
    },
    executor::{Arch, Capabilities, Executor as _},
    types::HostId,
};
use sandy_fabric_compose::validate_profile;
use sandy_fabric_local::{executor::VmBackendExecutor, inmem::InMem};

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
        || FakeSink::new(true),
        || FakeSink::new(false),
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
async fn gate_rejects_a_broken_channel_backend_even_though_its_slot_is_real() {
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
        || FakeSink::new(true),
        || FakeSink::new(false),
        FakeSink::captured,
    )
    .await;
    let violation = result.expect_err("a stream that ends instead of following must fail the gate");
    assert!(
        violation.rule.contains("the stream ended"),
        "violated `{}`, expected the live-follow rule",
        violation.rule
    );
}

/// Adversarial: swapping a still-PLACEHOLDER seam (`CapAuthority`) for a
/// broken variant also fails the gate — proving it's uniform regardless of a
/// slot's current real/fake status, not just for seams that happen to be real
/// yet. `NonAttenuatingAuthority` hands back the parent cap unchanged instead
/// of narrowing it.
#[tokio::test(flavor = "multi_thread")]
async fn gate_rejects_a_broken_cap_authority_even_though_its_slot_is_a_placeholder() {
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
        || FakeSink::new(true),
        || FakeSink::new(false),
        FakeSink::captured,
    )
    .await;
    let violation = result.expect_err("attenuation that doesn't narrow rights must fail the gate");
    assert!(
        violation.rule.contains("narrowed rights"),
        "violated `{}`, expected the narrowed-rights rule",
        violation.rule
    );
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
    let secret_dir = tempfile::tempdir().context("secret_dir")?;
    let secret_file = secret_dir.path().join("tok");
    let marker = b"s3cr3t-marker-v1";
    std::fs::write(&secret_file, marker).context("write secret file")?;
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
    let command = ["sh".to_owned(), "-c".to_owned(), "env".to_owned()];
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
    let marker = String::from_utf8_lossy(marker);
    assert!(
        !outcome.console.contains(marker.as_ref()),
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
