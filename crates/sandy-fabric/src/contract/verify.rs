//! The harness proves itself: each reference impl passes its suite (positive), and
//! each deliberately broken impl fails it on the rule it breaks (adversarial), so
//! no suite is a no-op.

use std::time::Duration;

use anyhow::Context;

use super::{
    ContractViolation, capacity_suite, capauth_suite, channel_backend_suite, discovery_suite, executor_suite, fakes::*,
    lifecycle_suite, minter_suite, telemetry_suite, transport_suite,
};
use crate::{
    executor::{Arch, Capabilities, SandboxKind},
    types::HostId,
};

/// Assert `res` failed on the rule containing `fragment`, not on some other rule.
#[track_caller]
fn assert_violates(res: Result<(), ContractViolation>, fragment: &str) {
    match res {
        Err(v) => assert!(
            v.rule.contains(fragment),
            "violated `{}`, expected `{fragment}`",
            v.rule
        ),
        Ok(()) => panic!("the suite passed a broken impl; expected `{fragment}`"),
    }
}

const PROCESS: Capabilities = Capabilities {
    kind: SandboxKind::Process,
    arch: Arch::X86_64,
    attestation: None,
};

fn deadline() -> tokio::time::Sleep {
    tokio::time::sleep(Duration::from_secs(2))
}

// ---- CapAuthority ----

#[test]
fn capauth_reference_passes() -> anyhow::Result<()> {
    capauth_suite(FakeAuthority::new).context("reference authority")
}

#[test]
fn capauth_suite_rejects_an_authority_that_does_not_attenuate() {
    assert_violates(
        capauth_suite(|| NonAttenuatingAuthority(FakeAuthority::new())),
        "exactly the narrowed rights",
    );
}

#[test]
fn capauth_suite_rejects_a_proof_that_does_not_cover_rights() {
    let make = || FakeAuthority {
        blind_to_rights: true,
        ..FakeAuthority::default()
    };
    assert_violates(capauth_suite(make), "rights edited");
}

#[test]
fn capauth_suite_rejects_attenuating_an_unverified_parent() {
    let make = || FakeAuthority {
        trusts_parent: true,
        ..FakeAuthority::default()
    };
    assert_violates(capauth_suite(make), "tampered parent");
}

// ---- Minter ----

#[tokio::test]
async fn minter_reference_passes() -> anyhow::Result<()> {
    minter_suite(FakeMinter::new).await.context("reference minter")
}

#[tokio::test]
async fn minter_suite_rejects_a_constant_secret() {
    assert_violates(minter_suite(|| ConstantMinter).await, "two mints for one job differ");
}

// ---- ChannelBackend ----

#[tokio::test]
async fn channel_backend_reference_passes() -> anyhow::Result<()> {
    channel_backend_suite(FakeBackend::default, deadline)
        .await
        .context("reference backend")
}

#[tokio::test]
async fn a_backend_stream_outlives_the_borrow_and_reads_from_a_spawned_task() -> anyhow::Result<()> {
    use futures_util::StreamExt;

    use crate::channel_backend::{ChannelBackend, Envelope, MSG_ID_KEY};

    let backend = FakeBackend::default();
    let stream = backend.stream_from(1);
    let reader = tokio::spawn(async move { std::pin::pin!(stream).next().await.map(|e| e.map(|e| e.sequence)) });
    let env = Envelope {
        sequence: 1,
        metadata: [(MSG_ID_KEY.to_owned(), "a".to_owned())].into(),
        ..Envelope::default()
    };
    backend.append(env).await.context("append")?;
    let got = tokio::time::timeout(Duration::from_secs(2), reader)
        .await
        .context("reader timed out")??;
    anyhow::ensure!(got == Some(Ok(1)), "spawned reader saw {got:?}");
    Ok(())
}

#[tokio::test]
async fn channel_backend_suite_rejects_a_snapshot_stream() {
    assert_violates(
        channel_backend_suite(SnapshotBackend::default, deadline).await,
        "follows an append",
    );
}

#[tokio::test]
async fn channel_backend_suite_rejects_arrival_order_fetches() {
    let make = || FakeBackend {
        arrival_order: true,
        ..FakeBackend::default()
    };
    assert_violates(channel_backend_suite(make, deadline).await, "sequence order");
}

#[tokio::test]
async fn channel_backend_suite_rejects_dedup_on_sequence() {
    let make = || FakeBackend {
        dedup_on_sequence: true,
        ..FakeBackend::default()
    };
    assert_violates(channel_backend_suite(make, deadline).await, "keeps the first");
}

// ---- Transport ----

#[tokio::test]
async fn transport_reference_passes() -> anyhow::Result<()> {
    transport_suite(FakeTransport::default)
        .await
        .context("reference transport")
}

#[tokio::test]
async fn transport_suite_rejects_dropping_frames_for_offline_peers() {
    assert_violates(
        transport_suite(LiveOnlyTransport::default).await,
        "stored and delivered",
    );
}

// ---- Executor ----

#[tokio::test]
async fn executor_reference_passes() -> anyhow::Result<()> {
    let make = || FakeExecutor {
        caps: PROCESS,
        collapse_failures: false,
    };
    executor_suite(PROCESS, "contract", make)
        .await
        .context("reference executor")
}

#[tokio::test]
async fn executor_suite_rejects_a_false_capability_claim() {
    let make = || FakeExecutor {
        caps: Capabilities {
            kind: SandboxKind::Vm,
            ..PROCESS
        },
        collapse_failures: false,
    };
    assert_violates(
        executor_suite(PROCESS, "contract", make).await,
        "reports what the executor provides",
    );
}

#[tokio::test]
async fn executor_suite_rejects_a_task_failure_reported_as_an_infra_fault() {
    let make = || FakeExecutor {
        caps: PROCESS,
        collapse_failures: true,
    };
    assert_violates(
        executor_suite(PROCESS, "contract", make).await,
        "task failure, not an infra fault",
    );
}

// ---- Discovery ----

#[tokio::test]
async fn discovery_reference_passes() -> anyhow::Result<()> {
    discovery_suite(FakeDiscovery::default)
        .await
        .context("reference discovery")
}

#[tokio::test]
async fn discovery_suite_rejects_ignoring_requirements() {
    let make = || FakeDiscovery {
        ignore_requirements: true,
        ..FakeDiscovery::default()
    };
    assert_violates(discovery_suite(make).await, "matches on kind");
}

// ---- Capacity ----

#[tokio::test]
async fn capacity_reference_passes() -> anyhow::Result<()> {
    let host = HostId::from("h1");
    capacity_suite(host.clone(), || FakeCapacity::new(host.clone(), 2))
        .await
        .context("reference capacity")
}

#[tokio::test]
async fn capacity_suite_rejects_a_probe_that_reserves() {
    let host = HostId::from("h1");
    let make = || FakeCapacity {
        reserving: true,
        ..FakeCapacity::new(host.clone(), 2)
    };
    assert_violates(capacity_suite(host.clone(), make).await, "reserves nothing");
}

#[tokio::test]
async fn capacity_suite_rejects_capacity_for_an_unknown_host() {
    let host = HostId::from("h1");
    let make = || FakeCapacity {
        phantom: true,
        ..FakeCapacity::new(host.clone(), 2)
    };
    assert_violates(capacity_suite(host.clone(), make).await, "unknown host");
}

// ---- Lifecycle ----

#[tokio::test]
async fn lifecycle_reference_passes() -> anyhow::Result<()> {
    lifecycle_suite(FakeLifecycle::default)
        .await
        .context("reference lifecycle")
}

#[tokio::test]
async fn lifecycle_suite_rejects_accepting_unknown_leases() {
    let make = || FakeLifecycle {
        accept_any: true,
        ..FakeLifecycle::default()
    };
    assert_violates(lifecycle_suite(make).await, "wrong host");
}

// ---- TelemetrySink ----

#[tokio::test]
async fn telemetry_reference_passes() -> anyhow::Result<()> {
    telemetry_suite(|| FakeSink::new(true), || FakeSink::new(false), FakeSink::captured)
        .await
        .context("reference sink")
}

#[tokio::test]
async fn telemetry_suite_rejects_recording_while_disabled() {
    let disabled = || FakeSink {
        ignore_disabled: true,
        ..FakeSink::new(false)
    };
    assert_violates(
        telemetry_suite(|| FakeSink::new(true), disabled, FakeSink::captured).await,
        "a disabled sink keeps nothing",
    );
}

#[tokio::test]
async fn telemetry_suite_rejects_dropping_records_while_enabled() {
    let lossy = || FakeSink {
        lossy: true,
        ..FakeSink::new(true)
    };
    assert_violates(
        telemetry_suite(lossy, || FakeSink::new(false), FakeSink::captured).await,
        "an enabled sink keeps every record",
    );
}
