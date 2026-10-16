//! The harness proves itself: each reference impl passes its suite (positive), and
//! each deliberately broken impl fails it (adversarial), so no suite is a no-op.

use anyhow::Context;

use super::{
    capacity_suite, capauth_suite, channel_backend_suite, discovery_suite, executor_suite, fakes::*, lifecycle_suite,
    minter_suite, telemetry_suite, transport_suite,
};
use crate::{
    executor::{Arch, Capabilities, SandboxKind},
    types::HostId,
};

/// Assert `res` failed on the rule containing `fragment`, not on some other rule.
#[track_caller]
fn assert_violates(res: Result<(), super::ContractViolation>, fragment: &str) {
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
fn minter_reference_passes() -> anyhow::Result<()> {
    minter_suite(FakeMinter::new).context("reference minter")
}

#[test]
fn minter_suite_rejects_a_constant_secret() {
    assert_violates(minter_suite(|| ConstantMinter), "two mints for one job differ");
}

#[tokio::test]
async fn channel_backend_reference_passes() -> anyhow::Result<()> {
    channel_backend_suite(FakeBackend::default)
        .await
        .context("reference backend")
}

#[tokio::test]
async fn channel_backend_suite_rejects_a_snapshot_stream() {
    assert_violates(
        channel_backend_suite(SnapshotBackend::default).await,
        "follows an append",
    );
}

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

#[tokio::test]
async fn executor_reference_passes() -> anyhow::Result<()> {
    let make = || FakeExecutor {
        caps: PROCESS,
        collapse_failures: false,
    };
    executor_suite(PROCESS, make).await.context("reference executor")
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
        executor_suite(PROCESS, make).await,
        "reports what the executor provides",
    );
}

#[tokio::test]
async fn executor_suite_rejects_a_task_failure_reported_as_an_infra_fault() {
    let make = || FakeExecutor {
        caps: PROCESS,
        collapse_failures: true,
    };
    assert_violates(executor_suite(PROCESS, make).await, "task failure, not an infra fault");
}

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

#[tokio::test]
async fn capacity_reference_passes() -> anyhow::Result<()> {
    let host = HostId::from("h1");
    capacity_suite(host.clone(), || FakeCapacity::new(host.clone(), 2))
        .await
        .context("reference capacity")
}

#[tokio::test]
async fn capacity_suite_rejects_a_leaky_probe() {
    let host = HostId::from("h1");
    let make = || FakeCapacity {
        leaky: true,
        ..FakeCapacity::new(host.clone(), 2)
    };
    assert_violates(capacity_suite(host.clone(), make).await, "reserves nothing");
}

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
    assert_violates(lifecycle_suite(make).await, "never issued");
}

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
