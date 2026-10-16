//! The composition root for the agent-fabric all-local MVP profile (spec §2,
//! §6; issue #115).
//!
//! [`validate_profile`] runs every seam's own contract suite against whatever
//! impls it's given — the composition's gate: an impl that fails its seam's
//! contract never gets composed into a real run. It is generic over every
//! seam's type, so this crate's production code never depends on a seam's
//! concrete choice, real or placeholder; a caller supplies a factory per seam.
//!
//! This crate holds the gate, not the choice. The all-local MVP's current
//! real-vs-placeholder mix (`FAKED_SEAMS`, the real/fake ratchet) lives in
//! `tests/acceptance.rs`, consuming `sandy_fabric::contract::fakes` as a
//! dev-dependency — never from here, so a test fixture never enters this
//! crate's production dependency graph. The eventual real all-local compose
//! root, once every seam lands, calls `validate_profile` with all-real
//! factories; nothing in `src/` has to change for that.

use sandy_fabric::{
    capauth::CapAuthority,
    channel_backend::ChannelBackend,
    contract::{
        ContractViolation, capacity_suite, capauth_suite, channel_backend_suite, discovery_suite, executor_suite,
        lifecycle_suite, minter_suite, telemetry_suite, transport_suite,
    },
    executor::{Capabilities, Executor},
    minter::Minter,
    placement::{Capacity, Discovery, Lifecycle},
    telemetry::TelemetrySink,
    transport::Transport,
    types::HostId,
};

/// A fresh timeout future for `channel_backend_suite`'s stream-wait steps (its
/// own runtime's sleep, per the suite's runtime-agnostic contract).
fn deadline() -> tokio::time::Sleep {
    tokio::time::sleep(std::time::Duration::from_secs(2))
}

/// Run every seam's own contract suite against the given per-seam factories.
/// Returns the first violation.
///
/// Generic rather than fixed to one profile: the all-local MVP's real choices
/// are one call site (see `tests/acceptance.rs`), and a deliberately broken
/// factory for a single seam is another — both go through the same gate, so a
/// broken swap is caught the same way whether that seam's current slot is a
/// real impl or still a placeholder.
///
/// # Errors
///
/// Returns [`ContractViolation`] naming the seam and the specific rule an impl
/// failed.
#[expect(
    clippy::too_many_arguments,
    reason = "one factory per seam (spec §6's nine), the gate for the whole profile in one call; splitting it would \
              just move the same nine-seam coupling into a builder with its own nine setters"
)]
pub async fn validate_profile<CA, M, CB, T, E, D, CP, L, TS>(
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
    telemetry_enabled: impl Fn() -> TS,
    telemetry_disabled: impl Fn() -> TS,
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
    telemetry_suite(telemetry_enabled, telemetry_disabled, telemetry_captured).await?;
    Ok(())
}
