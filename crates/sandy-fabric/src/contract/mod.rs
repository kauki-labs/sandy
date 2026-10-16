//! The shared seam contract-test harness: one suite per seam that every impl,
//! trivial or real, passes (spec §2).
//!
//! Each `*_suite` is generic over its seam; the caller supplies the impl through a
//! factory (a fresh instance per check) plus whatever the suite cannot derive on
//! its own, such as the capabilities an executor truly has. A suite returns
//! `Err(ContractViolation)` naming the broken rule, so a caller can assert on a
//! violation as well as on a pass. The async suites are runtime-agnostic: the
//! caller drives them on its own runtime.

use crate::{
    capauth::CapAuthority,
    channel_backend::ChannelBackend,
    executor::{Capabilities, Executor},
    minter::Minter,
    placement::{Capacity, Discovery, Lifecycle},
    telemetry::TelemetrySink,
    transport::Transport,
    types::HostId,
};

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod verify;

/// A seam implementation broke its contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{seam} contract violated: {rule}")]
pub struct ContractViolation {
    /// The seam whose contract was broken.
    pub seam: &'static str,
    /// The rule that was broken, and how.
    pub rule: String,
}

/// Run the [`CapAuthority`] contract.
pub fn capauth_suite<A: CapAuthority>(_make: impl Fn() -> A) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`Minter`] contract.
pub fn minter_suite<M: Minter>(_make: impl Fn() -> M) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`ChannelBackend`] contract.
pub async fn channel_backend_suite<B: ChannelBackend>(_make: impl Fn() -> B) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`Transport`] contract.
pub async fn transport_suite<T: Transport>(_make: impl Fn() -> T) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`Executor`] contract.
pub async fn executor_suite<E: Executor>(
    _expected: Capabilities,
    _make: impl Fn() -> E,
) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`Discovery`] contract.
pub async fn discovery_suite<D: Discovery>(_make: impl Fn() -> D) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`Capacity`] contract.
pub async fn capacity_suite<C: Capacity>(_known: HostId, _make: impl Fn() -> C) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`Lifecycle`] contract.
pub async fn lifecycle_suite<L: Lifecycle>(_make: impl Fn() -> L) -> Result<(), ContractViolation> {
    Ok(())
}

/// Run the [`TelemetrySink`] contract.
pub async fn telemetry_suite<S: TelemetrySink>(
    _make_enabled: impl Fn() -> S,
    _make_disabled: impl Fn() -> S,
    _captured: impl Fn(&S) -> usize,
) -> Result<(), ContractViolation> {
    Ok(())
}
