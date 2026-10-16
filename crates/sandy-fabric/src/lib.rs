//! `sandy-fabric`: the agent-fabric contract (spec: sandy-agent-fabric §2, §5).
//!
//! Traits and types only: the fabric's seams, their data and error types, and a
//! shared contract-test harness. No concrete impls live here; each one (process
//! executor, in-memory backend, local signer, …) is its own block and proves itself
//! against the harness.
//!
//! The I/O seams are async and `Send`, because the fabric is built for
//! store-and-forward over links nobody can assume are live:
//! [`Executor`](executor::Executor), [`ChannelBackend`](channel_backend::ChannelBackend),
//! [`Transport`](transport::Transport), [`Discovery`](placement::Discovery),
//! [`Capacity`](placement::Capacity), [`Lifecycle`](placement::Lifecycle) and
//! [`TelemetrySink`](telemetry::TelemetrySink), plus [`Minter`](minter::Minter),
//! whose controller-transit impl mints over the network.
//! [`CapAuthority`](capauth::CapAuthority) is sync: verify sits on the hot path of
//! every join, post and subscribe, and is pure crypto.
//!
//! The channel itself is not a seam: it is one concrete abstraction layered over
//! [`ChannelBackend`](channel_backend::ChannelBackend), carrying `sandy-proto`'s
//! [`Envelope`](channel_backend::Envelope).
//!
//! With the `contract-tests` feature, [`contract`] exposes one `*_suite` per seam
//! that an impl crate runs its implementation against.

pub mod capauth;
pub mod channel_backend;
pub mod executor;
pub mod minter;
pub mod placement;
pub mod telemetry;
pub mod transport;
pub mod types;

#[cfg(any(test, feature = "contract-tests"))]
pub mod contract;
