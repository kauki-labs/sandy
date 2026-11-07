//! `EnvironmentBackend` implementations for `sandyd` (#587).
//!
//! Today: [`ProcessEnvironmentBackend`], an opt-in backend that runs a service
//! (for example `t3 serve`) as a host process. It gives NO isolation: the
//! service runs as the daemon's user with the daemon's filesystem. It exists so
//! the whole chain (T3, MCP, broker, `sandyd`, driver, backend) can run before
//! the VM backend lands, and must stay off by default.
//!
//! [`VmEnvironmentBackend`] is the isolated one: a held agent-mode `VmBackend::run` per environment.

mod connections;
mod lifecycle;
pub mod mesh;
mod process;
mod vm;

pub use lifecycle::{GuardedBackend, RunGuard, RunGuards, guarded};
pub use process::{ProcessConfig, ProcessConfigError, ProcessEnvironmentBackend};
pub use vm::{BackendFactory, HeldBackend, ServiceProbe, StopRequest, VmEnvironmentBackend, VmEnvironmentConfig};
