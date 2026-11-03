//! `EnvironmentBackend` implementations for `sandyd` (#587).
//!
//! Today: [`ProcessEnvironmentBackend`], an opt-in backend that runs a service
//! (for example `t3 serve`) as a host process. It gives NO isolation: the
//! service runs as the daemon's user with the daemon's filesystem. It exists so
//! the whole chain (T3, MCP, broker, `sandyd`, driver, backend) can run before
//! the VM backend lands, and must stay off by default.

mod process;

pub use process::{ProcessConfig, ProcessConfigError, ProcessEnvironmentBackend};
