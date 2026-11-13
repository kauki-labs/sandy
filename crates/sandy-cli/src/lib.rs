//! Library surface of the `sandy` CLI.
//!
//! The binary (`src/main.rs`) is a thin argv shell over these modules. They are
//! exposed as a library target so the job-op logic (`plan`, `supervisor`) can be
//! exercised directly from integration tests with a `sandy_test_support::FakeBackend`
//! and a real [`sandy::Journal`], without booting a hypervisor.
//!
//! Output goes through one typed pipeline (#512): [`output::Render`] +
//! [`output::emit`]/[`output::emit_stream_to`] are the only sanctioned stdout
//! sinks, enforced by denying `print!`/`println!` everywhere else in this
//! crate — a command that prints directly fails clippy, not just review.
#![deny(clippy::print_stdout)]

pub mod app_register;
pub mod attach;
pub mod daemon_check;
pub mod doctor;
pub mod flake_wrap;
// `host_target` moved to `sandy-guest-template` (#332, a pure extraction
// shared with `sandy-host-executor`'s remote VM dispatch); re-exported here
// wholesale so `crate::host_target::host_target()` (doctor.rs, live_target.rs)
// and `sandy_cli::host_target::*` keep resolving unchanged.
pub use sandy_guest_template::host_target;
#[cfg(feature = "live")]
pub mod live_target;
pub mod output;
pub mod plan;
pub mod profiles;
pub mod signals;
pub mod submit;
pub mod supervisor;
pub mod wait;
