//! Library surface of the `sandy` CLI.
//!
//! The binary (`src/main.rs`) is a thin argv shell over these modules. They are
//! exposed as a library target so the job-op logic (`plan`, `supervisor`) can be
//! exercised directly from integration tests with a `sandy_test_support::FakeBackend`
//! and a real [`sandy::Journal`], without booting a hypervisor.

pub mod app_register;
pub mod attach;
pub mod doctor;
#[cfg(feature = "live")]
pub mod live_target;
pub mod output;
pub mod plan;
pub mod profiles;
pub mod supervisor;
