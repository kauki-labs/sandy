//! Library surface of the `sandy` CLI.
//!
//! The binary (`src/main.rs`) is a thin argv shell over these modules. They are
//! exposed as a library target so the job-op logic (`plan`, `supervisor`) can be
//! exercised directly from integration tests with a [`sandy::FakeBackend`] and a
//! real [`sandy::Journal`], without booting a hypervisor.

pub mod doctor;
pub mod plan;
pub mod supervisor;
