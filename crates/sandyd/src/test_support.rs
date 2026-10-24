//! Shared `#[cfg(test)]` helpers for the tracing-capture leak-regression
//! tests in [`crate::mesh_accept`] and [`crate::handler`] (#159's INV-1
//! addendum: a captured-output proof that no log line or error message
//! carries a raw link token, not just that a hand-written `Debug` impl
//! redacts it).

#![cfg(test)]

use std::sync::{Arc, Mutex, PoisonError};

/// A `Vec<u8>`-backed `tracing_subscriber` writer shared with the test, so a
/// subscriber installed for one scope can be inspected afterward. Mirrors
/// `sandy-cli`'s `tests/cli_jobs.rs::SharedBuf`.
#[derive(Clone, Default)]
pub(crate) struct SharedBuf(Arc<Mutex<Vec<u8>>>);

impl SharedBuf {
    pub(crate) fn contents(&self) -> anyhow::Result<String> {
        let bytes = self.0.lock().unwrap_or_else(PoisonError::into_inner).clone();
        anyhow::Context::context(String::from_utf8(bytes), "captured log is utf8")
    }
}

impl std::io::Write for SharedBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedBuf {
    type Writer = SharedBuf;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}
