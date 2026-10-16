//! Local-first telemetry (spec §3.5): an append-only local log that is off by
//! default, and [`LocalFirst`], which writes that log before forwarding anywhere.
//!
//! The log needs no network and survives an unreachable orchestrator: a record is
//! durable once `emit` returns. Forwarding (the channel sink, wired with #113) is
//! best effort on top and can never lose a record the log accepted.
//! Content-addressed pull of the log is deferred (spec §7).

use std::path::{Path, PathBuf};

use sandy_fabric::telemetry::{TelemetryError, TelemetryRecord, TelemetrySink};

/// A [`TelemetrySink`] appending one JSON record per line to a local file.
///
/// [`LocalLog::disabled`] (also the [`Default`]) is the off-by-default sink:
/// `emit` is a no-op and no file is created. [`LocalLog::open`] enables it.
#[derive(Debug, Default)]
pub struct LocalLog {
    path: Option<PathBuf>,
}

impl LocalLog {
    /// The disabled sink: records nothing, touches no file.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// An enabled sink appending to `path`, created `0600` on first emit.
    pub fn open(path: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(path.into()),
        }
    }

    /// The log file, if the sink is enabled.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The records in the log, in emit order. A torn last line (a crash mid-write)
    /// is skipped. A disabled sink, or one that has not emitted yet, has none.
    pub fn records(&self) -> Result<Vec<TelemetryRecord>, TelemetryError> {
        Ok(Vec::new())
    }
}

impl TelemetrySink for LocalLog {
    fn enabled(&self) -> bool {
        false
    }

    async fn emit(&self, record: &TelemetryRecord) -> Result<(), TelemetryError> {
        let _ = record;
        Ok(())
    }
}

/// Local-first delivery: every record goes to the local log, then to `forward`.
///
/// `emit` fails only when the local log fails. A forwarding failure (an
/// unreachable orchestrator, a dead channel) is logged and dropped; the record
/// is already durable locally.
#[derive(Debug)]
pub struct LocalFirst<S> {
    local: LocalLog,
    forward: S,
}

impl<S: TelemetrySink> LocalFirst<S> {
    /// Write to `local`, then forward to `forward`.
    pub fn new(local: LocalLog, forward: S) -> Self {
        Self { local, forward }
    }

    /// The local log.
    pub fn local(&self) -> &LocalLog {
        &self.local
    }
}

impl<S: TelemetrySink> TelemetrySink for LocalFirst<S> {
    fn enabled(&self) -> bool {
        false
    }

    async fn emit(&self, record: &TelemetryRecord) -> Result<(), TelemetryError> {
        let _ = (record, &self.forward);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        io::Write,
        os::unix::fs::PermissionsExt,
        sync::{Mutex, PoisonError},
    };

    use anyhow::Context;
    use sandy_fabric::contract::telemetry_suite;

    use super::*;

    fn record(kind: &str) -> TelemetryRecord {
        TelemetryRecord {
            kind: kind.to_owned(),
            fields: BTreeMap::from([("job".to_owned(), "j1".to_owned())]),
        }
    }

    fn captured(log: &LocalLog) -> usize {
        log.records().map_or(usize::MAX, |r| r.len())
    }

    /// A forwarding sink that is always down, or one that keeps what it receives.
    struct Forward {
        down: bool,
        got: Mutex<Vec<TelemetryRecord>>,
    }

    impl Forward {
        fn down() -> Self {
            Self {
                down: true,
                got: Mutex::new(Vec::new()),
            }
        }

        fn up() -> Self {
            Self {
                down: false,
                got: Mutex::new(Vec::new()),
            }
        }

        fn received(&self) -> usize {
            self.got.lock().unwrap_or_else(PoisonError::into_inner).len()
        }
    }

    impl TelemetrySink for Forward {
        fn enabled(&self) -> bool {
            true
        }

        async fn emit(&self, record: &TelemetryRecord) -> Result<(), TelemetryError> {
            if self.down {
                return Err(TelemetryError::Sink("orchestrator unreachable".to_owned()));
            }
            self.got
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(record.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn local_log_satisfies_the_telemetry_contract() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let n = std::sync::atomic::AtomicUsize::new(0);
        let fresh = || {
            let i = n.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            LocalLog::open(dir.path().join(format!("t{i}.jsonl")))
        };
        telemetry_suite(fresh, LocalLog::disabled, captured)
            .await
            .context("telemetry")
    }

    #[tokio::test]
    async fn an_enabled_log_appends_each_record_in_order() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let log = LocalLog::open(dir.path().join("t.jsonl"));
        for kind in ["a", "b", "a"] {
            log.emit(&record(kind)).await?;
        }
        let kinds: Vec<_> = log.records()?.into_iter().map(|r| r.kind).collect();
        anyhow::ensure!(kinds == ["a", "b", "a"], "read back {kinds:?}");
        Ok(())
    }

    #[tokio::test]
    async fn the_log_is_0600_and_survives_reopening() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("t.jsonl");
        LocalLog::open(&path).emit(&record("a")).await?;
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        anyhow::ensure!(mode == 0o600, "log mode {mode:o}");
        let reopened = LocalLog::open(&path);
        reopened.emit(&record("b")).await?;
        anyhow::ensure!(reopened.records()?.len() == 2, "a reopened log lost records");
        Ok(())
    }

    #[tokio::test]
    async fn a_torn_last_line_is_skipped_on_read() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("t.jsonl");
        let log = LocalLog::open(&path);
        log.emit(&record("whole")).await?;
        fs::OpenOptions::new()
            .append(true)
            .open(&path)?
            .write_all(b"{\"kind\":\"tor")?;
        let kinds: Vec<_> = log.records()?.into_iter().map(|r| r.kind).collect();
        anyhow::ensure!(kinds == ["whole"], "read back {kinds:?}");
        Ok(())
    }

    #[tokio::test]
    async fn off_by_default_writes_nothing() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let log = LocalLog::default();
        anyhow::ensure!(!log.enabled() && log.path().is_none(), "the default log is enabled");
        log.emit(&record("a")).await?;
        anyhow::ensure!(fs::read_dir(dir.path())?.count() == 0, "a disabled log wrote a file");
        anyhow::ensure!(log.records()?.is_empty(), "a disabled log kept a record");
        Ok(())
    }

    #[tokio::test]
    async fn a_dead_orchestrator_loses_no_telemetry() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let sink = LocalFirst::new(LocalLog::open(dir.path().join("t.jsonl")), Forward::down());
        for kind in ["a", "b"] {
            sink.emit(&record(kind))
                .await
                .context("a forwarding failure failed the emit")?;
        }
        anyhow::ensure!(sink.local().records()?.len() == 2, "records were lost locally");
        Ok(())
    }

    #[tokio::test]
    async fn local_first_forwards_every_record_it_logs() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let sink = LocalFirst::new(LocalLog::open(dir.path().join("t.jsonl")), Forward::up());
        sink.emit(&record("a")).await?;
        anyhow::ensure!(sink.enabled(), "an enabled local-first sink reports disabled");
        anyhow::ensure!(sink.local().records()?.len() == 1, "not logged locally");
        anyhow::ensure!(sink.forward.received() == 1, "not forwarded");
        Ok(())
    }

    #[tokio::test]
    async fn a_failing_local_log_fails_the_emit_and_forwards_nothing() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        // A directory where the log file should be: the local write cannot succeed.
        let path = dir.path().join("t.jsonl");
        fs::create_dir(&path)?;
        let sink = LocalFirst::new(LocalLog::open(&path), Forward::up());
        anyhow::ensure!(
            sink.emit(&record("a")).await.is_err(),
            "a failed local write was reported as success"
        );
        anyhow::ensure!(
            sink.forward.received() == 0,
            "forwarded a record the local log did not keep"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_disabled_local_first_sink_forwards_nothing() -> anyhow::Result<()> {
        let sink = LocalFirst::new(LocalLog::disabled(), Forward::up());
        sink.emit(&record("a")).await?;
        anyhow::ensure!(!sink.enabled(), "a disabled local-first sink reports enabled");
        anyhow::ensure!(sink.forward.received() == 0, "telemetry left the host while off");
        Ok(())
    }
}
