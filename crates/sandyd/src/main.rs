//! `sandyd`: the control-plane daemon binary (#212, B1 skeleton).
//!
//! Binds a UDS listener, serves one [`sandyd::serve_connection`] task per
//! accepted connection against a shared, sqlite-backed [`sandyd::store::JobStore`],
//! and shuts down on `SIGTERM`/`SIGINT`: stops accepting new connections and
//! waits (briefly, bounded) for in-flight ones to finish before exiting.

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};

use sandyd::{dispatch::JobRegistry, store::JobStore};
use tokio::net::UnixListener;

/// How long graceful shutdown waits for in-flight connections to finish on
/// their own before the process exits anyway. A control-plane request is
/// expected to be fast (it only touches the state store, no dispatch yet);
/// this is generous for that, not a promise to wait indefinitely for a client
/// that never closes its end.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How long the accept loop pauses after a failed `accept()` before trying
/// again. A persistent resource error (e.g. the process is out of file
/// descriptors) would otherwise spin this branch in a tight loop, burning
/// CPU and flooding the log faster than an operator could react.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let socket_path = match socket_path() {
        Ok(path) => path,
        Err(e) => {
            tracing::error!(error = %e, "could not resolve the control socket path");
            std::process::exit(1);
        }
    };
    let db_path = match db_path() {
        Ok(path) => path,
        Err(e) => {
            tracing::error!(error = %e, "could not resolve the job store path");
            std::process::exit(1);
        }
    };

    let store = match JobStore::open(&db_path) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            tracing::error!(error = %e, db = %db_path.display(), "could not open the job store");
            std::process::exit(1);
        }
    };

    let (listener, _lock) = match bind_unix_listener(&socket_path) {
        Ok(bound) => bound,
        Err(e) => {
            tracing::error!(error = %e, socket = %socket_path.display(), "could not bind the control socket");
            std::process::exit(1);
        }
    };
    tracing::info!(socket = %socket_path.display(), db = %db_path.display(), "sandyd listening");

    let registry = Arc::new(JobRegistry::default());
    let mut connections = tokio::task::JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let store = Arc::clone(&store);
                        let registry = Arc::clone(&registry);
                        connections.spawn(sandyd::serve_connection(stream, store, registry));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to accept a connection");
                        tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                    }
                }
            }
            // Reap finished connections as they complete, not only at
            // shutdown: `JoinSet` keeps a completed task's slot until
            // `join_next` retrieves it, so without this branch every served
            // connection would accumulate for the daemon's whole lifetime.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            () = &mut shutdown => {
                tracing::info!("shutdown signal received; no longer accepting new connections");
                break;
            }
        }
    }

    drop(listener); // stop accepting; existing connections keep running
    let _ = std::fs::remove_file(&socket_path);

    if tokio::time::timeout(SHUTDOWN_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tracing::warn!(
            remaining = connections.len(),
            "shutdown grace period elapsed with connections still in flight; exiting anyway"
        );
    }
}

/// Wait for `SIGTERM` or `SIGINT` (Ctrl-C); whichever arrives first resolves.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sigterm) => {
                sigterm.recv().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "could not install the SIGTERM handler; only SIGINT will stop sandyd");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Bind the control socket at `path`, `0600`. Returns the listener alongside
/// its lock file, which the caller must keep alive for the daemon's entire
/// run: dropping it early releases the exclusive flock this function takes
/// on `path`'s sibling `.lock` file before touching the socket at all.
///
/// A connect-then-check-then-remove probe (the previous approach here) is a
/// TOCTOU race between two `sandyd` instances starting against the same path
/// at nearly the same instant: both can pass the liveness check before
/// either removes the socket file, so the loser's `remove_file` can unlink
/// the winner's just-bound, live socket out from under it. The flock closes
/// this by construction instead of narrowing it — same
/// WouldBlock-proves-the-owner-is-live pattern as the per-job lockfile
/// (`crates/sandy/src/journal.rs`, INV-3): only the instance that wins the
/// lock may conclude the path is unclaimed, so a leftover socket file is then
/// provably stale, never a race against a live peer. The kernel releases the
/// flock automatically on a crash, so a process that dies without cleaning up
/// never blocks the next one from starting.
fn bind_unix_listener(path: &std::path::Path) -> std::io::Result<(UnixListener, std::fs::File)> {
    let lock_path = path.with_extension("lock");
    let lock_file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)?;
    if let Err(e) = fs2::FileExt::try_lock_exclusive(&lock_file) {
        return Err(if e.kind() == std::io::ErrorKind::WouldBlock {
            std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("another sandyd is already listening on {}", path.display()),
            )
        } else {
            e
        });
    }

    // The lock is ours, so any entry at `path` is provably stale, not a live
    // peer's socket — except we still refuse to touch it if it isn't a
    // socket at all (a misconfigured `SANDY_SOCK` could point at an
    // unrelated file); that is a user error to report, never silently
    // deleted.
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            use std::os::unix::fs::FileTypeExt;
            if !meta.file_type().is_socket() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }

    // Narrow the umask for the bind itself so the socket is never briefly
    // group/world-accessible between creation and the chmod below (the
    // default 0700 runtime dir already keeps this safe; a `SANDY_SOCK`
    // pointed outside it is a trusted deployer override, per house
    // convention, so this is defense in depth, not the only guard).
    let previous_umask = rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o177));
    let bind_result = UnixListener::bind(path);
    rustix::process::umask(previous_umask);
    let listener = bind_result?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, lock_file))
}

/// The control socket path: `$SANDY_SOCK` if set (a deployer's explicit
/// choice, trusted as given — no validation imposed on it), else
/// `sandyd.sock` under [`ensure_runtime_dir`].
fn socket_path() -> std::io::Result<PathBuf> {
    match std::env::var_os("SANDY_SOCK") {
        Some(path) => Ok(PathBuf::from(path)),
        None => Ok(ensure_runtime_dir()?.join("sandyd.sock")),
    }
}

/// The job store's sqlite file path: `$SANDY_DB` if set, else `sandyd.db`
/// under [`ensure_runtime_dir`].
fn db_path() -> std::io::Result<PathBuf> {
    match std::env::var_os("SANDY_DB") {
        Some(path) => Ok(PathBuf::from(path)),
        None => Ok(ensure_runtime_dir()?.join("sandyd.db")),
    }
}

/// A `sandyd`-owned directory to default the control socket and job store
/// into when `$SANDY_SOCK`/`$SANDY_DB` aren't set (CWE-377: a predictable name
/// directly under the shared OS temp dir lets another local user pre-create
/// it, or a symlink at it, ahead of the daemon). Reuses `sandy-fsutil`'s
/// already-validated staging base (CWE-732) as the trusted parent, then opens
/// or creates a `sandyd` subdirectory under it: `0700`, owned by this uid,
/// re-verified (never repaired) on every call, matching the same fail-closed
/// discipline the job-staging path already uses elsewhere in this workspace.
fn ensure_runtime_dir() -> std::io::Result<PathBuf> {
    let base = sandy_fsutil::ensure_sandy_staging_base().map_err(std::io::Error::other)?;
    let owned = sandy_fsutil::OwnedDir::open_or_create(&base.join("sandyd")).map_err(std::io::Error::other)?;
    Ok(owned.path().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (CodeRabbit, #220): the previous connect-then-remove probe
    /// let a second starting instance observe the first as dead and unlink
    /// its live socket out from under it. The flock refuses outright instead.
    #[tokio::test]
    async fn a_second_bind_is_refused_while_the_first_holds_the_lock() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let sock = tmp.path().join("sandyd.sock");

        let (_first_listener, _first_lock) = bind_unix_listener(&sock)?;
        let second = bind_unix_listener(&sock);
        assert!(
            matches!(&second, Err(e) if e.kind() == std::io::ErrorKind::AddrInUse),
            "a second bind while the first lock is held must be refused, got {second:?}"
        );
        Ok(())
    }

    /// A socket left behind by a process that held the lock but never cleaned
    /// up (a crash, or this test's own drop) is reclaimed once that lock is
    /// released, not treated as a live peer forever.
    #[tokio::test]
    async fn a_stale_socket_is_reclaimed_once_its_lock_is_released() -> std::io::Result<()> {
        let tmp = tempfile::tempdir()?;
        let sock = tmp.path().join("sandyd.sock");

        {
            let (_listener, _lock) = bind_unix_listener(&sock)?;
        }
        let (_listener, _lock) = bind_unix_listener(&sock)?;
        Ok(())
    }
}
