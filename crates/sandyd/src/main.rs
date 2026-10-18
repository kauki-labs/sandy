//! `sandyd`: the control-plane daemon binary (#212, B1 skeleton).
//!
//! Binds a UDS listener, serves one [`sandyd::serve_connection`] task per
//! accepted connection against a shared, sqlite-backed [`sandyd::store::JobStore`],
//! and shuts down on `SIGTERM`/`SIGINT`: stops accepting new connections and
//! waits (briefly, bounded) for in-flight ones to finish before exiting.

use std::{os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};

use sandy_conn::{ConnAddr, Listener as MeshListener};
use sandyd::{
    dispatch::JobRegistry,
    host_registry::{ExecutorAllowlist, HostRegistry},
    mesh_config::{parse_mesh_allowlist, parse_mesh_listen_addr},
    store::JobStore,
};
use tokio::net::UnixListener;

/// How long graceful shutdown waits for in-flight connections to finish on
/// their own before the process exits anyway. A control-plane request is
/// expected to be fast (it only touches the state store, no dispatch yet);
/// this is generous for that, not a promise to wait indefinitely for a client
/// that never closes its end.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// The starting delay an accept loop waits after a failed `accept()` before
/// trying again, doubling (capped at [`ACCEPT_ERROR_BACKOFF_MAX`]) on each
/// consecutive failure and resetting the moment `accept()` succeeds again. A
/// persistent resource error (e.g. the process is out of file descriptors)
/// would otherwise log and retry at this fixed fast cadence indefinitely,
/// burning CPU and flooding the log faster than an operator could react.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// The ceiling [`ACCEPT_ERROR_BACKOFF`]'s exponential growth never exceeds —
/// a resource error that lasts long enough to hit this is already a serious,
/// slow-moving incident; there's no benefit to backing off further than this.
const ACCEPT_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(5);

/// Capped exponential backoff for repeated `accept()` failures, shared by
/// every accept loop in this binary so they back off identically. Doubles on
/// each [`AcceptBackoff::wait_and_grow`], resets to [`ACCEPT_ERROR_BACKOFF`]
/// on [`AcceptBackoff::reset`] (call it after a successful `accept()`).
struct AcceptBackoff(Duration);

impl AcceptBackoff {
    fn new() -> Self {
        Self(ACCEPT_ERROR_BACKOFF)
    }

    /// Sleep for the current delay, then double it (capped).
    async fn wait_and_grow(&mut self) {
        tokio::time::sleep(self.0).await;
        self.0 = (self.0 * 2).min(ACCEPT_ERROR_BACKOFF_MAX);
    }

    /// Reset to the starting delay — call after a successful `accept()` so a
    /// transient blip doesn't leave the loop backed off far longer than the
    /// failure that caused it.
    fn reset(&mut self) {
        self.0 = ACCEPT_ERROR_BACKOFF;
    }
}

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

    let registry = match JobRegistry::new() {
        Ok(registry) => Arc::new(registry),
        Err(e) => {
            tracing::error!(error = %e, "could not create the job registry's capability authority");
            std::process::exit(1);
        }
    };

    // One shutdown signal, registered exactly once, shared with the mesh
    // task below via a `watch` channel: `shutdown_signal()` only resolves on
    // the first SIGTERM/SIGINT it observes after being polled, so two
    // independent calls (one here, one in the spawned mesh task) can each
    // miss a signal that arrives in the gap between their registrations —
    // tokio does not replay a signal to a listener that starts listening
    // after it fired. Broadcasting one fire-once event instead means every
    // consumer, however many ever exist, observes the same occurrence.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    // The mesh management-channel listener (#291): unset by default, so
    // sandyd stays local-only unless an operator explicitly configures M2
    // cross-machine dispatch. A configured listen address with an empty
    // allowlist is refused outright at startup, not silently bound — a
    // listener nobody can ever pass is a forgotten config line, not a
    // deliberate "allow no one" policy. Runs as its own task (not folded
    // into the daemon's main accept loop below) since it has its own
    // independent connection set and no shared state with the UDS
    // control-socket path beyond the process itself — but joined at
    // shutdown below, not fire-and-forgotten, so its own graceful drain
    // gets a real window to run.
    let mesh_task = match setup_mesh_listener().await {
        Ok(Some(mesh)) => Some(tokio::spawn(run_mesh_accept_loop(mesh, shutdown_rx.clone()))),
        Ok(None) => None,
        Err(e) => {
            tracing::error!(error = %e, "could not set up the mesh management-channel listener");
            std::process::exit(1);
        }
    };

    let mut connections = tokio::task::JoinSet::new();
    let mut backoff = AcceptBackoff::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        backoff.reset();
                        let store = Arc::clone(&store);
                        let registry = Arc::clone(&registry);
                        connections.spawn(sandyd::serve_connection(stream, store, registry));
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to accept a connection");
                        backoff.wait_and_grow().await;
                    }
                }
            }
            // Reap finished connections as they complete, not only at
            // shutdown: `JoinSet` keeps a completed task's slot until
            // `join_next` retrieves it, so without this branch every served
            // connection would accumulate for the daemon's whole lifetime.
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            _ = shutdown_rx.changed() => {
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

    // Join the mesh listener's own task so its shutdown drain (bounded by
    // its own SHUTDOWN_GRACE, started by the same shutdown signal) gets a
    // real window to run — a fire-and-forget spawn would let the runtime
    // drop it mid-drain the moment `main` returns, defeating the point of
    // coordinating the shutdown at all.
    if let Some(mesh_task) = mesh_task {
        if let Err(e) = mesh_task.await {
            tracing::warn!(error = %e, "the mesh listener's task panicked during shutdown");
        }
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

/// A bound mesh management-channel listener (#291), ready for
/// [`run_mesh_accept_loop`], plus the allowlist every accepted connection
/// authenticates against.
struct MeshSetup {
    listener: MeshListener,
    allowlist: Arc<ExecutorAllowlist>,
}

/// Resolve and bind the mesh management-channel listener from
/// `$SANDY_MESH_LISTEN`/`$SANDY_MESH_ALLOWLIST`. `Ok(None)` if
/// `$SANDY_MESH_LISTEN` is unset — `sandyd` stays local-only, the default.
///
/// # Errors
/// An env var fails to parse, the configured allowlist is empty (a listener
/// nobody could ever pass), or the bind itself fails.
async fn setup_mesh_listener() -> std::io::Result<Option<MeshSetup>> {
    let addr =
        parse_mesh_listen_addr(std::env::var("SANDY_MESH_LISTEN").ok().as_deref()).map_err(std::io::Error::other)?;
    let Some(addr) = addr else { return Ok(None) };

    let allowlist =
        parse_mesh_allowlist(std::env::var("SANDY_MESH_ALLOWLIST").ok().as_deref()).map_err(std::io::Error::other)?;
    if allowlist.is_empty() {
        return Err(std::io::Error::other(
            "SANDY_MESH_LISTEN is set but SANDY_MESH_ALLOWLIST is empty or unset; a listener nobody can ever pass is \
             a misconfiguration, not a deliberate allow-no-one policy",
        ));
    }

    let listener = sandy_conn::listen(&ConnAddr::Tcp(addr))
        .await
        .map_err(std::io::Error::other)?;
    tracing::info!(addr = %addr, "sandyd mesh management-channel listener bound");
    Ok(Some(MeshSetup {
        listener,
        allowlist: Arc::new(allowlist),
    }))
}

/// Accept host-client connections on `mesh.listener` until shutdown, serving
/// each with [`sandyd::host_conn::serve_host_client`] against one shared
/// [`HostRegistry`] for this listener's whole lifetime. Mirrors `main`'s own
/// UDS accept loop shape exactly (reap-as-you-go via `JoinSet`, exponential
/// backoff on a failed `accept()`, stop accepting on shutdown then drain
/// in-flight connections within [`SHUTDOWN_GRACE`]) — runs as its own
/// spawned task since it shares no state with the control-socket path beyond
/// the process, but shuts down in step with it via `shutdown_rx`, the same
/// shared signal `main` forwards from its own single `shutdown_signal()`
/// registration (never a second independent one here — a signal arriving in
/// the gap between two separate registrations would never reach the later
/// one, since tokio does not replay a signal to a listener that starts
/// listening after it fired).
async fn run_mesh_accept_loop(mesh: MeshSetup, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    let MeshSetup { listener, allowlist } = mesh;
    let host_registry = Arc::new(HostRegistry::default());
    let mut connections = tokio::task::JoinSet::new();
    let mut backoff = AcceptBackoff::new();

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((conn, peer)) => {
                        backoff.reset();
                        let allowlist = Arc::clone(&allowlist);
                        let host_registry = Arc::clone(&host_registry);
                        connections.spawn(async move {
                            sandyd::host_conn::serve_host_client(conn, peer, &allowlist, &host_registry).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to accept a mesh connection");
                        backoff.wait_and_grow().await;
                    }
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            _ = shutdown_rx.changed() => {
                tracing::info!("shutdown signal received; mesh listener no longer accepting new connections");
                break;
            }
        }
    }

    drop(listener); // stop accepting; existing host-client connections keep running

    if tokio::time::timeout(SHUTDOWN_GRACE, async {
        while connections.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tracing::warn!(
            remaining = connections.len(),
            "mesh listener's shutdown grace period elapsed with connections still in flight; exiting anyway"
        );
    }
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

    /// Regression (CodeRabbit, #293): a fixed retry delay on a persistent
    /// accept() failure logs and retries at a constant fast cadence
    /// indefinitely. The delay must double on each consecutive failure,
    /// capped, and reset the moment a success is reported. Drives the real
    /// `wait_and_grow`/`reset` methods over a paused virtual clock, not a
    /// test that pokes the field directly.
    #[tokio::test(start_paused = true)]
    async fn accept_backoff_doubles_caps_and_resets() {
        let mut backoff = AcceptBackoff::new();
        assert_eq!(backoff.0, ACCEPT_ERROR_BACKOFF);

        let mut previous = backoff.0;
        for _ in 0..10 {
            backoff.wait_and_grow().await;
            assert!(backoff.0 >= previous, "backoff must never shrink while growing");
            assert!(
                backoff.0 <= ACCEPT_ERROR_BACKOFF_MAX,
                "backoff must never exceed the cap"
            );
            previous = backoff.0;
        }
        assert_eq!(
            backoff.0, ACCEPT_ERROR_BACKOFF_MAX,
            "repeated growth must reach the cap, not stop short of it"
        );

        backoff.reset();
        assert_eq!(
            backoff.0, ACCEPT_ERROR_BACKOFF,
            "reset must return to the starting delay, not stay backed off"
        );
    }

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
