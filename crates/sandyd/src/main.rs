//! `sandyd`: the control-plane daemon binary (#212, B1 skeleton).
//!
//! Binds a UDS listener, serves one [`sandyd::serve_connection`] task per
//! accepted connection against a shared, sqlite-backed [`sandyd::store::JobStore`],
//! and shuts down on `SIGTERM`/`SIGINT`: stops accepting new connections and
//! waits (briefly, bounded) for in-flight ones to finish before exiting.

use std::{path::PathBuf, sync::Arc, time::Duration};

use sandyd::store::JobStore;
use tokio::net::UnixListener;

/// How long graceful shutdown waits for in-flight connections to finish on
/// their own before the process exits anyway. A control-plane request is
/// expected to be fast (it only touches the state store, no dispatch yet);
/// this is generous for that, not a promise to wait indefinitely for a client
/// that never closes its end.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() {
    let socket_path = socket_path();
    let db_path = db_path();

    let store = match JobStore::open(&db_path) {
        Ok(store) => Arc::new(store),
        Err(e) => {
            tracing::error!(error = %e, db = %db_path.display(), "could not open the job store");
            std::process::exit(1);
        }
    };

    let listener = match bind_unix_listener(&socket_path) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(error = %e, socket = %socket_path.display(), "could not bind the control socket");
            std::process::exit(1);
        }
    };
    tracing::info!(socket = %socket_path.display(), db = %db_path.display(), "sandyd listening");

    let mut connections = tokio::task::JoinSet::new();
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        let store = Arc::clone(&store);
                        connections.spawn(sandyd::serve_connection(stream, store));
                    }
                    Err(e) => tracing::warn!(error = %e, "failed to accept a connection"),
                }
            }
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
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("install SIGTERM handler");
        sigterm.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}

/// Bind the control socket at `path`. A stale socket file left by a daemon
/// that didn't shut down cleanly is removed and rebind is retried ONCE, but
/// only after confirming nothing is actually listening on it (an attempt to
/// connect fails) — never blindly unlinking a path another live daemon might
/// hold.
fn bind_unix_listener(path: &std::path::Path) -> std::io::Result<UnixListener> {
    match UnixListener::bind(path) {
        Ok(listener) => Ok(listener),
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("another sandyd is already listening on {}", path.display()),
                ));
            }
            // Nothing answered: a stale file from an unclean shutdown.
            std::fs::remove_file(path)?;
            UnixListener::bind(path)
        }
        Err(e) => Err(e),
    }
}

/// The control socket path: `$SANDY_SOCK`, or `sandyd.sock` under the OS temp
/// dir. A fixed, documented env var rather than a config file — the skeleton
/// has nothing else to configure yet.
fn socket_path() -> PathBuf {
    std::env::var_os("SANDY_SOCK")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("sandyd.sock"))
}

/// The job store's sqlite file path: `$SANDY_DB`, or `sandyd.db` under the OS
/// temp dir.
fn db_path() -> PathBuf {
    std::env::var_os("SANDY_DB")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("sandyd.db"))
}
