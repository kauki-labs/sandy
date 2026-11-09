//! `sandyd`: the control-plane daemon binary (#212, B1 skeleton).
//!
//! Binds a UDS listener, serves one [`sandyd::serve_connection`] task per
//! accepted connection against a shared, sqlite-backed [`sandyd::store::JobStore`],
//! and shuts down on `SIGTERM`/`SIGINT`: stops accepting new connections and
//! waits (briefly, bounded) for in-flight ones to finish before exiting.

use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::PathBuf, sync::Arc, time::Duration};

use sandy_conn::{Listener as MeshListener, TlsIdentity};
use sandyd::{
    build_rev::{log_startup, resolve_rev, version_line, wants_version},
    credential::{JobCredentials, TrustRootResolver},
    dispatch::JobRegistry,
    environment_backend::{self, BackendSettings},
    environment_driver::EnvironmentDriver,
    environment_store::{EnvironmentStore, RetentionPolicy},
    gate_spawn,
    host_registry::{ExecutorAllowlist, HostRegistry},
    mesh_config::{parse_mesh_allowlist, parse_mesh_listen_addr},
    spawn_gated_accept,
    store::{CancelOutcome, JobStore},
};
use tokio::net::UnixListener;

const BIN: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

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

/// The largest number of control-socket connections this daemon serves
/// concurrently (CF-L-1): past this, the accept loop stops accepting new
/// connections until one of the existing ones finishes, rather than spawning
/// an unbounded `JoinSet` entry per accept. Generous for a local, 0700-socket
/// control plane with one or a handful of operators/sub-agents at a time —
/// not a tuned production capacity figure.
const MAX_CONCURRENT_CONNECTIONS: usize = 256;

/// The largest number of mesh host-executor connections this daemon serves
/// concurrently (CF-L-1, #289 item 3): past this, the mesh management-channel
/// accept loop stops accepting new connections until one of the existing
/// ones finishes. Mirrors [`MAX_CONCURRENT_CONNECTIONS`]'s reasoning for the
/// UDS control socket — this loop had no cap at all before, so an unbounded
/// number of pre-auth connections from the mesh could spawn an unbounded
/// number of tasks and exhaust file descriptors.
const MAX_CONCURRENT_MESH_CONNECTIONS: usize = 256;

/// How long an accepted TCP connection on a mesh listener has to complete its
/// TLS handshake before it's dropped (decision 20's Consequences section:
/// "the implementation PR needs a handshake timeout on `listen_tls`'s accept
/// path... without one, a connection that completes TCP accept but never
/// finishes (or never starts) the TLS handshake occupies an accept slot
/// indefinitely"). Generous for a real mesh-local peer, short enough that a
/// stalled/adversarial one doesn't tie up a connection slot for long.
const MESH_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    // Set by nix at build time (flake `shortRev`/`dirtyShortRev`); unset under `cargo run`.
    let rev = resolve_rev(option_env!("SANDY_BUILD_REV"));
    if wants_version(std::env::args().skip(1)) {
        println!("{}", version_line(BIN, VERSION, rev));
        return;
    }

    if let Some(code) = run_operator_command() {
        std::process::exit(code);
    }
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    log_startup(BIN, VERSION, rev);

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

    let max_jobs = match max_jobs() {
        Ok(max_jobs) => max_jobs,
        Err(e) => {
            tracing::error!(error = %e, "SANDY_MAX_JOBS is not a valid non-negative integer");
            std::process::exit(1);
        }
    };

    let store = match JobStore::open(&db_path) {
        Ok(store) => Arc::new(store.with_max_rows(max_jobs)),
        Err(e) => {
            tracing::error!(error = %e, db = %db_path.display(), "could not open the job store");
            std::process::exit(1);
        }
    };

    let max_environments = match max_environments() {
        Ok(max_environments) => max_environments,
        Err(e) => {
            tracing::error!(error = %e, "SANDY_MAX_ENVIRONMENTS is not a valid non-negative integer");
            std::process::exit(1);
        }
    };

    // The environment audit log (#596) sits beside the database, named after its full file name so
    // `dev.db` and `dev.sqlite` never share a log, unless `SANDY_AUDIT_LOG` names it. A daemon that
    // cannot open it does not start: an unaudited operation never runs.
    let audit_path = std::env::var_os("SANDY_AUDIT_LOG").map_or_else(
        || {
            let mut name = db_path.file_name().unwrap_or_default().to_os_string();
            name.push(".audit.jsonl");
            db_path.with_file_name(name)
        },
        PathBuf::from,
    );
    let audit = match sandyd::audit::AuditLog::open(&audit_path) {
        Ok(audit) => Arc::new(audit),
        Err(e) => {
            tracing::error!(error = %e, "could not open the environment audit log");
            std::process::exit(1);
        }
    };
    if sandyd::audit::same_file(&audit_path, &db_path) {
        tracing::error!(path = %audit_path.display(), "SANDY_AUDIT_LOG names the database file; refusing to start");
        std::process::exit(1);
    }

    // The identity-profile registry (#704) is read once; a file that cannot be trusted stops the daemon. Unset
    // means no registry, and every environment create is then refused.
    let profiles = match std::env::var_os("SANDY_PROFILES") {
        None => None,
        Some(path) => match sandyd::profiles::load(std::path::Path::new(&path)) {
            Ok(profiles) => Some(Arc::new(profiles)),
            Err(e) => {
                tracing::error!(error = %e, "could not load SANDY_PROFILES; refusing to start");
                std::process::exit(1);
            }
        },
    };

    // Same file as the job store: one durable, 0600 database for the daemon.
    let environments = match EnvironmentStore::open(&db_path) {
        Ok(environments) => {
            let environments = environments.with_max_rows(max_environments).with_audit(audit);
            Arc::new(match profiles {
                Some(profiles) => environments.with_profiles(profiles),
                None => environments,
            })
        }
        Err(e) => {
            tracing::error!(error = %e, db = %db_path.display(), "could not open the environment store");
            std::process::exit(1);
        }
    };

    // `var(..).ok()` would read a non-UTF-8 value as unset and silently take the default.
    let retention_setting = |name: &str| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not valid UTF-8")),
    };
    let retention = match RetentionPolicy::from_env(retention_setting) {
        Ok(retention) => retention,
        Err(e) => {
            tracing::error!(error = %e, "invalid environment retention setting");
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

    // `sandyd cancel` locks the store, not the socket, so hold the store's lock too (the same file as
    // the socket's under the default paths, which is then already held).
    let _store_lock = if sandyd::operator::daemon_lock_path(&db_path) == socket_path.with_extension("lock") {
        None
    } else {
        match sandyd::operator::lock_store(&db_path) {
            Ok(lock) => Some(lock),
            Err(e) => {
                tracing::error!(error = %e, db = %db_path.display(), "could not lock the job store");
                std::process::exit(1);
            }
        }
    };
    tracing::info!(socket = %socket_path.display(), db = %db_path.display(), "sandyd listening");

    // The interactive attach data plane (#327): a sibling UDS socket, kept
    // SEPARATE from the control socket above — `docs/decisions/sandyd.md`
    // §1 keeps the control RPC pure request/response, so a client redeems
    // `Attach`'s cap here, not by streaming over the control connection
    // itself. Same bind discipline (flock, 0600, umask) as the control
    // socket, via the same `bind_unix_listener`.
    let attach_socket_path = sandy_control_proto::attach_socket_path(&socket_path);
    let (attach_listener, _attach_lock) = match bind_unix_listener(&attach_socket_path) {
        Ok(bound) => bound,
        Err(e) => {
            tracing::error!(error = %e, socket = %attach_socket_path.display(), "could not bind the attach data-plane socket");
            std::process::exit(1);
        }
    };
    tracing::info!(socket = %attach_socket_path.display(), "sandyd attach data plane listening");

    // #481: a Submit naming `credential` mints from this host's trust roots,
    // the ones `sandy cred github register` wrote.
    let registry = match JobRegistry::new() {
        Ok(registry) => Arc::new(registry.with_credentials(JobCredentials::new(Arc::new(TrustRootResolver)))),
        Err(e) => {
            tracing::error!(error = %e, "could not create the job registry's capability authority");
            std::process::exit(1);
        }
    };

    // One HostRegistry (#298), shared between the mesh management-channel
    // loop below (which registers connected host-executors), the
    // control-socket path (which reads it for placement on Submit), and the
    // attach-relay accept loop just below (which notifies a job's placed
    // host of an attach-state transition, #340) — not separate registries,
    // or a host registered on the mesh listener would be invisible to the
    // other two. Created here, ahead of its original spot further down,
    // specifically so the attach-relay loop can take a reference to it.
    let host_registry = Arc::new(HostRegistry::default());

    // Spawned plainly, like the mesh agent-link listener below: no
    // graceful-shutdown support of its own yet (same #289-class follow-up),
    // so it's abruptly cancelled on process exit — an in-flight attach
    // session is cheap to lose, unlike a registered host-executor's live
    // dispatch channel.
    {
        let registry = Arc::clone(&registry);
        let host_registry = Arc::clone(&host_registry);
        tokio::spawn(async move {
            sandyd::attach_relay::serve_attach_accept_loop(&attach_listener, &registry, &host_registry).await;
        });
    }

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

    // Peek both mesh listen addresses, unparsed error aside, before touching
    // the allowlist or the TLS identity at all: `sandyd` with neither env var
    // set must stay exactly as local-only as before decision 20 — no key
    // file written, no SANDY_MESH_ALLOWLIST format enforced — since binding
    // nothing is "exactly today's behavior" per `mesh_config`'s own doc.
    // Each `setup_*` function below re-parses its own address (cheap, pure);
    // this is only a peek to decide whether decision 20's machinery runs at
    // all, never the value either listener actually binds to.
    let any_mesh_listener_configured =
        std::env::var("SANDY_MESH_LISTEN").is_ok() || std::env::var("SANDY_MESH_AGENT_LINK_LISTEN").is_ok();

    // Decision 20: one pinned-fingerprint allowlist and one sandyd mesh TLS
    // identity, shared by BOTH mesh listeners below — an operator provisions
    // and pins exactly one fingerprint for this daemon, not a different one
    // per listener. Parsed/loaded once, ahead of either listener's own setup,
    // and ONLY if a mesh listener is actually configured (see above).
    let mesh_allowlist = if any_mesh_listener_configured {
        match parse_mesh_allowlist(std::env::var("SANDY_MESH_ALLOWLIST").ok().as_deref()) {
            Ok(allowlist) => Arc::new(allowlist),
            Err(e) => {
                tracing::error!(error = %e, "could not parse SANDY_MESH_ALLOWLIST");
                std::process::exit(1);
            }
        }
    } else {
        Arc::new(ExecutorAllowlist::default())
    };

    // The mesh management-channel listener (#291): unset by default, so
    // sandyd stays local-only unless an operator explicitly configures M2
    // cross-machine dispatch. A configured listen address with an empty
    // allowlist is refused outright at startup, not silently bound — a
    // listener nobody can ever pass is a forgotten config line, not a
    // deliberate "allow no one" policy. Runs as its own task (not folded
    // into the daemon's main accept loop below) since it has its own
    // independent connection set and no shared state with the UDS
    // control-socket path beyond `host_registry` and the process itself —
    // but joined at shutdown below, not fire-and-forgotten, so its own
    // graceful drain gets a real window to run.
    let mesh_task = if any_mesh_listener_configured {
        let management_identity = match load_mesh_tls_identity().await {
            Ok(identity) => identity,
            Err(e) => {
                tracing::error!(error = %e, "could not load or generate sandyd's mesh TLS identity");
                std::process::exit(1);
            }
        };
        match setup_mesh_listener(management_identity, Arc::clone(&mesh_allowlist)).await {
            Ok(Some(mesh)) => Some(tokio::spawn(run_mesh_accept_loop(
                mesh,
                Arc::clone(&host_registry),
                Arc::clone(&store),
                Arc::clone(&registry),
                shutdown_rx.clone(),
            ))),
            Ok(None) => None,
            Err(e) => {
                tracing::error!(error = %e, "could not set up the mesh management-channel listener");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // The mesh agent-link accept listener (#279/#298): where a dispatched
    // job's executor dials back to forward its agent link (decision 6).
    // Unset by default, like the management listener above — no address
    // configured means no remote placement is even reachable, so `handle`
    // never picks a remote host regardless of what's registered (see
    // `forward_back_addr` below). Spawned plainly, not joined at shutdown:
    // `sandyd::mesh_accept::serve_mesh_accept_loop` has no graceful-shutdown
    // support of its own yet (#289-class follow-up), so this loop is
    // abruptly cancelled on process exit like every other unhandled task —
    // an accepted-but-not-yet-authenticated agent-link connection is cheap
    // to lose, unlike a registered host-executor's live dispatch channel.
    //
    // Loaded a SECOND time (not cloned): `TlsIdentity` holds no `Clone`
    // impl, and `listen_tls` takes it by value since each listener owns its
    // own `rustls::ServerConfig`. `load_or_generate` reads the same
    // already-persisted files the management listener's own load just
    // wrote/read, so this is the same identity (same fingerprint), not a
    // fresh one.
    let forward_back_addr = if any_mesh_listener_configured {
        let agent_link_identity = match load_mesh_tls_identity().await {
            Ok(identity) => identity,
            Err(e) => {
                tracing::error!(error = %e, "could not load sandyd's mesh TLS identity for the agent-link listener");
                std::process::exit(1);
            }
        };
        match setup_mesh_agent_link_listener(agent_link_identity, mesh_allowlist.fingerprints()).await {
            Ok(Some((listener, addr))) => {
                let listener = Arc::new(listener);
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    sandyd::mesh_accept::serve_mesh_accept_loop(listener, &registry).await;
                });
                Some(addr)
            }
            Ok(None) => None,
            Err(e) => {
                tracing::error!(error = %e, "could not set up the mesh agent-link accept listener");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // The launch driver runs only when a backend is configured (#587). It starts after every lock and
    // bind above: the backend sweeps stale environment directories, which a second daemon that lost
    // a lock must never do.
    // Started only after every lock and bind above, so a second daemon on the same store, which
    // fails to bind, never sweeps with its own settings. Independent of the launch driver: a
    // deleted row is collected even with no backend configured.
    let _environment_retention = tokio::spawn(sandyd::environment::run_retention(
        Arc::clone(&environments),
        retention,
        sandyd::environment::RETENTION_INTERVAL,
        sandyd::environment_store::now_unix,
    ));

    let _environment_driver = start_environment_driver(&environments);

    let mut connections = tokio::task::JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        tokio::select! {
            (permit, accepted) = gate_spawn(&connection_semaphore, listener.accept()) => {
                let Ok(permit) = permit else {
                    // Never closed by this program (see gate_spawn's doc);
                    // handled rather than panicked, so a connection-accepting
                    // loop never crashes the daemon over an invariant that
                    // should be unreachable in practice.
                    tracing::error!("connection semaphore closed unexpectedly; no longer accepting new connections");
                    break;
                };
                match accepted {
                    Ok((stream, _addr)) => {
                        backoff.reset();
                        if let Err(refused) = sandyd::peer_cred::require_same_user(&stream) {
                            tracing::warn!(%refused, "refusing a control connection");
                            continue;
                        }
                        let store = Arc::clone(&store);
                        let environments = Arc::clone(&environments);
                        let registry = Arc::clone(&registry);
                        let host_registry = Arc::clone(&host_registry);
                        connections.spawn(async move {
                            let _permit = permit; // held for the connection's lifetime, released on drop
                            sandyd::serve_connection(stream, store, environments, registry, host_registry, forward_back_addr).await;
                        });
                    }
                    Err(e) => {
                        // `permit` drops here, releasing it immediately: this
                        // connection was never served.
                        tracing::warn!(error = %e, "failed to accept a connection");
                        // Raced against shutdown, not a plain await: at the
                        // backoff cap (5s) an unraced sleep would make
                        // shutdown wait up to 5s just to re-poll this select!,
                        // on top of the mesh task's own drain main then waits
                        // on — compounding delay for no reason once a
                        // shutdown signal has already arrived.
                        tokio::select! {
                            () = backoff.wait_and_grow() => {}
                            _ = shutdown_rx.changed() => {
                                tracing::info!("shutdown signal received during accept backoff; no longer accepting new connections");
                                break;
                            }
                        }
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
    let _ = std::fs::remove_file(&attach_socket_path);

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
    if let Some(mesh_task) = mesh_task
        && let Err(e) = mesh_task.await
    {
        tracing::warn!(error = %e, "the mesh listener's task panicked during shutdown");
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

/// `$SANDY_MESH_TLS_IDENTITY_DIR` if set, else `<runtime_dir>/mesh-tls`
/// (decision 20's deferred key-provisioning UX: a flag-driven keypair,
/// persisted so its [`sandy_conn::Fingerprint`] stays stable across
/// restarts, mirroring `socket_path`/`db_path`'s own optional-with-a-default
/// pattern).
fn mesh_tls_identity_dir() -> std::io::Result<PathBuf> {
    match std::env::var_os("SANDY_MESH_TLS_IDENTITY_DIR") {
        Some(path) => Ok(PathBuf::from(path)),
        None => Ok(ensure_runtime_dir()?.join("mesh-tls")),
    }
}

/// Load or generate sandyd's own mesh mutual-TLS identity — ONE identity
/// shared by both the management-channel listener and the agent-link accept
/// listener (decision 20's "scope: both mesh listeners" — an operator pins
/// one fingerprint for sandyd, not two).
async fn load_mesh_tls_identity() -> std::io::Result<TlsIdentity> {
    let dir = mesh_tls_identity_dir()?;
    tokio::task::spawn_blocking(move || TlsIdentity::load_or_generate(&dir))
        .await
        .map_err(std::io::Error::other)?
        .map_err(std::io::Error::other)
}

/// Resolve and bind the mesh management-channel listener from
/// `$SANDY_MESH_LISTEN`/`$SANDY_MESH_ALLOWLIST`, mutual-TLS-wrapped
/// (decision 20) using `identity` and the allowlist's pinned fingerprints.
/// `Ok(None)` if `$SANDY_MESH_LISTEN` is unset — `sandyd` stays local-only,
/// the default.
///
/// # Errors
/// An env var fails to parse, the configured allowlist is empty (a listener
/// nobody could ever pass), or the bind itself fails.
async fn setup_mesh_listener(
    identity: TlsIdentity,
    allowlist: Arc<ExecutorAllowlist>,
) -> std::io::Result<Option<MeshSetup>> {
    let addr =
        parse_mesh_listen_addr(std::env::var("SANDY_MESH_LISTEN").ok().as_deref()).map_err(std::io::Error::other)?;
    let Some(addr) = addr else { return Ok(None) };

    if allowlist.is_empty() {
        return Err(std::io::Error::other(
            "SANDY_MESH_LISTEN is set but SANDY_MESH_ALLOWLIST is empty or unset; a listener nobody can ever pass is \
             a misconfiguration, not a deliberate allow-no-one policy",
        ));
    }

    let listener = sandy_conn::listen_tls(
        addr,
        identity,
        allowlist.fingerprints(),
        MESH_TLS_HANDSHAKE_TIMEOUT,
        Some(sandy_conn::TcpKeepalive::HALF_OPEN_DETECTION),
    )
    .await
    .map_err(std::io::Error::other)?;
    tracing::info!(addr = %addr, "sandyd mesh management-channel listener bound (mutual TLS)");
    Ok(Some(MeshSetup { listener, allowlist }))
}

/// Resolve and bind the mesh agent-link accept listener (#279/#298) from
/// `$SANDY_MESH_AGENT_LINK_LISTEN` — the address a dispatched job's executor
/// dials back to forward its agent link (decision 6) — mutual-TLS-wrapped
/// (decision 20) using `identity` and `allowed` (the SAME pinned-fingerprint
/// set the management channel enforces: any executor dialing back must
/// present a key already pinned to register at all). `Ok(None)` if unset: no
/// remote placement is reachable in that case, regardless of what hosts are
/// registered on the management channel, since there is nowhere valid to
/// tell an executor to dial back to.
///
/// Keepalive-bound (#289 item 1, same `HALF_OPEN_DETECTION` profile as the
/// management-channel listener above): without it, a vanished executor
/// mid-run leaves `serve_agent_link` on this listener's accepted stream
/// waiting forever for a frame that will never arrive, an INV-11 violation
/// (a job's exit must come from the agent's own report, never a hang).
///
/// # Errors
/// The env var fails to parse (including naming an unspecified address, D5),
/// `allowed` is empty, or the bind itself fails.
async fn setup_mesh_agent_link_listener(
    identity: TlsIdentity,
    allowed: std::collections::HashSet<sandy_conn::Fingerprint>,
) -> std::io::Result<Option<(MeshListener, SocketAddr)>> {
    let addr = parse_mesh_listen_addr(std::env::var("SANDY_MESH_AGENT_LINK_LISTEN").ok().as_deref())
        .map_err(std::io::Error::other)?;
    let Some(addr) = addr else { return Ok(None) };

    let listener = sandy_conn::listen_tls(
        addr,
        identity,
        allowed,
        MESH_TLS_HANDSHAKE_TIMEOUT,
        Some(sandy_conn::TcpKeepalive::HALF_OPEN_DETECTION),
    )
    .await
    .map_err(std::io::Error::other)?;
    tracing::info!(addr = %addr, "sandyd mesh agent-link accept listener bound (mutual TLS)");
    Ok(Some((listener, addr)))
}

/// Accept host-executor connections on `mesh.listener` until shutdown, serving
/// each with [`sandyd::host_conn::serve_host_executor`] against `host_registry`
/// — the same registry the control-socket/handler path reads for placement
/// (#298), not a loop-local one: a host registered here must be visible to a
/// `Submit` landing on the UDS socket, or placement could never see it.
/// Mirrors `main`'s own UDS accept loop shape exactly (reap-as-you-go via
/// `JoinSet`, exponential backoff on a failed `accept()`, stop accepting on
/// shutdown then drain in-flight connections within [`SHUTDOWN_GRACE`]) —
/// runs as its own spawned task since it shares no state with the
/// control-socket path beyond `host_registry` and the process, but shuts
/// down in step with it via `shutdown_rx`, the same shared signal `main`
/// forwards from its own single `shutdown_signal()` registration (never a
/// second independent one here — a signal arriving in the gap between two
/// separate registrations would never reach the later one, since tokio does
/// not replay a signal to a listener that starts listening after it fired).
async fn run_mesh_accept_loop(
    mesh: MeshSetup,
    host_registry: Arc<HostRegistry>,
    store: Arc<JobStore>,
    job_registry: Arc<JobRegistry>,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let MeshSetup { listener, allowlist } = mesh;
    let listener = Arc::new(listener);
    let mut connections = tokio::task::JoinSet::new();
    let mut backoff = AcceptBackoff::new();
    let connection_semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_MESH_CONNECTIONS));

    // Decision 20's accept+handshake hazard: the raw TCP accept is spawned
    // via `spawn_gated_accept` into its own task, never polled directly
    // inside the `select!` below — a sibling branch (`connections.join_next()`)
    // resolving first would otherwise drop an in-progress accept. The SAME
    // `JoinHandle` is re-polled (`&mut accept_task`) across loop iterations
    // rather than re-created each time, so losing a `select!` race just means
    // the next iteration observes the same still-running task, never a fresh
    // one that silently abandons the old. The TLS handshake itself runs
    // inside the per-connection task spawned below, not inside `accept_task`,
    // so one peer's handshake (up to the handshake timeout) never delays the
    // next raw accept from starting.
    let mut accept_task = spawn_gated_accept(Arc::clone(&connection_semaphore), Arc::clone(&listener));

    loop {
        tokio::select! {
            result = &mut accept_task => {
                let Ok((permit, accepted)) = result else {
                    // The spawned accept task itself panicked (not expected
                    // in practice — `Listener::accept`/`gate_spawn` don't
                    // panic): nothing left to re-arm against, so this loop
                    // ends rather than spin re-spawning a task that just
                    // panicked.
                    tracing::error!("the mesh accept task panicked; no longer accepting new connections");
                    break;
                };
                // Re-arm immediately, before handling this result, so the
                // loop always has a pending accept — never a gap where a
                // slow connection handler delays the next accept call.
                accept_task = spawn_gated_accept(Arc::clone(&connection_semaphore), Arc::clone(&listener));
                let Ok(permit) = permit else {
                    // Never closed by this program (see gate_spawn's doc);
                    // handled rather than panicked, per house style.
                    tracing::error!("mesh connection semaphore closed unexpectedly; no longer accepting new connections");
                    break;
                };
                match accepted {
                    Ok(accepted_stream) => {
                        backoff.reset();
                        let allowlist = Arc::clone(&allowlist);
                        let host_registry = Arc::clone(&host_registry);
                        let store = Arc::clone(&store);
                        let job_registry = Arc::clone(&job_registry);
                        connections.spawn(async move {
                            let _permit = permit; // held for the connection's lifetime, released on drop
                            match accepted_stream.handshake().await {
                                Ok((conn, peer)) => {
                                    sandyd::host_conn::serve_host_executor(
                                        conn,
                                        peer,
                                        &allowlist,
                                        &host_registry,
                                        &store,
                                        &job_registry,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    // A per-peer TLS handshake failure (wrong
                                    // pinned key, a port scanner, a plaintext
                                    // dialer, a handshake that never
                                    // finishes) — confined to this one
                                    // connection's own task, never the shared
                                    // accept loop, so it cannot throttle any
                                    // OTHER peer's registration the way
                                    // backing off the whole listener would.
                                    tracing::warn!(error = %e, "mesh connection handshake failed");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        // `permit` drops here, releasing it immediately: this
                        // connection was never served. A real accept(2)
                        // fault (accept_raw's only error) — a per-peer
                        // handshake failure is handled inside the
                        // per-connection task above instead.
                        tracing::warn!(error = %e, "failed to accept a mesh connection");
                        // Raced against shutdown — see the UDS loop's own
                        // identical comment in main() for why an unraced
                        // sleep here would compound shutdown latency.
                        tokio::select! {
                            () = backoff.wait_and_grow() => {}
                            _ = shutdown_rx.changed() => {
                                tracing::info!("shutdown signal received during accept backoff; mesh listener no longer accepting new connections");
                                break;
                            }
                        }
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

    // The pending accept task holds its own `Arc<Listener>` clone, so
    // dropping `listener` here does not actually stop it from accepting —
    // abort it explicitly, mirroring `relay_dispatches`'s own
    // abort-then-await discipline for a task whose owned resource must stop
    // before this function proceeds.
    accept_task.abort();
    let _ = accept_task.await;
    drop(listener); // stop accepting; existing host-executor connections keep running

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

/// `sandyd cancel <job-id>` (#545): the operator's offline cancel. `None` when there is no argument, so the
/// daemon starts as usual; otherwise the exit code.
fn run_operator_command() -> Option<i32> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => return None,
        Some("cancel") => {}
        // `--version` was handled before this; any other argument is a typo, not a request to start.
        Some(other) => {
            eprintln!("sandyd: unknown argument `{other}`; usage: sandyd [--version | cancel <job-id>]");
            return Some(2);
        }
    }
    let (Some(job_id), None) = (args.next(), args.next()) else {
        eprintln!("usage: sandyd cancel <job-id>");
        return Some(2);
    };
    let db = match db_path() {
        Ok(db) => db,
        Err(e) => {
            eprintln!("sandyd cancel: could not resolve the store path: {e}");
            return Some(1);
        }
    };
    Some(match sandyd::operator::cancel_offline(&db, &job_id) {
        Ok(CancelOutcome::Cancelled) => {
            println!("cancelled {job_id}");
            0
        }
        Ok(CancelOutcome::NotFound) => {
            eprintln!("sandyd cancel: no job {job_id}");
            1
        }
        Ok(CancelOutcome::AlreadyTerminal(status)) => {
            eprintln!("sandyd cancel: job {job_id} is already {status:?}");
            1
        }
        Err(e) => {
            eprintln!("sandyd cancel: {e}");
            1
        }
    })
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

/// Parse `$SANDY_MAX_JOBS` (CF-M-2): the row cap [`JobStore::with_max_rows`]
/// enforces. `Ok(None)` if unset — uncapped, today's unchanged behavior.
///
/// # Errors
/// The env var is set but is not a valid non-negative integer.
fn max_jobs() -> Result<Option<usize>, std::num::ParseIntError> {
    std::env::var("SANDY_MAX_JOBS").ok().map(|v| v.parse()).transpose()
}

/// Start the environment launch driver if `SANDY_ENV_BACKEND` selects a backend
/// (#587). Off by default: environments then stay `Provisioning`. An invalid
/// setting stops the daemon, like every other startup setting.
fn start_environment_driver(environments: &Arc<EnvironmentStore>) -> Option<tokio::task::JoinHandle<()>> {
    // `var(..).ok()` would read a non-UTF-8 value as unset, and a lossy copy would alter a path.
    if let Some((name, _)) = std::env::vars_os()
        .filter(|(k, _)| k.to_string_lossy().starts_with("SANDY_ENV_"))
        .find(|(_, v)| v.to_str().is_none())
    {
        tracing::error!(name = %name.to_string_lossy(), "environment backend setting is not valid UTF-8");
        std::process::exit(1);
    }
    let config = match environment_backend::from_env(
        |name| std::env::var(name).ok(),
        || {
            ensure_runtime_dir()
                .map(|dir| dir.join("environments"))
                .map_err(|e| e.to_string())
        },
    ) {
        Ok(Some(config)) => config,
        Ok(None) => {
            tracing::info!(
                "environment launch driver off: SANDY_ENV_BACKEND is not set, environments stay Provisioning"
            );
            return None;
        }
        Err(e) => {
            tracing::error!(error = %e, "invalid environment backend settings");
            std::process::exit(1);
        }
    };
    let backend: Arc<dyn sandy_api::environment::EnvironmentBackend + Send + Sync> = match config.backend {
        BackendSettings::Process(process) => {
            tracing::warn!(
                "SANDY_ENV_BACKEND=process-insecure: environments run as host processes as this user with NO \
                 isolation; for trusted, local development only"
            );
            // Set before the driver starts: from here a create needs a TRUSTED submitter.
            environments.require_trusted_submitter();
            match sandy_environment::ProcessEnvironmentBackend::new(process) {
                Ok(backend) => Arc::new(backend),
                Err(e) => {
                    tracing::error!(error = %e, "could not start the process environment backend");
                    std::process::exit(1);
                }
            }
        }
        BackendSettings::VmQemu(vm) => vm_environment_backend(&vm),
        BackendSettings::VmVfkit(vm) => vfkit_environment_backend(&vm),
    };
    let driver = Arc::new(EnvironmentDriver::new(Arc::clone(environments), backend, config.driver));
    Some(tokio::spawn(driver.run(environment_backend::DRIVER_INTERVAL)))
}

/// The qemu microVM environment backend. Only Linux can run one, and `from_env` refuses `vm-qemu` elsewhere.
#[cfg(target_os = "linux")]
fn vm_environment_backend(
    vm: &environment_backend::VmSettings,
) -> Arc<dyn sandy_api::environment::EnvironmentBackend + Send + Sync> {
    Arc::new(sandyd::environment_vm::backend(vm, tokio::runtime::Handle::current()))
}

#[cfg(not(target_os = "linux"))]
fn vm_environment_backend(
    _vm: &environment_backend::VmSettings,
) -> Arc<dyn sandy_api::environment::EnvironmentBackend + Send + Sync> {
    tracing::error!("SANDY_ENV_BACKEND=vm-qemu needs Linux");
    std::process::exit(1);
}

/// The vfkit microVM environment backend. Only macOS can run one, and `from_env` refuses `vm-vfkit` elsewhere.
#[cfg(target_os = "macos")]
fn vfkit_environment_backend(
    vm: &environment_backend::VmSettings,
) -> Arc<dyn sandy_api::environment::EnvironmentBackend + Send + Sync> {
    match sandyd::environment_vm::vfkit_backend(vm, tokio::runtime::Handle::current()) {
        Ok(backend) => Arc::new(backend),
        Err(e) => {
            tracing::error!(error = %e, "could not start the vfkit environment backend");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn vfkit_environment_backend(
    _vm: &environment_backend::VmSettings,
) -> Arc<dyn sandy_api::environment::EnvironmentBackend + Send + Sync> {
    tracing::error!("SANDY_ENV_BACKEND=vm-vfkit needs macOS");
    std::process::exit(1);
}

/// Parse `$SANDY_MAX_ENVIRONMENTS`: the row cap [`EnvironmentStore::with_max_rows`]
/// enforces. `Ok(None)` if unset, which is uncapped.
///
/// # Errors
/// The env var is set but is not a valid non-negative integer.
fn max_environments() -> Result<Option<usize>, std::num::ParseIntError> {
    std::env::var("SANDY_MAX_ENVIRONMENTS")
        .ok()
        .map(|v| v.parse())
        .transpose()
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
    use anyhow::Context;

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

    /// CF-L-1: once every permit is held, a further `gate_spawn` call blocks
    /// — it does not accept past the configured cap — and resolves again the
    /// moment a held permit is released. Drives the real `gate_spawn` (not a
    /// bare `Semaphore` in isolation), with real short timeouts rather than a
    /// paused virtual clock: AGENTS.md flags `start_paused` paired with real
    /// I/O as flaky, and `tokio::time::timeout` racing a real `.await` here is
    /// exactly that shape.
    #[tokio::test]
    async fn gate_spawn_blocks_once_the_semaphore_is_exhausted() -> anyhow::Result<()> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(2));

        let (permit1, ()) = gate_spawn(&semaphore, async {}).await;
        let permit1 = permit1.context("permit1")?;
        let (permit2, ()) = gate_spawn(&semaphore, async {}).await;
        let permit2 = permit2.context("permit2")?;

        assert!(
            tokio::time::timeout(Duration::from_millis(50), gate_spawn(&semaphore, async {}))
                .await
                .is_err(),
            "a third gate_spawn must block while both permits are held"
        );

        drop(permit1);
        let (permit3, ()) = tokio::time::timeout(Duration::from_secs(5), gate_spawn(&semaphore, async {}))
            .await
            .context("gate_spawn must resolve once a permit is released")?;
        let _permit3 = permit3.context("permit3")?;

        drop(permit2);
        Ok(())
    }
}
