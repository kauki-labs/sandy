//! `sandy-host-executor`: the M2 remote executor binary (#269, #263, #288).
//!
//! Resolves its config from `SANDY_HOST_EXECUTOR_ORCHESTRATOR`/
//! `SANDY_HOST_EXECUTOR_ID`/`SANDY_AGENT_PATH`, dials the orchestrator, probes
//! and declares this host's real capabilities via `Register`, then handles
//! `Dispatch` messages sequentially (decision 14) until the connection closes
//! or `SIGTERM`/`SIGINT` arrives. No in-process reconnect loop: stage 1 has
//! no re-registration machinery (decision 12), so a disconnected or refused
//! host-executor simply exits non-zero and leaves restarting it to its
//! supervisor (the nix service, tracked separately, #287).

use sandy_conn::TcpKeepalive;
use sandy_host_executor::{
    build_rev::{log_startup, resolve_rev, version_line, wants_version},
    capability::{detect_register_capabilities, detect_vm_capability},
    client_config::{ExecutorConfig, parse_executor_config},
    dispatch::{Dispatched, handle_dispatch},
    run::{
        DispatchLoopExit, REGISTER_RESPONSE_TIMEOUT, failure_result_message, outcome_result_message_with_outputs,
        register, run_dispatch_loop,
    },
};
use sandy_impls_local::SystemdRunContainment;

const BIN: &str = env!("CARGO_PKG_NAME");
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main]
async fn main() {
    // Set by nix at build time (flake `shortRev`/`dirtyShortRev`); unset under `cargo run`.
    let rev = resolve_rev(option_env!("SANDY_BUILD_REV"));
    if wants_version(std::env::args().skip(1)) {
        println!("{}", version_line(BIN, VERSION, rev));
        return;
    }

    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();
    log_startup(BIN, VERSION, rev);

    let config = match resolve_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("sandy-host-executor: {e}");
            std::process::exit(1);
        }
    };

    // A crash or a kill skips the drop of a job's staging roots: remove the ones whose process is gone (#763).
    let swept = sandy_host_executor::staging_sweep::sweep_stale_roots(&std::env::temp_dir());
    if swept > 0 {
        tracing::info!(swept, "removed stale staging roots left by a process that is gone");
    }

    let capabilities = match detect_register_capabilities() {
        Ok(capabilities) => capabilities,
        Err(e) => {
            tracing::error!(error = %e, "cannot declare any capability; refusing to register");
            std::process::exit(1);
        }
    };

    let identity = match sandy_conn::TlsIdentity::load_or_generate(&config.tls_identity_dir) {
        Ok(identity) => std::sync::Arc::new(identity),
        Err(e) => {
            tracing::error!(error = %e, dir = %config.tls_identity_dir.display(), "could not load or generate this host's mesh TLS identity");
            std::process::exit(1);
        }
    };

    let mut conn = match sandy_conn::connect_tls(
        config.orchestrator,
        &identity,
        config.orchestrator_fingerprint,
        Some(TcpKeepalive::HALF_OPEN_DETECTION),
    )
    .await
    {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!(error = %e, orchestrator = %config.orchestrator, "could not dial the orchestrator");
            std::process::exit(1);
        }
    };

    if let Err(e) = register(&mut conn, &config.host_id, capabilities, REGISTER_RESPONSE_TIMEOUT).await {
        tracing::error!(error = %e, host_id = %config.host_id, "registration failed");
        std::process::exit(1);
    }
    tracing::info!(host_id = %config.host_id, orchestrator = %config.orchestrator, "registered with the orchestrator");

    let rt = tokio::runtime::Handle::current();
    let agent_path = config.agent_path;
    let mesh_tls = sandy_fabric_local::mesh_link::MeshTlsIdentity {
        identity,
        orchestrator_fingerprint: config.orchestrator_fingerprint,
    };
    let exit = run_dispatch_loop(
        &mut conn,
        move |dispatch, control| {
            let rt = rt.clone();
            let agent_path = agent_path.clone();
            let mesh_tls = mesh_tls.clone();
            async move {
                let job_id = dispatch.job_id.clone();
                tracing::info!(job_id, "running a dispatch");
                let result = tokio::task::spawn_blocking(move || {
                    let containment = Box::new(SystemdRunContainment::detect());
                    // Freshly re-probed per dispatch, same discipline as
                    // `containment` above (#332 — never trust this host's
                    // earlier `Register` capability declaration alone).
                    let vm_available = detect_vm_capability();
                    handle_dispatch(&dispatch, containment, agent_path, rt, vm_available, control, mesh_tls)
                })
                .await;
                // Report the outcome back to the orchestrator over the same
                // management connection (#292): the loop writes the returned
                // message on `conn`, so a finished job's result reaches the
                // orchestrator instead of being logged and forgotten here.
                let message = match result {
                    // Never log `outcome.console`: it carries up to 64 KiB of
                    // the job's own stdout/stderr, meant to flow to the
                    // orchestrator in this result message (and on to the result
                    // envelope's `logs.tail`), not into this host's own
                    // logs/journald. The other fields are safe to log.
                    Ok(Ok(Dispatched {
                        outcome,
                        outputs_follow,
                    })) => {
                        tracing::info!(
                            job_id,
                            booted = outcome.booted,
                            guest_exit = outcome.guest_exit,
                            timed_out = outcome.timed_out,
                            transport_error = outcome.transport_error.as_deref(),
                            outputs_follow,
                            "dispatch finished"
                        );
                        outcome_result_message_with_outputs(job_id, outcome, outputs_follow)
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(job_id, error = %e, "dispatch refused or failed");
                        e.result_message(job_id)
                    }
                    Err(e) => {
                        tracing::error!(job_id, error = %e, "the dispatch task panicked");
                        failure_result_message(job_id, format!("the dispatch task failed: {e}"))
                    }
                };
                Some(message)
            }
        },
        shutdown_signal(),
    )
    .await;

    // A requested shutdown (SIGTERM/SIGINT) exits 0; anything else means the
    // connection died out from under this process — exit non-zero so the
    // supervisor restarts it, matching stage 1's "no in-process reconnect,
    // the supervisor owns that" design (decision 12). Returning unconditionally
    // here would make a disconnected host-executor exit 0, silently defeating
    // that design (CodeRabbit finding on #294).
    match exit {
        DispatchLoopExit::Shutdown => {}
        DispatchLoopExit::Closed => {
            tracing::error!("the orchestrator closed the connection; exiting for the supervisor to restart");
            std::process::exit(1);
        }
        DispatchLoopExit::Faulted(reason) => {
            tracing::error!(reason, "the connection faulted; exiting for the supervisor to restart");
            std::process::exit(1);
        }
    }
}

/// `SANDY_HOST_EXECUTOR_ORCHESTRATOR`/`SANDY_HOST_EXECUTOR_ID`/`SANDY_AGENT_PATH`/
/// `SANDY_HOST_EXECUTOR_ORCHESTRATOR_FINGERPRINT`/`SANDY_HOST_EXECUTOR_TLS_IDENTITY_DIR`,
/// the only place `main` reads the real process environment — everything
/// downstream takes the already-parsed [`ExecutorConfig`].
fn resolve_config() -> Result<ExecutorConfig, sandy_host_executor::client_config::ExecutorConfigError> {
    parse_executor_config(
        std::env::var("SANDY_HOST_EXECUTOR_ORCHESTRATOR").ok().as_deref(),
        std::env::var("SANDY_HOST_EXECUTOR_ID").ok().as_deref(),
        std::env::var("SANDY_AGENT_PATH").ok().as_deref(),
        std::env::var("SANDY_HOST_EXECUTOR_ORCHESTRATOR_FINGERPRINT")
            .ok()
            .as_deref(),
        std::env::var("SANDY_HOST_EXECUTOR_TLS_IDENTITY_DIR").ok().as_deref(),
    )
}

/// Wait for `SIGTERM` or `SIGINT` (Ctrl-C); whichever arrives first resolves.
/// Mirrors `sandyd::main`'s own helper exactly — small enough, and local
/// enough to each binary's own shutdown wiring, that sharing it across crates
/// would cost more (a new shared dependency) than it saves.
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
                tracing::error!(error = %e, "could not install the SIGTERM handler; only SIGINT will stop this process");
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
