//! `sandy-host-client`: the M2 remote executor binary (#269, #263, #288).
//!
//! Resolves its config from `SANDY_HOST_CLIENT_ORCHESTRATOR`/
//! `SANDY_HOST_CLIENT_ID`/`SANDY_AGENT_PATH`, dials the orchestrator, probes
//! and declares this host's real capabilities via `Register`, then handles
//! `Dispatch` messages sequentially (decision 14) until the connection closes
//! or `SIGTERM`/`SIGINT` arrives. No in-process reconnect loop: stage 1 has
//! no re-registration machinery (decision 12), so a disconnected or refused
//! host-client simply exits non-zero and leaves restarting it to its
//! supervisor (the nix service, tracked separately, #287).

use sandy_conn::ConnAddr;
use sandy_host_client::{
    capability::detect_register_capabilities,
    client_config::{ClientConfig, parse_client_config},
    dispatch::handle_dispatch,
    run::{register, run_dispatch_loop},
};
use sandy_impls_local::SystemdRunContainment;

#[tokio::main]
async fn main() {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let config = match resolve_config() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("sandy-host-client: {e}");
            std::process::exit(1);
        }
    };

    let capabilities = match detect_register_capabilities() {
        Ok(capabilities) => capabilities,
        Err(e) => {
            tracing::error!(error = %e, "cannot declare any capability; refusing to register");
            std::process::exit(1);
        }
    };

    let mut conn = match sandy_conn::connect(&ConnAddr::Tcp(config.orchestrator)).await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!(error = %e, orchestrator = %config.orchestrator, "could not dial the orchestrator");
            std::process::exit(1);
        }
    };

    if let Err(e) = register(&mut conn, &config.host_id, capabilities).await {
        tracing::error!(error = %e, host_id = %config.host_id, "registration failed");
        std::process::exit(1);
    }
    tracing::info!(host_id = %config.host_id, orchestrator = %config.orchestrator, "registered with the orchestrator");

    let rt = tokio::runtime::Handle::current();
    let agent_path = config.agent_path;
    run_dispatch_loop(
        &mut conn,
        move |dispatch| {
            let rt = rt.clone();
            let agent_path = agent_path.clone();
            async move {
                let job_id = dispatch.job_id.clone();
                tracing::info!(job_id, "running a dispatch");
                let result = tokio::task::spawn_blocking(move || {
                    let containment = Box::new(SystemdRunContainment::detect());
                    handle_dispatch(&dispatch, containment, agent_path, rt)
                })
                .await;
                match result {
                    // Never log `outcome` itself: its `console` field carries
                    // up to 64 KiB of the job's own stdout/stderr, meant to
                    // flow to the result envelope's `logs.tail`, not into this
                    // host's own logs/journald.
                    Ok(Ok(outcome)) => tracing::info!(
                        job_id,
                        booted = outcome.booted,
                        guest_exit = outcome.guest_exit,
                        timed_out = outcome.timed_out,
                        transport_error = outcome.transport_error.as_deref(),
                        "dispatch finished"
                    ),
                    Ok(Err(e)) => tracing::warn!(job_id, error = %e, "dispatch refused or failed"),
                    Err(e) => tracing::error!(job_id, error = %e, "the dispatch task panicked"),
                }
            }
        },
        shutdown_signal(),
    )
    .await;
}

/// `SANDY_HOST_CLIENT_ORCHESTRATOR`/`SANDY_HOST_CLIENT_ID`/`SANDY_AGENT_PATH`,
/// the only place `main` reads the real process environment — everything
/// downstream takes the already-parsed [`ClientConfig`].
fn resolve_config() -> Result<ClientConfig, sandy_host_client::client_config::ClientConfigError> {
    parse_client_config(
        std::env::var("SANDY_HOST_CLIENT_ORCHESTRATOR").ok().as_deref(),
        std::env::var("SANDY_HOST_CLIENT_ID").ok().as_deref(),
        std::env::var("SANDY_AGENT_PATH").ok().as_deref(),
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
