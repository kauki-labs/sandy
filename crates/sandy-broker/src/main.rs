//! `sandy-broker`: the broker HTTP API binary (#591).

use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::PathBuf, process::ExitCode};

use clap::Parser;
use sandy_broker::{BrokerConfig, Client, serve};

/// The broker HTTP API tier over sandyd.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// sandyd's control socket.
    #[arg(long)]
    control_socket: PathBuf,
    /// Directory for the 0600 job-owner table.
    #[arg(long)]
    state_dir: PathBuf,
    /// Listen address. Loopback only.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: SocketAddr,
    /// JSON array of clients: id, token_sha256, max_isolation_class, roots. Must be mode 0600.
    #[arg(long)]
    clients_file: PathBuf,
}

fn load_clients(path: &std::path::Path) -> Result<Vec<Client>, String> {
    let mode = std::fs::metadata(path)
        .map_err(|e| format!("clients file {}: {e}", path.display()))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "clients file {} is mode {:o}; it must not be readable by group or others",
            path.display(),
            mode & 0o777
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("clients file {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("clients file {}: {e}", path.display()))
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();
    let clients = match load_clients(&args.clients_file) {
        Ok(clients) => clients,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let running = serve(BrokerConfig {
        control_socket: args.control_socket,
        state_dir: args.state_dir,
        bind: args.bind,
        clients,
    })
    .await;
    let mut running = match running {
        Ok(running) => running,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(addr = %running.addr, "broker listening");
    tokio::select! {
        () = running.wait() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    ExitCode::SUCCESS
}
