//! `sandy-broker`: the broker HTTP API binary (#591).

use std::{net::SocketAddr, os::unix::fs::PermissionsExt, path::PathBuf, process::ExitCode};

use clap::Parser;
use sandy_broker::{BrokerConfig, Client, Tuning, serve_with_tuning};

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

/// Env var: seconds a finished job's output stays readable.
const RETENTION_ENV: &str = "SANDY_BROKER_OUTPUT_RETENTION_SECS";
/// Upper bound for [`RETENTION_ENV`]: output lives in memory, so a longer window is a mistake.
const MAX_RETENTION_SECS: u64 = 7 * 24 * 60 * 60;

fn output_retention() -> Result<std::time::Duration, String> {
    parse_retention(std::env::var(RETENTION_ENV))
}

fn parse_retention(value: Result<String, std::env::VarError>) -> Result<std::time::Duration, String> {
    match value {
        Ok(v) => match v.parse::<u64>() {
            Ok(secs) if secs <= MAX_RETENTION_SECS => Ok(std::time::Duration::from_secs(secs)),
            Ok(_) => Err(format!(
                "{RETENTION_ENV}={v:?}: at most {MAX_RETENTION_SECS} seconds (7 days)"
            )),
            Err(e) => Err(format!("{RETENTION_ENV}={v:?}: {e}")),
        },
        Err(std::env::VarError::NotPresent) => Ok(Tuning::default().output_retention),
        Err(e) => Err(format!("{RETENTION_ENV}: {e}")),
    }
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
    let output_retention = match output_retention() {
        Ok(retention) => retention,
        Err(e) => {
            tracing::error!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let running = serve_with_tuning(
        BrokerConfig {
            control_socket: args.control_socket,
            rpc_deadline: std::time::Duration::from_secs(30),
            state_dir: args.state_dir,
            bind: args.bind,
            clients,
        },
        Tuning {
            output_retention,
            ..Tuning::default()
        },
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_defaults_parses_and_refuses_an_absurd_value() {
        assert_eq!(
            parse_retention(Err(std::env::VarError::NotPresent)),
            Ok(Tuning::default().output_retention)
        );
        assert_eq!(parse_retention(Ok("60".into())), Ok(std::time::Duration::from_secs(60)));
        for bad in ["x", "-1", "0", "18446744073709551615", "604801"] {
            assert!(parse_retention(Ok(bad.into())).is_err(), "{bad} must be refused");
        }
    }
}
