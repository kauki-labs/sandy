//! The `sandy-mcp` binary: an MCP server on stdio over the sandyd broker API.

use std::path::PathBuf;

use clap::Parser;
use sandy_mcp::{Api, Server, check_base_url, serve_stdio};

/// MCP stdio server for the sandyd broker API.
#[derive(Parser)]
struct Args {
    /// Base URL of the broker API.
    #[arg(long, default_value = "http://127.0.0.1:8787")]
    api_url: String,
    /// File holding the API credential. Read from a file, never from argv or env.
    #[arg(long)]
    credential_file: PathBuf,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    check_base_url(&args.api_url)?;
    let credential = std::fs::read_to_string(&args.credential_file)
        .map_err(|e| format!("cannot read {}: {e}", args.credential_file.display()))?;
    let server = Server::new(Api::new(&args.api_url, credential.trim()));
    serve_stdio(&server).await?;
    Ok(())
}
