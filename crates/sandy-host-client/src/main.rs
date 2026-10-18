//! `sandy-host-client`: the M2 remote executor binary (#269, #275).
//!
//! Stage 1 only runs capability detection — printing what this host would
//! declare on registration — since the receive-dispatch handler is blocked
//! on #263's `sandy-executor-proto` (sandy-91). Useful standalone today: an
//! operator can run this on a candidate host to check whether it would
//! register as trusted-process-capable before the rest of the pipeline
//! exists.

fn main() {
    match sandy_host_client::capability::detect_register_capabilities() {
        Ok(capabilities) => {
            println!("{capabilities:?}");
        }
        Err(e) => {
            eprintln!("sandy-host-client: cannot declare any capability: {e}");
            std::process::exit(1);
        }
    }
}
