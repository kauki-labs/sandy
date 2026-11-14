//! `live-vfkit-guest`: boots the service guest on vfkit with the service relay exposed at a host socket (#590, KSB4).
//!
//! The vfkit half of the guest service bridge's live gate. It runs one job through `VfkitBackend` with
//! `with_service_socket`, so vfkit's `connect` device listens at the given path, and holds the guest for the job's
//! lifetime. `scripts/dev/live-vfkit-bridge.sh` runs the sandy-conn live test against that socket meanwhile.
//!
//! Usage: `SANDY_LIVE=1 live-vfkit-guest <service-socket> <guest-script>`. The guest script runs as
//! `bash /run/sandy/inputs/guest.sh`. Prints the run outcome and exits nonzero unless the job exited zero.
//! Refuses off a live host (INV-S9): a live gate is never counted green from a skip.

use std::{path::PathBuf, process::ExitCode};

use sandy_api::backend::{Grants, Input, RunControl, RunSpec, VirtualizationBackend};
use sandy_backend::VfkitBackend;
use sandy_cli::live_target::{guest_flake, require_live};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("live-vfkit-guest: FAIL: {msg}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    require_live().map_err(|e| e.to_string())?;
    let mut args = std::env::args().skip(1);
    let (Some(socket), Some(script)) = (args.next().map(PathBuf::from), args.next().map(PathBuf::from)) else {
        return Err("usage: live-vfkit-guest <service-socket> <guest-script>".to_string());
    };
    let vfkit_bin = std::env::var("SANDY_VFKIT_BIN").unwrap_or_else(|_| "vfkit".to_string());
    let backend = VfkitBackend::new(vfkit_bin).with_service_socket(socket);
    let template = format!("{}#topologies.aarch64-linux.vfkit-service", guest_flake().display());
    let command = ["bash".to_string(), "/run/sandy/inputs/guest.sh".to_string()];
    let inputs = [Input {
        host: script,
        name: "guest.sh".to_string(),
        guest_path: None,
    }];
    let grants = Grants {
        secrets: false,
        agent: false,
        shares: true,
    };
    let control = RunControl::with_timeout_secs(900);
    let spec = RunSpec {
        template: &template,
        command: &command,
        inputs: &inputs,
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 900,
        control: &control,
        grants: &grants,
        outcome_file: None,
        secret_dir: None,
        egress: None,
        digests: false,
    };
    let outcome = backend.run(&spec).map_err(|e| format!("run: {e}"))?;
    println!("live-vfkit-guest: outcome {outcome:?}");
    if outcome.guest_exit == Some(0) {
        Ok(())
    } else {
        Err(format!("the guest job did not exit zero: {outcome:?}"))
    }
}
