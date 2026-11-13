//! `sandy doctor`'s check of the two-process setup (promote-and-remove prep, #483): `sandyd` answers on its control
//! socket and at least one host-executor is registered with it.
//!
//! The check is a library function, not yet a step of `sandy doctor`: the direct verbs need no daemon until they are
//! removed, so doctor refuses on a missing daemon only from the promotion on.

use std::{path::Path, time::Duration};

use sandy_control_proto::HostSummary;

use crate::doctor::DoctorResult;

/// Ask the `sandyd` on `socket` for its connected host-executors, within `bound` for the whole exchange.
///
/// # Errors
///
/// A message naming what failed: the socket could not be connected, the daemon did not answer within `bound`, it
/// answered with an error, or it answered something other than a host list.
pub async fn list_hosts(socket: &Path, bound: Duration) -> Result<Vec<HostSummary>, String> {
    let _ = (socket, bound);
    Ok(Vec::new())
}

/// The doctor verdict for the daemon check: ok with the executors listed, or a refusal (exit `2`, invalid environment)
/// that names the fix. `socket` is only named in the messages.
#[must_use]
pub fn daemon_check_result(socket: &Path, hosts: Result<Vec<HostSummary>, String>) -> DoctorResult {
    let _ = (socket, hosts);
    DoctorResult {
        exit_code: 0,
        message: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use sandy_control_proto::IsolationClass;

    use super::*;

    fn host(id: &str, kinds: &[&str], classes: &[IsolationClass], arch: &str) -> HostSummary {
        HostSummary {
            host_id: id.to_owned(),
            sandbox_kinds: kinds.iter().map(|k| (*k).to_owned()).collect(),
            isolation_classes: classes.iter().map(|c| i32::from(*c)).collect(),
            arch: arch.to_owned(),
        }
    }

    /// An unreachable daemon refuses with exit 2, naming the socket, the cause and the fix.
    #[test]
    fn an_unreachable_daemon_is_refused_naming_the_socket_and_the_fix() {
        let result = daemon_check_result(
            Path::new("/run/sandyd.sock"),
            Err("could not connect: No such file or directory".to_owned()),
        );
        assert_eq!(result.exit_code, 2, "{}", result.message);
        assert!(result.message.contains("/run/sandyd.sock"), "{}", result.message);
        assert!(result.message.contains("No such file"), "{}", result.message);
        assert!(result.message.contains("start `sandyd`"), "{}", result.message);
    }

    /// A daemon with no registered executor is up but cannot place anything: refused, naming the executor to start.
    #[test]
    fn a_daemon_with_no_executor_is_refused_naming_the_executor() {
        let result = daemon_check_result(Path::new("/run/sandyd.sock"), Ok(Vec::new()));
        assert_eq!(result.exit_code, 2, "{}", result.message);
        assert!(result.message.contains("no executor"), "{}", result.message);
        assert!(result.message.contains("sandy-host-executor"), "{}", result.message);
    }

    /// With executors registered the check passes and lists each one with what it declared.
    #[test]
    fn registered_executors_pass_and_are_listed() {
        let hosts = vec![
            host(
                "mac",
                &["vm"],
                &[IsolationClass::Trusted, IsolationClass::Untrusted],
                "aarch64",
            ),
            host("linux", &["process", "vm"], &[IsolationClass::Trusted], "x86_64"),
        ];
        let result = daemon_check_result(Path::new("/run/sandyd.sock"), Ok(hosts));
        assert_eq!(result.exit_code, 0, "{}", result.message);
        assert!(result.message.contains("2 executors"), "{}", result.message);
        assert!(
            result.message.contains("mac (vm; trusted, untrusted; aarch64)"),
            "{}",
            result.message
        );
        assert!(
            result.message.contains("linux (process, vm; trusted; x86_64)"),
            "{}",
            result.message
        );
    }
}
