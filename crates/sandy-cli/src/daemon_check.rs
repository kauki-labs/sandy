//! `sandy doctor`'s check of the two-process setup (promote-and-remove prep, #483): `sandyd` answers on its control
//! socket and at least one host-executor is registered with it.
//!
//! The check is a library function, not yet a step of `sandy doctor`: the direct verbs need no daemon until they are
//! removed, so doctor refuses on a missing daemon only from the promotion on.

use std::{path::Path, time::Duration};

use sandy::ProcessExit;
use sandy_control_proto::{HostSummary, IsolationClass, ListHostsRequest, control_request, control_response};

use crate::doctor::DoctorResult;

/// Ask the `sandyd` on `socket` for its connected host-executors, within `bound` for the whole exchange.
///
/// # Errors
///
/// A message naming what failed: the socket could not be connected, the daemon did not answer within `bound`, it
/// answered with an error, or it answered something other than a host list.
pub async fn list_hosts(socket: &Path, bound: Duration) -> Result<Vec<HostSummary>, String> {
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(socket)
            .await
            .map_err(|e| format!("could not connect to {}: {e}", socket.display()))?;
        let op = control_request::Op::ListHosts(ListHostsRequest {});
        let response = sandy_control_proto::client::call(&mut stream, 1, op)
            .await
            .map_err(|e| format!("the daemon call failed: {e}"))?;
        match response.result {
            Some(control_response::Result::Hosts(r)) => Ok(r.hosts),
            Some(control_response::Result::Error(e)) => Err(e.message),
            other => Err(format!("the daemon answered a host list request with {other:?}")),
        }
    };
    tokio::time::timeout(bound, exchange)
        .await
        .map_err(|_| format!("sandyd at {} did not answer within {bound:?}", socket.display()))?
}

/// The doctor verdict for the daemon check: ok with the executors listed, or a refusal (exit `2`, invalid environment)
/// that names the fix. `socket` is only named in the messages.
#[must_use]
pub fn daemon_check_result(socket: &Path, hosts: Result<Vec<HostSummary>, String>) -> DoctorResult {
    let refuse = |message: String| DoctorResult {
        exit_code: ProcessExit::InvalidPlan.code(),
        message: format!("sandy doctor: {message}"),
    };
    let hosts = match hosts {
        Ok(hosts) => hosts,
        Err(why) => {
            return refuse(format!(
                "sandyd is not reachable at {}: {why}; start `sandyd` (it listens on $SANDY_SOCK, else in the default \
                 runtime directory) and retry",
                socket.display()
            ));
        }
    };
    if hosts.is_empty() {
        return refuse(format!(
            "sandyd at {} has no executor registered, so no job can be placed; start `sandy-host-executor` against it \
             (see docs/design/host-executor/spec.md)",
            socket.display()
        ));
    }
    let listed: Vec<String> = hosts.iter().map(describe).collect();
    DoctorResult {
        exit_code: ProcessExit::Succeeded.code(),
        message: format!(
            "sandy doctor: sandyd at {} has {} executor{}: {} — OK",
            socket.display(),
            hosts.len(),
            if hosts.len() == 1 { "" } else { "s" },
            listed.join(", ")
        ),
    }
}

/// `id (kinds; classes; arch)`, as a host declared them.
fn describe(host: &HostSummary) -> String {
    let classes: Vec<&str> = host
        .isolation_classes
        .iter()
        .filter_map(|c| match IsolationClass::try_from(*c) {
            Ok(IsolationClass::Trusted) => Some("trusted"),
            Ok(IsolationClass::Untrusted) => Some("untrusted"),
            _ => None,
        })
        .collect();
    format!(
        "{} ({}; {}; {})",
        host.host_id,
        host.sandbox_kinds.join(", "),
        classes.join(", "),
        host.arch
    )
}

#[cfg(test)]
mod tests {
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
