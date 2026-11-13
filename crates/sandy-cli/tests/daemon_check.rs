//! `daemon_check::list_hosts` against a fake `sandyd` (promote-and-remove prep, #483): the reply arms and the bound.

use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use sandy_cli::daemon_check::{ListHostsError, list_hosts};
use sandy_control_proto::{
    ControlError, ControlRequest, ControlResponse, HostSummary, ListHostsResponse, ListResponse, control_request,
    control_response, read_frame, write_frame,
};
use tokio::net::UnixListener;

/// What the fake daemon does with a `ListHosts` request.
#[derive(Clone)]
enum Behaviour {
    Hosts(Vec<HostSummary>),
    Error(&'static str),
    WrongReply,
    Stall,
    /// Read the request, then close the connection without answering (a daemon that does not know it).
    Drop,
}

/// Serve `behaviour` on a fresh socket under `dir` until the test ends.
fn serve(dir: &std::path::Path, behaviour: Behaviour) -> anyhow::Result<PathBuf> {
    let sock = dir.join("sandyd.sock");
    let listener = Arc::new(UnixListener::bind(&sock).context("bind")?);
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let behaviour = behaviour.clone();
            tokio::spawn(async move {
                while let Ok(Some(request)) = read_frame::<ControlRequest>(&mut stream).await {
                    let result = match (&request.op, &behaviour) {
                        (Some(control_request::Op::ListHosts(_)), Behaviour::Hosts(hosts)) => {
                            control_response::Result::Hosts(ListHostsResponse { hosts: hosts.clone() })
                        }
                        (_, Behaviour::Error(message)) => control_response::Result::Error(ControlError {
                            message: (*message).to_owned(),
                        }),
                        (_, Behaviour::Stall) => std::future::pending().await,
                        (_, Behaviour::Drop) => break,
                        _ => control_response::Result::List(ListResponse { jobs: Vec::new() }),
                    };
                    let reply = ControlResponse {
                        request_id: request.request_id,
                        result: Some(result),
                    };
                    if write_frame(&mut stream, &reply).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    Ok(sock)
}

fn summary(id: &str) -> HostSummary {
    HostSummary {
        host_id: id.to_owned(),
        sandbox_kinds: vec!["vm".to_owned()],
        isolation_classes: Vec::new(),
        arch: "aarch64".to_owned(),
    }
}

/// A daemon that answers returns its hosts as they were sent.
#[tokio::test]
async fn the_connected_hosts_come_back_as_the_daemon_sent_them() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = serve(dir.path(), Behaviour::Hosts(vec![summary("mac"), summary("linux")]))?;
    let hosts = list_hosts(&sock, Duration::from_secs(5))
        .await
        .map_err(anyhow::Error::msg)?;
    let ids: Vec<&str> = hosts.iter().map(|h| h.host_id.as_str()).collect();
    assert_eq!(ids, ["mac", "linux"]);
    Ok(())
}

/// No daemon on the socket is an error naming the socket, not an empty list.
#[tokio::test]
async fn a_missing_socket_is_an_error_naming_it() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = dir.path().join("nobody-home.sock");
    let err = list_hosts(&sock, Duration::from_secs(5)).await.expect_err("no daemon");
    assert!(matches!(err, ListHostsError::Unreachable(_)), "{err:?}");
    assert!(err.to_string().contains("nobody-home.sock"), "{err}");
    Ok(())
}

/// The daemon's own refusal comes back as the error, with its message.
#[tokio::test]
async fn a_daemon_error_reply_is_the_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = serve(dir.path(), Behaviour::Error("not today"))?;
    let err = list_hosts(&sock, Duration::from_secs(5))
        .await
        .expect_err("an error reply");
    assert!(matches!(err, ListHostsError::Refused(_)), "{err:?}");
    assert!(err.to_string().contains("not today"), "{err}");
    Ok(())
}

/// A reply of another kind (a daemon that predates `ListHosts` answers nothing it knows) is an error naming the
/// mismatch, not an empty host list.
#[tokio::test]
async fn a_reply_of_another_kind_is_an_error() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = serve(dir.path(), Behaviour::WrongReply)?;
    let err = list_hosts(&sock, Duration::from_secs(5))
        .await
        .expect_err("wrong reply");
    assert!(matches!(err, ListHostsError::Refused(_)), "{err:?}");
    assert!(err.to_string().contains("host list"), "{err}");
    Ok(())
}

/// A daemon that accepts and never answers ends at the bound, naming it.
#[tokio::test]
async fn a_stalled_daemon_ends_at_the_bound() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = serve(dir.path(), Behaviour::Stall)?;
    let started = Instant::now();
    let outcome = tokio::time::timeout(Duration::from_secs(5), list_hosts(&sock, Duration::from_millis(200)))
        .await
        .context("the call hung past its bound")?;
    let err = outcome.expect_err("nothing answers");
    assert!(matches!(err, ListHostsError::Unreachable(_)), "{err:?}");
    assert!(err.to_string().contains("did not answer"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(3), "ended at the bound");
    Ok(())
}

/// A daemon that reads the request and closes the connection is running but does not answer it: refused (maybe an
/// older daemon), not unreachable.
#[tokio::test]
async fn a_daemon_that_drops_the_connection_is_refused_not_unreachable() -> anyhow::Result<()> {
    let dir = tempfile::tempdir().context("temp dir")?;
    let sock = serve(dir.path(), Behaviour::Drop)?;
    let err = list_hosts(&sock, Duration::from_secs(5))
        .await
        .expect_err("a dropped connection");
    assert!(matches!(err, ListHostsError::Refused(_)), "{err:?}");
    Ok(())
}
