//! The host-client's main loop (#288): register once, then receive
//! `Dispatch` frames off the same connection until it closes or shutdown is
//! requested. Pure protocol logic over any `AsyncRead + AsyncWrite`, kept
//! separate from `main.rs`'s real I/O (the mesh dial, the real
//! `SystemdRunContainment` probe, signal handling) so it's unit-testable
//! without a real socket or a real sandbox — the same "test the logic, defer
//! the wiring" split `sandyd::host_conn` already uses.
//!
//! Dispatches are handled strictly sequentially (decision 14): one `Dispatch`
//! runs to completion before the next is read. `Capabilities` declares no
//! concurrency slot, and M2's stage-1 acceptance is cross-machine, not
//! multiple concurrent jobs on one host — see the decision record for why
//! this isn't just an implementation shortcut.

use sandy_control_proto::{read_frame, write_frame};
use sandy_executor_proto::{
    Capabilities, Dispatch, HostClientMessage, OrchestratorMessage, host_client_message, orchestrator_message,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// A [`register`] failure: the orchestrator refused, or the exchange itself
/// didn't complete.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegisterError {
    /// The orchestrator replied `RegisterRefused`, naming `reason`.
    #[error("the orchestrator refused registration: {0}")]
    Refused(String),
    /// The connection closed before any response frame arrived.
    #[error("the connection closed before a Register response arrived")]
    ClosedBeforeResponse,
    /// Writing the `Register` frame failed.
    #[error("writing Register failed: {0}")]
    Write(String),
    /// Reading the response frame failed (a malformed frame, an I/O error).
    #[error("reading the Register response failed: {0}")]
    Read(String),
    /// The orchestrator's response was neither `Registered` nor
    /// `RegisterRefused` — stage 1 has no other message it could legitimately
    /// send first.
    #[error("the orchestrator's response was neither Registered nor RegisterRefused")]
    UnexpectedResponse,
}

/// Send `Register { host_id, capabilities }` over `conn` and wait for the
/// orchestrator's one response frame.
///
/// # Errors
/// See [`RegisterError`]'s variants.
pub async fn register(
    conn: &mut (impl AsyncRead + AsyncWrite + Unpin),
    host_id: &str,
    capabilities: Capabilities,
) -> Result<(), RegisterError> {
    let message = HostClientMessage {
        op: Some(host_client_message::Op::Register(sandy_executor_proto::Register {
            host_id: host_id.to_owned(),
            capabilities: Some(capabilities),
        })),
    };
    write_frame(conn, &message)
        .await
        .map_err(|e| RegisterError::Write(e.to_string()))?;

    let response: OrchestratorMessage = read_frame(conn)
        .await
        .map_err(|e| RegisterError::Read(e.to_string()))?
        .ok_or(RegisterError::ClosedBeforeResponse)?;
    match response.op {
        Some(orchestrator_message::Op::Registered(_)) => Ok(()),
        Some(orchestrator_message::Op::Refused(refused)) => Err(RegisterError::Refused(refused.reason)),
        _ => Err(RegisterError::UnexpectedResponse),
    }
}

/// Read `OrchestratorMessage` frames off `conn` until it closes, faults, or
/// `shutdown` resolves, calling `handle` with each `Dispatch` and awaiting it
/// to completion before reading the next frame (decision 14: sequential, one
/// job at a time). Any other frame shape is logged and ignored — stage 1's
/// orchestrator never sends anything else once registered (`sandyd::
/// host_conn`'s own doc says the same of an unexpected frame on its side).
pub async fn run_dispatch_loop<F, Fut>(
    conn: &mut (impl AsyncRead + AsyncWrite + Unpin),
    mut handle: F,
    shutdown: impl std::future::Future<Output = ()>,
) where
    F: FnMut(Dispatch) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            frame = read_frame::<OrchestratorMessage>(conn) => {
                match frame {
                    Ok(Some(message)) => match message.op {
                        Some(orchestrator_message::Op::Dispatch(dispatch)) => handle(dispatch).await,
                        _ => tracing::debug!("ignoring an unexpected frame from the orchestrator"),
                    },
                    Ok(None) => {
                        tracing::info!("the orchestrator closed the connection");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "the orchestrator connection faulted");
                        break;
                    }
                }
            }
            () = &mut shutdown => {
                tracing::info!("shutdown signal received; no longer reading new dispatches");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use anyhow::Context;
    use sandy_executor_proto::{Arch, IsolationClass, RegisterRefused, Registered, SandboxKind};

    use super::*;

    fn capabilities() -> Capabilities {
        Capabilities {
            kind: SandboxKind::Process.into(),
            arch: Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
        }
    }

    #[tokio::test]
    async fn register_sends_the_right_frame_and_accepts_registered() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let orchestrator = tokio::spawn(async move {
            let received: HostClientMessage = read_frame(&mut server).await?.context("expected Register")?;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Registered(Registered {
                        host_id: "ws01".to_owned(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(received)
        });

        register(&mut client, "ws01", capabilities()).await?;

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")?
            .context("orchestrator task panicked")??;
        match received.op {
            Some(host_client_message::Op::Register(r)) => {
                assert_eq!(r.host_id, "ws01");
                assert_eq!(r.capabilities, Some(capabilities()));
            }
            other => anyhow::bail!("expected Register, got {other:?}"),
        }
        Ok(())
    }

    #[tokio::test]
    async fn register_surfaces_a_refusal_reason() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let orchestrator = tokio::spawn(async move {
            let _received: HostClientMessage = read_frame(&mut server).await?.context("expected Register")?;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Refused(RegisterRefused {
                        reason: "not a permitted executor host".to_owned(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        });

        let err = register(&mut client, "impostor", capabilities())
            .await
            .expect_err("a RegisterRefused response must surface as an error");
        assert_eq!(err, RegisterError::Refused("not a permitted executor host".to_owned()));

        tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        Ok(())
    }

    #[tokio::test]
    async fn register_reports_a_clean_close_before_any_response() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(4096);

        let orchestrator = tokio::spawn(async move {
            let _received: HostClientMessage = read_frame(&mut server).await?.context("expected Register")?;
            drop(server); // closes after reading Register, before writing any response
            Ok::<_, anyhow::Error>(())
        });

        let err = register(&mut client, "ws01", capabilities())
            .await
            .expect_err("a connection closed with no response must be refused, not hang or panic");
        assert_eq!(err, RegisterError::ClosedBeforeResponse);

        tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        Ok(())
    }

    #[tokio::test]
    async fn the_dispatch_loop_calls_handle_for_each_dispatch_in_order() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let orchestrator = tokio::spawn(async move {
            for job_id in ["job-1", "job-2"] {
                write_frame(
                    &mut server,
                    &OrchestratorMessage {
                        op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                            job_id: job_id.to_owned(),
                            manifest: Vec::new(),
                            manifest_encoding: String::new(),
                            backend: SandboxKind::Process.into(),
                            link_token: vec![0u8; 32],
                            forward_back: "127.0.0.1:9000".to_owned(),
                            required_isolation_class: IsolationClass::Trusted.into(),
                        })),
                    },
                )
                .await?;
            }
            Ok::<_, anyhow::Error>(())
        });

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_loop = Arc::clone(&seen);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |dispatch| {
                    let seen = Arc::clone(&seen_in_loop);
                    async move {
                        seen.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(dispatch.job_id);
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;

        // Give the loop a moment to process both frames before asking it to
        // stop; the duplex staying open (server not dropped) means the loop
        // would otherwise wait forever for a third frame.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not stop after shutdown")?
            .context("dispatch loop task panicked")?;

        assert_eq!(
            *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["job-1".to_owned(), "job-2".to_owned()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_dispatch_loop_stops_reading_once_shutdown_resolves() -> anyhow::Result<()> {
        let (mut client, _server) = tokio::io::duplex(4096); // never writes, never closes

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(&mut client, |_dispatch: Dispatch| async {}, async {
                let _ = shutdown_rx.await;
            })
            .await;
        });

        shutdown_tx.send(()).expect("receiver still alive");
        tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("the loop did not stop once shutdown resolved, even with no frame ever arriving")?
            .context("dispatch loop task panicked")?;
        Ok(())
    }

    /// Adversarial: a frame that isn't `Dispatch` (stage 1 has no other
    /// orchestrator-sent message once registered) is ignored, not a reason to
    /// stop the loop — the next real `Dispatch` still gets handled.
    #[tokio::test]
    async fn an_unexpected_frame_is_ignored_not_fatal() -> anyhow::Result<()> {
        let (mut client, mut server) = tokio::io::duplex(8192);

        let orchestrator = tokio::spawn(async move {
            // Registered is a legitimate OrchestratorMessage variant, just
            // never expected again after registration — exercises the ignore
            // path without needing a malformed frame.
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Registered(Registered {
                        host_id: "ws01".to_owned(),
                    })),
                },
            )
            .await?;
            write_frame(
                &mut server,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Dispatch(Dispatch {
                        job_id: "job-1".to_owned(),
                        manifest: Vec::new(),
                        manifest_encoding: String::new(),
                        backend: SandboxKind::Process.into(),
                        link_token: vec![0u8; 32],
                        forward_back: "127.0.0.1:9000".to_owned(),
                        required_isolation_class: IsolationClass::Trusted.into(),
                    })),
                },
            )
            .await?;
            Ok::<_, anyhow::Error>(())
        });

        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_in_loop = Arc::clone(&seen);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut client,
                move |dispatch| {
                    let seen = Arc::clone(&seen_in_loop);
                    async move {
                        seen.lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .push(dispatch.job_id);
                    }
                },
                async {
                    let _ = shutdown_rx.await;
                },
            )
            .await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(2), orchestrator)
            .await
            .context("orchestrator task did not finish")??
            .context("orchestrator task failed")?;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let _ = shutdown_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(2), loop_task)
            .await
            .context("dispatch loop did not stop after shutdown")?
            .context("dispatch loop task panicked")?;

        assert_eq!(
            *seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner),
            vec!["job-1".to_owned()]
        );
        Ok(())
    }
}
