//! Drives one host-client's persistent connection (#263): read its
//! `Register`, authenticate and reply, then relay `Dispatch` messages queued
//! for it in [`HostRegistry`] down the same connection until it closes. The
//! connection staying open is the host's liveness signal (kubelet-watch
//! pattern) — there is no separate heartbeat protocol, and no re-registration
//! machinery for stage 1 (#269): a host that disconnects is simply gone until
//! it reconnects and registers again.

use sandy_conn::{Conn, PeerAddr};
use sandy_control_proto::{read_frame, write_frame};
use sandy_executor_proto::{
    HostClientMessage, OrchestratorMessage, RegisterRefused, Registered, host_client_message, orchestrator_message,
};

use crate::host_registry::{ExecutorAllowlist, HostRegistry};

/// Serve one accepted host-client connection end to end.
///
/// Expects `Register` as the first frame; anything else, or a stream that
/// closes before sending one, ends the connection without ever registering
/// the host. A `PeerAddr::Uds` peer is refused outright — a host-client only
/// ever connects over the mesh (`PeerAddr::Tcp`), so a UDS peer here would be
/// a caller bug, not a registration this code should entertain.
pub async fn serve_host_client(
    mut conn: Box<dyn Conn>,
    peer: PeerAddr,
    allowlist: &ExecutorAllowlist,
    registry: &HostRegistry,
) {
    let peer_ip = match peer {
        PeerAddr::Tcp(addr) => addr.ip(),
        PeerAddr::Uds => {
            tracing::warn!("a host-client connection arrived over UDS, not the mesh; refusing");
            return;
        }
    };

    let register = match read_frame::<HostClientMessage>(&mut conn).await {
        Ok(Some(HostClientMessage {
            op: Some(host_client_message::Op::Register(register)),
        })) => register,
        Ok(Some(_)) => {
            tracing::warn!(peer = %peer_ip, "host-client's first frame was not Register; closing");
            return;
        }
        Ok(None) => return, // clean close before any frame: nothing to log
        Err(e) => {
            tracing::warn!(peer = %peer_ip, error = %e, "host-client connection faulted reading Register");
            return;
        }
    };

    let host_id = register.host_id.clone();
    let capabilities = match register.capabilities {
        Some(capabilities) => capabilities,
        None => {
            tracing::warn!(peer = %peer_ip, host_id, "Register carried no capabilities; refusing");
            let _ = write_frame(
                &mut conn,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Refused(RegisterRefused {
                        reason: "capabilities required".to_owned(),
                    })),
                },
            )
            .await;
            return;
        }
    };

    let mut dispatch_rx = match registry.register(allowlist, peer_ip, host_id.clone(), capabilities) {
        Ok(dispatch_rx) => dispatch_rx,
        Err(e) => {
            // Refused and logged (D5's Register-authentication ruling, #263):
            // an unknown registrant's mesh identity never becomes
            // dispatch-eligible, and never gets more than "no" back.
            tracing::warn!(peer = %peer_ip, host_id, error = %e, "Register refused: not a permitted executor host");
            let _ = write_frame(
                &mut conn,
                &OrchestratorMessage {
                    op: Some(orchestrator_message::Op::Refused(RegisterRefused {
                        reason: e.to_string(),
                    })),
                },
            )
            .await;
            return;
        }
    };

    if write_frame(
        &mut conn,
        &OrchestratorMessage {
            op: Some(orchestrator_message::Op::Registered(Registered {
                host_id: host_id.clone(),
            })),
        },
    )
    .await
    .is_err()
    {
        registry.remove(&host_id);
        return;
    }
    tracing::info!(peer = %peer_ip, host_id, "host-client registered");

    loop {
        tokio::select! {
            dispatch = dispatch_rx.recv() => {
                let Some(dispatch) = dispatch else {
                    // The sending half was dropped: HostRegistry has no other
                    // reference to this channel, so this only happens if the
                    // registry entry was already replaced or removed.
                    break;
                };
                if write_frame(
                    &mut conn,
                    &OrchestratorMessage { op: Some(orchestrator_message::Op::Dispatch(dispatch)) },
                )
                .await
                .is_err()
                {
                    tracing::warn!(host_id, "failed writing Dispatch to host-client; closing");
                    break;
                }
            }
            frame = read_frame::<HostClientMessage>(&mut conn) => {
                match frame {
                    Ok(Some(_)) => {
                        // Stage 1 has no re-registration or capability-update
                        // machinery (#269): any further frame from the
                        // host-client is unexpected but not fatal on its own.
                        tracing::debug!(host_id, "ignoring an unexpected frame from a registered host-client");
                    }
                    Ok(None) => break, // clean close: the ordinary end of a connection
                    Err(e) => {
                        tracing::warn!(host_id, error = %e, "host-client connection faulted");
                        break;
                    }
                }
            }
        }
    }

    registry.remove(&host_id);
    tracing::info!(host_id, "host-client disconnected");
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use anyhow::Context;
    use sandy_executor_proto::{Arch, Capabilities, IsolationClass, Register, SandboxKind};

    use super::*;

    fn tcp_peer(ip: &str) -> PeerAddr {
        PeerAddr::Tcp(SocketAddr::new(ip.parse().unwrap(), 9000))
    }

    fn capabilities() -> Capabilities {
        Capabilities {
            kind: SandboxKind::Process.into(),
            arch: Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
        }
    }

    #[tokio::test]
    async fn an_allowed_host_registers_and_receives_a_queued_dispatch() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new(["100.64.0.7".parse()?]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostClientMessage {
                op: Some(host_client_message::Op::Register(Register {
                    host_id: "ws01".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        let registry = std::sync::Arc::new(registry);
        let allowlist = std::sync::Arc::new(allowlist);
        let serve = tokio::spawn({
            let registry = std::sync::Arc::clone(&registry);
            let allowlist = std::sync::Arc::clone(&allowlist);
            async move {
                serve_host_client(Box::new(server), tcp_peer("100.64.0.7"), &allowlist, &registry).await;
            }
        });

        let response: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;
        assert!(matches!(response.op, Some(orchestrator_message::Op::Registered(_))));

        let dispatch = sandy_executor_proto::Dispatch {
            job_id: "job-1".to_owned(),
            manifest: b"m".to_vec(),
            manifest_encoding: "test/v1".to_owned(),
            backend: SandboxKind::Process.into(),
            link_token: vec![0u8; 32],
            forward_back: "100.64.0.1:9000".to_owned(),
            required_isolation_class: IsolationClass::Trusted.into(),
        };
        registry.send_dispatch("ws01", dispatch.clone()).await?;

        let pushed: OrchestratorMessage = read_frame(&mut client).await?.context("expected a Dispatch push")?;
        match pushed.op {
            Some(orchestrator_message::Op::Dispatch(received)) => assert_eq!(received, dispatch),
            other => anyhow::bail!("expected Dispatch, got {other:?}"),
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;
        assert_eq!(
            registry.capabilities_of("ws01"),
            None,
            "disconnecting must remove the host"
        );
        Ok(())
    }

    /// Adversarial (#263, D5): a peer not on the allowlist gets
    /// `RegisterRefused`, never `Registered`, and is never dispatch-eligible.
    #[tokio::test]
    async fn an_unknown_peer_is_refused_not_registered() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new(["100.64.0.7".parse()?]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostClientMessage {
                op: Some(host_client_message::Op::Register(Register {
                    host_id: "impostor".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        let serving = tokio::spawn(async move {
            serve_host_client(Box::new(server), tcp_peer("100.64.0.9"), &allowlist, &registry).await;
            registry
        });

        let response: OrchestratorMessage = read_frame(&mut client).await?.context("expected a response")?;
        assert!(matches!(response.op, Some(orchestrator_message::Op::Refused(_))));

        drop(client);
        let registry = tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        assert_eq!(registry.capabilities_of("impostor"), None);
        Ok(())
    }
}
