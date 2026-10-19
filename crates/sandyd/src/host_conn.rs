//! Drives one host-executor's persistent connection (#263): read its
//! `Register`, authenticate and reply, then relay `Dispatch` messages queued
//! for it in [`HostRegistry`] down the same connection until it closes. The
//! connection staying open is the host's liveness signal (kubelet-watch
//! pattern) — there is no separate heartbeat protocol, and no re-registration
//! machinery for stage 1 (#269): a host that disconnects is simply gone until
//! it reconnects and registers again.

use sandy_conn::{Conn, PeerAddr};
use sandy_control_proto::{FrameError, read_frame, write_frame};
use sandy_executor_proto::{
    HostExecutorMessage, OrchestratorMessage, RegisterRefused, Registered, host_executor_message, orchestrator_message,
};
use tokio::sync::mpsc;

use crate::host_registry::{ExecutorAllowlist, HostRegistry, RegisterError};

/// How long a freshly accepted connection has to send its `Register` frame
/// before it's closed. Without a deadline here, a peer that opens a
/// connection and never writes anything would hold it (and the accept
/// loop's resources for it) open indefinitely — a slowloris-style resource
/// exhaustion, not just a slow client.
const REGISTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a single `Dispatch` write may take before its host-executor is
/// treated as hung and disconnected (#289 item 2). Expiry closes the
/// connection and deregisters the host, which also closes
/// [`HostRegistry`]'s per-host `mpsc` sender — the transitive fix #301 found:
/// a `send_dispatch`/`send_dispatch_if_current` call blocked on that channel
/// filling up (capacity 8) now fails fast with `ConnectionClosing` once this
/// fires, instead of hanging on a dead host indefinitely.
const DISPATCH_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Serve one accepted host-executor connection end to end.
///
/// Expects `Register` as the first frame within [`REGISTER_TIMEOUT`];
/// anything else, a stream that closes before sending one, or one that never
/// sends it in time, ends the connection without ever registering the host.
/// A `PeerAddr::Uds` peer is refused outright — a host-executor only ever
/// connects over the mesh (`PeerAddr::Tcp`), so a UDS peer here would be a
/// caller bug, not a registration this code should entertain.
///
/// CAUTION (#289): the three refusal writes before registration (not
/// allowlisted, missing capabilities, `host_id` already claimed) still have
/// no deadline. A peer that stops reading after opening a connection can
/// stall one of those indefinitely — their cost is just the connection slot,
/// since no registry entry exists yet, which is why they're deliberately
/// deferred. The one write that mattered more — the registered `Dispatch`
/// push, which stalls a live, dispatch-eligible registry entry — has
/// [`DISPATCH_WRITE_TIMEOUT`] (#289 item 2, landed). The connection loop's
/// own read is cancel-safe (#289 item 3, landed) via [`forward_frames`].
pub async fn serve_host_executor(
    mut conn: Box<dyn Conn>,
    peer: PeerAddr,
    allowlist: &ExecutorAllowlist,
    registry: &HostRegistry,
) {
    let peer_ip = match peer {
        PeerAddr::Tcp(addr) => addr.ip(),
        PeerAddr::Uds => {
            tracing::warn!("a host-executor connection arrived over UDS, not the mesh; refusing");
            return;
        }
    };

    let register = match tokio::time::timeout(REGISTER_TIMEOUT, read_frame::<HostExecutorMessage>(&mut conn)).await {
        Ok(Ok(Some(HostExecutorMessage {
            op: Some(host_executor_message::Op::Register(register)),
        }))) => register,
        Ok(Ok(Some(_))) => {
            tracing::warn!(peer = %peer_ip, "host-executor's first frame was not Register; closing");
            return;
        }
        Ok(Ok(None)) => return, // clean close before any frame: nothing to log
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer_ip, error = %e, "host-executor connection faulted reading Register");
            return;
        }
        Err(_elapsed) => {
            tracing::warn!(peer = %peer_ip, "host-executor did not send Register within the timeout; closing");
            return;
        }
    };

    let host_id = register.host_id.clone();

    // Allowlist membership first, before anything about the frame's content
    // is checked (D5, #263): refusing on a missing `capabilities` field
    // before this would hand an unauthenticated peer a different, more
    // specific error than an allowlisted one — leaking that it passed a
    // stage a merely-curious peer never should have reached. Every
    // non-allowlisted peer gets the exact same generic refusal, regardless
    // of what else is or isn't in its `Register` frame.
    if !allowlist.permits(peer_ip) {
        tracing::warn!(peer = %peer_ip, host_id, "Register refused: not a permitted executor host");
        // #289: no deadline — a non-reading peer stalls this task, but the
        // connection slot is the only cost (no registry entry exists yet).
        let _ = write_frame(
            &mut conn,
            &OrchestratorMessage {
                op: Some(orchestrator_message::Op::Refused(RegisterRefused {
                    reason: RegisterError::NotAllowed.to_string(),
                })),
            },
        )
        .await;
        return;
    }

    let capabilities = match register.capabilities {
        Some(capabilities) => capabilities,
        None => {
            tracing::warn!(peer = %peer_ip, host_id, "Register carried no capabilities; refusing");
            // #289: same undeadlined write as the allowlist refusal above.
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

    let (mut dispatch_rx, registration) = match registry.register(allowlist, peer_ip, host_id.clone(), capabilities) {
        Ok(registered) => registered,
        Err(e) => {
            // The allowlist check above already covers RegisterError::NotAllowed;
            // reaching this arm means host_id was claimed by a different peer
            // (D5's Register-authentication ruling, #263) — refused and
            // logged, never more than "no" back.
            tracing::warn!(peer = %peer_ip, host_id, error = %e, "Register refused: host_id already claimed");
            // #289: same undeadlined write as the allowlist refusal above.
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

    // #289: undeadlined, and unlike the three refusal writes above, the
    // registry entry already exists at this point — a non-reading peer here
    // stalls the registered host-executor's own task with a live, dispatch-
    // eligible entry nothing else will clean up until this write resolves.
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
        registry.remove(&host_id, registration);
        return;
    }
    tracing::info!(peer = %peer_ip, host_id, "host-executor registered");

    // Split the connection here, not before: the handshake above never races
    // `read_frame` against anything else (each `.await` runs to completion or
    // the whole connection ends), so it's cancel-safe without this. The loop
    // below is not — it needs to select! a read against `dispatch_rx.recv()`
    // — so reading happens in its own task from here on, forwarding complete
    // frames over `frame_rx`: a channel `recv()` is cancel-safe (a dropped
    // `.await` never loses a value already sent), unlike `read_frame` itself,
    // which does separate awaits for the length prefix and the payload and
    // would drop whatever it had read so far if raced and cancelled
    // mid-frame (#289 item 3).
    let (read_half, mut write_half) = tokio::io::split(conn);
    let (frame_tx, mut frame_rx) = mpsc::channel(1);
    tokio::spawn(forward_frames(read_half, frame_tx));

    loop {
        tokio::select! {
            dispatch = dispatch_rx.recv() => {
                let Some(dispatch) = dispatch else {
                    // The sending half was dropped: HostRegistry has no other
                    // reference to this channel, so this only happens if the
                    // registry entry was already replaced or removed.
                    break;
                };
                match tokio::time::timeout(
                    DISPATCH_WRITE_TIMEOUT,
                    write_frame(&mut write_half, &OrchestratorMessage { op: Some(orchestrator_message::Op::Dispatch(dispatch)) }),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {
                        tracing::warn!(host_id, "failed writing Dispatch to host-executor; closing");
                        break;
                    }
                    Err(_elapsed) => {
                        tracing::warn!(host_id, "writing Dispatch to host-executor timed out; treating it as hung");
                        break;
                    }
                }
            }
            frame = frame_rx.recv() => {
                match frame {
                    Some(Ok(Some(_))) => {
                        // Stage 1 has no re-registration or capability-update
                        // machinery (#269): any further frame from the
                        // host-executor is unexpected but not fatal on its own.
                        tracing::debug!(host_id, "ignoring an unexpected frame from a registered host-executor");
                    }
                    Some(Ok(None)) => break, // clean close: the ordinary end of a connection
                    Some(Err(e)) => {
                        tracing::warn!(host_id, error = %e, "host-executor connection faulted");
                        break;
                    }
                    // The reader task only exits after sending a terminal
                    // Ok(None)/Err, so a closed channel with nothing left to
                    // receive is the same "connection is gone" case as those,
                    // just observed through the channel closing instead of a
                    // value arriving — not a distinct failure to log.
                    None => break,
                }
            }
        }
    }

    registry.remove(&host_id, registration);
    tracing::info!(host_id, "host-executor disconnected");
}

/// Reads frames from `read_half` sequentially — never raced against anything
/// else, so each `read_frame` call always either completes or the whole task
/// ends, which is what makes it cancel-safe from [`serve_host_executor`]'s
/// perspective: the `select!` loop only ever observes this through
/// `frame_tx`'s `recv()`, a plain channel read. Ends after forwarding the
/// first terminal result (`Ok(None)` or `Err`), matching `read_frame`'s own
/// contract that nothing more should be read from a stream once either
/// occurs.
async fn forward_frames<R: tokio::io::AsyncRead + Unpin>(
    mut read_half: R,
    frame_tx: mpsc::Sender<Result<Option<HostExecutorMessage>, FrameError>>,
) {
    loop {
        let frame = read_frame::<HostExecutorMessage>(&mut read_half).await;
        let is_terminal = !matches!(frame, Ok(Some(_)));
        if frame_tx.send(frame).await.is_err() {
            return; // serve_host_executor's loop already ended; nothing left to forward to
        }
        if is_terminal {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use anyhow::Context;
    use sandy_executor_proto::{Arch, Capabilities, IsolationClass, Register, SandboxKind};

    use super::*;

    fn tcp_peer(ip: &str) -> PeerAddr {
        PeerAddr::Tcp(SocketAddr::new(ip.parse().expect("ip literal"), 9000))
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
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
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
                serve_host_executor(Box::new(server), tcp_peer("100.64.0.7"), &allowlist, &registry).await;
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
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "impostor".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        let serving = tokio::spawn(async move {
            serve_host_executor(Box::new(server), tcp_peer("100.64.0.9"), &allowlist, &registry).await;
            registry
        });

        let response: OrchestratorMessage = read_frame(&mut client).await?.context("expected a response")?;
        assert!(matches!(response.op, Some(orchestrator_message::Op::Refused(_))));

        drop(client);
        let registry = tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        assert_eq!(registry.capabilities_of("impostor"), None);
        Ok(())
    }

    /// Regression (sandy-91/infra-f3): a non-allowlisted peer must get the
    /// exact same generic refusal regardless of what its `Register` frame
    /// carries. Checking `capabilities` before the allowlist would hand an
    /// unauthenticated peer a more specific error ("capabilities required")
    /// than the generic one — leaking that it passed a stage it never
    /// should have reached.
    #[tokio::test]
    async fn an_unknown_peer_with_no_capabilities_gets_the_generic_refusal() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new(["100.64.0.7".parse()?]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "impostor".to_owned(),
                    capabilities: None,
                })),
            },
        )
        .await?;

        let serving = tokio::spawn(async move {
            serve_host_executor(Box::new(server), tcp_peer("100.64.0.9"), &allowlist, &registry).await;
        });

        let response: OrchestratorMessage = read_frame(&mut client).await?.context("expected a response")?;
        match response.op {
            Some(orchestrator_message::Op::Refused(RegisterRefused { reason })) => {
                assert_eq!(reason, RegisterError::NotAllowed.to_string());
            }
            other => anyhow::bail!("expected Refused with the generic reason, got {other:?}"),
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        Ok(())
    }

    /// Regression: a connection that never sends `Register` must not be held
    /// open forever — it's closed once `REGISTER_TIMEOUT` elapses.
    #[tokio::test(start_paused = true)]
    async fn a_host_that_never_sends_register_is_disconnected_after_the_timeout() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new(["100.64.0.7".parse()?]);
        let registry = HostRegistry::default();
        let (client, server) = tokio::io::duplex(4096);

        let serving = tokio::spawn(async move {
            serve_host_executor(Box::new(server), tcp_peer("100.64.0.7"), &allowlist, &registry).await;
        });

        tokio::time::advance(REGISTER_TIMEOUT + std::time::Duration::from_millis(1)).await;
        serving.await?; // bounded by the virtual-clock advance above, not real time
        drop(client);
        Ok(())
    }

    /// Regression (#289 item 2, with the #301 propagation it names): a
    /// registered host that stops reading must not stall `Dispatch` delivery
    /// forever. A tiny duplex buffer fits the Register/Registered handshake
    /// (drained before the Dispatch write) but not a Dispatch frame, so a
    /// peer that stops reading genuinely blocks the write exactly like a full
    /// TCP receive buffer would.
    ///
    /// Proves the documented `ConnectionClosing` result directly, not just
    /// that *some* later call fails (CodeRabbit on #311): fills the
    /// `HostRegistry` channel (capacity 8, one slot already drained into the
    /// stalled write) so a 9th `send_dispatch` genuinely blocks on a full
    /// channel, same as a real caller racing the timeout would. Once the
    /// write's deadline expires and `registry.remove` drops the channel's
    /// receiver, that blocked send resolves — asserted to be exactly
    /// `DispatchSendError::ConnectionClosing`, not merely "an error."
    #[tokio::test(start_paused = true)]
    async fn a_hung_host_is_disconnected_after_the_dispatch_write_timeout() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new(["100.64.0.7".parse()?]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(64);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
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
                serve_host_executor(Box::new(server), tcp_peer("100.64.0.7"), &allowlist, &registry).await;
            }
        });

        let _registered: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;

        // The first send is picked up by the connection loop's select! and
        // its write stalls immediately (the duplex buffer is too small for
        // even one frame) — this one slot is never returned to the channel.
        registry.send_dispatch("ws01", test_dispatch("job-1")).await?;

        // Fill the channel's full capacity (8) behind the stalled write:
        // these succeed immediately since nothing has consumed from the
        // channel since the first send.
        for n in 0..8 {
            registry
                .send_dispatch("ws01", test_dispatch(&format!("job-fill-{n}")))
                .await?;
        }

        // The 9th send has no room left and genuinely blocks — exactly the
        // caller this fix exists for. Spawned so the test can advance the
        // clock concurrently with it being blocked.
        let blocked_registry = std::sync::Arc::clone(&registry);
        let blocked_send = tokio::spawn(async move {
            blocked_registry
                .send_dispatch("ws01", test_dispatch("job-overflow"))
                .await
        });

        // Give the spawned send a chance to actually reach the blocking
        // point before the clock advances, so the race is real rather than
        // incidental: with the clock paused, a bare `yield_now` lets the
        // runtime poll `blocked_send` once without passing any virtual time.
        tokio::task::yield_now().await;

        // Never read further from `client`: the Dispatch write stays
        // stalled, standing in for a hung peer. Plain `.await` on `serve`
        // below, not a second real-time `timeout` wrapper: with the clock
        // paused, `advance` already drives the runtime past the one timer
        // this task is waiting on, so nothing further needs to pass virtual
        // time — matching the pattern the `REGISTER_TIMEOUT` regression test
        // above uses.
        tokio::time::advance(DISPATCH_WRITE_TIMEOUT + std::time::Duration::from_millis(1)).await;
        serve.await?;

        let blocked_result = blocked_send.await?;
        assert_eq!(
            blocked_result,
            Err(crate::host_registry::DispatchSendError::ConnectionClosing),
            "a send blocked on the full channel must resolve to ConnectionClosing once the write times out, not hang"
        );

        assert_eq!(
            registry.capabilities_of("ws01"),
            None,
            "a hung Dispatch write must disconnect and deregister the host"
        );

        let resend = registry.send_dispatch("ws01", test_dispatch("job-2")).await;
        assert!(
            matches!(resend, Err(crate::host_registry::DispatchSendError::NoSuchHost)),
            "a send after full deregistration must fail with NoSuchHost, not hang: got {resend:?}"
        );
        drop(client);
        Ok(())
    }

    fn test_dispatch(job_id: &str) -> sandy_executor_proto::Dispatch {
        sandy_executor_proto::Dispatch {
            job_id: job_id.to_owned(),
            manifest: b"m".to_vec(),
            manifest_encoding: "test/v1".to_owned(),
            backend: SandboxKind::Process.into(),
            link_token: vec![0u8; 32],
            forward_back: "100.64.0.1:9000".to_owned(),
            required_isolation_class: IsolationClass::Trusted.into(),
        }
    }

    /// Regression guard (#289 item 3), NOT a discriminating red/green test:
    /// checked (200 runs against the pre-fix code, spliced onto the old
    /// racing `select! { ... read_frame(&mut conn) ... }` structure) and it
    /// passed every time there too. Forcing the actual race — the dispatch
    /// branch winning `select!` at the exact instant a `read_frame` future
    /// has completed only its first `.await` (the length prefix) and not its
    /// second (the payload) — needs control over poll ordering this test
    /// doesn't have; tokio's cooperative scheduling doesn't happen to produce
    /// that interleaving from this setup, on either the old or new code. The
    /// correctness argument here is structural, not this test: before the
    /// fix, `read_frame` was raced directly inside the loop's `select!`
    /// against `dispatch_rx.recv()`, so a drop mid-read was POSSIBLE even if
    /// this harness can't force it; after the fix, reading happens in
    /// `forward_frames`, its own task where nothing ever races it, so a drop
    /// mid-read is no longer possible at all, full stop, independent of
    /// scheduling. This test exists to catch an actual regression in that
    /// structure (e.g. someone re-inlining the read into the `select!`) and
    /// to prove the new code still handles interleaved host-sent frames
    /// correctly, not to demonstrate the old bug.
    #[tokio::test]
    async fn dispatches_interleaved_with_an_unexpected_frame_are_all_still_delivered_correctly() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new(["100.64.0.7".parse()?]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
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
                serve_host_executor(Box::new(server), tcp_peer("100.64.0.7"), &allowlist, &registry).await;
            }
        });

        let _registered: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;

        registry.send_dispatch("ws01", test_dispatch("job-1")).await?;

        // An unexpected frame from the host, sent right as the first dispatch
        // is in flight — the interleaving this test exists to exercise. The
        // loop's `Ok(Some(_))` arm just logs and continues, never fatal.
        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "ws01".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        registry.send_dispatch("ws01", test_dispatch("job-2")).await?;
        registry.send_dispatch("ws01", test_dispatch("job-3")).await?;

        for expected_job_id in ["job-1", "job-2", "job-3"] {
            let pushed: OrchestratorMessage = read_frame(&mut client).await?.context("expected a Dispatch push")?;
            match pushed.op {
                Some(orchestrator_message::Op::Dispatch(received)) => assert_eq!(
                    received.job_id, expected_job_id,
                    "a framing desync would corrupt or misorder a later dispatch, not necessarily the one interleaved \
                     with the unexpected frame"
                ),
                other => anyhow::bail!("expected a Dispatch push for {expected_job_id}, got {other:?}"),
            }
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;
        Ok(())
    }
}
