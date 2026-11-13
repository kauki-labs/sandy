//! Drives one host-executor's persistent connection (#263): read its
//! `Register`, authenticate and reply, then relay `Dispatch` messages queued
//! for it in [`HostRegistry`] down the same connection until it closes. The
//! connection staying open is the host's liveness signal (kubelet-watch
//! pattern) — there is no separate heartbeat protocol, and no re-registration
//! machinery for stage 1 (#269): a host that disconnects is simply gone until
//! it reconnects and registers again.

use std::{collections::HashSet, sync::Arc};

use sandy::OutputStatus;
use sandy_conn::{Conn, PeerAddr};
use sandy_control_proto::{FrameError, JobStatus, read_frame, write_frame};
use sandy_executor_proto::{
    HostExecutorMessage, JobResult, OrchestratorMessage, RegisterRefused, Registered, host_executor_message,
    orchestrator_message,
};
use tokio::sync::mpsc;

use crate::{
    credential::Redaction,
    dispatch::JobRegistry,
    envelope::RunFacts,
    host_registry::{ExecutorAllowlist, HostRegistry, RegisterError, Registration},
    store::{JobStore, Transition},
};

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

/// Serve one accepted host-executor connection end to end: authenticate it
/// via [`register_and_authenticate`], then, on success, relay dispatches over
/// it via [`relay_dispatches`] until it closes. See each function's own doc
/// for the behavior it owns.
pub async fn serve_host_executor(
    conn: Box<dyn Conn>,
    peer: PeerAddr,
    allowlist: &ExecutorAllowlist,
    registry: &HostRegistry,
    store: &Arc<JobStore>,
    job_registry: &JobRegistry,
) {
    let Some((conn, registration)) = register_and_authenticate(conn, peer, allowlist, registry).await else {
        return;
    };
    let registration_id = registration.registration;
    let host_id = registration.host_id.clone();

    relay_dispatches(conn, registration, store, job_registry).await;

    registry.remove(&host_id, registration_id);
    tracing::info!(host_id, "host-executor disconnected");
}

/// Read, authenticate, and acknowledge a host-executor's `Register` frame.
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
/// [`DISPATCH_WRITE_TIMEOUT`], enforced by [`relay_dispatches`] (#289 item 2,
/// landed).
///
/// Returns `None` once the connection has already been fully handled
/// (refused, timed out, or faulted) — there is nothing left for the caller to
/// do but return. On success, hands back the still-open connection and its
/// [`Registration`], the only state [`relay_dispatches`] needs.
async fn register_and_authenticate(
    mut conn: Box<dyn Conn>,
    peer: PeerAddr,
    allowlist: &ExecutorAllowlist,
    registry: &HostRegistry,
) -> Option<(Box<dyn Conn>, Registration)> {
    let (peer_ip, fingerprint) = match peer {
        PeerAddr::TcpTls(addr, fingerprint) => (addr.ip(), fingerprint),
        PeerAddr::Tcp(addr) => {
            // Decision 20: fail closed, no plaintext fallback. This listener
            // is bound via `listen_tls` once wired, so a bare `Tcp` peer here
            // means a caller constructed this connection outside that
            // listener — a bug in the caller, not a real host-executor.
            tracing::warn!(peer = %addr.ip(), "a host-executor connection arrived without mutual TLS; refusing");
            return None;
        }
        PeerAddr::Uds => {
            tracing::warn!("a host-executor connection arrived over UDS, not the mesh; refusing");
            return None;
        }
    };

    let register = match tokio::time::timeout(REGISTER_TIMEOUT, read_frame::<HostExecutorMessage>(&mut conn)).await {
        Ok(Ok(Some(HostExecutorMessage {
            op: Some(host_executor_message::Op::Register(register)),
        }))) => register,
        Ok(Ok(Some(_))) => {
            tracing::warn!(peer = %peer_ip, "host-executor's first frame was not Register; closing");
            return None;
        }
        Ok(Ok(None)) => return None, // clean close before any frame: nothing to log
        Ok(Err(e)) => {
            tracing::warn!(peer = %peer_ip, error = %e, "host-executor connection faulted reading Register");
            return None;
        }
        Err(_elapsed) => {
            tracing::warn!(peer = %peer_ip, "host-executor did not send Register within the timeout; closing");
            return None;
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
    if !allowlist.permits(peer_ip, fingerprint) {
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
        return None;
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
            return None;
        }
    };

    tracing::debug!(
        peer = %peer_ip,
        host_id,
        supported_isolation_classes = ?capabilities.supported_isolation_classes,
        "decoded Register capabilities"
    );

    // `register` logs any same-peer reclaim itself (#292 item 4), so the
    // superseded registration is ignored here.
    let registration = match registry.register(allowlist, peer_ip, fingerprint, host_id.clone(), capabilities) {
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
            return None;
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
        registry.remove(&host_id, registration.registration);
        return None;
    }
    tracing::info!(peer = %peer_ip, host_id, "host-executor registered");

    Some((conn, registration))
}

/// Relay queued `Dispatch`/`AttachStateChanged` messages down a registered
/// host-executor's connection until it closes, feeding reported `JobResult`s
/// back into `store` and `job_registry`. `registration` is the only state
/// carried over from [`register_and_authenticate`]: this function never
/// touches the allowlist and never re-derives capabilities. Does not remove
/// the registry entry — that is `serve_host_executor`'s job once this
/// returns, since `registry` itself is not one of this function's
/// parameters.
async fn relay_dispatches(
    conn: Box<dyn Conn>,
    registration: Registration,
    store: &Arc<JobStore>,
    job_registry: &JobRegistry,
) {
    let Registration {
        mut dispatch_rx,
        mut attach_state_rx,
        mut cancel_rx,
        host_id,
        ..
    } = registration;

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
    let reader_task = tokio::spawn(forward_frames(read_half, frame_tx));

    // Jobs popped off `dispatch_rx` that have not yet reported a result
    // (#292). A job is added the moment it's popped — whether or not the
    // write to the wire that follows then actually succeeds — and removed
    // when its `JobResult` arrives; whatever remains when the connection
    // ends (including a dispatch whose write failed, timed out, or was never
    // attempted because the loop ended first) never ran to a reported result
    // and is failed terminally below, so a job can never stay stuck
    // PENDING/RUNNING after its host is gone.
    let mut in_flight: HashSet<String> = HashSet::new();
    // Succeeded jobs waiting for their outputs (#482 slice 6c-2). They stay in `in_flight` until settled, so the
    // cleanup below fails them if the host goes away first.
    let mut awaiting = futures_util::stream::FuturesUnordered::new();
    let mut awaiting_ids: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            Some(settled) = futures_util::StreamExt::next(&mut awaiting), if !awaiting.is_empty() => {
                in_flight.remove(&settled);
                awaiting_ids.remove(&settled);
            }
            dispatch = dispatch_rx.recv() => {
                let Some(dispatch) = dispatch else {
                    // The sending half was dropped: HostRegistry has no other
                    // reference to this channel, so this only happens if the
                    // registry entry was already replaced or removed.
                    break;
                };
                let job_id = dispatch.job_id.clone();
                // Track this job from the moment it's popped off the channel,
                // BEFORE the write below even starts (#292's silent-Pending
                // family) — not only once the write succeeds. If the write
                // fails or times out, the loop breaks without ever reaching
                // the success arm; without this, that dispatch would never
                // enter `in_flight` and the cleanup after the loop (below)
                // would have nothing to fail it with, leaving it stuck
                // PENDING forever despite having been popped and attempted.
                in_flight.insert(job_id.clone());
                match tokio::time::timeout(
                    DISPATCH_WRITE_TIMEOUT,
                    write_frame(&mut write_half, &OrchestratorMessage { op: Some(orchestrator_message::Op::Dispatch(dispatch)) }),
                )
                .await
                {
                    Ok(Ok(())) => {
                        // The dispatch reached the host: advance the job
                        // PENDING -> RUNNING and track it until its result
                        // comes back (or the connection dies).
                        mark_job_running(store, &job_id).await;
                    }
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
            attach_state = attach_state_rx.recv() => {
                let Some(attach_state) = attach_state else {
                    // Same reasoning as `dispatch_rx` above: only happens if
                    // this registry entry was already replaced or removed.
                    break;
                };
                let job_id = attach_state.job_id.clone();
                let attached = attach_state.attached;
                match tokio::time::timeout(
                    DISPATCH_WRITE_TIMEOUT,
                    write_frame(
                        &mut write_half,
                        &OrchestratorMessage { op: Some(orchestrator_message::Op::AttachStateChanged(attach_state)) },
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {
                        tracing::debug!(host_id, job_id, attached, "sent AttachStateChanged to host-executor");
                    }
                    Ok(Err(_)) => {
                        tracing::warn!(host_id, "failed writing AttachStateChanged to host-executor; closing");
                        break;
                    }
                    Err(_elapsed) => {
                        tracing::warn!(
                            host_id,
                            "writing AttachStateChanged to host-executor timed out; treating it as hung"
                        );
                        break;
                    }
                }
            }
            cancel = cancel_rx.recv() => {
                let Some(cancel) = cancel else {
                    // Same reasoning as `dispatch_rx` above: only happens if
                    // this registry entry was already replaced or removed.
                    break;
                };
                let job_id = cancel.job_id.clone();
                match tokio::time::timeout(
                    DISPATCH_WRITE_TIMEOUT,
                    write_frame(
                        &mut write_half,
                        &OrchestratorMessage { op: Some(orchestrator_message::Op::Cancel(cancel)) },
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {
                        tracing::debug!(host_id, job_id, "sent Cancel to host-executor");
                    }
                    Ok(Err(_)) => {
                        tracing::warn!(host_id, "failed writing Cancel to host-executor; closing");
                        break;
                    }
                    Err(_elapsed) => {
                        tracing::warn!(host_id, "writing Cancel to host-executor timed out; treating it as hung");
                        break;
                    }
                }
            }
            frame = frame_rx.recv() => {
                match frame {
                    Some(Ok(Some(message))) => match message.op {
                        Some(host_executor_message::Op::Result(result)) => {
                            if let Some(awaited) = record_job_result(store, job_registry, &mut in_flight, &mut awaiting_ids, result).await {
                                // The relay keeps reading frames and dispatching while the outputs arrive.
                                awaiting.push(awaited.settle(store, job_registry, OUTPUTS_WAIT));
                            }
                        }
                        // Stage 1 has no re-registration or capability-update
                        // machinery (#269): any other frame from the
                        // host-executor is unexpected but not fatal on its own.
                        _ => tracing::debug!(host_id, "ignoring an unexpected frame from a registered host-executor"),
                    },
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

    // The loop's own exit never ends `forward_frames` on its own: dropping
    // `frame_tx`'s receiver doesn't cancel the task sending into it, and
    // `tokio::io::split` keeps the underlying connection alive as long as
    // EITHER half is held — so a loop exit that leaves `reader_task` running
    // (e.g. a Dispatch write timeout, where the read side may still be
    // blocked waiting for bytes that will never come) would leak both the
    // task and the open socket, even after this function returns and drops
    // `write_half` (CodeRabbit, #312). `abort` forces the task to drop
    // `read_half` even mid-read; awaiting the handle (ignoring its
    // cancellation error) makes that drop happen before this function
    // returns, so the connection is actually closed, not just forgotten.
    reader_task.abort();
    let _ = reader_task.await;

    // The loop above can end with dispatches still sitting UNREAD in
    // `dispatch_rx`'s buffer — e.g. a same-peer reclaim (#292 item 4) whose
    // `register` call drops this connection's senders concurrently with
    // dispatches still queued behind a stalled write; `select!` can resolve
    // a different, also-ready branch (`frame_rx`/`attach_state_rx` going to
    // `None`) before ever observing them. Without draining here, those items
    // would simply be dropped when `dispatch_rx` goes out of scope at the
    // end of this function — the same silent loss #292 items 2/3 describe,
    // just via a different trigger than the write failing outright. `close()`
    // first so a `send` racing this drain can't land in the gap between it
    // and `serve_host_executor`'s `registry.remove` after this function
    // returns, and be lost the exact same way; everything already buffered
    // is then folded into `in_flight` so the cleanup loop immediately below
    // fails it like any other stranded job.
    dispatch_rx.close();
    while let Ok(dispatch) = dispatch_rx.try_recv() {
        in_flight.insert(dispatch.job_id);
    }

    // The connection is gone. Any job still in flight on it never reported a
    // result and never will (decision 12: no reconnect, no redelivery) — fail
    // it terminally rather than leaving it stuck PENDING/RUNNING forever
    // (#292). `finish` refuses from a terminal state, so a job that reported
    // just before the close, or was cancelled, is left as-is.
    for job_id in in_flight {
        fail_disconnected_job(store, job_registry, &job_id).await;
    }
}

/// Classify a reported [`JobResult`] into the terminal [`JobStatus`] to record
/// and the exit code to keep with it. The host reports physical facts; the
/// orchestrator decides the band (the same split the backend seam draws). A
/// clean `exit 0` of a booted guest — no timeout, no transport fault — is the
/// only `Succeeded`; a non-zero exit, a timeout, a transport fault, a guest
/// that never booted, or a run that never produced an exit at all is `Failed`,
/// carrying whatever exit code it did report (which may be none).
fn classify(result: &JobResult) -> (JobStatus, Option<i32>) {
    match result.exit_code {
        // A run that says it never booted is not a success whatever exit it carries (#829): the envelope's own
        // classifier says the same.
        Some(0) if result.booted && !result.timed_out && result.transport_error.is_none() => {
            (JobStatus::Succeeded, Some(0))
        }
        other => (JobStatus::Failed, other),
    }
}

/// Advance a dispatched job PENDING -> RUNNING off the connection task, via the
/// store's synchronous connection on a blocking thread. Best-effort: a store
/// fault is logged, never fatal to the connection — the dispatch already went
/// out, and a later result or disconnect still drives the job terminal.
async fn mark_job_running(store: &Arc<JobStore>, job_id: &str) {
    let store = Arc::clone(store);
    let jid = job_id.to_owned();
    match tokio::task::spawn_blocking(move || store.mark_running(&jid)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(job_id, error = %e, "could not mark the dispatched job running"),
        Err(e) => tracing::warn!(job_id, error = %e, "the mark-running store task failed"),
    }
}

/// How long a succeeded job waits for its outputs after its result arrives: the receive's own total limit and a
/// margin for the executor to open the link when the result reached us first.
const OUTPUTS_WAIT: std::time::Duration =
    std::time::Duration::from_secs(crate::data_link_recv::DEFAULT_TOTAL.as_secs() + 5 * 60);

/// Record a host-executor's reported result for one job, moving it to its
/// terminal state (#292), and drop it from `in_flight` so a later disconnect
/// does not then also fail it.
///
/// A succeeded job that declared outputs is not terminal yet (#482 slice 6c-2): the executor sends them over the
/// data link, and the job is recorded once they are in place. That job stays in `in_flight`, so a host that
/// disconnects meanwhile still fails it, and the caller gets an [`AwaitedOutputs`] to settle. sandyd decides from
/// its own record of what the job declared, never from the host's `outputs_follow`: a succeeded job that owes
/// outputs whose host says nothing follows is a failure, not a success with outputs missing.
///
/// NEVER logs `result.console`: it carries up to ~64 KiB of the job's OWN
/// stdout/stderr, which belongs in the job's record for `status`/`attach` to
/// surface, not in this host's own journald logs (INV-1, the host-executor's
/// matching no-log-the-console discipline on the other end).
async fn record_job_result(
    store: &Arc<JobStore>,
    job_registry: &JobRegistry,
    in_flight: &mut HashSet<String>,
    awaiting: &mut HashSet<String>,
    result: JobResult,
) -> Option<AwaitedOutputs> {
    let (status, exit_code) = classify(&result);
    let job_id = result.job_id.clone();
    let facts = RunFacts {
        booted: result.booted,
        timed_out: result.timed_out,
        transport_error: result.transport_error.clone(),
        egress: crate::envelope::egress_from_report(result.egress.as_ref()),
    };
    // Only a job dispatched on this connection may have its credential ended
    // here: a buggy or hostile executor must not revoke another host's job (#481).
    // A result for a job this connection never ran is not recorded either: it
    // would mark another host's job terminal and strand its credential.
    if !in_flight.contains(&job_id) {
        tracing::warn!(
            job_id,
            "a job result arrived for a job not dispatched on this connection; ignored"
        );
        return None;
    }
    // A second result for a job already waiting on its outputs is a buggy or hostile executor: it must not start a
    // second wait or fail the first.
    if awaiting.contains(&job_id) {
        tracing::warn!(
            job_id,
            "a second result arrived for a job awaiting its outputs; ignored"
        );
        return None;
    }
    let Some(job) = job_registry.get(&job_id) else {
        // A job the registry lost cannot be shown to owe nothing, so a success is not trusted.
        in_flight.remove(&job_id);
        if status == JobStatus::Succeeded {
            tracing::warn!(
                job_id,
                "a succeeded job is not registered, so its outputs cannot be checked; failing it"
            );
            let console = format!(
                "{}\n[sandy: the job is not registered, so its outputs cannot be checked]",
                result.console
            );
            finish_job(
                store,
                job_registry,
                &job_id,
                JobStatus::Failed,
                exit_code,
                console,
                &facts,
                OutputStatus::RequiredMissing,
            )
            .await;
        } else {
            finish_job(
                store,
                job_registry,
                &job_id,
                status,
                exit_code,
                result.console,
                &facts,
                OutputStatus::Complete,
            )
            .await;
        }
        return None;
    };
    if !job.data_outputs.is_empty() {
        // The host collects and sends after any run that returns, a non-zero exit included, so the wait does not
        // depend on the status: the exit is recorded as classified once the outputs are in.
        if result.outputs_follow {
            // The run is over: nothing uses the job's credential while its outputs arrive, so revoke it now, not
            // when they settle (up to `OUTPUTS_WAIT` later). `finish_job` releases again; that is a no-op.
            // Redact first: once the credential is released, `finish_job` can no longer find the token to redact.
            let (credentials, jid, console) = (job_registry.credentials().cloned(), job_id.clone(), result.console);
            let console = tokio::task::spawn_blocking(move || redact_console(credentials.as_deref(), &jid, console))
                .await
                .unwrap_or_else(|_| "[console withheld: it could not be redacted]".to_owned());
            job_registry.release_credential(&job_id);
            awaiting.insert(job_id.clone());
            return Some(AwaitedOutputs {
                job_id,
                status,
                exit_code,
                console,
                facts,
            });
        }
        if status == JobStatus::Succeeded {
            tracing::warn!(
                job_id,
                "the host reported no outputs for a job that declares outputs; failing it"
            );
            in_flight.remove(&job_id);
            let console = format!(
                "{}\n[sandy: the host reported no outputs for a job that declares outputs]",
                result.console
            );
            finish_job(
                store,
                job_registry,
                &job_id,
                JobStatus::Failed,
                exit_code,
                console,
                &facts,
                OutputStatus::RequiredMissing,
            )
            .await;
            return None;
        }
    }
    in_flight.remove(&job_id);
    finish_job(
        store,
        job_registry,
        &job_id,
        status,
        exit_code,
        result.console,
        &facts,
        OutputStatus::Complete,
    )
    .await;
    None
}

/// `console` with the staged token of `job_id` redacted. Blocking: it reads the staged file.
fn redact_console(credentials: Option<&crate::credential::JobCredentials>, job_id: &str, console: String) -> String {
    match credentials {
        Some(credentials) => match credentials.redact_bytes(job_id, console.into_bytes()) {
            Redaction::Redacted(bytes) | Redaction::NotHeld(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Redaction::Unavailable => "[console withheld: the job's credential could not be redacted]".to_owned(),
        },
        None => console,
    }
}

/// Move `job_id` to its terminal `status`, off the connection task, and end its credential and its outputs slot.
#[allow(
    clippy::too_many_arguments,
    reason = "the terminal record: the lifecycle status, its envelope facts and where it ran"
)]
async fn finish_job(
    store: &Arc<JobStore>,
    job_registry: &JobRegistry,
    job_id: &str,
    status: JobStatus,
    exit_code: Option<i32>,
    console: String,
    facts: &RunFacts,
    outputs: OutputStatus,
) {
    let store = Arc::clone(store);
    let credentials = job_registry.credentials().cloned();
    let jid = job_id.to_owned();
    let facts = facts.clone();
    let (host_id, allow) = job_registry
        .get(job_id)
        .map_or((None, None), |job| (job.host_id.clone(), job.egress_allow.clone()));
    let transition = tokio::task::spawn_blocking(move || {
        // The staged token never reaches the stored console, whatever the job printed.
        let console = redact_console(credentials.as_deref(), &jid, console);
        let console = crate::envelope::tail(&console, crate::envelope::MAX_CONSOLE_BYTES).to_owned();
        // The envelope carries the same redacted console, and its message (the executor's own words) is redacted
        // the same way, so neither holds the token.
        let mut envelope = crate::envelope::from_run(
            &jid,
            &facts,
            exit_code,
            outputs,
            console.clone(),
            host_id.as_deref(),
            allow.as_ref(),
        );
        let message = redact_console(credentials.as_deref(), &jid, envelope.message);
        envelope.message = crate::envelope::tail(&message, crate::envelope::MAX_MESSAGE_BYTES).to_owned();
        // The executor's egress reason is its own words too: redacted whole, then cut.
        crate::envelope::bound_egress_reason(&mut envelope, |reason| {
            redact_console(credentials.as_deref(), &jid, reason)
        });
        store.finish_with(&jid, status, exit_code, &console, Some(&envelope))
    })
    .await;
    match transition {
        Ok(Ok(Transition::Applied)) => {
            job_registry.mark_terminal(job_id);
            tracing::info!(job_id, ?status, ?exit_code, "recorded a job result");
        }
        Ok(Ok(Transition::Refused(current))) => {
            tracing::info!(
                job_id,
                ?current,
                "a job result arrived for an already-terminal job; keeping the existing one"
            )
        }
        Ok(Ok(Transition::NotFound)) => {
            tracing::warn!(job_id, "a job result arrived for a job this daemon does not know")
        }
        Ok(Err(e)) => tracing::warn!(job_id, error = %e, "could not record the job result"),
        Err(e) => tracing::warn!(job_id, error = %e, "the record-result store task failed"),
    }
    // The job is over: a receive still waiting on its link gives up (the first outcome stands, so a receive that
    // finished keeps its result).
    if let Some(job) = job_registry.get(job_id) {
        job.outputs
            .publish(crate::output_slot::OutputsState::Failed("the job ended".to_owned()));
    }
    // The job is over on its host whatever the store said: revoke its credential (#481).
    job_registry.release_credential(job_id);
}

/// A succeeded job whose outputs are still owed (#482 slice 6c-2): its terminal status waits for the receive.
#[derive(Debug)]
pub(crate) struct AwaitedOutputs {
    job_id: String,
    /// The status the run's own result classified to: what the job is recorded as once the outputs are in.
    status: JobStatus,
    exit_code: Option<i32>,
    console: String,
    /// The run's own physical facts, for the envelope built once the outputs settle.
    facts: RunFacts,
}

impl AwaitedOutputs {
    /// The awaited job.
    #[cfg(test)]
    pub(crate) fn job_id(&self) -> &str {
        &self.job_id
    }

    /// Wait for the outputs, at most `within`, then record the job's terminal status: `Succeeded` when they are in
    /// place, `Failed` when the receive failed or they did not arrive. Returns the job's id.
    pub(crate) async fn settle(
        self,
        store: &Arc<JobStore>,
        job_registry: &JobRegistry,
        within: std::time::Duration,
    ) -> String {
        let state = match job_registry.get(&self.job_id) {
            Some(job) => job.outputs.wait(within).await,
            None => crate::output_slot::OutputsState::Failed("the job is no longer registered".to_owned()),
        };
        let (status, console, outputs) = match state {
            crate::output_slot::OutputsState::Received(received) => {
                tracing::info!(
                    job_id = self.job_id,
                    files = received.files,
                    bytes = received.bytes,
                    "the job's outputs are in place"
                );
                (self.status, self.console, OutputStatus::Complete)
            }
            crate::output_slot::OutputsState::Failed(reason) => {
                tracing::warn!(
                    job_id = self.job_id,
                    reason,
                    "the job's outputs did not arrive; failing it"
                );
                (
                    JobStatus::Failed,
                    format!(
                        "{}\n[sandy: the job's outputs were not received: {reason}]",
                        self.console
                    ),
                    OutputStatus::RequiredMissing,
                )
            }
            // `wait` never returns a pending slot.
            crate::output_slot::OutputsState::Pending => {
                (JobStatus::Failed, self.console, OutputStatus::RequiredMissing)
            }
        };
        finish_job(
            store,
            job_registry,
            &self.job_id,
            status,
            self.exit_code,
            console,
            &self.facts,
            outputs,
        )
        .await;
        self.job_id
    }
}

/// Fail a job whose host-executor disconnected before reporting a result
/// (#292). `finish` refuses from a terminal state, so this is a no-op for a job
/// that reached a terminal status (a result that raced the close, a cancel)
/// just before the connection ended.
async fn fail_disconnected_job(store: &Arc<JobStore>, job_registry: &JobRegistry, job_id: &str) {
    let store = Arc::clone(store);
    let jid = job_id.to_owned();
    let host_id = job_registry.get(job_id).and_then(|job| job.host_id.clone());
    let transition = tokio::task::spawn_blocking(move || {
        let reason = "host-executor disconnected before reporting a result";
        let envelope = crate::envelope::infra_fault(&jid, reason, host_id.as_deref());
        store.finish_with(&jid, JobStatus::Failed, None, reason, Some(&envelope))
    })
    .await;
    match transition {
        Ok(Ok(Transition::Applied)) => {
            job_registry.mark_terminal(job_id);
            tracing::warn!(
                job_id,
                "failed an in-flight job: its host-executor disconnected before reporting a result"
            )
        }
        // Already terminal (a result raced the close, or the job was
        // cancelled): nothing to fail.
        Ok(Ok(_)) => {}
        Ok(Err(e)) => tracing::warn!(job_id, error = %e, "could not fail the in-flight job after a disconnect"),
        Err(e) => tracing::warn!(job_id, error = %e, "the disconnect-fail store task failed"),
    }
    // The host-executor is gone, so the job's RemoteLink (if it has one)
    // will never be presented by the executor it was minted for — a late
    // stream must not still be able to authenticate with it (#269: job
    // status alone doesn't gate authentication).
    job_registry.invalidate_remote_link(job_id);
    // Its credential (#481) has no live consumer left either.
    job_registry.release_credential(job_id);
}

/// Reads frames from `read_half` sequentially — never raced against anything
/// else, so each `read_frame` call always either completes or the whole task
/// ends, which is what makes it cancel-safe from [`relay_dispatches`]'s
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
            return; // relay_dispatches's loop already ended; nothing left to forward to
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

    /// Wraps a stream, counting how many times its read side returns
    /// `Pending` — a way to OBSERVE "the read has genuinely parked waiting
    /// for more bytes" from outside, instead of assuming it via timing
    /// (`yield_now`, which turned out not to reliably schedule a spawned
    /// task at a specific intermediate point — see the commit message on the
    /// test that uses this).
    struct PendingCounter<T> {
        inner: T,
        pending_reads: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for PendingCounter<T> {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            let result = std::pin::Pin::new(&mut this.inner).poll_read(cx, buf);
            if result.is_pending() {
                this.pending_reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            result
        }
    }

    impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for PendingCounter<T> {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    /// Waits until a [`PendingCounter`]'s count has risen above `baseline`,
    /// meaning its read has returned `Pending` again since `baseline` was
    /// captured — i.e. it consumed whatever was written and parked on the
    /// next thing it needs. Bounded to 10,000 yields: a loud failure, not a
    /// silent hang, if the read is never even attempted.
    async fn wait_for_read_to_park(
        pending_reads: &std::sync::atomic::AtomicUsize,
        baseline: usize,
    ) -> anyhow::Result<()> {
        for _ in 0..10_000 {
            if pending_reads.load(std::sync::atomic::Ordering::SeqCst) > baseline {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
        anyhow::bail!("the connection's read never parked again after the write")
    }

    /// A deterministic test fingerprint — not a real certificate digest, a
    /// fixed 64-hex-char value these tests pin `tcp_peer`'s IP to in
    /// [`ExecutorAllowlist`].
    fn test_fp() -> sandy_conn::Fingerprint {
        sandy_conn::Fingerprint::from_hex(&"aa".repeat(32)).expect("64-char hex literal")
    }

    /// A TLS mesh peer (decision 20: this listener is `listen_tls`-only once
    /// wired), carrying [`test_fp`]'s fingerprint.
    fn tcp_peer(ip: &str) -> PeerAddr {
        PeerAddr::TcpTls(SocketAddr::new(ip.parse().expect("ip literal"), 9000), test_fp())
    }

    /// A throwaway in-memory store for the connection-protocol tests that do
    /// not assert on job state — the dedicated result-propagation coverage
    /// lives in `handler.rs`'s real-wire tests, which drive `handle` + the
    /// store together.
    fn test_store() -> Arc<JobStore> {
        Arc::new(JobStore::open_in_memory().expect("in-memory store"))
    }

    /// A throwaway registry for tests that only need `serve_host_executor`'s
    /// `job_registry` parameter satisfied, not real job/remote-link state.
    fn test_job_registry() -> JobRegistry {
        JobRegistry::new().expect("getrandom for a test registry")
    }

    /// A registry whose terminal-retention sweep (#270) fires immediately,
    /// for tests that need to observe a job being reaped rather than wait
    /// out the real production default.
    fn test_job_registry_zero_retention() -> JobRegistry {
        JobRegistry::new()
            .expect("getrandom for a test registry")
            .with_retention(std::time::Duration::ZERO)
    }

    /// Regression (#368): `fail_disconnected_job` must invalidate the job's
    /// `RemoteLink`, not just mark it `Failed` in the store — job status
    /// alone doesn't gate agent-link authentication, so a late stream could
    /// otherwise still present the genuine, never-claimed token after the
    /// host-executor it was minted for disconnected.
    #[tokio::test]
    async fn fail_disconnected_job_invalidates_the_remote_link() -> anyhow::Result<()> {
        let store = test_store();
        store.insert_pending("job-1", b"m", "test/v1")?;
        let job_registry = test_job_registry();
        let peer_ip: std::net::IpAddr = "100.64.0.7".parse().context("peer ip literal")?;
        let mut job = crate::dispatch::mint_job_channel("job-1", job_registry.authority())
            .await
            .context("mint job channel")?;
        job.remote_link = Some(crate::link_auth::RemoteLink::new(peer_ip).context("mint remote link")?);
        let token = *job
            .remote_link
            .as_ref()
            .context("the minted job must have a remote link")?
            .token()
            .as_bytes();
        job_registry.insert("job-1".to_owned(), job);

        fail_disconnected_job(&store, &job_registry, "job-1").await;

        assert_eq!(store.status("job-1")?, Some(JobStatus::Failed));
        let auth = job_registry
            .authenticate_remote_link("job-1", peer_ip, &token)
            .map(drop);
        assert!(
            matches!(auth, Err(crate::link_auth::LinkAuthError::AlreadyClaimed)),
            "the genuine token must be refused once the disconnected job's host-executor is gone: {auth:?}"
        );
        Ok(())
    }

    /// #270: `fail_disconnected_job` must call `JobRegistry::mark_terminal`,
    /// not just mark the job `Failed` in the store — otherwise a job failed
    /// this way would sit in the registry forever, never reached by the
    /// retention sweep.
    #[tokio::test]
    async fn fail_disconnected_job_marks_the_job_terminal_for_the_registrys_retention_sweep() -> anyhow::Result<()> {
        let store = test_store();
        store.insert_pending("job-1", b"m", "test/v1")?;
        let job_registry = test_job_registry_zero_retention();
        let job = crate::dispatch::mint_job_channel("job-1", job_registry.authority())
            .await
            .context("mint job channel")?;
        job_registry.insert("job-1".to_owned(), job);

        fail_disconnected_job(&store, &job_registry, "job-1").await;

        // A second insert is what the sweep is tied to (#270).
        let job2 = crate::dispatch::mint_job_channel("job-2", job_registry.authority())
            .await
            .context("mint job channel")?;
        job_registry.insert("job-2".to_owned(), job2);

        assert!(
            job_registry.get("job-1").is_none(),
            "a disconnected job's channel must be reaped once retention elapses"
        );
        Ok(())
    }

    /// #270: `record_job_result` must call `JobRegistry::mark_terminal`
    /// whenever `store.finish` actually applies the transition — otherwise a
    /// normally-completed job's channel would sit in the registry forever.
    #[tokio::test]
    async fn record_job_result_marks_the_job_terminal_for_the_registrys_retention_sweep() -> anyhow::Result<()> {
        let store = test_store();
        store.insert_pending("job-1", b"m", "test/v1")?;
        let job_registry = test_job_registry_zero_retention();
        let job = crate::dispatch::mint_job_channel("job-1", job_registry.authority())
            .await
            .context("mint job channel")?;
        job_registry.insert("job-1".to_owned(), job);

        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let result = JobResult {
            digests: None,
            job_id: "job-1".to_owned(),
            booted: true,
            exit_code: Some(0),
            timed_out: false,
            transport_error: None,
            console: String::new(),
            outputs_follow: false,
            egress: None,
        };
        record_job_result(&store, &job_registry, &mut in_flight, &mut HashSet::new(), result).await;
        assert_eq!(store.status("job-1")?, Some(JobStatus::Succeeded));

        // A second insert is what the sweep is tied to (#270).
        let job2 = crate::dispatch::mint_job_channel("job-2", job_registry.authority())
            .await
            .context("mint job channel")?;
        job_registry.insert("job-2".to_owned(), job2);

        assert!(
            job_registry.get("job-1").is_none(),
            "a succeeded job's channel must be reaped once retention elapses"
        );
        Ok(())
    }

    fn capabilities() -> Capabilities {
        Capabilities {
            digests: false,
            supported_sandbox_kinds: vec![SandboxKind::Process.into()],
            arch: Arch::X8664.into(),
            attestation: false,
            supported_isolation_classes: vec![IsolationClass::Trusted.into()],
            shares_submitter_filesystem: false,
            transfer: false,
            egress_proxy: false,
        }
    }

    #[tokio::test]
    async fn an_allowed_host_registers_and_receives_a_queued_dispatch() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
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
                serve_host_executor(
                    Box::new(server),
                    tcp_peer("100.64.0.7"),
                    &allowlist,
                    &registry,
                    &test_store(),
                    &test_job_registry(),
                )
                .await;
            }
        });

        let response: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;
        assert!(matches!(response.op, Some(orchestrator_message::Op::Registered(_))));

        let dispatch = sandy_executor_proto::Dispatch {
            digests: false,
            job_id: "job-1".to_owned(),
            manifest: b"m".to_vec(),
            manifest_encoding: "test/v1".to_owned(),
            backend: SandboxKind::Process.into(),
            link_token: vec![0u8; 32],
            forward_back: "100.64.0.1:9000".to_owned(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
        };
        registry.send_dispatch("remote-host", dispatch.clone()).await?;

        let pushed: OrchestratorMessage = read_frame(&mut client).await?.context("expected a Dispatch push")?;
        match pushed.op {
            Some(orchestrator_message::Op::Dispatch(received)) => assert_eq!(received, dispatch),
            other => anyhow::bail!("expected Dispatch, got {other:?}"),
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;
        assert_eq!(
            registry.capabilities_of("remote-host"),
            None,
            "disconnecting must remove the host"
        );
        Ok(())
    }

    /// Regression (live M2 cross-machine run, reported by infra-f3): a host
    /// registered through the REAL wire path — `write_frame` encoding a
    /// `Register` frame, decoded by `serve_host_executor` off an actual byte
    /// stream — must be a placement candidate for the isolation class it
    /// declared. Every existing `pick_host_for` test (`host_registry.rs`)
    /// registers via a hand-built `Capabilities` fed directly to
    /// `HostRegistry::register`, bypassing the wire decode entirely; this is
    /// the one gap that distinguished the test suite (all green) from the
    /// live repro (`sandy daemon submit` returning a job that stayed
    /// `Pending` forever, zero placement activity, no dispatch error).
    #[tokio::test]
    async fn a_host_registered_through_a_real_wire_frame_is_a_placement_candidate() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
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
                serve_host_executor(
                    Box::new(server),
                    tcp_peer("100.64.0.7"),
                    &allowlist,
                    &registry,
                    &test_store(),
                    &test_job_registry(),
                )
                .await;
            }
        });

        let response: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;
        assert!(matches!(response.op, Some(orchestrator_message::Op::Registered(_))));

        let candidate = registry
            .pick_host_for(IsolationClass::Trusted.into(), SandboxKind::Process.into(), false)
            .expect("a host that declared Trusted over the real wire must be a Trusted placement candidate");
        assert_eq!(candidate.host_id, "remote-host");

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;
        Ok(())
    }

    /// Adversarial (decision 20: fail closed, no plaintext fallback): a peer
    /// that arrives as a bare `PeerAddr::Tcp` — not `TcpTls` — is refused
    /// outright, even one whose IP is genuinely allowlisted. Once this
    /// listener is bound via `listen_tls`, a plaintext peer here would mean a
    /// caller bug, never a real host-executor; this must not silently fall
    /// back to IP-only authorization.
    #[tokio::test]
    async fn a_plaintext_peer_is_refused_even_with_an_allowlisted_ip() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        // A REAL `Register` frame for an allowlisted IP's own host_id — on
        // the old code (no TcpTls-only check), this would register and get a
        // `Registered` reply. Writing it is what makes this test fail on the
        // old code instead of passing vacuously (a client that never writes
        // anything would also see no `Registered` reply before
        // `REGISTER_TIMEOUT`, regardless of whether the plaintext check
        // exists).
        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        let plaintext_peer = PeerAddr::Tcp(SocketAddr::new("100.64.0.7".parse()?, 9000));
        let serving = tokio::spawn(async move {
            serve_host_executor(
                Box::new(server),
                plaintext_peer,
                &allowlist,
                &registry,
                &test_store(),
                &test_job_registry(),
            )
            .await;
            registry
        });

        // The server must close having sent nothing, not a `Registered`
        // reply — read to EOF, not a single `read_frame` call, since a
        // `read_frame` that happens to return `Ok(None)` already proves
        // "no frame", but reading raw bytes first is the more direct check
        // that nothing at all was written before the close.
        use tokio::io::AsyncReadExt;
        let mut leftover = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut leftover))
            .await
            .context("a plaintext peer must be refused promptly, not held open")?
            .context("reading to EOF")?;
        assert!(
            leftover.is_empty(),
            "a plaintext peer must never receive a Registered reply, got {leftover:?}"
        );

        let registry = tokio::time::timeout(std::time::Duration::from_secs(5), serving).await??;
        assert_eq!(
            registry.capabilities_of("remote-host"),
            None,
            "a plaintext peer must never register, regardless of its IP or a real Register frame"
        );
        Ok(())
    }

    /// Adversarial (#263, D5): a peer not on the allowlist gets
    /// `RegisterRefused`, never `Registered`, and is never dispatch-eligible.
    #[tokio::test]
    async fn an_unknown_peer_is_refused_not_registered() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
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
            serve_host_executor(
                Box::new(server),
                tcp_peer("100.64.0.9"),
                &allowlist,
                &registry,
                &test_store(),
                &test_job_registry(),
            )
            .await;
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
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
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
            serve_host_executor(
                Box::new(server),
                tcp_peer("100.64.0.9"),
                &allowlist,
                &registry,
                &test_store(),
                &test_job_registry(),
            )
            .await;
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
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (client, server) = tokio::io::duplex(4096);

        let serving = tokio::spawn(async move {
            serve_host_executor(
                Box::new(server),
                tcp_peer("100.64.0.7"),
                &allowlist,
                &registry,
                &test_store(),
                &test_job_registry(),
            )
            .await;
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
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(64);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
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
                serve_host_executor(
                    Box::new(server),
                    tcp_peer("100.64.0.7"),
                    &allowlist,
                    &registry,
                    &test_store(),
                    &test_job_registry(),
                )
                .await;
            }
        });

        let _registered: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;

        // The first send is picked up by the connection loop's select! and
        // its write stalls immediately (the duplex buffer is too small for
        // even one frame) — this one slot is never returned to the channel.
        registry.send_dispatch("remote-host", test_dispatch("job-1")).await?;

        // Fill the channel's full capacity (8) behind the stalled write:
        // these succeed immediately since nothing has consumed from the
        // channel since the first send.
        for n in 0..8 {
            registry
                .send_dispatch("remote-host", test_dispatch(&format!("job-fill-{n}")))
                .await?;
        }

        // The 9th send has no room left and genuinely blocks — exactly the
        // caller this fix exists for. Spawned so the test can advance the
        // clock concurrently with it being blocked.
        let blocked_registry = std::sync::Arc::clone(&registry);
        let blocked_send = tokio::spawn(async move {
            blocked_registry
                .send_dispatch("remote-host", test_dispatch("job-overflow"))
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

        // Nothing past this point is time-gated; resume real time so the
        // EOF check below has a real timeout to fail against if the cleanup
        // it's checking for regresses, instead of a virtual one nothing
        // would ever advance.
        tokio::time::resume();

        let blocked_result = blocked_send.await?;
        assert_eq!(
            blocked_result,
            Err(crate::host_registry::DispatchSendError::ConnectionClosing),
            "a send blocked on the full channel must resolve to ConnectionClosing once the write times out, not hang"
        );

        assert_eq!(
            registry.capabilities_of("remote-host"),
            None,
            "a hung Dispatch write must disconnect and deregister the host"
        );

        let resend = registry.send_dispatch("remote-host", test_dispatch("job-2")).await;
        assert!(
            matches!(resend, Err(crate::host_registry::DispatchSendError::NoSuchHost)),
            "a send after full deregistration must fail with NoSuchHost, not hang: got {resend:?}"
        );

        // The peer must see the connection actually close, not just the
        // registry forget about it (CodeRabbit, #312): `tokio::io::split`
        // keeps the duplex stream alive as long as either half survives, so
        // reading to EOF here only completes if `serve_host_executor` dropped
        // BOTH `write_half` (on function return) and the `forward_frames`
        // task's `read_half` (via the explicit abort+await) before `serve`
        // resolved. `read_to_end`, not a single read: the stalled `Dispatch`
        // write left whatever bytes it managed to push before blocking still
        // sitting in the duplex buffer, which a one-shot read would observe
        // as "more data," not EOF.
        use tokio::io::AsyncReadExt;
        let mut leftover = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.read_to_end(&mut leftover))
            .await
            .context("the host-executor's peer must observe EOF once the connection is torn down, not hang")?
            .context("reading the leftover bytes to EOF")?;

        drop(client);
        Ok(())
    }

    /// Regression (#292 items 2/3's silent-Pending family, and the new
    /// strand this same fix covers): every dispatch popped off `dispatch_rx`
    /// before the connection ends must land in a terminal store state, never
    /// left silently `Pending` — whether its own write failed, timed out, or
    /// (job-2/job-3 here) was never even attempted because job-1's write
    /// stalled first and the loop exited on its timeout before draining the
    /// rest of the channel. Unlike `a_hung_host_is_disconnected_after_the_dispatch_write_timeout`,
    /// which only proves the channel-level `DispatchSendError` behaviour
    /// against a throwaway store, this inserts each job `Pending` first and
    /// asserts the real terminal status — a store with no rows for these ids
    /// would let a broken fix pass vacuously (`fail_disconnected_job`'s
    /// `NotFound` case is silently ignored).
    #[tokio::test(start_paused = true)]
    async fn every_dispatch_popped_before_the_connection_ends_is_failed_not_left_pending() -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(64);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        let store = test_store();
        let job_registry = test_job_registry();
        for job_id in ["job-1", "job-2", "job-3"] {
            store.insert_pending(job_id, b"m", "test/v1")?;
        }

        let registry = std::sync::Arc::new(registry);
        let allowlist = std::sync::Arc::new(allowlist);
        let serve = tokio::spawn({
            let registry = std::sync::Arc::clone(&registry);
            let allowlist = std::sync::Arc::clone(&allowlist);
            let store = std::sync::Arc::clone(&store);
            async move {
                serve_host_executor(
                    Box::new(server),
                    tcp_peer("100.64.0.7"),
                    &allowlist,
                    &registry,
                    &store,
                    &job_registry,
                )
                .await;
            }
        });

        let _registered: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;

        // job-1's write stalls immediately (the duplex buffer is too small
        // for even one frame); job-2 and job-3 queue behind it in the
        // channel, never popped before the loop below exits on the write
        // timeout.
        registry.send_dispatch("remote-host", test_dispatch("job-1")).await?;
        registry.send_dispatch("remote-host", test_dispatch("job-2")).await?;
        registry.send_dispatch("remote-host", test_dispatch("job-3")).await?;

        tokio::time::advance(DISPATCH_WRITE_TIMEOUT + std::time::Duration::from_millis(1)).await;
        serve.await?;

        for job_id in ["job-1", "job-2", "job-3"] {
            assert_eq!(
                store.status(job_id)?,
                Some(JobStatus::Failed),
                "{job_id} must be failed, not left silently Pending, once its host-executor connection ends"
            );
        }

        drop(client);
        Ok(())
    }

    fn test_dispatch(job_id: &str) -> sandy_executor_proto::Dispatch {
        sandy_executor_proto::Dispatch {
            digests: false,
            job_id: job_id.to_owned(),
            manifest: b"m".to_vec(),
            manifest_encoding: "test/v1".to_owned(),
            backend: SandboxKind::Process.into(),
            link_token: vec![0u8; 32],
            forward_back: "100.64.0.1:9000".to_owned(),
            required_isolation_class: IsolationClass::Trusted.into(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            secrets: Vec::new(),
            data_link_token: Vec::new(),
            egress: None,
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
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
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
                serve_host_executor(
                    Box::new(server),
                    tcp_peer("100.64.0.7"),
                    &allowlist,
                    &registry,
                    &test_store(),
                    &test_job_registry(),
                )
                .await;
            }
        });

        let _registered: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;

        registry.send_dispatch("remote-host", test_dispatch("job-1")).await?;

        // An unexpected frame from the host, sent right as the first dispatch
        // is in flight — the interleaving this test exists to exercise. The
        // loop's `Ok(Some(_))` arm just logs and continues, never fatal.
        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        registry.send_dispatch("remote-host", test_dispatch("job-2")).await?;
        registry.send_dispatch("remote-host", test_dispatch("job-3")).await?;

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

    /// Genuinely discriminating regression test (CodeRabbit on #312, after
    /// the honest admission that the one above never reproduces the race
    /// through real scheduling): forces the exact interleaving the old code
    /// was vulnerable to by controlling the wire bytes and synchronization
    /// directly, rather than hoping `select!`'s poll order cooperates. Took
    /// two real attempts to get right — recorded here since both failure
    /// modes are easy to reintroduce silently:
    ///
    /// 1. A `yield_now` between writing the length prefix and calling `send_dispatch` does NOT reliably get the spawned
    ///    connection task polled at that intermediate point — confirmed via tracing, the task's first real poll didn't
    ///    happen until this test's own task hit a genuinely blocking `.await` much later, by which point the full frame
    ///    AND the dispatch were already both available, so `select!` saw two ready branches (a coin flip) instead of
    ///    one ready and one pending (deterministic). Fixed with [`PendingCounter`], which makes "the read has genuinely
    ///    parked on the payload" an observed fact instead of a scheduling assumption.
    /// 2. Even with that fixed, writing the payload immediately after `send_dispatch` could still let both branches
    ///    become ready before the connection task's next poll, reintroducing the same coin flip one step later. Fixed
    ///    by reading the `job-1` dispatch push back to completion BEFORE writing the payload: that read only completes
    ///    once `select!` has already resolved the dispatch branch (and dropped the sibling read with it), so the
    ///    payload genuinely lands on a connection that has nothing pending to confuse it with.
    ///
    /// Verified both directions empirically, not assumed: 30/30 runs failed
    /// against the pre-fix code (this exact test grafted onto commit
    /// `a4e3e7b`, before the `forward_frames` split existed) and 30/30 runs
    /// passed against the code as committed here.
    #[tokio::test]
    async fn a_dispatch_becoming_ready_while_an_inbound_frame_is_only_half_written_does_not_desync_the_next_frame()
    -> anyhow::Result<()> {
        let allowlist = ExecutorAllowlist::new([("100.64.0.7".parse()?, test_fp())]);
        let registry = HostRegistry::default();
        let (mut client, server) = tokio::io::duplex(4096);

        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;

        // `yield_now` alone does not reliably get a spawned task polled at a
        // specific intermediate point — checked directly (see the commit
        // message): the spawned server task doesn't actually run until this
        // test's own task hits a GENUINELY blocking await, which a one-shot
        // `yield_now` after a `write_all` that itself completes without
        // blocking does not provide. `PendingCounter` makes the wait for "the
        // read side has genuinely parked on the payload" an observed fact
        // instead of an assumption about scheduling.
        let pending_reads = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = PendingCounter {
            inner: server,
            pending_reads: std::sync::Arc::clone(&pending_reads),
        };

        let registry = std::sync::Arc::new(registry);
        let allowlist = std::sync::Arc::new(allowlist);
        let serve = tokio::spawn({
            let registry = std::sync::Arc::clone(&registry);
            let allowlist = std::sync::Arc::clone(&allowlist);
            async move {
                serve_host_executor(
                    Box::new(server),
                    tcp_peer("100.64.0.7"),
                    &allowlist,
                    &registry,
                    &test_store(),
                    &test_job_registry(),
                )
                .await;
            }
        });

        let _registered: OrchestratorMessage = read_frame(&mut client)
            .await?
            .context("expected a Registered response")?;

        // An "unexpected" inbound frame (stage 1 has no real host→orchestrator
        // message; another Register stands in), split manually into its
        // length prefix and payload so each can be written separately.
        use sandy_executor_proto::Message;
        let unexpected = HostExecutorMessage {
            op: Some(host_executor_message::Op::Register(Register {
                host_id: "remote-host".to_owned(),
                capabilities: Some(capabilities()),
            })),
        };
        let payload = unexpected.encode_to_vec();
        let len = u32::try_from(payload.len()).context("payload length")?;

        use tokio::io::AsyncWriteExt;
        let baseline = pending_reads.load(std::sync::atomic::Ordering::SeqCst);
        client
            .write_all(&len.to_be_bytes())
            .await
            .context("write the length prefix alone")?;
        client.flush().await?;

        // Wait for an OBSERVED fact — the connection's read has genuinely
        // returned `Pending` at least once more since the write above — not
        // an assumed one.
        wait_for_read_to_park(&pending_reads, baseline)
            .await
            .context("the connection's read never parked waiting for more bytes after the length-prefix-only write")?;

        // The length prefix is now consumed with no payload bytes behind it:
        // the read is necessarily still pending on `read_exact`, not a race,
        // an observed fact about what's been written and already polled.
        registry.send_dispatch("remote-host", test_dispatch("job-1")).await?;

        // Read the resulting push back BEFORE writing the payload, not
        // after: this was the second gap once `pending_reads` fixed the
        // first one — writing the payload right after `send_dispatch` can
        // still let BOTH branches become ready before the connection task is
        // next polled (if neither this test's `.await`s nor `send_dispatch`
        // itself happens to yield control in between), turning the
        // deterministic "ready vs pending" case back into the same
        // scheduling-order coin flip this test exists to not depend on.
        // Reading this push to completion proves `select!` already resolved
        // the dispatch branch — and with it, dropped the sibling read that
        // had consumed the length prefix — before a single payload byte
        // exists for it to be confused with.
        let pushed: OrchestratorMessage = read_frame(&mut client).await?.context("expected a Dispatch push")?;
        match pushed.op {
            Some(orchestrator_message::Op::Dispatch(received)) => assert_eq!(received.job_id, "job-1"),
            other => anyhow::bail!("expected a Dispatch push for job-1, got {other:?}"),
        }

        // `select!` on the old code already deterministically picked the
        // ready dispatch branch over the still-pending read (proven by the
        // read above), dropping the length prefix already consumed. Only
        // now does the payload follow.
        let before_payload = pending_reads.load(std::sync::atomic::Ordering::SeqCst);
        client.write_all(&payload).await.context("write the payload")?;
        client.flush().await?;
        // Same discipline as above, not just for the forced split: confirm
        // the reader actually consumed this frame and parked again before
        // trusting the dispatch delivery that follows to say anything about
        // it (CodeRabbit, #312) — the 30/30 empirical result already proved
        // this test discriminates correctly without it, but asserting the
        // intermediate state explicitly, consistently, costs nothing and
        // means a future change to any step doesn't quietly lose the
        // guarantee this one still relies on scheduling luck for.
        wait_for_read_to_park(&pending_reads, before_payload)
            .await
            .context("the reader must decode the completed frame and park on the next prefix")?;

        registry.send_dispatch("remote-host", test_dispatch("job-2")).await?;
        let pushed: OrchestratorMessage = read_frame(&mut client).await?.context("expected a Dispatch push")?;
        match pushed.op {
            Some(orchestrator_message::Op::Dispatch(received)) => assert_eq!(
                received.job_id, "job-2",
                "the deliberately-forced interleaving must not desync a later dispatch"
            ),
            other => anyhow::bail!("expected a Dispatch push for job-2, got {other:?}"),
        }

        // The assertions above only cover the orchestrator→host-executor
        // direction (outbound dispatches), which a desync on the OTHER
        // direction (host-executor→orchestrator, what was actually forced
        // above) can't corrupt — write_frame on `write_half` has nothing to
        // do with whatever garbage the read side may have landed on
        // (CodeRabbit, #312: "the write half can deliver all three dispatches
        // even if the reader loses inbound bytes"). Send one more, cleanly
        // framed inbound message and confirm the connection is still alive
        // and dispatch-eligible afterward: on a desync, the next `read_frame`
        // call starts misaligned on whatever bytes follow the dropped
        // read's already-consumed prefix, which this cleanly-framed message
        // supplies — almost certainly failing to parse as a valid frame
        // (`TooLarge` or `Decode`), breaking the loop and deregistering the
        // host before this check runs.
        let before_clean = pending_reads.load(std::sync::atomic::Ordering::SeqCst);
        write_frame(
            &mut client,
            &HostExecutorMessage {
                op: Some(host_executor_message::Op::Register(Register {
                    host_id: "remote-host".to_owned(),
                    capabilities: Some(capabilities()),
                })),
            },
        )
        .await?;
        wait_for_read_to_park(&pending_reads, before_clean)
            .await
            .context("the reader must consume the clean frame before the registration check")?;
        registry
            .send_dispatch("remote-host", test_dispatch("job-3"))
            .await
            .context(
                "the host must still be registered and dispatch-eligible after a clean frame following the forced \
                 interleaving — a desync would have broken the connection by now",
            )?;
        let pushed: OrchestratorMessage = read_frame(&mut client).await?.context("expected a Dispatch push")?;
        match pushed.op {
            Some(orchestrator_message::Op::Dispatch(received)) => assert_eq!(received.job_id, "job-3"),
            other => anyhow::bail!("expected a Dispatch push for job-3, got {other:?}"),
        }

        drop(client);
        tokio::time::timeout(std::time::Duration::from_secs(5), serve).await??;
        Ok(())
    }

    /// A registered, running job that declares one output, as a `transfer` host's job would.
    async fn job_owing_outputs(store: &Arc<JobStore>, job_registry: &JobRegistry, job_id: &str) -> anyhow::Result<()> {
        store.insert_pending(job_id, b"m", "test/v1")?;
        store.mark_running(job_id)?;
        let mut job = crate::dispatch::mint_job_channel(job_id, job_registry.authority())
            .await
            .context("mint job channel")?;
        job.data_outputs = vec![sandy_executor_proto::Output {
            name: Some("out".to_owned()),
            dest: "/nowhere".to_owned(),
        }];
        job_registry.insert(job_id.to_owned(), job);
        Ok(())
    }

    fn result_for(job_id: &str, exit_code: i32, outputs_follow: bool) -> JobResult {
        JobResult {
            digests: None,
            job_id: job_id.to_owned(),
            booted: true,
            exit_code: Some(exit_code),
            timed_out: false,
            transport_error: None,
            console: String::new(),
            outputs_follow,
            egress: None,
        }
    }

    const SOON: std::time::Duration = std::time::Duration::from_secs(5);

    /// #482 slice 6c-2: a succeeded job that owes outputs is not terminal when its result arrives; it is terminal
    /// once the receive says the outputs are in place.
    #[tokio::test]
    async fn a_succeeded_job_that_owes_outputs_is_terminal_once_they_arrive() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);

        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 0, true),
        )
        .await
        .context("a job that owes outputs must wait for them")?;
        assert_eq!(awaited.job_id(), "job-1");
        assert_eq!(
            store.status("job-1")?,
            Some(JobStatus::Running),
            "not terminal before the outputs"
        );
        assert!(
            in_flight.contains("job-1"),
            "still in flight: a disconnect must still fail it"
        );

        let job = job_registry.get("job-1").context("registered")?;
        job.outputs.publish(crate::output_slot::OutputsState::Received(
            crate::data_link_recv::Received { files: 1, bytes: 3 },
        ));
        awaited.settle(&store, &job_registry, SOON).await;
        assert_eq!(store.status("job-1")?, Some(JobStatus::Succeeded));
        Ok(())
    }

    /// A job whose outputs failed to arrive is a failure, never a success with missing outputs.
    #[tokio::test]
    async fn a_failed_receive_fails_the_job() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 0, true),
        )
        .await
        .context("owed")?;
        let job = job_registry.get("job-1").context("registered")?;
        job.outputs
            .publish(crate::output_slot::OutputsState::Failed("the link closed".to_owned()));
        awaited.settle(&store, &job_registry, SOON).await;
        assert_eq!(store.status("job-1")?, Some(JobStatus::Failed));
        Ok(())
    }

    /// A job registered and running, owing nothing: its result goes straight to the terminal record.
    async fn running_job(store: &Arc<JobStore>, job_registry: &JobRegistry, job_id: &str) -> anyhow::Result<()> {
        store.insert_pending(job_id, b"m", "test/v1")?;
        store.mark_running(job_id)?;
        let job = crate::dispatch::mint_job_channel(job_id, job_registry.authority())
            .await
            .context("mint job channel")?;
        job_registry.insert(job_id.to_owned(), job);
        Ok(())
    }

    /// A2 (#483): a terminal job carries the same locked result envelope a direct run prints (INV-11): the status and
    /// retryable flag `classify_outcome` gives the same physical facts, one row per `JobResult` shape. `JobStatus`
    /// stays the two-valued lifecycle band it is today.
    #[tokio::test]
    async fn a_terminal_job_records_the_envelope_the_direct_classifier_gives() -> anyhow::Result<()> {
        use sandy::Status;
        // (name, booted, exit_code, timed_out, transport_error, JobStatus, envelope status, retryable)
        type Row<'a> = (
            &'a str,
            bool,
            Option<i32>,
            bool,
            Option<&'a str>,
            JobStatus,
            Status,
            bool,
        );
        let rows: [Row<'_>; 6] = [
            (
                "exit 0",
                true,
                Some(0),
                false,
                None,
                JobStatus::Succeeded,
                Status::Succeeded,
                false,
            ),
            (
                "guest failure",
                true,
                Some(3),
                false,
                None,
                JobStatus::Failed,
                Status::Failed,
                false,
            ),
            (
                "timeout",
                true,
                None,
                true,
                None,
                JobStatus::Failed,
                Status::Failed,
                false,
            ),
            (
                "transport error",
                true,
                Some(0),
                false,
                Some("link lost"),
                JobStatus::Failed,
                Status::Failed,
                true,
            ),
            (
                "never booted",
                false,
                None,
                false,
                None,
                JobStatus::Failed,
                Status::Failed,
                true,
            ),
            // #829: a result that says it never booted cannot be a success, whatever exit code it carries.
            (
                "never booted, exit 0",
                false,
                Some(0),
                false,
                None,
                JobStatus::Failed,
                Status::Failed,
                true,
            ),
        ];
        for (name, booted, exit_code, timed_out, transport_error, job_status, status, retryable) in rows {
            let (store, job_registry) = (test_store(), test_job_registry());
            running_job(&store, &job_registry, "job-1").await?;
            let result = JobResult {
                digests: None,
                job_id: "job-1".to_owned(),
                booted,
                exit_code,
                timed_out,
                transport_error: transport_error.map(str::to_owned),
                console: "hi\n".to_owned(),
                outputs_follow: false,
                egress: None,
            };
            record_job_result(
                &store,
                &job_registry,
                &mut HashSet::from(["job-1".to_owned()]),
                &mut HashSet::new(),
                result,
            )
            .await;
            assert_eq!(store.status("job-1")?, Some(job_status), "{name}: lifecycle status");
            let envelope = store
                .envelope("job-1")?
                .with_context(|| format!("{name}: a terminal job must carry an envelope"))?;
            assert_eq!(envelope.status, status, "{name}: envelope status");
            assert_eq!(envelope.retryable, retryable, "{name}: retryable");
            assert_eq!(envelope.job_id, "job-1", "{name}");
            assert_eq!(envelope.result_schema_version, sandy::RESULT_SCHEMA_VERSION, "{name}");
            assert_eq!(envelope.logs.tail, "hi\n", "{name}: the console is the log tail");
        }
        Ok(())
    }

    /// A2 (#483): the envelope's audit receipt is honest about what the daemon knows. `who` is the local-uid fallback
    /// (`authenticated: false`, #413), and the egress boundary is `Unenforced` with a reason, never "applied", while no
    /// executor reports an outcome (A2b).
    #[tokio::test]
    async fn the_envelope_receipt_does_not_claim_what_the_daemon_did_not_observe() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        running_job(&store, &job_registry, "job-1").await?;
        record_job_result(
            &store,
            &job_registry,
            &mut HashSet::from(["job-1".to_owned()]),
            &mut HashSet::new(),
            result_for("job-1", 0, false),
        )
        .await;
        let envelope = store.envelope("job-1")?.context("a terminal job carries an envelope")?;
        let receipt = envelope.receipt.context("the envelope carries the audit receipt")?;
        assert!(!receipt.host_observed.who.authenticated, "no verified caps yet (#413)");
        assert_eq!(
            receipt.host_observed.egress.status,
            sandy::EgressEnforcement::Unenforced
        );
        assert!(
            receipt
                .host_observed
                .egress
                .reason
                .is_some_and(|reason| reason.contains("not report")),
            "the reason says the executor reported nothing"
        );
        assert_eq!(receipt.guest_reported.exit_code, Some(0));
        Ok(())
    }

    /// A2 (#483): the envelope is final only once the outputs are settled: a receive that fails turns an exit-0 run
    /// into a failed envelope, and one that succeeds keeps it succeeded.
    #[tokio::test]
    async fn the_envelope_of_a_job_owing_outputs_follows_the_receive() -> anyhow::Result<()> {
        use sandy::Status;
        for (received, want) in [(true, Status::Succeeded), (false, Status::Failed)] {
            let (store, job_registry) = (test_store(), test_job_registry());
            job_owing_outputs(&store, &job_registry, "job-1").await?;
            let awaited = record_job_result(
                &store,
                &job_registry,
                &mut HashSet::from(["job-1".to_owned()]),
                &mut HashSet::new(),
                result_for("job-1", 0, true),
            )
            .await
            .context("owed")?;
            assert!(
                store.envelope("job-1")?.is_none(),
                "no envelope before the outputs settle"
            );
            let job = job_registry.get("job-1").context("registered")?;
            job.outputs.publish(if received {
                crate::output_slot::OutputsState::Received(crate::data_link_recv::Received { files: 1, bytes: 3 })
            } else {
                crate::output_slot::OutputsState::Failed("the link closed".to_owned())
            });
            awaited.settle(&store, &job_registry, SOON).await;
            let envelope = store.envelope("job-1")?.context("settled: an envelope")?;
            assert_eq!(envelope.status, want, "received={received}");
        }
        Ok(())
    }

    /// A2 (#483, sandy-5e F3 on #828): `Status` carries the console twice, as `console_tail` and inside the envelope's
    /// log tail, and the executor's own frame can be near the 1 MiB limit. The daemon bounds both to a tail, so even a
    /// console of control characters (six bytes each as JSON) leaves a `Status` reply that fits one frame.
    #[tokio::test]
    async fn a_huge_console_leaves_a_status_reply_that_fits_one_frame() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        running_job(&store, &job_registry, "job-1").await?;
        let console = "\u{1}".repeat(900 * 1024);
        record_job_result(
            &store,
            &job_registry,
            &mut HashSet::from(["job-1".to_owned()]),
            &mut HashSet::new(),
            JobResult {
                console,
                ..result_for("job-1", 0, false)
            },
        )
        .await;
        let detail = store.detail("job-1")?.context("job detail")?;
        let envelope = store.envelope_json("job-1")?.context("an envelope")?;
        let reply = sandy_control_proto::StatusResponse {
            job_id: "job-1".to_owned(),
            status: i32::from(detail.status),
            exit_code: detail.exit_code,
            console_tail: detail.console,
            result_envelope: Some(envelope.into_bytes()),
        };
        assert!(
            sandy_executor_proto::Message::encoded_len(&reply) < sandy_control_proto::MAX_FRAME_LEN as usize,
            "the Status reply must fit one frame"
        );
        Ok(())
    }

    /// The allow-list a test job was dispatched with.
    fn allow() -> sandy::AllowList {
        sandy::AllowList {
            rules: vec![sandy::EgressRule {
                host: "example.com".to_owned(),
                port: 443,
            }],
        }
    }

    /// The egress receipt of the envelope the daemon records for a job dispatched with `allow()` whose executor sent
    /// `report`.
    async fn egress_receipt_for(
        report: Option<sandy_executor_proto::EgressReport>,
    ) -> anyhow::Result<sandy::EgressReceipt> {
        egress_receipt_dispatched_with(report, Some(allow())).await
    }

    /// [`egress_receipt_for`] for a job dispatched with `allow` (`None` for a job with no policy).
    async fn egress_receipt_dispatched_with(
        report: Option<sandy_executor_proto::EgressReport>,
        allow: Option<sandy::AllowList>,
    ) -> anyhow::Result<sandy::EgressReceipt> {
        let (store, job_registry) = (test_store(), test_job_registry());
        store.insert_pending("job-1", b"m", "test/v1")?;
        store.mark_running("job-1")?;
        let mut job = crate::dispatch::mint_job_channel("job-1", job_registry.authority())
            .await
            .context("mint job channel")?;
        job.egress_allow = allow;
        job_registry.insert("job-1".to_owned(), job);
        record_job_result(
            &store,
            &job_registry,
            &mut HashSet::from(["job-1".to_owned()]),
            &mut HashSet::new(),
            JobResult {
                egress: report,
                ..result_for("job-1", 0, false)
            },
        )
        .await;
        let envelope = store.envelope("job-1")?.context("a terminal job carries an envelope")?;
        Ok(envelope
            .receipt
            .context("the envelope carries the audit receipt")?
            .host_observed
            .egress)
    }

    /// A2b (#483): the envelope's egress receipt reads the executor's report: proxied is enforced with the allow-list
    /// the job was dispatched with; unenforced and failed carry their reason and no allow-list; no report, or an
    /// unspecified one, is unenforced and says the executor reported nothing. Never applied without a report.
    #[tokio::test]
    async fn the_egress_receipt_reads_the_executors_report() -> anyhow::Result<()> {
        use sandy::EgressEnforcement::{Enforced, Unenforced};
        use sandy_executor_proto::{EgressReport, EgressState};
        let report = |state: EgressState, reason: Option<&str>| {
            Some(EgressReport {
                state: state.into(),
                reason: reason.map(str::to_owned),
            })
        };
        let rows = vec![
            ("proxied", report(EgressState::Proxied, None), Enforced, None, true),
            (
                "unenforced",
                report(EgressState::Unenforced, Some("macOS has no boundary")),
                Unenforced,
                Some("macOS has no boundary"),
                false,
            ),
            (
                "failed",
                report(EgressState::Failed, Some("proxy refused")),
                Unenforced,
                Some("proxy refused"),
                false,
            ),
            ("no report", None, Unenforced, Some("did not report"), false),
            (
                "unspecified",
                report(EgressState::Unspecified, None),
                Unenforced,
                Some("did not report"),
                false,
            ),
        ];
        for (name, sent, status, reason, applied) in rows {
            let receipt = egress_receipt_for(sent).await?;
            assert_eq!(receipt.status, status, "{name}: status");
            if let Some(reason) = reason {
                assert!(
                    receipt.reason.as_deref().is_some_and(|r| r.contains(reason)),
                    "{name}: reason {:?}",
                    receipt.reason
                );
            }
            assert_eq!(receipt.allow_list, applied.then(allow), "{name}: allow-list");
        }
        Ok(())
    }

    /// A2b (#483, sandy-5e F2 on #835): a report for a job dispatched with no policy is ignored. `PROXIED` would
    /// otherwise read as `Enforced` with an empty allow-list for a job that never asked for a boundary.
    #[tokio::test]
    async fn an_egress_report_for_a_job_without_a_policy_is_ignored() -> anyhow::Result<()> {
        let report = sandy_executor_proto::EgressReport {
            state: sandy_executor_proto::EgressState::Proxied.into(),
            reason: None,
        };
        let receipt = egress_receipt_dispatched_with(Some(report), None).await?;
        assert_eq!(receipt.status, sandy::EgressEnforcement::Unenforced);
        assert_eq!(receipt.allow_list, None);
        Ok(())
    }

    /// A2b (#483, sandy-5e F1 on #835): the executor's egress reason can be as large as its frame, so it is cut like
    /// the message is: a huge one leaves a `Status` reply that fits one frame.
    #[tokio::test]
    async fn a_huge_egress_reason_leaves_a_status_reply_that_fits_one_frame() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        store.insert_pending("job-1", b"m", "test/v1")?;
        store.mark_running("job-1")?;
        let mut job = crate::dispatch::mint_job_channel("job-1", job_registry.authority())
            .await
            .context("mint job channel")?;
        job.egress_allow = Some(allow());
        job_registry.insert("job-1".to_owned(), job);
        let report = sandy_executor_proto::EgressReport {
            state: sandy_executor_proto::EgressState::Failed.into(),
            reason: Some("\u{1}".repeat(900 * 1024)),
        };
        record_job_result(
            &store,
            &job_registry,
            &mut HashSet::from(["job-1".to_owned()]),
            &mut HashSet::new(),
            JobResult {
                egress: Some(report),
                ..result_for("job-1", 0, false)
            },
        )
        .await;
        let envelope = store.envelope_json("job-1")?.context("an envelope")?;
        assert!(
            envelope.len() < sandy_control_proto::MAX_FRAME_LEN as usize / 2,
            "the stored envelope is {} bytes",
            envelope.len()
        );
        Ok(())
    }

    /// A2b (#483): parity with the direct path. The same run, through the executor's report and the daemon's receipt,
    /// gives exactly the egress receipt the direct supervisor builds from `proxy_receipt_result`: one row per way a
    /// proxy-mode run can end.
    #[tokio::test]
    async fn the_daemons_egress_receipt_equals_the_direct_paths() -> anyhow::Result<()> {
        use sandy_api::backend::{BackendError, Outcome};
        let outcome = |booted: bool| Outcome {
            booted,
            guest_exit: Some(0),
            transport_error: None,
            timed_out: false,
            console: String::new(),
            digests: None,
        };
        let runs: Vec<(&str, Result<Outcome, BackendError>)> = vec![
            ("booted guest", Ok(outcome(true))),
            ("guest never booted", Ok(outcome(false))),
            (
                "refused before boot",
                Err(BackendError::Spawn("no proxy binary".to_owned())),
            ),
            (
                "proxy dead before boot",
                Err(BackendError::EgressProxyDied {
                    status: Some(1),
                    booted: false,
                    guest_exit: None,
                }),
            ),
            (
                "proxy dead after boot",
                Err(BackendError::EgressProxyDied {
                    status: Some(1),
                    booted: true,
                    guest_exit: None,
                }),
            ),
        ];
        for (name, run) in runs {
            let direct = sandy::build_egress_receipt(&sandy::proxy_receipt_result(&run), &allow());
            let reported = sandy_host_executor::dispatch::egress_report(&run);
            let daemon = egress_receipt_for(Some(reported)).await?;
            assert_eq!(daemon, direct, "{name}");
        }
        Ok(())
    }

    /// A2 (#483): a job that is not terminal has no envelope, and one whose host disconnected gets a failed,
    /// retryable one, so every terminal path leaves exactly what a direct run would.
    #[tokio::test]
    async fn only_a_terminal_job_has_an_envelope_and_a_disconnect_fails_it_retryably() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        running_job(&store, &job_registry, "job-1").await?;
        assert!(store.envelope("job-1")?.is_none(), "a running job has no envelope");
        assert!(store.envelope("ghost")?.is_none(), "an unknown job has none");
        fail_disconnected_job(&store, &job_registry, "job-1").await;
        let envelope = store.envelope("job-1")?.context("a failed job carries an envelope")?;
        assert_eq!(envelope.status, sandy::Status::Failed);
        assert!(envelope.retryable, "an infra fault is retryable");
        Ok(())
    }

    /// Outputs that never arrive do not hold the job forever.
    #[tokio::test]
    async fn outputs_that_never_arrive_fail_the_job_at_the_wait_limit() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 0, true),
        )
        .await
        .context("owed")?;
        awaited
            .settle(&store, &job_registry, std::time::Duration::from_millis(50))
            .await;
        assert_eq!(store.status("job-1")?, Some(JobStatus::Failed));
        Ok(())
    }

    /// sandyd decides from its own record of what the job declared. A host that reports nothing follows for a job
    /// that owes outputs is wrong, and the job is not a success.
    #[tokio::test]
    async fn a_host_that_says_nothing_follows_for_a_job_that_owes_outputs_fails_it_at_once() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 0, false),
        )
        .await;
        assert!(awaited.is_none(), "nothing to wait for: the host says nothing follows");
        assert_eq!(store.status("job-1")?, Some(JobStatus::Failed));
        assert!(!in_flight.contains("job-1"));
        Ok(())
    }

    /// A failed run sends no outputs, so there is nothing to wait for.
    #[tokio::test]
    async fn a_failed_run_that_owes_outputs_is_terminal_at_once() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 1, false),
        )
        .await;
        assert!(awaited.is_none());
        assert_eq!(store.status("job-1")?, Some(JobStatus::Failed));
        Ok(())
    }

    /// The host's flag alone never makes sandyd wait: a job that declared no outputs finishes at once.
    #[tokio::test]
    async fn a_job_that_owes_nothing_is_terminal_at_once_whatever_the_host_flag_says() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        store.insert_pending("job-1", b"m", "test/v1")?;
        store.mark_running("job-1")?;
        let job = crate::dispatch::mint_job_channel("job-1", job_registry.authority())
            .await
            .context("mint job channel")?;
        job_registry.insert("job-1".to_owned(), job);
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 0, true),
        )
        .await;
        assert!(awaited.is_none());
        assert_eq!(store.status("job-1")?, Some(JobStatus::Succeeded));
        Ok(())
    }

    /// A host that disconnects while a succeeded job waits for its outputs fails the job: it stayed in flight.
    #[tokio::test]
    async fn a_host_that_disconnects_while_outputs_are_awaited_fails_the_job() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let _awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 0, true),
        )
        .await
        .context("owed")?;
        for job_id in in_flight {
            fail_disconnected_job(&store, &job_registry, &job_id).await;
        }
        assert_eq!(store.status("job-1")?, Some(JobStatus::Failed));
        let job = job_registry.get("job-1").context("registered")?;
        tokio::time::timeout(SOON, job.outputs.decided())
            .await
            .context("the receive waiting on the link must be released")?;
        Ok(())
    }

    /// A booted job that exits non-zero still has its outputs collected and sent (the host sends after any run that
    /// returns): sandyd waits for them, and the job stays `Failed`.
    #[tokio::test]
    async fn a_failed_run_whose_outputs_follow_waits_for_them_and_stays_failed() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 1, true),
        )
        .await
        .context("a failed run whose outputs follow must wait for them")?;
        assert_eq!(
            store.status("job-1")?,
            Some(JobStatus::Running),
            "not terminal before the outputs"
        );
        let job = job_registry.get("job-1").context("registered")?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), job.outputs.decided())
                .await
                .is_err(),
            "the receive must not be told the job ended while its outputs are coming"
        );
        job.outputs.publish(crate::output_slot::OutputsState::Received(
            crate::data_link_recv::Received { files: 1, bytes: 1 },
        ));
        awaited.settle(&store, &job_registry, SOON).await;
        assert_eq!(
            store.status("job-1")?,
            Some(JobStatus::Failed),
            "the exit status is not overturned"
        );
        Ok(())
    }

    /// An executor that reports the same job twice must not push a second wait for it, or fail the awaiting job.
    #[tokio::test]
    async fn a_duplicate_result_for_an_awaiting_job_is_ignored() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        job_owing_outputs(&store, &job_registry, "job-1").await?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let mut awaiting = HashSet::new();
        let first = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut awaiting,
            result_for("job-1", 0, true),
        )
        .await;
        assert!(first.is_some());
        let second = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut awaiting,
            result_for("job-1", 0, false),
        )
        .await;
        assert!(second.is_none());
        assert_eq!(
            store.status("job-1")?,
            Some(JobStatus::Running),
            "a duplicate must not fail the awaiting job"
        );
        Ok(())
    }

    /// A succeeded job the registry no longer knows cannot be shown to owe nothing: it fails closed.
    #[tokio::test]
    async fn a_succeeded_job_the_registry_lost_fails_closed() -> anyhow::Result<()> {
        let (store, job_registry) = (test_store(), test_job_registry());
        store.insert_pending("job-1", b"m", "test/v1")?;
        store.mark_running("job-1")?;
        let mut in_flight = HashSet::from(["job-1".to_owned()]);
        let awaited = record_job_result(
            &store,
            &job_registry,
            &mut in_flight,
            &mut HashSet::new(),
            result_for("job-1", 0, true),
        )
        .await;
        assert!(awaited.is_none());
        assert_eq!(store.status("job-1")?, Some(JobStatus::Failed));
        Ok(())
    }
}
