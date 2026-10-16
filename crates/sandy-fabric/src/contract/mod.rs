//! The shared seam contract-test harness: one suite per seam that every impl,
//! trivial or real, passes (spec §2).
//!
//! Each `*_suite` is generic over its seam; the caller supplies the impl through a
//! factory (a fresh instance per check) plus whatever the suite cannot derive on
//! its own, such as the capabilities an executor truly has. A suite returns
//! `Err(ContractViolation)` naming the broken rule, so a caller can assert on a
//! violation as well as on a pass. The async suites are runtime-agnostic: the
//! caller drives them on its own runtime, and a stream read never waits on an
//! envelope that is not already stored, so a broken stream fails instead of hanging.

use std::{collections::BTreeMap, fmt::Display, pin::pin};

use futures_util::{FutureExt, StreamExt};
use sandy_api::backend::{Grants, RunSpec};

use crate::{
    capauth::{CapAuthority, CapError, CapRights, CapScope},
    channel_backend::{ChannelBackend, ChannelBackendError},
    envelope::{Envelope, MSG_ID_KEY},
    executor::{Arch, Capabilities, Executor, Requirements, SandboxKind},
    minter::{Minter, SecretRequest},
    placement::{Capacity, CapacityError, Discovery, HostDescriptor, Lease, Lifecycle},
    telemetry::{TelemetryRecord, TelemetrySink},
    transport::{Frame, Transport},
    types::{HostId, PeerId},
};

#[cfg(test)]
mod fakes;
#[cfg(test)]
mod verify;

/// A seam implementation broke its contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{seam} contract violated: {rule}")]
pub struct ContractViolation {
    /// The seam whose contract was broken.
    pub seam: &'static str,
    /// The rule that was broken, and how.
    pub rule: String,
}

/// Fail with `rule` unless `ok`.
fn require(seam: &'static str, ok: bool, rule: &str) -> Result<(), ContractViolation> {
    if ok {
        Ok(())
    } else {
        Err(ContractViolation {
            seam,
            rule: rule.to_owned(),
        })
    }
}

/// Unwrap a seam call the contract expects to succeed.
fn expect_ok<T, E: Display>(seam: &'static str, call: &str, res: Result<T, E>) -> Result<T, ContractViolation> {
    res.map_err(|e| ContractViolation {
        seam,
        rule: format!("{call} failed unexpectedly: {e}"),
    })
}

/// Run the [`CapAuthority`] contract: a minted cap verifies to its scope, a
/// tampered cap does not, and attenuation narrows exactly and never widens.
pub fn capauth_suite<A: CapAuthority>(make: impl Fn() -> A) -> Result<(), ContractViolation> {
    const SEAM: &str = "CapAuthority";
    let authority = make();
    let full = CapRights {
        post: true,
        read: true,
        invite: true,
    };
    let scope = CapScope {
        peer: PeerId::from("parent"),
        channel: "c1".into(),
        rights: full,
        expires_at: None,
    };

    let cap = expect_ok(SEAM, "mint", authority.mint(scope.clone()))?;
    let verified = expect_ok(SEAM, "verify of a minted cap", authority.verify(&cap))?;
    require(SEAM, verified == scope, "verify returns the minted scope")?;

    let mut rescoped = cap.clone();
    rescoped.scope.channel = "c2".into();
    require(
        SEAM,
        authority.verify(&rescoped).is_err(),
        "a cap re-scoped to another channel is rejected",
    )?;
    let mut reproved = cap.clone();
    reproved.proof.push(0);
    require(
        SEAM,
        authority.verify(&reproved).is_err(),
        "a cap with an altered proof is rejected",
    )?;

    let read_only = CapRights {
        read: true,
        ..CapRights::default()
    };
    let child = expect_ok(SEAM, "attenuate to a subset", authority.attenuate(&cap, read_only))?;
    let child_scope = expect_ok(SEAM, "verify of an attenuated cap", authority.verify(&child))?;
    require(
        SEAM,
        child_scope.rights == read_only,
        "an attenuated cap carries exactly the narrowed rights",
    )?;
    require(
        SEAM,
        child_scope.channel == scope.channel && child_scope.peer == scope.peer,
        "attenuation keeps the parent's peer and channel",
    )?;
    require(
        SEAM,
        matches!(authority.attenuate(&child, full), Err(CapError::Widened)),
        "attenuating beyond the parent's rights fails with Widened",
    )
}

/// Run the [`Minter`] contract: every mint is non-empty and fresh.
pub fn minter_suite<M: Minter>(make: impl Fn() -> M) -> Result<(), ContractViolation> {
    const SEAM: &str = "Minter";
    let minter = make();
    let req = |job: &str| SecretRequest { job: job.to_owned() };
    let a1 = expect_ok(SEAM, "mint", minter.mint(&req("a")))?;
    let a2 = expect_ok(SEAM, "mint", minter.mint(&req("a")))?;
    let b = expect_ok(SEAM, "mint", minter.mint(&req("b")))?;
    require(SEAM, !a1.bytes.is_empty(), "a minted secret is non-empty")?;
    require(SEAM, a1 != a2, "two mints for one job differ")?;
    require(SEAM, a1 != b && a2 != b, "mints for different jobs differ")
}

/// Run the [`ChannelBackend`] contract: seq-ordered and `>= from_seq` fetches,
/// dedup on the content id, rejection of an id-less envelope, and a stream that
/// replays then follows live appends.
pub async fn channel_backend_suite<B: ChannelBackend>(make: impl Fn() -> B) -> Result<(), ContractViolation> {
    const SEAM: &str = "ChannelBackend";
    let env = |seq: u64, id: &str| Envelope {
        seq,
        msg_type: "text".to_owned(),
        content_type: "text/plain".to_owned(),
        payload: id.as_bytes().to_vec(),
        metadata: BTreeMap::from([(MSG_ID_KEY.to_owned(), id.to_owned())]),
    };
    let seqs = |envs: &[Envelope]| envs.iter().map(|e| e.seq).collect::<Vec<_>>();
    let backend = make();

    require(
        SEAM,
        expect_ok(SEAM, "fetch", backend.fetch(0).await)?.is_empty(),
        "a fresh backend is empty",
    )?;

    expect_ok(SEAM, "append", backend.append(env(2, "b")).await)?;
    expect_ok(SEAM, "append", backend.append(env(1, "a")).await)?;
    let all = expect_ok(SEAM, "fetch", backend.fetch(0).await)?;
    require(
        SEAM,
        seqs(&all) == [1, 2],
        "fetch is in seq order regardless of arrival order",
    )?;
    let tail = expect_ok(SEAM, "fetch", backend.fetch(2).await)?;
    require(SEAM, seqs(&tail) == [2], "fetch returns only seq >= from_seq")?;

    expect_ok(SEAM, "append of a duplicate", backend.append(env(1, "a")).await)?;
    let all = expect_ok(SEAM, "fetch", backend.fetch(0).await)?;
    require(SEAM, all.len() == 2, "a repeated msg_id is stored once")?;

    let mut anonymous = env(9, "x");
    anonymous.metadata.clear();
    require(
        SEAM,
        matches!(backend.append(anonymous).await, Err(ChannelBackendError::MissingMsgId)),
        "an envelope without a msg_id is rejected with MissingMsgId",
    )?;

    let mut stream = pin!(backend.stream_from(1));
    let mut next_seq = || {
        stream
            .next()
            .now_or_never()
            .flatten()
            .and_then(Result::ok)
            .map(|e| e.seq)
    };
    require(
        SEAM,
        next_seq() == Some(1),
        "stream_from replays the first stored envelope",
    )?;
    require(SEAM, next_seq() == Some(2), "stream_from replays in seq order")?;
    expect_ok(SEAM, "append", backend.append(env(3, "c")).await)?;
    require(
        SEAM,
        next_seq() == Some(3),
        "stream_from follows an append made after the stream was opened",
    )
}

/// Run the [`Transport`] contract: frames queue for a peer that has not yet
/// polled, arrive in send order with their sender, and are delivered once.
pub async fn transport_suite<T: Transport>(make: impl Fn() -> T) -> Result<(), ContractViolation> {
    const SEAM: &str = "Transport";
    let transport = make();
    let (a, b, c) = (PeerId::from("a"), PeerId::from("b"), PeerId::from("c"));

    expect_ok(SEAM, "send", transport.send(&a, &b, b"1").await)?;
    expect_ok(SEAM, "send", transport.send(&a, &b, b"2").await)?;
    let got = expect_ok(SEAM, "poll", transport.poll(&b).await)?;
    let want = [b"1", b"2"].map(|bytes| Frame {
        from: a.clone(),
        bytes: bytes.to_vec(),
    });
    require(
        SEAM,
        got == want,
        "frames sent before the recipient polled are stored and delivered in order",
    )?;
    require(
        SEAM,
        expect_ok(SEAM, "poll", transport.poll(&b).await)?.is_empty(),
        "a frame is delivered once",
    )?;
    require(
        SEAM,
        expect_ok(SEAM, "poll", transport.poll(&c).await)?.is_empty(),
        "a peer receives only frames addressed to it",
    )
}

/// Build a `RunSpec` for `command` with no inputs, outputs, or secrets.
fn run_spec<'a>(command: &'a [String], grants: &'a Grants) -> RunSpec<'a> {
    RunSpec {
        template: "contract",
        command,
        inputs: &[],
        outputs: &[],
        secrets: &[],
        env: &[],
        cpu: None,
        mem: None,
        timeout_secs: 30,
        grants,
        outcome_file: None,
        secret_dir: None,
    }
}

/// Run the [`Executor`] contract.
///
/// `expected` is what the impl truly provides (for an adapter: the wrapped
/// backend's kind and the host arch), so an executor that claims another
/// capability fails. The checks: no boxes when fresh, killing an unknown box is
/// defined, `true` exits 0 cleanly and leaves no box, and `sh -c "exit 3"` is
/// carried as a task failure (exit 3), never as an infra fault.
pub async fn executor_suite<E: Executor>(
    expected: Capabilities,
    make: impl Fn() -> E,
) -> Result<(), ContractViolation> {
    const SEAM: &str = "Executor";
    let executor = make();
    let caps = executor.capabilities();
    require(
        SEAM,
        caps == expected,
        "capabilities() reports what the executor provides",
    )?;
    require(SEAM, executor.capabilities() == caps, "capabilities() is stable")?;

    require(
        SEAM,
        expect_ok(SEAM, "observe", executor.observe().await)?.is_empty(),
        "a fresh executor runs no boxes",
    )?;
    expect_ok(SEAM, "kill of an unknown box", executor.kill("does-not-exist").await)?;

    let grants = Grants {
        secrets: false,
        agent: false,
        shares: false,
    };
    let success = ["true".to_owned()];
    let outcome = expect_ok(SEAM, "run", executor.run(&run_spec(&success, &grants)).await)?;
    require(
        SEAM,
        outcome.booted && outcome.guest_exit == Some(0) && outcome.transport_error.is_none() && !outcome.timed_out,
        "a successful job boots and exits 0 with no fault",
    )?;
    require(
        SEAM,
        expect_ok(SEAM, "observe", executor.observe().await)?.is_empty(),
        "no box lingers after a synchronous run",
    )?;

    let failure = ["sh", "-c", "exit 3"].map(str::to_owned);
    let outcome = expect_ok(SEAM, "run", executor.run(&run_spec(&failure, &grants)).await)?;
    require(
        SEAM,
        outcome.guest_exit == Some(3) && outcome.transport_error.is_none(),
        "a non-zero exit is carried as a task failure, not an infra fault",
    )
}

/// Run the [`Discovery`] contract: `find` returns exactly the registered hosts
/// whose capabilities satisfy the requirements, and re-registering replaces.
pub async fn discovery_suite<D: Discovery>(make: impl Fn() -> D) -> Result<(), ContractViolation> {
    const SEAM: &str = "Discovery";
    let host = |id: &str, kind, arch| HostDescriptor {
        host: HostId::from(id),
        capabilities: Capabilities {
            kind,
            arch,
            attestation: None,
        },
    };
    let need = |kind, arch| Requirements { kind, arch };
    let discovery = make();
    let found = async |req: Requirements| -> Result<Vec<String>, ContractViolation> {
        let mut ids: Vec<_> = expect_ok(SEAM, "find", discovery.find(&req).await)?
            .into_iter()
            .map(|h| h.host.0)
            .collect();
        ids.sort();
        Ok(ids)
    };

    require(
        SEAM,
        found(need(SandboxKind::Process, None)).await?.is_empty(),
        "a fresh registry finds nothing",
    )?;
    expect_ok(
        SEAM,
        "register",
        discovery
            .register(host("proc", SandboxKind::Process, Arch::X86_64))
            .await,
    )?;
    expect_ok(
        SEAM,
        "register",
        discovery.register(host("vm", SandboxKind::Vm, Arch::Aarch64)).await,
    )?;

    require(
        SEAM,
        found(need(SandboxKind::Process, None)).await? == ["proc"],
        "find matches on kind",
    )?;
    require(
        SEAM,
        found(need(SandboxKind::Vm, Some(Arch::Aarch64))).await? == ["vm"],
        "find matches on kind and arch",
    )?;
    require(
        SEAM,
        found(need(SandboxKind::Vm, Some(Arch::X86_64))).await?.is_empty(),
        "find excludes a host whose arch does not match",
    )?;

    expect_ok(
        SEAM,
        "re-register",
        discovery.register(host("proc", SandboxKind::Vm, Arch::X86_64)).await,
    )?;
    require(
        SEAM,
        found(need(SandboxKind::Process, None)).await?.is_empty(),
        "re-registering a host replaces its advertisement",
    )
}

/// Run the [`Capacity`] contract against a source that knows `known`: probing
/// is read-only, and an unknown host is an error rather than spare capacity.
pub async fn capacity_suite<C: Capacity>(known: HostId, make: impl Fn() -> C) -> Result<(), ContractViolation> {
    const SEAM: &str = "Capacity";
    let capacity = make();
    let first = expect_ok(SEAM, "probe", capacity.probe(&known).await)?;
    let second = expect_ok(SEAM, "probe", capacity.probe(&known).await)?;
    require(SEAM, first == second, "a probe reserves nothing")?;

    let unknown = HostId(format!("{}-unknown", known.0));
    require(
        SEAM,
        matches!(capacity.probe(&unknown).await, Err(CapacityError::UnknownHost(h)) if h == unknown),
        "an unknown host fails with UnknownHost",
    )
}

/// Run the [`Lifecycle`] contract: registration makes a host live, heartbeat and
/// deregister accept only a lease that was issued and is still held, and
/// deregistration ends liveness.
pub async fn lifecycle_suite<L: Lifecycle>(make: impl Fn() -> L) -> Result<(), ContractViolation> {
    const SEAM: &str = "Lifecycle";
    let lifecycle = make();
    let host = HostId::from("h1");

    require(
        SEAM,
        expect_ok(SEAM, "live", lifecycle.live().await)?.is_empty(),
        "nothing is live before registration",
    )?;
    let lease = expect_ok(SEAM, "register", lifecycle.register(host.clone()).await)?;
    require(SEAM, lease.host == host, "the lease names the registered host")?;
    require(
        SEAM,
        expect_ok(SEAM, "live", lifecycle.live().await)?.contains(&host),
        "a registered host is live",
    )?;
    expect_ok(SEAM, "heartbeat", lifecycle.heartbeat(&lease).await)?;

    let forged = Lease {
        host: HostId::from("ghost"),
        id: lease.id,
    };
    require(
        SEAM,
        lifecycle.heartbeat(&forged).await.is_err(),
        "a heartbeat on a lease that was never issued fails",
    )?;

    expect_ok(SEAM, "deregister", lifecycle.deregister(&lease).await)?;
    require(
        SEAM,
        !expect_ok(SEAM, "live", lifecycle.live().await)?.contains(&host),
        "a deregistered host is not live",
    )?;
    require(
        SEAM,
        lifecycle.heartbeat(&lease).await.is_err(),
        "a heartbeat on a deregistered lease fails",
    )?;
    require(
        SEAM,
        lifecycle.deregister(&lease).await.is_err(),
        "deregistering twice fails",
    )
}

/// Run the [`TelemetrySink`] contract. `captured` observes how many records a
/// sink kept (for a local log, its line count): an enabled sink keeps every
/// record, a disabled one keeps none.
pub async fn telemetry_suite<S: TelemetrySink>(
    make_enabled: impl Fn() -> S,
    make_disabled: impl Fn() -> S,
    captured: impl Fn(&S) -> usize,
) -> Result<(), ContractViolation> {
    const SEAM: &str = "TelemetrySink";
    let record = TelemetryRecord {
        kind: "contract".to_owned(),
        fields: BTreeMap::from([("k".to_owned(), "v".to_owned())]),
    };

    for (sink, enabled, kept) in [(make_enabled(), true, 3), (make_disabled(), false, 0)] {
        require(
            SEAM,
            sink.enabled() == enabled && sink.enabled() == enabled,
            "enabled() reflects the configuration and is stable",
        )?;
        for _ in 0..3 {
            expect_ok(SEAM, "emit", sink.emit(&record).await)?;
        }
        require(
            SEAM,
            captured(&sink) == kept,
            if enabled {
                "an enabled sink keeps every record"
            } else {
                "a disabled sink keeps nothing"
            },
        )?;
    }
    Ok(())
}
