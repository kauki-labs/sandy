//! The shared seam contract-test harness: one suite per seam that every impl,
//! trivial or real, passes (spec §2).
//!
//! Each `*_suite` is generic over its seam; the caller supplies the impl through a
//! factory (a fresh instance per check) plus whatever the suite cannot derive on
//! its own, such as the capabilities an executor truly has. A suite returns
//! `Err(ContractViolation)` naming the broken rule, so a caller can assert on a
//! violation as well as on a pass. The async suites are runtime-agnostic: the
//! caller drives them on its own runtime. Where a suite waits on a stream, the
//! caller also supplies a deadline future (a sleep on its runtime), so a broken
//! stream fails instead of hanging and a correct I/O-backed stream gets time to
//! deliver.
//!
//! The suites assume read-your-writes: once a call returns, its effect is visible
//! to the next call on the same instance. That is the step-1 contract for every
//! seam; an eventually-consistent impl (DHT, batching sink) settles before
//! returning, or brings its own settle step to the suite when it lands.

use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    future::Future,
    pin::pin,
    time::{SystemTime, UNIX_EPOCH},
};

use futures_core::Stream;
use futures_util::{
    StreamExt,
    future::{Either, select},
};
use sandy_api::backend::{Grants, RunSpec};
use sandy_proto::{MessageType, PeerMsg};

use crate::{
    capauth::{CapAuthority, CapError, CapRights, CapScope},
    channel_backend::{ChannelBackend, ChannelBackendError, Envelope, MSG_ID_KEY},
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

/// A violation of `rule` on `seam`.
fn violation(seam: &'static str, rule: impl Into<String>) -> ContractViolation {
    ContractViolation {
        seam,
        rule: rule.into(),
    }
}

/// Fail with `rule` unless `ok`.
fn require(seam: &'static str, ok: bool, rule: &str) -> Result<(), ContractViolation> {
    if ok { Ok(()) } else { Err(violation(seam, rule)) }
}

/// Unwrap a seam call the contract expects to succeed.
fn expect_ok<T, E: Display>(seam: &'static str, call: &str, res: Result<T, E>) -> Result<T, ContractViolation> {
    res.map_err(|e| violation(seam, format!("{call} failed unexpectedly: {e}")))
}

/// Run the [`CapAuthority`] contract: a minted cap verifies to its scope; editing
/// any scope field or the proof makes it [`CapError::Forged`]; a past expiry is
/// [`CapError::Expired`]; attenuation narrows exactly, never widens or extends the
/// expiry, and refuses a tampered parent.
pub fn capauth_suite<A: CapAuthority>(make: impl Fn() -> A) -> Result<(), ContractViolation> {
    const SEAM: &str = "CapAuthority";
    let authority = make();
    let full = CapRights {
        post: true,
        read: true,
        invite: true,
    };
    let read_only = CapRights {
        read: true,
        ..CapRights::default()
    };
    let later = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) + 3600;
    let scope = |rights, expires_at| CapScope {
        peer: PeerId::from("parent"),
        channel: "c1".into(),
        rights,
        expires_at,
    };

    let cap = expect_ok(SEAM, "mint", authority.mint(scope(full, Some(later))))?;
    let verified = expect_ok(SEAM, "verify of a minted cap", authority.verify(&cap))?;
    require(
        SEAM,
        verified.peer == cap.scope.peer && verified.channel == cap.scope.channel && verified.rights == full,
        "verify returns the minted peer, channel and rights",
    )?;
    require(
        SEAM,
        verified.expires_at.is_some_and(|t| t <= later),
        "verify never reports a later expiry than was minted",
    )?;

    // Each edit to a read-only cap is an escalation attempt the proof must catch.
    let read_cap = expect_ok(SEAM, "mint", authority.mint(scope(read_only, Some(later))))?;
    let mut tampered: Vec<(&str, _)> = Vec::new();
    let mut edit = |rule, f: &dyn Fn(&mut crate::capauth::Cap)| {
        let mut c = read_cap.clone();
        f(&mut c);
        tampered.push((rule, c));
    };
    edit("a cap with its peer edited is Forged", &|c| {
        c.scope.peer = "intruder".into()
    });
    edit("a cap with its channel edited is Forged", &|c| {
        c.scope.channel = "c2".into()
    });
    edit("a cap with its rights edited is Forged", &|c| c.scope.rights = full);
    edit("a cap with its expiry removed is Forged", &|c| {
        c.scope.expires_at = None
    });
    edit(
        "a cap with an altered proof is Forged",
        &|c| match c.proof.first_mut() {
            Some(b) => *b ^= 1,
            None => c.proof.push(1),
        },
    );
    edit("a cap with an emptied proof is Forged", &|c| c.proof.clear());
    for (rule, cap) in &tampered {
        require(SEAM, matches!(authority.verify(cap), Err(CapError::Forged)), rule)?;
    }

    let expired = match authority.mint(scope(read_only, Some(1))) {
        Err(CapError::Expired) => true,
        Ok(c) => matches!(authority.verify(&c), Err(CapError::Expired)),
        Err(_) => false,
    };
    require(SEAM, expired, "a cap past its expiry is refused with Expired")?;

    let child = expect_ok(SEAM, "attenuate to a subset", authority.attenuate(&cap, read_only))?;
    let child_scope = expect_ok(SEAM, "verify of an attenuated cap", authority.verify(&child))?;
    require(
        SEAM,
        child_scope.rights == read_only,
        "an attenuated cap carries exactly the narrowed rights",
    )?;
    require(
        SEAM,
        child_scope.channel == cap.scope.channel && child_scope.peer == cap.scope.peer,
        "attenuation keeps the parent's peer and channel",
    )?;
    require(
        SEAM,
        child_scope.expires_at.is_some_and(|t| t <= later),
        "attenuation never extends the parent's expiry",
    )?;
    require(
        SEAM,
        matches!(authority.attenuate(&child, full), Err(CapError::Widened)),
        "attenuating beyond the parent's rights fails with Widened",
    )?;
    let (_, forged_parent) = &tampered[2];
    require(
        SEAM,
        matches!(authority.attenuate(forged_parent, full), Err(CapError::Forged)),
        "attenuating a tampered parent fails with Forged",
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

/// The next envelope's `sequence` from `stream`, or a violation of `rule` if the
/// stream errors, ends, or yields nothing before `deadline`.
async fn next_sequence<S, F>(
    stream: &mut std::pin::Pin<&mut S>,
    deadline: F,
    rule: &str,
) -> Result<u64, ContractViolation>
where
    S: Stream<Item = Result<Envelope, ChannelBackendError>>,
    F: Future<Output = ()>,
{
    const SEAM: &str = "ChannelBackend";
    match select(stream.next(), pin!(deadline)).await {
        Either::Left((Some(Ok(env)), _)) => Ok(env.sequence),
        Either::Left((Some(Err(e)), _)) => Err(violation(SEAM, format!("{rule}: the stream yielded {e}"))),
        Either::Left((None, _)) => Err(violation(SEAM, format!("{rule}: the stream ended"))),
        Either::Right(((), _)) => Err(violation(SEAM, format!("{rule}: nothing arrived before the deadline"))),
    }
}

/// Run the [`ChannelBackend`] contract: sequence-ordered, `>= from_seq` fetches;
/// dedup on the content id, keeping the first; rejection of an id-less envelope; a
/// stream that starts at `from_seq`, replays, then follows live appends; and a
/// resubscription at the cursor that does the same.
///
/// `deadline` returns a fresh timeout future (a sleep on the caller's runtime)
/// bounding each wait on the stream.
pub async fn channel_backend_suite<B, F>(
    make: impl Fn() -> B,
    deadline: impl Fn() -> F,
) -> Result<(), ContractViolation>
where
    B: ChannelBackend,
    F: Future<Output = ()>,
{
    const SEAM: &str = "ChannelBackend";
    let env = |sequence: u64, id: &str| Envelope {
        sequence,
        content_type: sandy_proto::CONTENT_TYPE_TEXT.to_owned(),
        payload: id.as_bytes().to_vec(),
        metadata: HashMap::from([(MSG_ID_KEY.to_owned(), id.to_owned())]),
        message_type: Some(MessageType::PeerMsg(PeerMsg {})),
    };
    let sequences = |envs: &[Envelope]| envs.iter().map(|e| e.sequence).collect::<Vec<_>>();
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
        sequences(&all) == [1, 2],
        "fetch is in sequence order regardless of arrival order",
    )?;
    let tail = expect_ok(SEAM, "fetch", backend.fetch(2).await)?;
    require(SEAM, sequences(&tail) == [2], "fetch returns only sequence >= from_seq")?;

    // A re-post carries the same content id under a new sequence.
    expect_ok(SEAM, "append of a re-post", backend.append(env(5, "a")).await)?;
    let all = expect_ok(SEAM, "fetch", backend.fetch(0).await)?;
    require(
        SEAM,
        sequences(&all) == [1, 2],
        "a re-post with a stored msg_id is a no-op that keeps the first",
    )?;

    let mut anonymous = env(9, "x");
    anonymous.metadata.clear();
    require(
        SEAM,
        matches!(backend.append(anonymous).await, Err(ChannelBackendError::MissingMsgId)),
        "an envelope without a msg_id is rejected with MissingMsgId",
    )?;

    {
        let mut stream = pin!(backend.stream_from(2));
        let rule = "stream_from starts at from_seq";
        require(SEAM, next_sequence(&mut stream, deadline(), rule).await? == 2, rule)?;
        expect_ok(SEAM, "append", backend.append(env(3, "c")).await)?;
        let rule = "stream_from follows an append made after the stream was opened";
        require(SEAM, next_sequence(&mut stream, deadline(), rule).await? == 3, rule)?;
    }

    // A dropped subscriber resumes at its cursor and misses nothing from there.
    let mut stream = pin!(backend.stream_from(3));
    let rule = "a resubscription at the cursor replays from it";
    require(SEAM, next_sequence(&mut stream, deadline(), rule).await? == 3, rule)?;
    expect_ok(SEAM, "append", backend.append(env(4, "d")).await)?;
    let rule = "a resubscription follows live appends";
    require(SEAM, next_sequence(&mut stream, deadline(), rule).await? == 4, rule)
}

/// Run the [`Transport`] contract: frames queue for a peer that has not yet
/// polled, arrive in send order with their senders, and are delivered once.
pub async fn transport_suite<T: Transport>(make: impl Fn() -> T) -> Result<(), ContractViolation> {
    const SEAM: &str = "Transport";
    let transport = make();
    let (a, b, c, d) = (
        PeerId::from("a"),
        PeerId::from("b"),
        PeerId::from("c"),
        PeerId::from("d"),
    );

    expect_ok(SEAM, "send", transport.send(&a, &b, b"1").await)?;
    expect_ok(SEAM, "send", transport.send(&c, &b, b"x").await)?;
    expect_ok(SEAM, "send", transport.send(&a, &b, b"2").await)?;
    let got = expect_ok(SEAM, "poll", transport.poll(&b).await)?;
    let frame = |from: &PeerId, bytes: &[u8]| Frame {
        from: from.clone(),
        bytes: bytes.to_vec(),
    };
    require(
        SEAM,
        got == [frame(&a, b"1"), frame(&c, b"x"), frame(&a, b"2")],
        "frames sent before the recipient polled are stored and delivered in send order with their senders",
    )?;
    require(
        SEAM,
        expect_ok(SEAM, "poll", transport.poll(&b).await)?.is_empty(),
        "a frame is delivered once",
    )?;
    require(
        SEAM,
        expect_ok(SEAM, "poll", transport.poll(&d).await)?.is_empty(),
        "a peer receives only frames addressed to it",
    )
}

/// Build a `RunSpec` for `command` in `template` with no inputs, outputs, or secrets.
fn run_spec<'a>(template: &'a str, command: &'a [String], grants: &'a Grants) -> RunSpec<'a> {
    RunSpec {
        template,
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
/// capability fails. `template` is a guest the executor can boot (ignored by a
/// process executor). The jobs are `true` and `sh -c "exit 3"`, so the guest needs
/// a POSIX shell. The checks: no boxes when fresh, killing an unknown box is
/// defined, `true` exits 0 cleanly and leaves no box, and `exit 3` is carried as a
/// task failure (exit 3), never as an infra fault.
pub async fn executor_suite<E: Executor>(
    expected: Capabilities,
    template: &str,
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
    let outcome = expect_ok(SEAM, "run", executor.run(&run_spec(template, &success, &grants)).await)?;
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
    let outcome = expect_ok(SEAM, "run", executor.run(&run_spec(template, &failure, &grants)).await)?;
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
/// is read-only, and an unknown host is an error rather than spare capacity. The
/// caller holds `known`'s load steady for the run.
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

/// Run the [`Lifecycle`] contract: registration makes a host live; heartbeat and
/// deregister accept only the exact lease that was issued and is still held; a
/// failed heartbeat revives nothing; deregistration ends liveness.
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

    let wrong_host = Lease {
        host: HostId::from("ghost"),
        id: lease.id,
    };
    require(
        SEAM,
        lifecycle.heartbeat(&wrong_host).await.is_err(),
        "a heartbeat naming the wrong host fails",
    )?;
    let unissued = Lease {
        host: host.clone(),
        id: lease.id.wrapping_add(1000),
    };
    require(
        SEAM,
        lifecycle.heartbeat(&unissued).await.is_err(),
        "a heartbeat on a lease id that was never issued fails",
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
        !expect_ok(SEAM, "live", lifecycle.live().await)?.contains(&host),
        "a failed heartbeat does not revive a lease",
    )?;
    require(
        SEAM,
        lifecycle.deregister(&lease).await.is_err(),
        "deregistering twice fails",
    )
}

/// Run the [`TelemetrySink`] contract. `captured` observes how many records a
/// sink kept (for a local log, its line count): an enabled sink keeps every
/// record by the time `emit` returns, a disabled one keeps none.
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
