//! End-to-end provisioning: host facts -> strategy -> routed outcome.
//!
//! Wires `sandy`'s capability classifier to `sandy-provider`'s router,
//! remote-build orchestration, and locked-down-Linux fallback — the real public
//! code — with the host-nix backend and the remote builder injected through
//! their traits as fakes. No hypervisor and no network: this exercises the
//! decision + dispatch seam the host tiers boot behind.

use std::cell::RefCell;

use sandy::{
    BootAxis, BuildAxis, HostFacts, HostNixProvisioner, Job, Logs, Provenance, ProvisionOutcome, ProvisioningStrategy,
    RESULT_SCHEMA_VERSION, RemoteArtifacts, RemoteBuilder, RemoteError, ResultEnvelope, Status, classify,
    decide_fallback, provision, provision_remote_build,
};

const TARGET: &str = "x86_64-linux";

/// A host-nix backend double that records the jobs it was handed, so a test can
/// assert the router forwarded the job unchanged and called it the right number
/// of times.
struct RecordingBackend {
    seen: RefCell<Vec<Job>>,
}

impl RecordingBackend {
    fn new() -> Self {
        Self {
            seen: RefCell::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.seen.borrow().len()
    }
}

impl HostNixProvisioner for RecordingBackend {
    fn provision_host_nix(&self, job: &Job, _arch: &str) -> ResultEnvelope {
        self.seen.borrow_mut().push(job.clone());
        succeeded_envelope()
    }
}

/// A remote builder double: advertises `arch`, and once reached either returns
/// artifacts or reports itself unreachable. Records whether a build was
/// attempted so a test can prove an arch mismatch skips the build.
struct FakeRemote {
    advertised_arch: String,
    reachable_build: bool,
    build_attempted: RefCell<bool>,
}

impl FakeRemote {
    fn new(advertised_arch: &str, reachable_build: bool) -> Self {
        Self {
            advertised_arch: advertised_arch.to_string(),
            reachable_build,
            build_attempted: RefCell::new(false),
        }
    }
}

impl RemoteBuilder for FakeRemote {
    fn probe_arch(&self, _host: &str) -> Result<String, RemoteError> {
        Ok(self.advertised_arch.clone())
    }

    fn build_remote(&self, _derivation: &str, host: &str, _arch: &str) -> Result<RemoteArtifacts, RemoteError> {
        *self.build_attempted.borrow_mut() = true;
        if self.reachable_build {
            Ok(RemoteArtifacts {
                output_store_path: "/nix/store/zzz-out".to_string(),
            })
        } else {
            Err(RemoteError::Unreachable(host.to_string()))
        }
    }
}

fn succeeded_envelope() -> ResultEnvelope {
    ResultEnvelope {
        result_schema_version: RESULT_SCHEMA_VERSION,
        job_id: "job".to_string(),
        box_id: Some("box".to_string()),
        status: Status::Succeeded,
        retryable: false,
        message: "ok".to_string(),
        exit_code: Some(0),
        outputs: Vec::new(),
        receipts: Vec::new(),
        provenance: Provenance {
            template_store_path: "/nix/store/xxx-template".to_string(),
        },
        logs: Logs { tail: String::new() },
    }
}

fn sample_job() -> Job {
    Job {
        template: "tpl".to_string(),
        command: vec!["echo".to_string(), "hi".to_string()],
    }
}

/// Host facts with the two independent axes plus the target arch; the optional
/// seed / remote-builder default to absent.
fn facts(boot: BootAxis, build: BuildAxis, arch_ok: bool) -> HostFacts {
    HostFacts {
        boot,
        build,
        target_arch: TARGET.to_string(),
        build_can_produce_target: arch_ok,
        seed: None,
        remote_builder: None,
    }
}

/// A bootable host with Nix at the target arch classifies as `HostNix`, and the
/// router then drives the backend exactly once with the job forwarded unchanged.
#[test]
fn host_nix_host_classifies_and_runs_the_job() {
    let job = sample_job();
    let backend = RecordingBackend::new();

    let strategy = classify(&facts(BootAxis::Ok, BuildAxis::HostNix, true));
    assert_eq!(
        strategy,
        ProvisioningStrategy::HostNix {
            arch: TARGET.to_string()
        }
    );

    let outcome = provision(strategy, &job, &backend);
    assert!(matches!(outcome, ProvisionOutcome::Provisioned(_)));
    assert_eq!(backend.call_count(), 1, "the backend runs exactly once");
    assert_eq!(backend.seen.borrow()[0], job, "the job is forwarded unchanged");
}

/// A Nix-free-but-installable host routes the same way: install becomes a
/// host-nix host, so classify yields `HostNix` and the job runs.
#[test]
fn installable_host_routes_host_nix() {
    let backend = RecordingBackend::new();
    let strategy = classify(&facts(BootAxis::Ok, BuildAxis::NixFreeInstallable, true));
    assert!(matches!(
        provision(strategy, &sample_job(), &backend),
        ProvisionOutcome::Provisioned(_)
    ));
    assert_eq!(backend.call_count(), 1);
}

/// A failed boot is a hard prerequisite: classify refuses naming the boot axis
/// and the router never touches the backend.
#[test]
fn failed_boot_refuses_without_touching_the_backend() {
    let backend = RecordingBackend::new();
    let strategy = classify(&facts(BootAxis::Failed, BuildAxis::HostNix, true));

    let ProvisionOutcome::Refused { reason } = provision(strategy, &sample_job(), &backend) else {
        panic!("a failed boot must refuse");
    };
    assert!(reason.contains("boot"), "refusal names the boot axis: {reason}");
    assert_eq!(backend.call_count(), 0, "a refusal never reaches the backend");
}

/// A producing build axis that cannot target the requested arch refuses naming
/// `arch`, with no build attempted (the backend is never called).
#[test]
fn arch_mismatch_refuses_without_building() {
    let backend = RecordingBackend::new();
    let strategy = classify(&facts(BootAxis::Ok, BuildAxis::HostNix, false));

    let ProvisionOutcome::Refused { reason } = provision(strategy, &sample_job(), &backend) else {
        panic!("an arch mismatch must refuse");
    };
    assert!(reason.contains("arch"), "refusal names the arch axis: {reason}");
    assert_eq!(backend.call_count(), 0);
}

/// Facts carrying a builder-VM seed classify as `BuilderVM`, which the router
/// refuses at this stage with a stage-C pointer — never attempting the unbuilt
/// path.
#[test]
fn builder_vm_seed_refuses_with_a_stage_c_pointer() {
    let backend = RecordingBackend::new();
    let seeded = HostFacts {
        seed: Some("seed-1".to_string()),
        ..facts(BootAxis::Ok, BuildAxis::None, true)
    };
    let strategy = classify(&seeded);
    assert!(matches!(strategy, ProvisioningStrategy::BuilderVM { .. }));

    let ProvisionOutcome::Refused { reason } = provision(strategy, &sample_job(), &backend) else {
        panic!("BuilderVM must refuse at this stage");
    };
    assert!(reason.contains("stage C"), "points at stage C: {reason}");
    assert_eq!(backend.call_count(), 0);
}

/// Facts carrying a remote builder classify as `RemoteBuild`, which the router
/// refuses with a stage-D pointer.
#[test]
fn remote_builder_facts_refuse_with_a_stage_d_pointer() {
    let backend = RecordingBackend::new();
    let remote = HostFacts {
        remote_builder: Some("builder.example".to_string()),
        ..facts(BootAxis::Ok, BuildAxis::None, true)
    };
    let strategy = classify(&remote);
    assert!(matches!(strategy, ProvisioningStrategy::RemoteBuild { .. }));

    let ProvisionOutcome::Refused { reason } = provision(strategy, &sample_job(), &backend) else {
        panic!("RemoteBuild must refuse at this stage");
    };
    assert!(reason.contains("stage D"), "points at stage D: {reason}");
}

/// The locked-down-Linux fallback prefers a reachable seed, then a reachable
/// remote builder, and otherwise refuses naming both missing axes.
#[test]
fn locked_down_fallback_prefers_seed_then_remote_then_refuses() {
    let seeded = HostFacts {
        seed: Some("seed-7".to_string()),
        ..facts(BootAxis::Ok, BuildAxis::None, false)
    };
    assert!(matches!(
        decide_fallback(&seeded, true, false),
        ProvisioningStrategy::BuilderVM { .. }
    ));

    let remote = HostFacts {
        remote_builder: Some("builder.example".to_string()),
        ..facts(BootAxis::Ok, BuildAxis::None, false)
    };
    assert!(matches!(
        decide_fallback(&remote, false, true),
        ProvisioningStrategy::RemoteBuild { .. }
    ));

    let ProvisioningStrategy::Refuse { reason } =
        decide_fallback(&facts(BootAxis::Ok, BuildAxis::None, false), false, false)
    else {
        panic!("no fallback must refuse");
    };
    assert!(
        reason.contains("seed") && reason.contains("remote"),
        "names both blockers: {reason}"
    );
}

/// The remote-build path confirms the remote's arch before delegating: a
/// mismatch refuses naming `arch` with no build attempted.
#[test]
fn remote_build_arch_mismatch_refuses_without_building() {
    let remote = FakeRemote::new("aarch64-linux", true);
    let outcome = provision_remote_build(&sample_job(), "builder.example", TARGET, &remote);

    let ProvisionOutcome::Refused { reason } = outcome else {
        panic!("an arch mismatch must refuse");
    };
    assert!(reason.contains("arch"), "names the arch axis: {reason}");
    assert!(!*remote.build_attempted.borrow(), "no build is attempted on mismatch");
}

/// A remote unreachable mid-build is an infra fault: the result is failed and
/// retryable, never confused with a guest exit.
#[test]
fn remote_build_unreachable_is_a_retryable_infra_fault() {
    let remote = FakeRemote::new(TARGET, false);
    let ProvisionOutcome::Provisioned(env) = provision_remote_build(&sample_job(), "builder.example", TARGET, &remote)
    else {
        panic!("an infra fault maps to a failed envelope");
    };
    assert_eq!(env.status, Status::Failed);
    assert!(env.retryable, "an infra fault is retryable");
}

/// A reachable remote of the right arch builds and copies artifacts back,
/// yielding a succeeded result.
#[test]
fn remote_build_success_provisions_the_job() {
    let remote = FakeRemote::new(TARGET, true);
    let ProvisionOutcome::Provisioned(env) = provision_remote_build(&sample_job(), "builder.example", TARGET, &remote)
    else {
        panic!("a successful remote build must provision");
    };
    assert_eq!(env.status, Status::Succeeded);
    assert!(!env.retryable);
    assert!(*remote.build_attempted.borrow(), "the build ran");
}
