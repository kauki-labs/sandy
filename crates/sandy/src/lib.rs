//! The `sandy` library: one deep crate behind a small, curated API.
//!
//! The implementation modules are private; the public surface is the curated
//! `pub use` facade re-exported below — the operations, their contract types, and
//! the injection trait seams. The capabilities, all provable without a hypervisor:
//!
//! - **Run plane** — the pinned [`VmBackend`] seam plus the `snake_case` data types (INV-8) and a [`FakeBackend`]
//!   double; the LOCKED result envelope [`ResultEnvelope`] (INV-11); the [`Journal`] of one atomic, flock-guarded
//!   record per job (INV-3/5/6); exit-0-only `O_NOFOLLOW` [`collect`]ion (INV-2/4); and [`reconcile_job`] under the
//!   job's flock (INV-3).
//! - **Provisioning** — [`classify`] host facts into a [`ProvisioningStrategy`], then [`provision`] /
//!   [`provision_remote_build`] / [`decide_fallback`] over the [`HostNixProvisioner`] and [`RemoteBuilder`] seams.
//! - **Seed identity** — [`acquire`] a [`VerifiedSeed`] via a [`SignatureVerifier`].
//! - **Egress** — [`to_nftables`] translation and [`macos_egress_statement`].
//! - **Nix topology** — a typed [`Topology`] read from a guest flake attr via [`topology`] / [`parse_topology`]
//!   (INV-TOPOLOGY).
//! - **Operability** — [`RunMetrics`] and staging [`plan_eviction`].

// Deep crate: the module tree is private. The curated `pub use` facade below is
// the entire public surface — operations, their contract types, and the trait
// seams — so callers cannot reach into an implementation module.
mod backend;
mod collect;
mod config;
mod cred;
mod egress;
mod error;
mod gc;
mod journal;
mod metrics;
mod nix;
mod provision;
mod reconcile;
mod result;
mod schema;
mod seed;
mod stage;
mod strategy;

pub use backend::{
    BackendError, BoxState, FakeBackend, Grants, Mount, Outcome, PlanError, RunSpec, SecretRef, SecretSource,
    VmBackend, validate_no_secret_leak,
};
pub use collect::{CollectError, OutputSpec, collect};
pub use config::CollectionConfig;
pub use egress::{AllowList, EgressRule, macos_egress_statement, to_nftables};
pub use error::CoreError;
pub use gc::{StagedImage, plan_eviction};
pub use journal::{JobLock, Journal, detect_fs_type, ensure_local_posix_fs, is_networked_fs, new_job_id};
pub use metrics::{RunMetrics, RunPhase};
pub use nix::{Hypervisor, Share, StoreBacking, Topology, parse_topology, topology};
pub use provision::{
    HostNixProvisioner, Job, ProvisionOutcome, RemoteArtifacts, RemoteBuilder, RemoteError, decide_fallback, provision,
    provision_remote_build,
};
pub use reconcile::reconcile_job;
pub use result::{
    Classification, Logs, OutputRef, OutputStatus, ProcessExit, Provenance, RESULT_SCHEMA_VERSION, Receipt,
    ResultEnvelope, Status, classify_backend_error, classify_invalid_plan, classify_outcome,
};
pub use schema::v1::{JOURNAL_SCHEMA_VERSION, JobRecord, JobState};
pub use seed::{
    ALLOWED_IMAGE_FORMATS, ArtifactEntry, MinisignVerifier, Requirements, SeedManifest, SeedRefusal, SignatureVerifier,
    VerifiedSeed, acquire, sha256_hex,
};
pub use stage::{StagedSecret, TagPool, mount_args, stage_secrets, wipe};
pub use strategy::{BootAxis, BuildAxis, HostFacts, ProvisioningStrategy, classify};

/// fsync a directory so a preceding create/rename within it is durable across a
/// crash (INV-4/INV-6).
pub(crate) fn fsync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}
