# `sandy` public API snapshot

The deep-crate contract: `sandy` is one library with a **private module tree** and
this curated facade as its entire public surface — operations, their contract
types, and the injection trait seams. Every implementation module (`journal`,
`reconcile`, `collect`, `schema`, `config`, `gc`, `metrics`, `backend`, `result`,
`strategy`, `egress`, `seed`, `provision`, `cred`) is declared `mod`, not
`pub mod`, so nothing reaches into it from outside the crate.

A change to this list is an API change: update this file in the same commit and
justify it in review. (When `cargo public-api` is available, regenerate with
`cargo public-api -p sandy` and diff against this file; it is not in the dev shell
today, so this list is maintained from `crates/sandy/src/lib.rs`'s `pub use`
facade.)

## Run plane

- `backend`: `BackendError`, `BoxState`, `FakeBackend`, `Grants`, `Mount`, `Outcome`, `PlanError`, `RunSpec`, `SecretRef`, `SecretSource`, `VmBackend`, `validate_no_secret_leak`
- `result`: `Classification`, `Logs`, `OutputRef`, `OutputStatus`, `ProcessExit`, `Provenance`, `RESULT_SCHEMA_VERSION`, `Receipt`, `ResultEnvelope`, `Status`, `classify_backend_error`, `classify_invalid_plan`, `classify_outcome`
- `journal`: `JobLock`, `Journal`, `detect_fs_type`, `ensure_local_posix_fs`, `is_networked_fs`, `new_job_id`
- `schema::v1`: `JOURNAL_SCHEMA_VERSION`, `JobRecord`, `JobState`
- `collect`: `CollectError`, `OutputSpec`, `collect`
- `config`: `CollectionConfig`
- `reconcile`: `reconcile_job`
- `error`: `CoreError`

## Provisioning

- `strategy`: `BootAxis`, `BuildAxis`, `HostFacts`, `ProvisioningStrategy`, `classify`
- `provision`: `HostNixProvisioner`, `Job`, `ProvisionOutcome`, `RemoteArtifacts`, `RemoteBuilder`, `RemoteError`, `decide_fallback`, `provision`, `provision_remote_build`

## Seed identity

- `seed`: `ALLOWED_IMAGE_FORMATS`, `ArtifactEntry`, `MinisignVerifier`, `Requirements`, `SeedManifest`, `SeedRefusal`, `SignatureVerifier`, `VerifiedSeed`, `acquire`, `sha256_hex`

## Egress

- `egress`: `AllowList`, `EgressRule`, `macos_egress_statement`, `to_nftables`

## Operability

- `gc`: `StagedImage`, `plan_eviction`
- `metrics`: `RunMetrics`, `RunPhase`

## Credential minting

- `cred`: (stub — no public items yet; surface lands with the credential-minting block)
