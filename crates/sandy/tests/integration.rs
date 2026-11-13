//! Tier-2 integration tests (sandbox-runnable): collection flows against fixtures on a generic POSIX FS. No hypervisor.
//!
//! These cover the Block 4 verification and adversarial rows.

use anyhow::Context;
use sandy::{CollectionConfig, Outcome, OutputSpec, collect};

const CAP: u64 = 1 << 20;

fn exit_zero() -> Outcome {
    Outcome {
        digests: None,
        booted: true,
        guest_exit: Some(0),
        transport_error: None,
        timed_out: false,
        console: String::new(),
    }
}

/// Verification: exit-0 collect — a declared output is collected to `out/`.
#[test]
fn exit_zero_collects_declared_output() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    std::fs::write(source.join("result.txt"), b"hello").context("write output")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let collected = collect(&exit_zero(), &source, &job, &declared, &config).context("collect declared output")?;

    assert_eq!(collected.len(), 1);
    assert_eq!(collected[0].path, "result.txt");
    assert!(job.join("out").join("result.txt").exists());
    Ok(())
}

/// Adversarial: required-missing — exit 0 but a required output is absent →
/// error, and no partial `out/`.
#[test]
fn required_missing_fails_without_partial_out() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    let declared = [OutputSpec {
        guest_path: "missing.txt".to_string(),
        name: "missing.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(result.is_err(), "missing required output must fail");
    assert!(!job.join("out").exists(), "no partial out/ may be observable");
    Ok(())
}

/// Adversarial: torn-on-kill — a leftover half-populated `out.tmp/` must never
/// be promoted to `out/`.
#[test]
fn torn_out_tmp_never_promoted() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(job.join("out.tmp")).context("create stale out.tmp")?;
    // A torn partial left by a previous killed run.
    std::fs::write(job.join("out.tmp").join("partial.txt"), b"half").context("write partial")?;
    std::fs::write(source.join("result.txt"), b"hello").context("write real output")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let _ = collect(&exit_zero(), &source, &job, &declared, &config).context("collect over a torn out.tmp")?;
    assert!(
        !job.join("out").join("partial.txt").exists(),
        "a torn partial must never surface in out/"
    );
    Ok(())
}

/// Adversarial: symlink — an output that is a symlink is refused by
/// `O_NOFOLLOW`; the target bytes are never collected (INV-2).
#[test]
fn symlink_output_is_refused() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    let secret = tmp.path().join("host-secret");
    std::fs::write(&secret, b"TOP-SECRET").context("write host secret")?;
    std::os::unix::fs::symlink(&secret, source.join("result.txt")).context("make symlink")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(result.is_err(), "a symlink output must be refused");
    let collected = job.join("out").join("result.txt");
    if collected.exists() {
        let bytes = std::fs::read(&collected).context("read collected")?;
        assert_ne!(bytes, b"TOP-SECRET", "symlink target bytes must not leak");
    }
    Ok(())
}

/// Adversarial: intermediate symlink — an output reachable only through a parent
/// the guest turned into a symlink out of the RW area is refused; host bytes
/// outside the RW area are never collected (INV-2).
#[test]
fn intermediate_symlink_output_is_refused() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    std::fs::create_dir_all(&outside).context("create outside dir")?;
    std::fs::write(outside.join("host-secret"), b"TOP-SECRET").context("write host secret")?;
    // The guest replaces a parent directory with a link pointing out of the RW area.
    std::os::unix::fs::symlink(&outside, source.join("link")).context("make parent symlink")?;
    let declared = [OutputSpec {
        guest_path: "link/host-secret".to_string(),
        name: "host-secret".to_string(),
        required: true,
    }];
    let config = CollectionConfig { per_job_cap_bytes: CAP };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(
        result.is_err(),
        "an output behind an escaping parent symlink must be refused"
    );
    let collected = job.join("out").join("host-secret");
    if collected.exists() {
        let bytes = std::fs::read(&collected).context("read collected")?;
        assert_ne!(bytes, b"TOP-SECRET", "host bytes outside the RW area must not leak");
    }
    Ok(())
}

/// Adversarial: over-quota — an output beyond the per-job cap fails; the file is
/// not truncated.
#[test]
fn over_quota_fails_without_truncation() -> anyhow::Result<()> {
    let tmp = tempfile::tempdir()?;
    let source = tmp.path().join("rw");
    let job = tmp.path().join("job");
    std::fs::create_dir_all(&source).context("create rw dir")?;
    std::fs::create_dir_all(&job).context("create job dir")?;
    let big = vec![b'x'; 2048];
    std::fs::write(source.join("result.txt"), &big).context("write oversized output")?;
    let declared = [OutputSpec {
        guest_path: "result.txt".to_string(),
        name: "result.txt".to_string(),
        required: true,
    }];
    let config = CollectionConfig {
        per_job_cap_bytes: 1024,
    };

    let result = collect(&exit_zero(), &source, &job, &declared, &config);
    assert!(result.is_err(), "exceeding the cap must fail");
    let meta = std::fs::metadata(source.join("result.txt")).context("stat source")?;
    assert_eq!(meta.len(), 2048, "source must not be truncated");
    Ok(())
}
