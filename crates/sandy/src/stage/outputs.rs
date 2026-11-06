//! Output staging and collection: a writable share the guest writes into, copied
//! to host destinations at teardown.
//!
//! [`prepare_outputs`] creates a `0700` dir (and a `<name>` subdir per *named*
//! output); the backend shares it read-write at a fixed [`OUTPUT_MOUNT_TAG`] and
//! the guest mounts it at `/run/sandy/outputs`, so the job writes under
//! `/run/sandy/outputs` (catch-all) or `/run/sandy/outputs/<name>` (named).
//! [`collect_outputs`] copies, per output, either the `<name>` subtree or the whole
//! output dir (catch-all, `name = None`) to its host [`Output::dest`] at teardown.
//!
//! The output share is the one guest-writable, host-visible surface, so collection
//! is adversarial-safe: it **skips symlinks** entirely (a job can drop
//! `out/name/x -> /etc/shadow`; following it would copy the host file's bytes, and
//! even preserving it would expose the host target when the dest is later read), it
//! never follows a symlinked directory, and it caps total bytes and entries so a
//! runaway job cannot exhaust the host (INV-1 on the way out). Copying only regular
//! files and directories; preserving in-tree relative symlinks is a follow-up.

use std::{
    fs,
    io::{self, Read},
    os::unix::fs::PermissionsExt,
    path::Path,
};

use sandy_api::result::{ContentDigests, FileDigest, SkipReason, SkippedEntry};
use sandy_fsutil::{Beneath, EntryKind};
use sha2::{Digest, Sha256};

use super::{digest::join_logical, fs_err};
use crate::backend::{BackendError, Output};

/// The virtiofs `mountTag` for the writable outputs share. Fixed, not per-run, so
/// the guest can statically mount it at `/run/sandy/outputs`; it MUST match the
/// guest flake's `fileSystems` device for that mount.
pub const OUTPUT_MOUNT_TAG: &str = "sandy-outputs";

/// A collection ceiling: refuse to copy out more than this many bytes or entries
/// per run, so a runaway job cannot fill the host disk from inside the sandbox.
const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_OUTPUT_ENTRIES: u64 = 100_000;

/// Create a `0700` outputs dir, with an empty writable `<name>` subdir per *named*
/// output (a catch-all needs no subdir; the guest writes the dir root).
///
/// Returns the number of outputs prepared; `0` means the backend attaches no
/// share (the guest mount is `nofail`, so a run with no outputs still boots).
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] when the dir cannot be prepared or a name is
/// not a single safe path component.
pub fn prepare_outputs(outputs: &[Output], outputs_dir: &Path) -> Result<usize, BackendError> {
    if outputs.is_empty() {
        return Ok(0);
    }
    fs::create_dir_all(outputs_dir).map_err(|e| err("create outputs dir", outputs_dir, &e))?;
    fs::set_permissions(outputs_dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| err("tighten outputs dir to 0700", outputs_dir, &e))?;
    for output in outputs {
        if let Some(name) = &output.name {
            validate_output_name(name)?;
            let sub = outputs_dir.join(name);
            fs::create_dir_all(&sub).map_err(|e| err("create output subdir", &sub, &e))?;
        }
    }
    Ok(outputs.len())
}

/// Copy each output's `<name>` subtree from `outputs_dir` to its host destination.
///
/// Best-effort per output (a failure is returned, not silently dropped); the
/// caller runs this before wiping the share. Symlinks are skipped (never followed
/// or recreated), and the run-wide byte/entry ceiling is enforced.
///
/// With `digests` set (#373, `RunSpec::digests`) the copy also hashes each
/// collected file in the same pass, so there is no second read, and returns the
/// report: a sha256 per regular file at its logical path (`<name>/<relpath>` for
/// a named output, `<relpath>` for a catch-all) plus every symlink or special
/// file skipped. The ceiling stays a hard error, so no entry is ever dropped
/// silently under it. With `digests` unset nothing is hashed and the result is
/// `None`.
///
/// # Errors
///
/// Returns [`BackendError::Spawn`] on a copy failure or when the ceiling is hit.
pub fn collect_outputs(
    outputs: &[Output],
    outputs_dir: &Path,
    digests: bool,
) -> Result<Option<ContentDigests>, BackendError> {
    let mut budget = Budget {
        bytes: MAX_OUTPUT_BYTES,
        entries: MAX_OUTPUT_ENTRIES,
    };
    let mut report = digests.then(ContentDigests::default);
    for output in outputs {
        // A named output collects its subtree; a catch-all (`name = None`) collects
        // the whole output dir root.
        let src = match &output.name {
            Some(name) => outputs_dir.join(name),
            None => outputs_dir.to_path_buf(),
        };
        collect_one(
            &src,
            &output.dest,
            output.name.as_deref().unwrap_or(""),
            &mut budget,
            report.as_mut(),
        )?;
        tracing::debug!(name = ?output.name, dest = %output.dest.display(), "collected output");
    }
    if let Some(report) = report.as_mut() {
        report.sort();
    }
    Ok(report)
}

/// Remaining collection ceiling, decremented as entries are copied.
struct Budget {
    bytes: u64,
    entries: u64,
}

impl Budget {
    fn charge(&mut self, bytes: u64, path: &Path) -> Result<(), BackendError> {
        self.entries = self.entries.checked_sub(1).ok_or_else(|| {
            BackendError::Spawn(format!(
                "output collection exceeded {MAX_OUTPUT_ENTRIES} entries at {}",
                path.display()
            ))
        })?;
        self.bytes = self.bytes.checked_sub(bytes).ok_or_else(|| {
            BackendError::Spawn(format!(
                "output collection exceeded {MAX_OUTPUT_BYTES} bytes at {}",
                path.display()
            ))
        })?;
        Ok(())
    }
}

/// An output name is a single safe path component: non-empty, no `/`, and not `.`
/// or `..` — it is a directory entry under the outputs share.
fn validate_output_name(name: &str) -> Result<(), BackendError> {
    let safe = !name.is_empty() && name != "." && name != ".." && !name.contains('/');
    if !safe {
        return Err(BackendError::Spawn(format!(
            "output name {name:?} must be a single path component (no `/`, not `.`/`..`)"
        )));
    }
    Ok(())
}

/// Collect one output: the guest-written `src` to the host `dest`, charging the budget. A directory is created and its
/// entries copied, and a regular file is streamed. A symlink is skipped (never followed, never recreated, see the
/// module docs), as is any other special file (fifo, socket, device). `logical` is the entry's logical path; when
/// `report` is `Some`, each file's sha256 is recorded as it is copied and each skipped entry is recorded with its
/// reason.
///
/// The destination is host-chosen and the source is guest-written, so neither is followed through a link (#618):
/// each is opened once without following one, and everything below is created or read through directory handles.
/// A link at the destination, or planted inside it, is refused with an error, not written through.
fn collect_one(
    src: &Path,
    dest: &Path,
    logical: &str,
    budget: &mut Budget,
    report: Option<&mut ContentDigests>,
) -> Result<(), BackendError> {
    let meta = match fs::symlink_metadata(src) {
        Ok(meta) => meta,
        // The guest declared but never wrote the output: nothing to collect.
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(err("stat output entry", src, &e)),
    };
    let ty = meta.file_type();

    if ty.is_symlink() {
        tracing::warn!(path = %src.display(), "skipping symlink in collected output (host-escape guard)");
        record_skipped(report, logical, SkipReason::Symlink);
        return Ok(());
    }

    budget.charge(if ty.is_file() { meta.len() } else { 0 }, src)?;

    if ty.is_dir() {
        let from = Beneath::open_dir(src).map_err(fs_err)?;
        let to = Beneath::create_dir_at(dest).map_err(fs_err)?;
        copy_dir(&from, &to, logical, budget, report)
    } else if ty.is_file() {
        let mut from = sandy_fsutil::beneath::open_file(src).map_err(fs_err)?;
        let mut to = sandy_fsutil::beneath::create_file_at(dest).map_err(fs_err)?;
        let sha256 = stream_copy(&mut from, &mut to, (src, dest), report.is_some())?;
        record_file(report, logical, sha256);
        Ok(())
    } else {
        tracing::warn!(path = %src.display(), "skipping non-regular output entry");
        record_skipped(report, logical, SkipReason::NonRegular);
        Ok(())
    }
}

/// Copy the entries of the directory `from` into the directory `to`, through the two handles.
fn copy_dir(
    from: &Beneath,
    to: &Beneath,
    logical: &str,
    budget: &mut Budget,
    mut report: Option<&mut ContentDigests>,
) -> Result<(), BackendError> {
    for entry in from.entries().map_err(fs_err)? {
        let (name, kind) = entry.map_err(fs_err)?;
        let path = from.path().join(&name);
        let entry_logical = join_logical(logical, &name.to_string_lossy());
        match kind {
            EntryKind::Symlink => {
                // Counted though skipped: every entry scanned costs the ceiling, so a guest cannot make the host walk
                // an unbounded directory of links.
                budget.charge(0, &path)?;
                tracing::warn!(path = %path.display(), "skipping symlink in collected output (host-escape guard)");
                record_skipped(report.as_deref_mut(), &entry_logical, SkipReason::Symlink);
            }
            EntryKind::Dir => {
                budget.charge(0, &path)?;
                let sub_from = from.open_subdir(&name).map_err(fs_err)?;
                let sub_to = to.create_dir(&name).map_err(fs_err)?;
                copy_dir(&sub_from, &sub_to, &entry_logical, budget, report.as_deref_mut())?;
            }
            EntryKind::File => {
                let mut file = from.open_file(&name).map_err(fs_err)?;
                let len = file.metadata().map_err(|e| err("stat output file", &path, &e))?.len();
                budget.charge(len, &path)?;
                let dest_path = to.path().join(&name);
                let mut out = to.create_file(&name).map_err(fs_err)?;
                let sha256 = stream_copy(&mut file, &mut out, (&path, &dest_path), report.is_some())?;
                record_file(report.as_deref_mut(), &entry_logical, sha256);
            }
            EntryKind::Other => {
                budget.charge(0, &path)?;
                tracing::warn!(path = %path.display(), "skipping non-regular output entry");
                record_skipped(report.as_deref_mut(), &entry_logical, SkipReason::NonRegular);
            }
        }
    }
    Ok(())
}

fn record_file(report: Option<&mut ContentDigests>, logical: &str, sha256: Option<String>) {
    if let (Some(report), Some(sha256)) = (report, sha256) {
        report.files.push(FileDigest {
            path: logical.to_owned(),
            sha256,
        });
    }
}

fn record_skipped(report: Option<&mut ContentDigests>, logical: &str, reason: SkipReason) {
    if let Some(report) = report {
        report.skipped.push(SkippedEntry {
            path: logical.to_owned(),
            reason,
        });
    }
}

/// Stream the open file `reader` to `writer` a block at a time (outputs may be large). `paths` is (source,
/// destination), for messages. With `hash` set, the bytes written are also fed through sha256 and its lowercase hex is
/// returned; otherwise nothing is hashed.
fn stream_copy(
    reader: &mut fs::File,
    writer: &mut fs::File,
    paths: (&Path, &Path),
    hash: bool,
) -> Result<Option<String>, BackendError> {
    let (src, dest) = paths;
    let mut hasher = hash.then(Sha256::new);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).map_err(|e| err("read output file", src, &e))?;
        if n == 0 {
            break;
        }
        io::Write::write_all(writer, &buf[..n]).map_err(|e| err("write output file", dest, &e))?;
        if let Some(hasher) = hasher.as_mut() {
            hasher.update(&buf[..n]);
        }
    }
    Ok(hasher.map(|h| hex::encode(h.finalize())))
}

/// A named [`BackendError::Spawn`] carrying the failed op, path, and os error.
fn err(op: &str, path: &Path, e: &std::io::Error) -> BackendError {
    BackendError::Spawn(format!("{op} {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;

    /// `prepare_outputs` makes a `0700` dir with an empty writable subdir per
    /// output, and `collect_outputs` copies what the "guest" wrote to each dest.
    #[test]
    fn prepares_subdirs_and_collects_to_dest() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let dest = run.path().join("collected");
        let outputs = [Output {
            name: Some("result".to_string()),
            dest: dest.clone(),
        }];

        let n = prepare_outputs(&outputs, &outputs_dir)?;
        assert_eq!(n, 1);
        assert_eq!(fs::metadata(&outputs_dir)?.permissions().mode() & 0o777, 0o700);
        // The "guest" writes into the share.
        fs::write(outputs_dir.join("result").join("f"), b"produced")?;
        fs::create_dir(outputs_dir.join("result").join("sub"))?;
        fs::write(outputs_dir.join("result").join("sub").join("g"), b"deep")?;

        collect_outputs(&outputs, &outputs_dir, false)?;

        assert_eq!(fs::read(dest.join("f"))?, b"produced");
        assert_eq!(fs::read(dest.join("sub").join("g"))?, b"deep");
        Ok(())
    }

    /// Adversarial: a symlink the "guest" drops into the share pointing at a host
    /// file is skipped during collection — neither its bytes nor the symlink itself
    /// reach the dest, so the host file is not exposed when the dest is read.
    #[test]
    fn a_symlink_escape_is_skipped() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let dest = run.path().join("collected");
        let secret = run.path().join("host-secret");
        fs::write(&secret, b"TOP-SECRET")?;
        let outputs = [Output {
            name: Some("o".to_string()),
            dest: dest.clone(),
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        std::os::unix::fs::symlink(&secret, outputs_dir.join("o").join("leak"))?;
        fs::write(outputs_dir.join("o").join("real"), b"ok")?;

        collect_outputs(&outputs, &outputs_dir, false)?;

        assert!(
            fs::symlink_metadata(dest.join("leak")).is_err(),
            "the escaping symlink must not be collected at all"
        );
        // Real files alongside it are still collected.
        assert_eq!(fs::read(dest.join("real"))?, b"ok");
        Ok(())
    }

    /// #618: a symlink at the destination of a collected directory is refused, not followed. Followed, the files
    /// would land in whatever the link names, written as the daemon's user.
    #[test]
    fn a_symlink_at_the_destination_is_refused() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let victim = run.path().join("victim-dir");
        fs::create_dir(&victim)?;
        let dest = run.path().join("collected");
        std::os::unix::fs::symlink(&victim, &dest)?;
        let outputs = [Output {
            name: Some("o".to_string()),
            dest,
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        fs::write(outputs_dir.join("o").join("f"), b"produced")?;

        let result = collect_outputs(&outputs, &outputs_dir, false);

        assert!(result.is_err(), "a symlinked destination must be refused");
        assert!(!victim.join("f").exists(), "nothing was written through the link");
        Ok(())
    }

    /// #618: the same for a file: a link at its destination must not let the daemon overwrite the file it names.
    #[test]
    fn a_symlink_at_a_destination_file_is_refused() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let victim = run.path().join("victim-file");
        fs::write(&victim, b"HOST-FILE")?;
        let dest = run.path().join("out.txt");
        std::os::unix::fs::symlink(&victim, &dest)?;
        let outputs = [Output {
            name: Some("o".to_string()),
            dest,
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        // The guest replaces the output directory with a file.
        fs::remove_dir(outputs_dir.join("o"))?;
        fs::write(outputs_dir.join("o"), b"produced")?;

        let result = collect_outputs(&outputs, &outputs_dir, false);

        assert!(result.is_err(), "a symlinked destination file must be refused");
        assert_eq!(fs::read(&victim)?, b"HOST-FILE", "the file the link names is untouched");
        Ok(())
    }

    /// #618: a link planted inside the destination tree (a subdirectory swapped for a link) is refused, not followed.
    #[test]
    fn a_symlink_inside_the_destination_tree_is_refused() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let victim = run.path().join("victim-dir");
        fs::create_dir(&victim)?;
        let dest = run.path().join("collected");
        fs::create_dir(&dest)?;
        std::os::unix::fs::symlink(&victim, dest.join("sub"))?;
        let outputs = [Output {
            name: Some("o".to_string()),
            dest,
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        fs::create_dir(outputs_dir.join("o").join("sub"))?;
        fs::write(outputs_dir.join("o").join("sub").join("g"), b"produced")?;

        let result = collect_outputs(&outputs, &outputs_dir, false);

        assert!(result.is_err(), "a link inside the destination must be refused");
        assert!(!victim.join("g").exists(), "nothing was written through the link");
        Ok(())
    }

    /// #618 (review): the components above the destination resolve as the OS resolves them, so a destination under a
    /// linked directory (macOS `/tmp`) works. Only the destination itself and what is below it are not followed.
    #[test]
    fn a_destination_under_a_symlinked_parent_is_collected() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let real = run.path().join("real");
        fs::create_dir(&real)?;
        let linked = run.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked)?;
        let outputs = [Output {
            name: Some("o".to_string()),
            dest: linked.join("collected"),
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        fs::write(outputs_dir.join("o").join("f"), b"produced")?;

        collect_outputs(&outputs, &outputs_dir, false)?;

        assert_eq!(fs::read(real.join("collected").join("f"))?, b"produced");
        Ok(())
    }

    /// #680 (review): every entry scanned counts against the ceiling, a skipped symlink included, so a guest cannot
    /// make the host walk an unbounded directory of links.
    #[test]
    fn skipped_symlinks_count_against_the_entry_ceiling() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let src = run.path().join("src");
        fs::create_dir(&src)?;
        for i in 0..5 {
            std::os::unix::fs::symlink("/nonexistent", src.join(format!("l{i}")))?;
        }
        let dest = run.path().join("dest");
        let from = Beneath::open_dir(&src)?;
        let to = Beneath::create_dir_at(&dest)?;
        let mut budget = Budget {
            bytes: u64::MAX,
            entries: 3,
        };

        let result = copy_dir(&from, &to, "", &mut budget, None);

        assert!(result.is_err(), "5 links must exceed a ceiling of 3 entries");
        Ok(())
    }

    /// #373: with digests off nothing is hashed and there is no report.
    #[test]
    fn digests_off_returns_no_report() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let outputs = [Output {
            name: Some("o".to_string()),
            dest: run.path().join("collected"),
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        fs::write(outputs_dir.join("o").join("f"), b"hello")?;

        assert_eq!(collect_outputs(&outputs, &outputs_dir, false)?, None);
        Ok(())
    }

    /// #373: digests on gives a known sha256 per collected file at its logical
    /// path (named: `<name>/<rel>`; catch-all: `<rel>`), sorted, with the bytes
    /// at the destination matching.
    #[test]
    fn digests_on_hashes_each_collected_file_by_logical_path() -> anyhow::Result<()> {
        const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let named_dest = run.path().join("named");
        let loose_dest = run.path().join("loose");
        let named = [Output {
            name: Some("result".to_string()),
            dest: named_dest.clone(),
        }];
        prepare_outputs(&named, &outputs_dir)?;
        fs::write(outputs_dir.join("result").join("f"), b"hello")?;
        fs::create_dir(outputs_dir.join("result").join("sub"))?;
        fs::write(outputs_dir.join("result").join("sub").join("e"), b"")?;

        let report = collect_outputs(&named, &outputs_dir, true)?.context("report when digests are on")?;

        let got: Vec<(&str, &str)> = report
            .files
            .iter()
            .map(|d| (d.path.as_str(), d.sha256.as_str()))
            .collect();
        assert_eq!(got, [("result/f", HELLO), ("result/sub/e", EMPTY)]);
        assert!(report.skipped.is_empty());
        assert_eq!(fs::read(named_dest.join("f"))?, b"hello");

        let catch_all = [Output {
            name: None,
            dest: loose_dest,
        }];
        fs::write(outputs_dir.join("top"), b"hello")?;
        let report = collect_outputs(&catch_all, &outputs_dir, true)?.context("catch-all report")?;
        assert!(
            report.files.iter().any(|d| d.path == "top" && d.sha256 == HELLO),
            "catch-all path has no name prefix: {report:?}"
        );
        assert!(report.files.iter().any(|d| d.path == "result/f"));
        Ok(())
    }

    /// #373: a symlink the guest planted is recorded as skipped (and still not
    /// collected), not silently omitted.
    #[test]
    fn digests_record_a_skipped_symlink() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let dest = run.path().join("collected");
        let outputs = [Output {
            name: Some("o".to_string()),
            dest: dest.clone(),
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        std::os::unix::fs::symlink("/etc/hostname", outputs_dir.join("o").join("leak"))?;
        fs::write(outputs_dir.join("o").join("real"), b"hello")?;

        let report = collect_outputs(&outputs, &outputs_dir, true)?.context("report")?;

        assert_eq!(
            report.skipped,
            [SkippedEntry {
                path: "o/leak".to_string(),
                reason: SkipReason::Symlink
            }]
        );
        assert_eq!(report.files.len(), 1);
        assert!(fs::symlink_metadata(dest.join("leak")).is_err());
        Ok(())
    }

    /// #373: a fifo is recorded as skipped (`non_regular`).
    #[test]
    fn digests_record_a_skipped_special_file() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let outputs = [Output {
            name: Some("o".to_string()),
            dest: run.path().join("collected"),
        }];
        prepare_outputs(&outputs, &outputs_dir)?;
        let fifo = outputs_dir.join("o").join("pipe");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
        anyhow::ensure!(status.success(), "mkfifo failed");

        let report = collect_outputs(&outputs, &outputs_dir, true)?.context("report")?;

        assert_eq!(
            report.skipped,
            [SkippedEntry {
                path: "o/pipe".to_string(),
                reason: SkipReason::NonRegular
            }]
        );
        Ok(())
    }

    /// No outputs prepares nothing and creates no dir.
    #[test]
    fn no_outputs_prepares_nothing() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        assert_eq!(prepare_outputs(&[], &outputs_dir)?, 0);
        assert!(!outputs_dir.exists());
        Ok(())
    }

    /// A catch-all output (`name = None`) collects everything the "guest" wrote
    /// under the output dir root — named subdirs and loose files alike.
    #[test]
    fn catch_all_collects_the_whole_output_dir() -> anyhow::Result<()> {
        let run = tempfile::TempDir::new()?;
        let outputs_dir = run.path().join("outputs");
        let dest = run.path().join("collected");
        let outputs = [Output {
            name: None,
            dest: dest.clone(),
        }];

        let n = prepare_outputs(&outputs, &outputs_dir)?;
        assert_eq!(n, 1);
        // The "guest" writes loose into the share root (no declared name).
        fs::write(outputs_dir.join("top"), b"root")?;
        fs::create_dir(outputs_dir.join("d"))?;
        fs::write(outputs_dir.join("d").join("nested"), b"deep")?;

        collect_outputs(&outputs, &outputs_dir, false)?;

        assert_eq!(fs::read(dest.join("top"))?, b"root");
        assert_eq!(fs::read(dest.join("d").join("nested"))?, b"deep");
        Ok(())
    }

    /// Adversarial: an output name with a separator or `..` is rejected.
    #[test]
    fn rejects_a_name_that_escapes_the_share() {
        let run = tempfile::TempDir::new().expect("tempdir");
        for bad in ["../escape", "a/b", "..", "."] {
            let outputs = [Output {
                name: Some(bad.to_string()),
                dest: run.path().join("d"),
            }];
            assert!(
                prepare_outputs(&outputs, &run.path().join("outputs")).is_err(),
                "name {bad:?} must be rejected"
            );
        }
    }
}
