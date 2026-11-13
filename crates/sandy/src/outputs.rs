//! List the files a run left at a job's declared output destinations: the paths for the envelope (`OutputRef`) and the
//! paths with sizes and digests for the audit receipt (`OutputSizeRef`, #361). Shared by the direct supervisor and by
//! `sandyd`, so the two build the same lists from the same destinations.

use std::{collections::HashMap, path::Path};

use crate::result::{ContentDigests, OutputRef, OutputSizeRef};

/// One declared output: its name (`None` for a catch-all) and the host directory it is collected to.
pub type DeclaredOutput<'a> = (Option<&'a str>, &'a Path);

/// List the files the backend collected to each declared output's destination as
/// `(logical path, size in bytes)` pairs. The path is logical, not a host path:
/// `<name>/<relpath>` for a named output (`--out NAME:DEST`) and `<relpath>` for a
/// catch-all (`--out DEST`), so it identifies what the job produced independent of
/// where on the host the caller sent it. Sorted by path for a deterministic
/// envelope. Best-effort: an unreadable destination or an unstatable file
/// contributes no entry — shared by [`collect_output_refs`] (envelope.outputs) and
/// [`collect_output_size_refs`] (the receipt's `guest_reported.outputs`, #361),
/// so the two never disagree on what was collected.
pub fn collect_output_entries(outputs: &[DeclaredOutput<'_>]) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    for (name, dest) in outputs {
        walk_outputs(dest, name.unwrap_or(""), &mut entries);
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// [`collect_output_entries`] as [`OutputRef`]s (`envelope.outputs`).
pub fn collect_output_refs(outputs: &[DeclaredOutput<'_>]) -> Vec<OutputRef> {
    collect_output_entries(outputs)
        .into_iter()
        .map(|(path, _)| OutputRef { path })
        .collect()
}

/// [`collect_output_entries`] as [`OutputSizeRef`]s (the receipt's
/// `guest_reported.outputs`, #361). With `digests` (#373, the backend's report
/// of what it collected) each entry carries the sha256 recorded for its logical
/// path; an entry with no recorded digest (a file already at the destination
/// that this run did not collect) carries none.
pub fn collect_output_size_refs(
    outputs: &[DeclaredOutput<'_>],
    digests: Option<&ContentDigests>,
) -> Vec<OutputSizeRef> {
    let by_path: HashMap<&str, &str> = digests
        .into_iter()
        .flat_map(|d| d.files.iter())
        .map(|f| (f.path.as_str(), f.sha256.as_str()))
        .collect();
    collect_output_entries(outputs)
        .into_iter()
        .map(|(path, size_bytes)| {
            let sha256 = by_path.get(path.as_str()).map(|s| (*s).to_owned());
            OutputSizeRef {
                path,
                size_bytes,
                sha256,
            }
        })
        .collect()
}

/// Recurse `dir`, pushing one `(logical path, size)` entry per regular file with a
/// `<prefix>/<name>` logical path (an empty `prefix` yields the bare relative
/// path). Symlinks and special files are skipped — collection already dropped
/// escaping symlinks, so none should remain, and a stray one is not an output.
fn walk_outputs(dir: &Path, prefix: &str, entries: &mut Vec<(String, u64)>) {
    let Ok(dir_entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in dir_entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let rel = if prefix.is_empty() {
            name.into_owned()
        } else {
            format!("{prefix}/{name}")
        };
        match entry.file_type() {
            Ok(ft) if ft.is_dir() => walk_outputs(&entry.path(), &rel, entries),
            Ok(ft) if ft.is_file() => {
                if let Ok(metadata) = entry.metadata() {
                    entries.push((rel, metadata.len()));
                }
            }
            _ => {}
        }
    }
}
