//! Collect the files a backend wrote to a job's declared output destinations,
//! for both the envelope (`OutputRef`) and the audit receipt
//! (`OutputSizeRef`, #361).

use std::path::Path;

use sandy::{OutputRef, OutputSizeRef};

use crate::plan::JobPlan;

/// List the files the backend collected to each declared output's destination as
/// `(logical path, size in bytes)` pairs. The path is logical, not a host path:
/// `<name>/<relpath>` for a named output (`--out NAME:DEST`) and `<relpath>` for a
/// catch-all (`--out DEST`), so it identifies what the job produced independent of
/// where on the host the caller sent it. Sorted by path for a deterministic
/// envelope. Best-effort: an unreadable destination or an unstatable file
/// contributes no entry — shared by [`collect_output_refs`] (envelope.outputs) and
/// [`collect_output_size_refs`] (the receipt's `guest_reported.outputs`, #361),
/// so the two never disagree on what was collected.
fn collect_output_entries(plan: &JobPlan) -> Vec<(String, u64)> {
    let mut entries = Vec::new();
    for output in &plan.outputs {
        walk_outputs(&output.dest, output.name.as_deref().unwrap_or(""), &mut entries);
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    entries
}

/// [`collect_output_entries`] as [`OutputRef`]s (`envelope.outputs`).
pub(super) fn collect_output_refs(plan: &JobPlan) -> Vec<OutputRef> {
    collect_output_entries(plan)
        .into_iter()
        .map(|(path, _)| OutputRef { path })
        .collect()
}

/// [`collect_output_entries`] as [`OutputSizeRef`]s (the receipt's
/// `guest_reported.outputs`, #361).
pub(super) fn collect_output_size_refs(plan: &JobPlan) -> Vec<OutputSizeRef> {
    collect_output_entries(plan)
        .into_iter()
        .map(|(path, size_bytes)| OutputSizeRef { path, size_bytes })
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
