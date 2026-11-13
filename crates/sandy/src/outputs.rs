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

/// The entries [`collect_output_size_refs_capped`] kept, and whether there were more files than the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CappedOutputs {
    /// At most `cap` entries: the first in logical-path order, the same prefix the unlimited listing starts with.
    pub entries: Vec<OutputSizeRef>,
    /// Whether the destinations held more files than `cap`.
    pub more: bool,
}

/// [`collect_output_size_refs`] bounded to `cap` entries (A2c, #838): the walk stops once it has seen `cap + 1` files
/// per destination, so a destination that already holds a very large tree costs a bounded number of stats, not one per
/// file. Children are visited in logical-path order, so what is kept is the same prefix the unlimited listing starts
/// with, whatever order the filesystem lists a directory in.
#[must_use]
pub fn collect_output_size_refs_capped(
    outputs: &[DeclaredOutput<'_>],
    digests: Option<&ContentDigests>,
    cap: usize,
) -> CappedOutputs {
    let by_path: HashMap<&str, &str> = digests
        .into_iter()
        .flat_map(|d| d.files.iter())
        .map(|f| (f.path.as_str(), f.sha256.as_str()))
        .collect();
    // Each destination yields at most `cap + 1` files in logical-path order; the first `cap` of their union are the
    // first `cap` of the whole, and a `cap + 1`th file anywhere means there were more.
    let mut found: Vec<(String, std::path::PathBuf)> = Vec::new();
    for (name, dest) in outputs {
        walk_capped(dest, name.unwrap_or(""), cap.saturating_add(1), &mut found);
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    let more = found.len() > cap;
    found.truncate(cap);
    let entries = found
        .into_iter()
        .filter_map(|(path, file)| {
            let size_bytes = std::fs::metadata(file).ok()?.len();
            let sha256 = by_path.get(path.as_str()).map(|s| (*s).to_owned());
            Some(OutputSizeRef {
                path,
                size_bytes,
                sha256,
            })
        })
        .collect();
    CappedOutputs { entries, more }
}

/// Collect up to `limit` regular files under `dir` as `(logical path, host path)`, visiting children in logical-path
/// order: each name is compared with a trailing `/` for a directory, so a file `a.txt` comes before the children of a
/// directory `a` exactly as the strings `a.txt` and `a/x` compare. Symlinks and special files are skipped, as in
/// [`walk_outputs`]. Returns once `limit` files are held.
fn walk_capped(dir: &Path, prefix: &str, limit: usize, found: &mut Vec<(String, std::path::PathBuf)>) {
    let Ok(dir_entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut children: Vec<(String, std::path::PathBuf, bool)> = dir_entries
        .flatten()
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            let is_dir = file_type.is_dir();
            (is_dir || file_type.is_file()).then(|| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let key = if is_dir { format!("{name}/") } else { name };
                (key, entry.path(), is_dir)
            })
        })
        .collect();
    children.sort_by(|a, b| a.0.cmp(&b.0));
    let start = found.len();
    for (key, path, is_dir) in children {
        if found.len().saturating_sub(start) >= limit {
            return;
        }
        let name = key.trim_end_matches('/');
        let rel = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}/{name}")
        };
        if is_dir {
            walk_capped(&path, &rel, limit - found.len().saturating_sub(start), found);
        } else {
            found.push((rel, path));
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// #838: a capped listing is the first `cap` entries of the unlimited one in logical-path order, however the
    /// filesystem lists directories, and says there were more. The names are the hard cases for the order: a file whose
    /// name sorts before a directory's children (`a.txt` against `a/x`), and a dash.
    #[test]
    fn a_capped_listing_is_the_unlimited_listings_prefix_and_says_there_were_more() -> anyhow::Result<()> {
        let dest = tempfile::tempdir()?;
        for (dir, file) in [
            ("a", "x"),
            ("a", "y"),
            ("a-b", "c"),
            ("b", "z"),
            ("", "a.txt"),
            ("", "a0"),
            ("", "m"),
        ] {
            let d = dest.path().join(dir);
            std::fs::create_dir_all(&d)?;
            std::fs::write(d.join(file), b"1")?;
        }
        let declared = [(Some("out"), dest.path())];
        let all = collect_output_size_refs(&declared, None);
        assert_eq!(all.len(), 7);
        for cap in [1, 3, 6] {
            let capped = collect_output_size_refs_capped(&declared, None, cap);
            assert_eq!(capped.entries, all[..cap], "cap {cap}: the unlimited listing's prefix");
            assert!(capped.more, "cap {cap}: there were more files");
        }
        for cap in [7, 100] {
            let capped = collect_output_size_refs_capped(&declared, None, cap);
            assert_eq!(capped.entries, all, "cap {cap}: everything");
            assert!(!capped.more, "cap {cap}: nothing more");
        }
        Ok(())
    }

    /// #838: with several declared destinations the cap applies to the merged listing.
    #[test]
    fn the_cap_applies_to_the_merged_listing_of_several_destinations() -> anyhow::Result<()> {
        let one = tempfile::tempdir()?;
        let two = tempfile::tempdir()?;
        for i in 0..4 {
            std::fs::write(one.path().join(format!("f{i}")), b"1")?;
            std::fs::write(two.path().join(format!("g{i}")), b"1")?;
        }
        let declared = [(Some("one"), one.path()), (Some("two"), two.path())];
        let all = collect_output_size_refs(&declared, None);
        let capped = collect_output_size_refs_capped(&declared, None, 5);
        assert_eq!(capped.entries, all[..5]);
        assert!(capped.more);
        Ok(())
    }
}
