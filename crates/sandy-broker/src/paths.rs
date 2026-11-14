//! Host-path confinement for a submit body (decision 4).

use std::{
    io,
    path::{Component, Path, PathBuf},
};

/// Whether `path` is absolute, free of `..`, inside one of `roots`, and
/// reaches its target through no symlink below the root. A symlink anywhere
/// under the root is refused, including a dangling one, because sandyd later
/// opens and writes the path and follows links. A part that does not exist yet
/// (an output destination) is allowed, since there is nothing to follow. An
/// empty `roots` allows nothing.
///
/// A path confined to one of the operator's roots, in the form `sandyd` opens (#618).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rooted {
    /// The operator's configured root, canonical: never a spelling the client chose. `sandyd` follows the root, so a
    /// root the client controls (a symlink it can retarget after the check below) would let it redirect every open
    /// beneath it.
    pub root: PathBuf,
    /// The path rewritten onto `root`: `root` joined with the components the client named below its own spelling of
    /// the root.
    pub path: PathBuf,
}

/// This is a check at one moment. It cannot stop a client that swaps a directory for a link after the check, so
/// the root and the rewritten path ([`root_for`]) go to sandyd, which opens the path beneath the root without
/// following a link (decision 4, #618).
#[cfg(test)]
pub(crate) fn within_roots(path: &str, roots: &[PathBuf]) -> bool {
    root_for(path, roots).is_some()
}

/// Confine `path` to one of `roots` and return it as sandyd opens it (#618): the same checks as [`within_roots`], then
/// the canonical root and the path rewritten onto it, so the client's spelling of the root (an alias it controls) is
/// dropped. When several roots contain the path, the nearest wins, so a nested root confines more.
pub(crate) fn root_for(path: &str, roots: &[PathBuf]) -> Option<Rooted> {
    let path = Path::new(path);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    roots
        .iter()
        .filter_map(|root| confined(path, root))
        .max_by_key(|rooted| rooted.root.components().count())
}

/// `path` beneath `root` when it reaches its target through no symlink below the root.
fn confined(path: &Path, root: &Path) -> Option<Rooted> {
    let real_root = root.canonicalize().ok()?;
    // The caller may name the root through any alias. Take the shortest ancestor
    // that resolves to the root, so every component below it is walked.
    let spelled = path
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .find(|a| a.canonicalize().is_ok_and(|c| c == real_root))?;
    let rest = path.strip_prefix(spelled).ok()?;
    let mut names = Vec::new();
    for part in rest.components() {
        match part {
            Component::Normal(name) => names.push(name),
            Component::CurDir => {}
            _ => return None,
        }
    }
    let mut at = real_root.clone();
    for name in &names {
        at.push(name);
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => return None,
            Ok(_) => {}
            // A part that does not exist yet (an output destination) has nothing to follow below it.
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(_) => return None,
        }
    }
    let path = names.iter().fold(real_root.clone(), |path, name| path.join(name));
    Some(Rooted { root: real_root, path })
}

/// Resolve every configured root to its canonical path, once, at startup (#618). The broker sends that path to
/// `sandyd` as the root, so it must be the operator's value and not something a client can retarget.
///
/// # Errors
///
/// A message naming the root that does not exist or cannot be resolved.
pub(crate) fn canonical_roots(roots: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    canonical_roots_with(roots, |root| root.canonicalize())
}

/// [`canonical_roots`] with the resolver injected, so a test can name a root the file system of the test host cannot
/// hold (a non-UTF-8 name, which macOS refuses to create).
fn canonical_roots_with(
    roots: &[PathBuf],
    resolve: impl Fn(&Path) -> io::Result<PathBuf>,
) -> Result<Vec<PathBuf>, String> {
    roots
        .iter()
        .map(|root| resolve(root).map_err(|e| format!("root {} cannot be resolved: {e}", root.display())))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use anyhow::Context as _;

    use super::*;

    fn root_with_outside() -> anyhow::Result<(tempfile::TempDir, PathBuf, PathBuf)> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("root");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&root)?;
        std::fs::create_dir(&outside)?;
        Ok((dir, root, outside))
    }

    #[test]
    fn a_symlink_out_of_the_root_is_refused() -> anyhow::Result<()> {
        let (_dir, root, outside) = root_with_outside()?;
        symlink(&outside, root.join("link"))?;
        assert!(!within_roots(&root.join("link").to_string_lossy(), &[root]));
        Ok(())
    }

    #[test]
    fn a_path_under_a_symlinked_directory_is_refused() -> anyhow::Result<()> {
        let (_dir, root, outside) = root_with_outside()?;
        symlink(&outside, root.join("out"))?;
        assert!(!within_roots(&root.join("out").join("x").to_string_lossy(), &[root]));
        Ok(())
    }

    #[test]
    fn a_dangling_symlink_is_refused() -> anyhow::Result<()> {
        let (dir, root, _outside) = root_with_outside()?;
        symlink(dir.path().join("absent"), root.join("d"))?;
        assert!(!within_roots(&root.join("d").to_string_lossy(), &[root]));
        Ok(())
    }

    #[test]
    fn a_symlink_that_stays_inside_the_root_is_still_refused() -> anyhow::Result<()> {
        let (_dir, root, _outside) = root_with_outside()?;
        std::fs::write(root.join("real"), b"x")?;
        symlink(root.join("real"), root.join("alias"))?;
        assert!(!within_roots(&root.join("alias").to_string_lossy(), &[root]));
        Ok(())
    }

    #[test]
    fn a_new_nested_destination_inside_the_root_is_allowed() -> anyhow::Result<()> {
        let (_dir, root, _outside) = root_with_outside()?;
        assert!(within_roots(
            &root.join("a").join("b").join("new.txt").to_string_lossy(),
            std::slice::from_ref(&root)
        ));
        Ok(())
    }

    #[test]
    fn a_relative_path_a_dotdot_path_and_an_empty_roots_list_are_refused() -> anyhow::Result<()> {
        let (_dir, root, _outside) = root_with_outside()?;
        assert!(!within_roots("new.txt", std::slice::from_ref(&root)));
        assert!(!within_roots(
            &root.join("..").join("x").to_string_lossy(),
            std::slice::from_ref(&root)
        ));
        assert!(!within_roots(&root.join("x").to_string_lossy(), &[]));
        Ok(())
    }

    /// #618 (review of #889): the root sent to sandyd is the canonical configured root, never the spelling the client
    /// chose, and the path is rewritten onto it. A client that names a path through an alias it controls cannot make
    /// the alias the root. The nearest of several roots wins.
    #[test]
    fn the_root_sent_is_the_canonical_configured_root_and_the_path_is_rewritten_onto_it() -> anyhow::Result<()> {
        let (dir, root, _outside) = root_with_outside()?;
        let real = root.canonicalize()?;
        let nested = root.join("deep");
        std::fs::create_dir(&nested)?;
        let alias = dir.path().join("alias-root");
        symlink(&root, &alias)?;

        for spelling in [root.join("a/./f"), alias.join("a/f")] {
            assert_eq!(
                root_for(&spelling.to_string_lossy(), std::slice::from_ref(&root)),
                Some(Rooted {
                    root: real.clone(),
                    path: real.join("a/f")
                }),
                "{spelling:?}: the configured root and the path below it, not the client's spelling"
            );
        }
        let deep = nested.join("f");
        let nearest = root_for(&deep.to_string_lossy(), &[root.clone(), nested.clone()]).context("a nested root")?;
        assert_eq!(nearest.root, nested.canonicalize()?);
        assert_eq!(nearest.path, nested.canonicalize()?.join("f"));
        assert_eq!(root_for(&root.join("x").to_string_lossy(), &[]), None);
        Ok(())
    }

    /// #618 (review of #889): the canonical root goes on the wire as UTF-8 text. A root whose real name is not valid
    /// UTF-8 would be sent lossily as another directory (`b"/srv/raw-\xff"` becomes `/srv/raw-\u{fffd}`), so startup
    /// refuses it, naming the configured root.
    #[test]
    fn a_root_whose_canonical_name_is_not_utf8_is_refused_at_startup() {
        use std::{ffi::OsStr, os::unix::ffi::OsStrExt as _};
        let configured = PathBuf::from("/srv/alias");
        let canonical = PathBuf::from(OsStr::from_bytes(b"/srv/raw-\xff"));

        let err = canonical_roots_with(std::slice::from_ref(&configured), |_| Ok(canonical.clone()))
            .expect_err("a root that is not UTF-8 must be refused");

        assert!(err.contains("/srv/alias"), "must name the configured root: {err}");
        assert!(err.contains("UTF-8"), "must say why: {err}");
    }

    /// #618: a root that does not exist cannot be resolved at startup, and the error names it.
    #[test]
    fn a_root_that_cannot_be_resolved_is_named() -> anyhow::Result<()> {
        let (dir, root, _outside) = root_with_outside()?;
        let missing = dir.path().join("absent");

        let ok = canonical_roots(std::slice::from_ref(&root)).map_err(anyhow::Error::msg)?;
        let err = canonical_roots(&[root, missing.clone()]).expect_err("a missing root must be refused");

        assert_eq!(ok, [std::fs::canonicalize(dir.path().join("root"))?]);
        assert!(err.contains(&missing.display().to_string()), "{err}");
        Ok(())
    }

    #[test]
    fn a_root_reached_through_a_symlink_is_judged_by_its_real_path() -> anyhow::Result<()> {
        let (dir, root, _outside) = root_with_outside()?;
        let alias = dir.path().join("alias-root");
        symlink(&root, &alias)?;
        std::fs::write(root.join("f"), b"x")?;
        assert!(within_roots(&root.join("f").to_string_lossy(), &[alias]));
        Ok(())
    }
}
