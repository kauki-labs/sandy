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
/// This is a check at one moment. It cannot stop a client that swaps a directory for a link after the check, so
/// the root it found goes to sandyd ([`root_for`]), which opens the path beneath it without following a link
/// (decision 4, #618).
#[cfg(test)]
pub(crate) fn within_roots(path: &str, roots: &[PathBuf]) -> bool {
    root_for(path, roots).is_some()
}

/// The root `path` lies beneath, as the submit body sends it to sandyd (#618): the same checks as
/// [`within_roots`], and the answer is a prefix of `path` as spelled, so sandyd can strip it. When the client has
/// several roots that contain the path, the one nearest the path wins, so a nested root confines more.
pub(crate) fn root_for(path: &str, roots: &[PathBuf]) -> Option<PathBuf> {
    let path = Path::new(path);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return None;
    }
    roots
        .iter()
        .filter_map(|root| confined(path, root))
        .max_by_key(|root| root.components().count())
}

/// The prefix of `path` that names `root` (as `path` spells it) when `path` reaches its target through no symlink
/// below it.
fn confined(path: &Path, root: &Path) -> Option<PathBuf> {
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
    let mut at = real_root;
    for part in rest.components() {
        match part {
            Component::Normal(name) => at.push(name),
            Component::CurDir => continue,
            _ => return None,
        }
        match std::fs::symlink_metadata(&at) {
            Ok(meta) if meta.file_type().is_symlink() => return None,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Some(spelled.to_owned()),
            Err(_) => return None,
        }
    }
    Some(spelled.to_owned())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

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

    /// #618: the root sent to sandyd is a prefix of the path as spelled, even when the client names the root
    /// through an alias, and the nearest of several roots wins.
    #[test]
    fn the_root_sent_is_a_prefix_of_the_path_as_spelled_and_the_nearest_wins() -> anyhow::Result<()> {
        let (dir, root, _outside) = root_with_outside()?;
        let nested = root.join("deep");
        std::fs::create_dir(&nested)?;
        let alias = dir.path().join("alias-root");
        symlink(&root, &alias)?;

        let under_root = root.join("f");
        assert_eq!(
            root_for(&under_root.to_string_lossy(), std::slice::from_ref(&alias)),
            Some(root.clone()),
            "the alias is only a way to name the root: the path's own spelling is sent"
        );
        let under_alias = alias.join("f");
        assert_eq!(
            root_for(&under_alias.to_string_lossy(), std::slice::from_ref(&root)),
            Some(alias),
            "a path spelled through an alias keeps that spelling"
        );
        let deep = nested.join("f");
        assert_eq!(
            root_for(&deep.to_string_lossy(), &[root.clone(), nested.clone()]),
            Some(nested)
        );
        assert_eq!(root_for(&root.join("x").to_string_lossy(), &[]), None);
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
