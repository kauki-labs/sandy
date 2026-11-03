//! Host-path confinement for a submit body (decision 4).

use std::path::{Component, Path, PathBuf};

/// Whether `path` is absolute, free of `..`, and, once symlinks are resolved,
/// inside one of `roots`. A path that does not exist yet (an output
/// destination) is judged by its parent directory. An empty `roots` allows
/// nothing.
pub(crate) fn within_roots(path: &str, roots: &[PathBuf]) -> bool {
    let path = Path::new(path);
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return false;
    }
    let Some(resolved) = resolve(path) else {
        return false;
    };
    roots
        .iter()
        .filter_map(|root| root.canonicalize().ok())
        .any(|root| resolved.starts_with(root))
}

fn resolve(path: &Path) -> Option<PathBuf> {
    if let Ok(real) = path.canonicalize() {
        return Some(real);
    }
    let parent = path.parent()?.canonicalize().ok()?;
    Some(parent.join(path.file_name()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_symlink_out_of_the_root_is_refused() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("root");
        std::fs::create_dir(&root)?;
        let outside = dir.path().join("outside");
        std::fs::create_dir(&outside)?;
        std::os::unix::fs::symlink(&outside, root.join("link"))?;
        assert!(!within_roots(&root.join("link").to_string_lossy(), &[root]));
        Ok(())
    }

    #[test]
    fn a_new_file_inside_the_root_is_allowed_and_a_relative_path_is_not() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let root = dir.path().to_path_buf();
        assert!(within_roots(
            &root.join("new.txt").to_string_lossy(),
            std::slice::from_ref(&root)
        ));
        assert!(!within_roots("new.txt", &[root]));
        Ok(())
    }
}
