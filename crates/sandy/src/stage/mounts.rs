//! Mount-arg assembly (E3): a [`Mount`] slice becomes the virtiofs share argv,
//! each share tagged from a [`TagPool`] and read-only shares flagged `,ro`.

use crate::backend::{BackendError, Mount};

/// A generator of unique virtiofs mount tags.
///
/// Each [`TagPool::next_tag`] hands out a fresh `mountTag` so no two shares
/// collide within one guest.
#[derive(Debug, Default)]
pub struct TagPool {
    /// The next tag ordinal to hand out.
    #[allow(dead_code, reason = "read by next_tag, whose body is a red-first todo!()")]
    next: u32,
}

impl TagPool {
    /// A pool that starts numbering tags from zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hand out the next unique mount tag.
    pub fn next_tag(&mut self) -> String {
        todo!("yield a unique mountTag from {self:?} (E3)")
    }
}

/// Assemble the virtiofs share arguments for `mounts`, drawing a unique tag from
/// `tags` per share.
///
/// Each mount yields `sharedDir=<host>,mountTag=<tag>`, with `,ro` appended for
/// a read-only ([`Mount::ro`]) share. A mount whose [`host`](Mount::host) does
/// not exist is a hard error, never a silent drop.
///
/// # Errors
///
/// Returns a named [`BackendError`] when a [`Mount::host`] path does not exist.
pub fn mount_args(mounts: &[Mount], tags: &mut TagPool) -> Result<Vec<String>, BackendError> {
    let _ = tags;
    todo!(
        "assemble virtiofs sharedDir/mountTag args for {} mount(s), missing host → error (E3)",
        mounts.len()
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    /// E3: two mounts (one RO, one RW) produce one `sharedDir=…,mountTag=…` arg
    /// each, with the read-only share flagged `,ro` and the writable one not.
    #[test]
    fn mount_args_ro_and_rw() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let ro_host = tmp.path().join("ro-share");
        let rw_host = tmp.path().join("rw-share");
        std::fs::create_dir_all(&ro_host)?;
        std::fs::create_dir_all(&rw_host)?;
        let mounts = [
            Mount {
                host: ro_host.clone(),
                guest: PathBuf::from("/in"),
                ro: true,
            },
            Mount {
                host: rw_host.clone(),
                guest: PathBuf::from("/out"),
                ro: false,
            },
        ];
        let mut tags = TagPool::new();

        let args = mount_args(&mounts, &mut tags)?;

        assert_eq!(args.len(), 2, "one arg per mount");
        let (ro_arg, rw_arg) = (&args[0], &args[1]);

        assert!(
            ro_arg.contains(&format!("sharedDir={}", ro_host.display())),
            "RO arg names its host: {ro_arg}"
        );
        assert!(ro_arg.contains("mountTag="), "RO arg carries a mount tag: {ro_arg}");
        assert!(ro_arg.contains(",ro"), "RO arg must be flagged read-only: {ro_arg}");

        assert!(
            rw_arg.contains(&format!("sharedDir={}", rw_host.display())),
            "RW arg names its host: {rw_arg}"
        );
        assert!(rw_arg.contains("mountTag="), "RW arg carries a mount tag: {rw_arg}");
        assert!(
            !rw_arg.contains(",ro"),
            "RW arg must not be flagged read-only: {rw_arg}"
        );
        Ok(())
    }

    /// Adversarial: a nonexistent host path is a named [`BackendError`], not a
    /// silent drop.
    #[test]
    fn missing_host_mount_named_error() -> anyhow::Result<()> {
        let tmp = tempfile::TempDir::new()?;
        let missing = tmp.path().join("does-not-exist");
        let mounts = [Mount {
            host: missing,
            guest: PathBuf::from("/in"),
            ro: true,
        }];
        let mut tags = TagPool::new();

        let err = mount_args(&mounts, &mut tags).expect_err("missing host must be rejected");

        assert!(
            matches!(err, BackendError::Spawn(_)),
            "expected a named Spawn error, got {err:?}"
        );
        Ok(())
    }
}
