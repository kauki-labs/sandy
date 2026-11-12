//! The host side of the output transfer around a run (#482 slice 6c, sandyd.md §22): where the backend collects a
//! remote job's outputs, and sending them to the orchestrator once the run is over.
//!
//! A job with a data link does not collect its outputs to the submitter's paths: those are on the orchestrator's
//! machine. The backend collects each declared output into `<root>/<i>`, a private directory this host owns, and the
//! staged trees go back over the retained data link with [`crate::output_send`], tagged with their position `i`.
//! `<root>/<i>` is not created here: for a named output whose staged root is a file, the backend writes that file at
//! the destination itself, and a directory already there would break it.

use std::{io, path::Path};

use sandy_api::backend::Output;
use tokio::io::AsyncWrite;

use crate::output_send::OutputSource;

/// The staging root of one dispatch's outputs, and what the run and the sender need from it. Dropping it removes the
/// root and everything the run collected into it.
#[derive(Debug)]
pub struct OutputStaging {
    root: tempfile::TempDir,
    run_outputs: Vec<Output>,
    sources: Vec<OutputSource>,
}

impl OutputStaging {
    /// Create a private root under `parent` and plan one destination `<root>/<i>` per declared output.
    ///
    /// # Errors
    /// The root could not be created.
    pub fn new(_parent: &Path, _declared: &[sandy_executor_proto::Output]) -> io::Result<Self> {
        Err(io::Error::other("not implemented"))
    }

    /// The outputs for `RunSpec`: each declared output's name, with its destination inside the root.
    #[must_use]
    pub fn run_outputs(&self) -> &[Output] {
        &self.run_outputs
    }

    /// The root, for messages and tests.
    #[must_use]
    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// The staged trees, in declaration order: what [`crate::output_send::send_outputs`] reads.
    #[must_use]
    pub fn sources(&self) -> &[OutputSource] {
        &self.sources
    }
}

/// Send the staged outputs over `link` after the run, and say whether outputs follow. Blocks on `rt`: it runs on the
/// blocking thread that runs the dispatch.
///
/// The answer is `true` whenever the transfer was started, including when it failed (the link is gone, a staged entry
/// could not be read): the orchestrator is told a transfer error on the link when it can be, and a failed send must
/// never read as "nothing follows" (#482).
pub fn send_staged_outputs(
    _link: &mut (impl AsyncWrite + Unpin),
    _staging: &OutputStaging,
    _rt: &tokio::runtime::Handle,
) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use anyhow::Context;
    use sandy_control_proto::read_frame;
    use sandy_executor_proto::{DataLinkMessage, data_link_message::Op};

    use super::*;

    fn declared(name: Option<&str>, dest: &str) -> sandy_executor_proto::Output {
        sandy_executor_proto::Output {
            name: name.map(str::to_owned),
            dest: dest.to_owned(),
        }
    }

    /// Every output's destination is `<root>/<position>`, its name is kept, the submitter's own path is never used, and
    /// nothing is created there yet (the backend creates it: a directory for a tree, a file for a bare named output).
    #[test]
    fn each_output_is_staged_under_a_private_root_by_position() -> anyhow::Result<()> {
        let parent = tempfile::tempdir().context("parent")?;
        let outputs = [
            declared(Some("results"), "/submitter/results"),
            declared(None, "/submitter/everything"),
        ];
        let staging = OutputStaging::new(parent.path(), &outputs).context("stage")?;

        let root = staging.root().to_path_buf();
        assert!(root.starts_with(parent.path()));
        assert_eq!(
            staging.run_outputs(),
            &[
                Output {
                    name: Some("results".to_owned()),
                    dest: root.join("0")
                },
                Output {
                    name: None,
                    dest: root.join("1")
                },
            ]
        );
        assert!(
            !root.join("0").exists() && !root.join("1").exists(),
            "the backend creates them"
        );
        assert_eq!(staging.sources().len(), 2);
        assert_eq!(staging.sources()[0].name.as_deref(), Some("results"));
        assert_eq!(staging.sources()[1].root, root.join("1"));

        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&root).context("stat root")?.permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "the staging root must be private");
        }
        drop(staging);
        assert!(!root.exists(), "dropping the staging removes the root");
        Ok(())
    }

    /// A parent that cannot hold the root is an error, not a root somewhere else.
    #[test]
    fn a_missing_parent_is_an_error() {
        let missing = PathBuf::from("/nonexistent/sandy-output-staging-parent");
        assert!(OutputStaging::new(&missing, &[declared(None, "/x")]).is_err());
    }

    /// The acceptance test for the host side: collect a guest's outputs with the backend's own `collect_outputs` into
    /// the staged destinations, send them, and read the frames the orchestrator would see: the right names and
    /// positions for a named tree, a named file and a catch-all that covers both, then `OutputEnd`.
    #[tokio::test]
    async fn what_the_backend_collected_goes_out_by_name_and_position() -> anyhow::Result<()> {
        let guest = tempfile::tempdir().context("guest outputs")?;
        std::fs::create_dir_all(guest.path().join("report")).context("report dir")?;
        std::fs::write(guest.path().join("report/x.txt"), b"X").context("x")?;
        std::fs::write(guest.path().join("single"), b"ONE").context("single")?;
        std::fs::write(guest.path().join("top.txt"), b"T").context("top")?;

        let parent = tempfile::tempdir().context("parent")?;
        let outputs = [
            declared(Some("report"), "/submitter/report"),
            declared(Some("single"), "/submitter/single.bin"),
            declared(None, "/submitter/all"),
        ];
        let staging = OutputStaging::new(parent.path(), &outputs).context("stage")?;
        let collect_into: Vec<sandy::Output> = staging
            .run_outputs()
            .iter()
            .map(|o| sandy::Output {
                name: o.name.clone(),
                dest: o.dest.clone(),
            })
            .collect();
        sandy::collect_outputs(&collect_into, guest.path(), false).context("the backend's collection")?;

        let (mut near, mut far) = tokio::io::duplex(1024 * 1024);
        let rt = tokio::runtime::Handle::current();
        let follows = tokio::task::spawn_blocking(move || {
            let followed = send_staged_outputs(&mut near, &staging, &rt);
            drop(near);
            (followed, staging)
        })
        .await
        .context("the send task")?;
        assert!(follows.0, "outputs followed");

        let mut chunks = Vec::new();
        let mut ends = 0;
        while let Some(message) = read_frame::<DataLinkMessage>(&mut far).await.context("read a frame")? {
            match message.op.context("an empty message")? {
                Op::OutputChunk(c) => chunks.push((c.output_index, c.name, c.bytes)),
                Op::OutputEnd(_) => ends += 1,
                other => anyhow::bail!("unexpected frame {other:?}"),
            }
        }
        chunks.sort();
        assert_eq!(
            chunks,
            vec![
                (0, "report/x.txt".to_owned(), b"X".to_vec()),
                (1, "single".to_owned(), b"ONE".to_vec()),
                (2, "report/x.txt".to_owned(), b"X".to_vec()),
                (2, "single".to_owned(), b"ONE".to_vec()),
                (2, "top.txt".to_owned(), b"T".to_vec()),
            ]
        );
        assert_eq!(ends, 1, "exactly one OutputEnd");
        Ok(())
    }

    /// A send that fails (the link is gone) still reports that outputs follow: `false` would tell the orchestrator that
    /// nothing is owed, and a job with missing outputs would be recorded as a success.
    #[tokio::test]
    async fn a_failed_send_still_reports_that_outputs_follow() -> anyhow::Result<()> {
        let guest = tempfile::tempdir().context("guest outputs")?;
        std::fs::write(guest.path().join("a.txt"), b"A").context("a")?;
        let parent = tempfile::tempdir().context("parent")?;
        let staging = OutputStaging::new(parent.path(), &[declared(None, "/submitter/all")]).context("stage")?;
        let collect_into = [sandy::Output {
            name: None,
            dest: staging.run_outputs()[0].dest.clone(),
        }];
        sandy::collect_outputs(&collect_into, guest.path(), false).context("collect")?;

        let (mut near, far) = tokio::io::duplex(1024);
        drop(far);
        let rt = tokio::runtime::Handle::current();
        let follows = tokio::task::spawn_blocking(move || send_staged_outputs(&mut near, &staging, &rt))
            .await
            .context("the send task")?;
        assert!(follows, "a failed send must still say outputs follow");
        Ok(())
    }
}
