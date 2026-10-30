//! The git revision this binary was built from (so "does the deployed binary
//! predate PR #N" is one `--version` call or one startup log line).
//!
//! Nix passes the revision at compile time as `SANDY_BUILD_REV` (the flake's
//! `shortRev`/`dirtyShortRev`); outside nix (`cargo run` in the dev shell) it
//! is unset and the revision reads [`UNKNOWN_REV`]. Every function takes the
//! revision as a parameter so tests inject it instead of depending on git.

/// Reported when the build did not carry a revision.
pub const UNKNOWN_REV: &str = "unknown";

/// The compile-time revision, or [`UNKNOWN_REV`] when unset or empty.
#[must_use]
pub fn resolve_rev(compiled: Option<&'static str>) -> &'static str {
    compiled.filter(|rev| !rev.is_empty()).unwrap_or(UNKNOWN_REV)
}

/// The `--version` output: `<bin> <package version> (rev <rev>)`.
#[must_use]
pub fn version_line(bin: &str, version: &str, rev: &str) -> String {
    format!("{bin} {version} (rev {rev})")
}

/// Whether the first CLI argument asks for the version.
#[must_use]
pub fn wants_version(args: impl IntoIterator<Item = String>) -> bool {
    matches!(args.into_iter().next().as_deref(), Some("--version" | "-V"))
}

/// Log the build revision once, at startup.
pub fn log_startup(bin: &str, version: &str, rev: &str) {
    tracing::info!(bin, version, rev, "starting");
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            self.0.lock().expect("buf lock").extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn version_line_carries_the_injected_rev() {
        assert_eq!(
            version_line("sandy-host-executor", "0.1.1", "abc1234"),
            "sandy-host-executor 0.1.1 (rev abc1234)"
        );
    }

    #[test]
    fn startup_log_line_carries_the_injected_rev() {
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_writer({
                let buf = buf.clone();
                move || buf.clone()
            })
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(sub, || log_startup("sandy-host-executor", "0.1.1", "abc1234"));
        let out = String::from_utf8(buf.0.lock().expect("buf lock").clone()).expect("utf8");
        assert!(out.contains(r#"rev="abc1234""#), "startup log lacks the rev: {out}");
    }

    #[test]
    fn missing_or_empty_rev_reads_unknown() {
        assert_eq!(resolve_rev(None), UNKNOWN_REV);
        assert_eq!(resolve_rev(Some("")), UNKNOWN_REV);
        assert_eq!(resolve_rev(Some("abc1234")), "abc1234");
    }

    #[test]
    fn only_a_leading_version_flag_asks_for_the_version() {
        let args = |v: &[&str]| v.iter().map(ToString::to_string).collect::<Vec<_>>();
        assert!(wants_version(args(&["--version"])));
        assert!(wants_version(args(&["-V"])));
        assert!(!wants_version(args(&[])));
        assert!(!wants_version(args(&["--other"])));
    }
}
