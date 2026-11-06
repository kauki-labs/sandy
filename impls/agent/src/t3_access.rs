//! The guest side of `t3-access` (#669): lift the pairing credential `t3 serve` prints at
//! startup out of the job transcript and keep it in a `0600` file.
//!
//! The credential never reaches a log, a `Debug` print or a tool result: [`Access`] redacts
//! its token, and only [`AccessFile`] writes it, through the one `0600` secret writer.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use sandy_fsutil::OwnedDir;
use serde::{Deserialize, Serialize};

/// The pairing fragment `t3 serve` appends to its connection URL: `<url>/pair#token=<token>`.
const TOKEN_FRAGMENT: &str = "#token=";

/// File name under the access directory.
pub const ACCESS_FILE: &str = "t3-access.json";

/// The pairing token. Only the token is kept: the host in the printed URL is the guest's own view of itself,
/// and a consumer builds the URL it hands out from the host-side bridge, never from this file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Access {
    /// The token from the URL fragment.
    pub token: String,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Access").field("token", &"<redacted>").finish()
    }
}

/// The bytes of the transcript scanned. The credential is printed at startup; a longer prefix only costs
/// memory on a job that floods its output.
const SCAN_CAP: u64 = 1 << 20;

/// What replaces a token in output the agent forwards.
const REDACTED: &str = "<redacted>";

/// Characters that end a URL word: whitespace, controls, quotes, brackets and sentence punctuation.
fn ends_word(c: char) -> bool {
    c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ']' | ',' | ';')
}

/// The first `http(s)://…#token=<token>` word in `output`, or `None`.
#[must_use]
pub fn scan_startup_credential(output: &str) -> Option<Access> {
    output.split(ends_word).find_map(|word| {
        let start = word.find("http://").or_else(|| word.find("https://"))?;
        let (_, token) = word[start..].split_once(TOKEN_FRAGMENT)?;
        let token = token.trim_end_matches('.');
        (!token.is_empty()).then(|| Access {
            token: token.to_owned(),
        })
    })
}

/// `output` with every `#token=<token>` fragment's token replaced, so the credential does not leave through the
/// job console or the archive. Anything else is kept byte for byte.
#[must_use]
pub fn redact(output: &[u8]) -> Vec<u8> {
    const KEY: &[u8] = TOKEN_FRAGMENT.as_bytes();
    let mut out = Vec::with_capacity(output.len());
    let mut i = 0;
    while i < output.len() {
        if output[i..].starts_with(KEY) {
            out.extend_from_slice(KEY);
            i += KEY.len();
            out.extend_from_slice(REDACTED.as_bytes());
            while i < output.len() && !ends_word(char::from(output[i])) && output[i] < 0x80 {
                i += 1;
            }
        } else {
            out.push(output[i]);
            i += 1;
        }
    }
    out
}

/// How often the transcript is re-read.
const POLL: Duration = Duration::from_millis(250);

/// Poll the job transcript at `log` until it holds a pairing credential, then write it to `file`.
///
/// Returns `Ok(true)` when written and `Ok(false)` when `timeout` passed first. The credential is valid only
/// for a window after the server starts, so capture runs from the job's first byte.
///
/// # Errors
///
/// The credential was found but the private write failed.
pub async fn capture(log: &Path, file: &AccessFile, timeout: Duration) -> Result<bool, AccessFileError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        // Not yet created, or mid-write: try again next tick.
        if let Some(head) = read_head(log).await
            && let Some(access) = scan_startup_credential(&String::from_utf8_lossy(&head))
        {
            file.write(&access)?;
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(POLL).await;
    }
}

/// The first [`SCAN_CAP`] bytes of `path`; `None` if it cannot be read yet.
async fn read_head(path: &Path) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut head = Vec::new();
    tokio::fs::File::open(path)
        .await
        .ok()?
        .take(SCAN_CAP)
        .read_to_end(&mut head)
        .await
        .ok()?;
    Some(head)
}

/// Why the credential file could not be written or read.
#[derive(Debug, thiserror::Error)]
pub enum AccessFileError {
    /// The access directory is unsafe or a step of the private write failed.
    #[error("access file: {0}")]
    Fs(#[from] sandy_fsutil::FsError),
    /// The file is not valid JSON of the expected shape. Never carries file content.
    #[error("access file is not valid")]
    Invalid,
    /// Reading the file failed.
    #[error("access file read failed: {0}")]
    Read(std::io::Error),
}

/// The `0600` file holding the credential.
#[derive(Debug)]
pub struct AccessFile {
    dir: OwnedDir,
}

impl AccessFile {
    /// Open or create the private directory `dir` (this user's, not group- or world-writable).
    ///
    /// # Errors
    ///
    /// [`AccessFileError::Fs`] when the directory is unsafe or cannot be created.
    pub fn open(dir: &Path) -> Result<Self, AccessFileError> {
        Ok(Self {
            dir: OwnedDir::open_or_create(dir)?,
        })
    }

    /// Path of the file, written or not.
    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.dir.path().join(ACCESS_FILE)
    }

    /// Write `access`, replacing any earlier file. A reader sees the old file or the new one.
    ///
    /// # Errors
    ///
    /// [`AccessFileError::Fs`] when the private write fails.
    pub fn write(&self, access: &Access) -> Result<(), AccessFileError> {
        // A struct of two strings always serialises.
        let bytes = serde_json::to_vec(access).map_err(|_| AccessFileError::Invalid)?;
        self.dir.write_secret(ACCESS_FILE, &bytes)?;
        Ok(())
    }

    /// Read the credential back.
    ///
    /// # Errors
    ///
    /// [`AccessFileError::Read`] when the file is absent or unreadable, [`AccessFileError::Invalid`]
    /// when it is malformed.
    pub fn read(&self) -> Result<Access, AccessFileError> {
        let bytes = std::fs::read(self.path()).map_err(AccessFileError::Read)?;
        serde_json::from_slice(&bytes).map_err(|_| AccessFileError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Context;

    use super::*;

    const URL: &str = "http://127.0.0.1:3773/pair#token=abc123DEF-_";

    #[test]
    fn a_pairing_url_in_server_output_is_found_with_its_token() {
        let out = format!("t3 serve ready\nPair a client: {URL}\nlistening\n");
        let access = scan_startup_credential(&out).expect("credential");
        assert_eq!(access.token, "abc123DEF-_");
    }

    #[test]
    fn a_url_wrapped_in_quotes_or_escapes_is_found_without_them() {
        let out = format!("\u{1b}[32m\"{URL}\"\u{1b}[0m");
        assert_eq!(scan_startup_credential(&out).expect("credential").token, "abc123DEF-_");
    }

    #[test]
    fn output_without_a_token_fragment_yields_nothing() {
        for out in [
            "",
            "listening on http://127.0.0.1:3773/",
            "token=abc without a url",
            "http://127.0.0.1:3773/pair#token=",
        ] {
            assert!(scan_startup_credential(out).is_none(), "{out:?}");
        }
    }

    #[test]
    fn the_first_credential_wins() {
        let out = format!("{URL}\nhttp://x/pair#token=second");
        assert_eq!(scan_startup_credential(&out).expect("credential").token, "abc123DEF-_");
    }

    #[test]
    fn punctuation_after_the_url_is_not_part_of_the_token() {
        for out in [format!("({URL})"), format!("see {URL}."), format!("[{URL}], next")] {
            assert_eq!(
                scan_startup_credential(&out).expect("credential").token,
                "abc123DEF-_",
                "{out:?}"
            );
        }
    }

    #[test]
    fn redaction_replaces_the_token_and_keeps_everything_else() {
        let out = format!("before\n\u{1b}[32mPair: {URL}\u{1b}[0m after\nnon-ascii é ok\n");
        let redacted = String::from_utf8(redact(out.as_bytes())).expect("utf8");
        assert!(!redacted.contains("abc123"), "{redacted:?}");
        assert!(redacted.contains("/pair#token=<redacted>"), "{redacted:?}");
        assert!(
            redacted.contains("before\n") && redacted.contains("non-ascii é ok"),
            "{redacted:?}"
        );
        assert_eq!(redact(b"no credential here"), b"no credential here");
    }

    #[test]
    fn redaction_covers_every_occurrence() {
        let out = format!("{URL} and again {URL}");
        assert!(
            !String::from_utf8(redact(out.as_bytes()))
                .expect("utf8")
                .contains("abc123")
        );
    }

    #[test]
    fn debug_output_never_shows_the_token() {
        let access = scan_startup_credential(URL).expect("credential");
        let shown = format!("{access:?}");
        assert!(!shown.contains("abc123"), "{shown}");
    }

    #[test]
    fn the_credential_is_written_0600_and_read_back() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("access");
        let file = AccessFile::open(&dir).context("open")?;
        let access = scan_startup_credential(URL).context("scan")?;
        file.write(&access).context("write")?;
        let mode = std::fs::metadata(file.path())?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(file.read().context("read")?, access);
        Ok(())
    }

    #[test]
    fn a_second_credential_replaces_the_first() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let file = AccessFile::open(&tmp.path().join("access"))?;
        file.write(&scan_startup_credential(URL).context("scan")?)?;
        let newer = scan_startup_credential("https://h/pair#token=newer").context("scan")?;
        file.write(&newer)?;
        assert_eq!(file.read()?.token, "newer");
        Ok(())
    }

    #[test]
    fn a_malformed_file_is_invalid_and_does_not_echo_its_content() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let file = AccessFile::open(&tmp.path().join("access"))?;
        let dir = OwnedDir::open(&tmp.path().join("access"))?;
        dir.write_secret(ACCESS_FILE, b"secret-not-json")?;
        let err = file.read().expect_err("malformed");
        assert!(matches!(err, AccessFileError::Invalid));
        assert!(!err.to_string().contains("secret-not-json"));
        Ok(())
    }

    #[test]
    fn reading_before_any_credential_is_a_read_error() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let file = AccessFile::open(&tmp.path().join("access"))?;
        assert!(matches!(file.read(), Err(AccessFileError::Read(_))));
        Ok(())
    }

    #[tokio::test]
    async fn capture_writes_the_credential_once_the_server_prints_it() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let log = tmp.path().join("job.log");
        let file = AccessFile::open(&tmp.path().join("access"))?;
        let late = log.clone();
        let writer = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            std::fs::write(late, format!("booting\n{URL}\n")).expect("write transcript");
        });
        assert!(capture(&log, &file, Duration::from_secs(10)).await.context("capture")?);
        writer.await?;
        assert_eq!(file.read()?.token, "abc123DEF-_");
        Ok(())
    }

    /// The real transcript (tmux `pipe-pane` behind a pty) carries the line the way a server prints it.
    #[tokio::test]
    async fn capture_reads_the_credential_from_a_real_tmux_transcript() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let file = AccessFile::open(&tmp.path().join("access"))?;
        let job = vec![
            "sh".into(),
            "-c".into(),
            format!("printf 'Pair: {URL}\\n'; sleep 30").into(),
        ];
        let tmux_job = crate::tmux_pty::TmuxJob::start(&job, None, 1000)?;
        let found = capture(tmux_job.log_path(), &file, Duration::from_secs(10)).await;
        tmux_job.kill();
        assert!(found.context("capture")?);
        assert_eq!(file.read()?.token, "abc123DEF-_");
        Ok(())
    }

    #[tokio::test]
    async fn capture_ignores_a_credential_past_the_scan_cap() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let log = tmp.path().join("job.log");
        let mut flood = vec![b'x'; usize::try_from(SCAN_CAP)? + 16];
        flood.push(b'\n');
        flood.extend_from_slice(URL.as_bytes());
        std::fs::write(&log, flood)?;
        let file = AccessFile::open(&tmp.path().join("access"))?;
        assert!(
            !capture(&log, &file, Duration::from_millis(300))
                .await
                .context("capture")?
        );
        Ok(())
    }

    #[tokio::test]
    async fn capture_gives_up_when_no_credential_appears() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let log = tmp.path().join("job.log");
        std::fs::write(&log, "no pairing here\n")?;
        let file = AccessFile::open(&tmp.path().join("access"))?;
        assert!(
            !capture(&log, &file, Duration::from_millis(600))
                .await
                .context("capture")?
        );
        assert!(matches!(file.read(), Err(AccessFileError::Read(_))));
        Ok(())
    }

    #[test]
    fn a_group_writable_directory_is_refused() -> anyhow::Result<()> {
        let tmp = tempfile::tempdir()?;
        let dir = tmp.path().join("access");
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o770))?;
        assert!(AccessFile::open(&dir).is_err());
        Ok(())
    }
}
