//! A bounded copy of each held VM's console (#727).
//!
//! `sandyd` keeps no console log, and a held run only returns its console once the
//! box is gone. A hypervisor backend pushes the console bytes it reads into a
//! [`ConsoleSink`] as they arrive, so a failed provision can say what the guest
//! printed. The copy lives here, apart from the run, so it survives the run's end
//! and a kill that fails.
//!
//! The text is for a failure reason an operator reads: control characters are
//! stripped, key-shaped tokens are masked, and only the last lines are kept. A
//! base64 command frame on the console is not text a mask can see into.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};

/// How many console bytes one environment's ring keeps. Older bytes are dropped first.
const RING_BYTES: usize = 64 * 1024;

/// The most lines [`ConsoleTaps::take_tail`] returns.
pub const TAIL_LINES: usize = 40;

/// The most bytes [`ConsoleTaps::take_tail`] returns.
pub const TAIL_BYTES: usize = 4 * 1024;

/// Where a hypervisor backend sends the console bytes it reads. Called from the
/// console reader's thread, so it must not block.
pub type ConsoleSink = Arc<dyn Fn(&[u8]) + Send + Sync>;

#[derive(Default)]
struct Ring {
    bytes: VecDeque<u8>,
    /// Older bytes were dropped, so the first line may start mid-token.
    wrapped: bool,
}

/// How many environments keep a ring at once. A tail is taken only on a failed provision, so the rings of
/// environments that ended well would pile up; the oldest go first.
const MAX_RINGS: usize = 256;

#[derive(Default)]
struct Rings {
    by_id: BTreeMap<String, Arc<Mutex<Ring>>>,
    /// Ids in the order their rings were made, oldest first.
    order: VecDeque<String>,
}

/// The console ring of every environment launched through one backend.
#[derive(Default)]
pub struct ConsoleTaps {
    rings: Mutex<Rings>,
}

impl ConsoleTaps {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A sink for a new launch of `environment_id`. It replaces the id's earlier ring, so a
    /// stale run's late bytes never land in the new launch's tail.
    #[must_use]
    pub fn sink_for(&self, environment_id: &str) -> ConsoleSink {
        let ring = Arc::new(Mutex::new(Ring::default()));
        {
            let mut rings = self.rings.lock().unwrap_or_else(PoisonError::into_inner);
            rings.order.retain(|id| id != environment_id);
            rings.order.push_back(environment_id.to_owned());
            rings.by_id.insert(environment_id.to_owned(), Arc::clone(&ring));
            while rings.order.len() > MAX_RINGS {
                if let Some(oldest) = rings.order.pop_front() {
                    rings.by_id.remove(&oldest);
                }
            }
        }
        Arc::new(move |chunk: &[u8]| {
            let mut ring = ring.lock().unwrap_or_else(PoisonError::into_inner);
            ring.bytes.extend(chunk);
            let over = ring.bytes.len().saturating_sub(RING_BYTES);
            if over > 0 {
                ring.bytes.drain(..over);
                ring.wrapped = true;
            }
        })
    }

    /// The cleaned last lines of `environment_id`'s console, taken: a second call returns
    /// `None`. `None` too when the id has no ring or printed nothing.
    #[must_use]
    pub fn take_tail(&self, environment_id: &str) -> Option<String> {
        let ring = {
            let mut rings = self.rings.lock().unwrap_or_else(PoisonError::into_inner);
            rings.order.retain(|id| id != environment_id);
            rings.by_id.remove(environment_id)?
        };
        // Copy the bytes and let go of the ring before the cleaning: the console reader's sink waits on this lock.
        let (raw, wrapped) = {
            let ring = ring.lock().unwrap_or_else(PoisonError::into_inner);
            (ring.bytes.iter().copied().collect::<Vec<u8>>(), ring.wrapped)
        };
        let tail = tail_text(&raw, wrapped);
        (!tail.is_empty()).then_some(tail)
    }
}

/// Clean `raw`, mask secrets, and keep the last [`TAIL_LINES`] lines within [`TAIL_BYTES`].
/// `partial_start` says the ring dropped older bytes, so the first line may have lost its
/// beginning and is dropped: a token cut in half would otherwise show its tail without the
/// prefix a mask looks for. The caps below cut masked text, which holds no token any more.
fn tail_text(raw: &[u8], partial_start: bool) -> String {
    let cleaned = strip_controls(&String::from_utf8_lossy(raw));
    let masked = mask_secrets(&cleaned);
    let mut lines: Vec<&str> = masked.split('\n').map(str::trim_end).collect();
    if partial_start && !lines.is_empty() {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let keep = lines.len().saturating_sub(TAIL_LINES);
    let text = lines[keep..].join("\n");
    if text.len() <= TAIL_BYTES {
        return text;
    }
    let mut cut = text.len() - TAIL_BYTES;
    while !text.is_char_boundary(cut) {
        cut += 1;
    }
    text[cut..].to_owned()
}

/// What replaces a masked secret.
const MASK: &str = "[redacted]";

/// Prefixes of tokens that must not reach a failure reason, compared ASCII-case-insensitively:
/// the mesh join keys and the GitHub token families.
const TOKEN_PREFIXES: [&str; 8] = [
    "hskey-auth-",
    "tskey-",
    "ghs_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghr_",
    "github_pat_",
];

/// Mask known secret shapes in one pass: a token behind one of [`TOKEN_PREFIXES`] (the prefix and
/// the token's `[A-Za-z0-9_-]` run), `user:password` in a `scheme://user:password@host` URL, and the
/// token after `Bearer `. The caller scrubs exact values it knows (the staged credential) on top of
/// this: a shape mask cannot know a token that has no known shape.
fn mask_secrets(text: &str) -> String {
    let bytes = text.as_bytes();
    let lower = text.to_ascii_lowercase();
    let lower = lower.as_bytes();
    let token_len = |from: usize| {
        bytes[from..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric() || **b == b'-' || **b == b'_')
            .count()
    };
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        let rest = &lower[i..];
        if let Some(prefix) = TOKEN_PREFIXES.iter().find(|p| rest.starts_with(p.as_bytes())) {
            let end = i + prefix.len() + token_len(i + prefix.len());
            out.push_str(&text[copied..i]);
            out.push_str(MASK);
            (i, copied) = (end, end);
        } else if rest.starts_with(b"bearer ") {
            let from = i + "bearer ".len();
            // A bearer value is any run up to whitespace: JWTs and base64 carry `.`, `+`, `/` and `=`.
            let end = from + bytes[from..].iter().take_while(|b| !b.is_ascii_whitespace()).count();
            out.push_str(&text[copied..from]);
            if end > from {
                out.push_str(MASK);
            }
            (i, copied) = (end, end.max(from));
        } else if rest.starts_with(b"://") {
            let from = i + 3;
            // Userinfo ends at `@` before the first `/`, `?`, `#` or whitespace of the authority.
            let authority_end = bytes[from..]
                .iter()
                .position(|b| matches!(b, b'/' | b'?' | b'#') || b.is_ascii_whitespace())
                .map_or(bytes.len(), |n| from + n);
            let at = bytes[from..authority_end].iter().rposition(|b| *b == b'@');
            match at {
                Some(at) if at > 0 => {
                    out.push_str(&text[copied..from]);
                    out.push_str(MASK);
                    (i, copied) = (from + at, from + at);
                }
                _ => i = from,
            }
        } else {
            i += 1;
        }
    }
    out.push_str(&text[copied..]);
    out
}

/// Drop ANSI escape sequences and every control character but `\n` and `\t`. A lone `\r`
/// goes away and `\r\n` becomes `\n`, so a terminal's cursor games cannot rewrite what an
/// operator reads.
fn strip_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => {
                // CSI: ESC [ params, then a final byte in @..~. Any other ESC takes one char with it.
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for n in chars.by_ref() {
                        if ('@'..='~').contains(&n) {
                            break;
                        }
                    }
                } else {
                    chars.next();
                }
            }
            '\n' | '\t' => out.push(c),
            // Bidirectional overrides would reorder what an operator reads.
            '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' => {}
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(taps: &ConsoleTaps, id: &str, chunks: &[&[u8]]) -> ConsoleSink {
        let sink = taps.sink_for(id);
        for chunk in chunks {
            sink(chunk);
        }
        sink
    }

    #[test]
    fn the_tail_is_the_last_lines_in_order() {
        let taps = ConsoleTaps::new();
        let text: String = (1..=100).map(|n| format!("line {n}\n")).collect();
        feed(&taps, "e", &[text.as_bytes()]);
        let tail = taps.take_tail("e").expect("a tail");
        let lines: Vec<&str> = tail.lines().collect();
        assert_eq!(lines.len(), TAIL_LINES);
        assert_eq!(lines.first(), Some(&"line 61"));
        assert_eq!(lines.last(), Some(&"line 100"));
    }

    #[test]
    fn the_tail_is_taken_once() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &[b"hello\n"]);
        assert_eq!(taps.take_tail("e").as_deref(), Some("hello"));
        assert_eq!(taps.take_tail("e"), None, "a second take must not return a stale tail");
        assert_eq!(taps.take_tail("never-launched"), None);
    }

    #[test]
    fn an_empty_console_has_no_tail() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &[b"\r\n\x1b[2J \n"]);
        assert_eq!(taps.take_tail("e"), None);
    }

    #[test]
    fn terminal_control_is_stripped_but_newlines_stay() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &[b"\x1b[31mred\x1b[0m\r\nbell\x07 and\x08 tab\tok\r\n"]);
        assert_eq!(taps.take_tail("e").as_deref(), Some("red\nbell and tab\tok"));
    }

    #[test]
    fn a_token_is_masked_even_when_it_arrives_in_two_chunks() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &[b"join key tskey-auth-abc", b"DEF123 done\n"]);
        let tail = taps.take_tail("e").expect("a tail");
        assert!(!tail.contains("abcDEF123"), "{tail}");
        assert!(!tail.contains("tskey-"), "{tail}");
        assert!(tail.contains("done"), "{tail}");
    }

    /// The byte cap cuts masked text, so it keeps the newest bytes even when the tail is one line.
    #[test]
    fn the_byte_cap_keeps_the_newest_text_of_a_long_line() {
        let taps = ConsoleTaps::new();
        let line = "é".repeat(100);
        let text = format!("{line}\n").repeat(200);
        feed(&taps, "e", &[text.as_bytes()]);
        let tail = taps.take_tail("e").expect("a tail");
        assert!(tail.len() <= TAIL_BYTES, "{}", tail.len());
        assert!(tail.len() > TAIL_BYTES - 4, "the cap fills the budget: {}", tail.len());
        assert!(tail.ends_with(&line), "the newest line is whole");
    }

    /// Progress output made of carriage returns is one long line once the returns are gone: it is cut, not dropped.
    #[test]
    fn a_single_long_line_is_cut_to_the_cap_and_not_dropped() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &["x".repeat(10_000).as_bytes()]);
        let tail = taps.take_tail("e").expect("a tail");
        assert_eq!(tail.len(), TAIL_BYTES);
        assert!(tail.bytes().all(|b| b == b'x'));
    }

    /// The ring drops its oldest bytes in the middle of a token. What is left of the token has no prefix for a mask
    /// to find, so the partial first line must go. Without that drop the suffix survives.
    #[test]
    fn a_ring_that_wraps_inside_a_token_drops_what_is_left_of_it() {
        let taps = ConsoleTaps::new();
        let sink = taps.sink_for("e");
        let first = b"abtskey-auth-SECRETSUFFIX0123\n";
        sink(first);
        // 16 bytes over the ring: the front loses "abtskey-auth-SEC", cutting inside the token.
        let filler = RING_BYTES + 16 - first.len();
        assert_eq!(filler % 2, 0);
        sink("y\n".repeat(filler / 2).as_bytes());
        let tail = taps.take_tail("e").expect("a tail");
        assert!(!tail.contains("SUFFIX"), "a token suffix survived the wrap: {tail:.80}");
        assert!(tail.ends_with('y'), "the newest lines stay");
    }

    #[test]
    fn github_tokens_url_credentials_and_bearer_values_are_masked() {
        let taps = ConsoleTaps::new();
        let text = "fatal: unable to access https://x-access-token:ghs_AbC123xyz@github.com/org/repo.git/\ntoken \
                    ghp_0123456789abcdef and GHO_Upper and github_pat_11AAA_bbb\nAuthorization: Bearer abc.DEF-123 \
                    end\nclone ssh://deploy@host:22/repo ok\n";
        feed(&taps, "e", &[text.as_bytes()]);
        let tail = taps.take_tail("e").expect("a tail");
        for secret in [
            "ghs_AbC123xyz",
            "x-access-token",
            "ghp_0123",
            "GHO_Upper",
            "github_pat_11",
            "abc.DEF",
        ] {
            assert!(!tail.contains(secret), "{secret} survived: {tail}");
        }
        assert!(tail.contains("https://[redacted]@github.com/org/repo.git/"), "{tail}");
        assert!(tail.contains("Bearer [redacted]"), "{tail}");
        assert!(
            tail.contains("ssh://[redacted]@host:22/repo ok"),
            "a user name is userinfo too: {tail}"
        );
    }

    #[test]
    fn text_that_only_looks_like_a_token_is_left_alone() {
        let taps = ConsoleTaps::new();
        feed(
            &taps,
            "e",
            &[b"ghsomething and ghs without underscore, a http://host/path@x, bearer\n"],
        );
        assert_eq!(
            taps.take_tail("e").as_deref(),
            Some("ghsomething and ghs without underscore, a http://host/path@x, bearer")
        );
    }

    /// A guest printing many tokens must not make the cleaning quadratic: the ring lock is released first.
    #[test]
    fn a_console_full_of_tokens_is_cleaned_in_linear_time() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &["tskey-a ".repeat(RING_BYTES / 8).as_bytes()]);
        let started = std::time::Instant::now();
        let tail = taps.take_tail("e").expect("a tail");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert!(!tail.contains("tskey-"));
    }

    #[test]
    fn bidirectional_overrides_are_stripped() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &["safe \u{202e}txet\u{2067} ok\n".as_bytes()]);
        assert_eq!(taps.take_tail("e").as_deref(), Some("safe txet ok"));
    }

    #[test]
    fn a_relaunch_starts_a_fresh_tail_and_a_stale_run_cannot_write_into_it() {
        let taps = ConsoleTaps::new();
        let old = feed(&taps, "e", &[b"old boot\n"]);
        let new = taps.sink_for("e");
        old(b"late bytes from the killed run\n");
        new(b"new boot\n");
        assert_eq!(taps.take_tail("e").as_deref(), Some("new boot"));
    }

    #[test]
    fn only_the_newest_rings_are_kept() {
        let taps = ConsoleTaps::new();
        for n in 0..(MAX_RINGS + 10) {
            feed(&taps, &format!("e{n}"), &[b"boot\n"]);
        }
        assert_eq!(taps.take_tail("e0"), None, "the oldest ring is gone");
        assert_eq!(taps.take_tail("e9"), None);
        assert_eq!(taps.take_tail("e10").as_deref(), Some("boot"));
        assert_eq!(taps.take_tail(&format!("e{}", MAX_RINGS + 9)).as_deref(), Some("boot"));
    }

    #[test]
    fn invalid_utf8_does_not_panic_and_shows_a_replacement() {
        let taps = ConsoleTaps::new();
        feed(&taps, "e", &[b"ok \xff\xfe end\n"]);
        let tail = taps.take_tail("e").expect("a tail");
        assert!(tail.starts_with("ok ") && tail.ends_with(" end"), "{tail}");
    }
}
