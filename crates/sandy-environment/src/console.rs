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

use crate::mesh::redact;

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
        let ring = ring.lock().unwrap_or_else(PoisonError::into_inner);
        let raw: Vec<u8> = ring.bytes.iter().copied().collect();
        let tail = tail_text(&raw, ring.wrapped);
        (!tail.is_empty()).then_some(tail)
    }
}

/// Clean `raw`, mask tokens, and keep the last [`TAIL_LINES`] lines within [`TAIL_BYTES`].
/// `partial_start` says the first line may have lost its beginning, so it is dropped: a
/// token cut in half would otherwise show its tail without the prefix a mask looks for.
fn tail_text(raw: &[u8], partial_start: bool) -> String {
    let cleaned = strip_controls(&String::from_utf8_lossy(raw));
    // Mask first, on whole tokens; the caps below only remove text.
    let masked = redact(&cleaned);
    let mut lines: Vec<&str> = masked.split('\n').map(str::trim_end).collect();
    if partial_start && !lines.is_empty() {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    let keep = lines.len().saturating_sub(TAIL_LINES);
    let mut text = lines[keep..].join("\n");
    if text.len() > TAIL_BYTES {
        let mut cut = text.len() - TAIL_BYTES;
        while !text.is_char_boundary(cut) {
            cut += 1;
        }
        // The cut may land inside a line; drop that partial line so no token loses its prefix.
        let next_line = text[cut..].find('\n').map_or(text.len(), |i| cut + i + 1);
        text = text[next_line.min(text.len())..].to_owned();
    }
    text
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

    #[test]
    fn the_byte_cap_cuts_at_a_line_and_keeps_the_newest_text() {
        let taps = ConsoleTaps::new();
        // 201-byte lines of a multi-byte character: forty of them are more than the byte cap.
        let line = format!("{}\n", "é".repeat(100));
        let text = line.repeat(200);
        feed(&taps, "e", &[text.as_bytes()]);
        let tail = taps.take_tail("e").expect("a tail");
        assert!(tail.len() <= TAIL_BYTES, "{}", tail.len());
        assert!(tail.lines().all(|l| l == "é".repeat(100)), "only whole lines remain");
    }

    #[test]
    fn a_token_cut_by_the_byte_cap_leaves_no_suffix() {
        let taps = ConsoleTaps::new();
        let token = "tskey-auth-SECRETSUFFIX0123456789";
        // The token sits in a line the byte cap will cut through.
        let filler = format!("{}\n", "x".repeat(TAIL_BYTES - 10));
        let text = format!("lead {token}\n{filler}end\n");
        feed(&taps, "e", &[text.as_bytes()]);
        let tail = taps.take_tail("e").expect("a tail");
        assert!(!tail.contains("SECRETSUFFIX"), "{tail}");
        assert!(tail.ends_with("end"), "{tail}");
    }

    #[test]
    fn the_ring_keeps_the_newest_bytes_and_drops_the_partial_first_line() {
        let taps = ConsoleTaps::new();
        let sink = taps.sink_for("e");
        // Push a token so the ring wraps in the middle of it.
        sink(b"tskey-auth-WRAPPEDSECRET\n");
        for _ in 0..(RING_BYTES / 100 + 8) {
            sink(format!("{}\n", "y".repeat(99)).as_bytes());
        }
        sink(b"newest\n");
        let tail = taps.take_tail("e").expect("a tail");
        assert!(tail.ends_with("newest"), "{tail}");
        assert!(!tail.contains("WRAPPEDSECRET"), "{tail}");
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
