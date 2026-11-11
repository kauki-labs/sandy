//! What a data-link receiver must check before acting on a message (#482, sandyd.md §22).
//!
//! The codec decodes whatever fits one frame (`sandy_control_proto::MAX_FRAME_LEN`, 1 MiB), so a decoded chunk can
//! carry four times `MAX_CHUNK_BYTES`. The peer on the other end is untrusted on this boundary (§22: sandyd
//! re-validates every name a host-executor reports), so no limit is trusted because the sender claims to keep it.
//! [`DataLinkMessage::validate`] is the one place the receiver applies them; it is pure, so each rule is tested
//! without a socket.

use crate::{DataLinkMessage, MAX_CHUNK_BYTES, MAX_CHUNK_NAME_BYTES, data_link_message::Op};

/// Why a data-link message is refused. No variant carries the peer's name or bytes: a violation is logged and
/// answered with a `TransferError`, and neither may echo attacker-chosen content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DataLinkViolation {
    /// The message names no operation.
    #[error("the data-link message carries no operation")]
    Empty,
    /// A chunk carries more than `MAX_CHUNK_BYTES` file bytes.
    #[error("a chunk carries {len} bytes, over the {MAX_CHUNK_BYTES} a chunk may carry")]
    ChunkTooLarge {
        /// The chunk's byte length.
        len: usize,
    },
    /// A chunk name is longer than `MAX_CHUNK_NAME_BYTES`.
    #[error("a chunk name is {len} bytes, over the {MAX_CHUNK_NAME_BYTES} allowed")]
    NameTooLong {
        /// The name's byte length.
        len: usize,
    },
    /// A chunk name is empty.
    #[error("a chunk name is empty")]
    NameEmpty,
    /// A chunk name is absolute.
    #[error("a chunk name is an absolute path")]
    NameAbsolute,
    /// A chunk name has an empty, `.` or `..` component.
    #[error("a chunk name has an empty, `.` or `..` component")]
    NameComponent,
    /// A chunk name holds a NUL byte.
    #[error("a chunk name holds a NUL byte")]
    NameNul,
    /// An input chunk's `offset` plus its length does not fit in a `u64`.
    #[error("an input chunk's offset plus its length overflows")]
    OffsetOverflow,
}

impl DataLinkMessage {
    /// Checks the message against the limits §22 sets, before anything acts on it.
    ///
    /// A chunk's `bytes` are at most `MAX_CHUNK_BYTES` and its `name` at most `MAX_CHUNK_NAME_BYTES`; the name is a
    /// relative path of plain components (no empty, `.` or `..` component, not absolute, no NUL); an input chunk's
    /// `offset + len` must not overflow. A symlink in the destination is a check on the filesystem, made when the
    /// bytes are written, not one a name can show.
    ///
    /// # Errors
    /// The first [`DataLinkViolation`] found.
    pub fn validate(&self) -> Result<(), DataLinkViolation> {
        match self.op.as_ref().ok_or(DataLinkViolation::Empty)? {
            Op::InputChunk(chunk) => {
                validate_chunk(&chunk.name, chunk.bytes.len())?;
                // The file offset after this chunk must be representable, or the receiver's running count wraps.
                u64::try_from(chunk.bytes.len())
                    .ok()
                    .and_then(|len| chunk.offset.checked_add(len))
                    .map(drop)
                    .ok_or(DataLinkViolation::OffsetOverflow)
            }
            Op::OutputChunk(chunk) => validate_chunk(&chunk.name, chunk.bytes.len()),
            Op::InputEnd(_) | Op::OutputEnd(_) | Op::TransferError(_) => Ok(()),
        }
    }
}

fn validate_chunk(name: &str, len: usize) -> Result<(), DataLinkViolation> {
    if len > MAX_CHUNK_BYTES {
        return Err(DataLinkViolation::ChunkTooLarge { len });
    }
    validate_name(name)
}

/// A relative path of plain components. Checked in the order that names the most specific cause first.
fn validate_name(name: &str) -> Result<(), DataLinkViolation> {
    if name.len() > MAX_CHUNK_NAME_BYTES {
        return Err(DataLinkViolation::NameTooLong { len: name.len() });
    }
    if name.is_empty() {
        return Err(DataLinkViolation::NameEmpty);
    }
    if name.contains('\0') {
        return Err(DataLinkViolation::NameNul);
    }
    if name.starts_with('/') {
        return Err(DataLinkViolation::NameAbsolute);
    }
    if name.split('/').any(|part| matches!(part, "" | "." | "..")) {
        return Err(DataLinkViolation::NameComponent);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{InputChunk, OutputChunk, TransferError};

    fn input(name: &str, offset: u64, len: usize) -> DataLinkMessage {
        DataLinkMessage {
            op: Some(Op::InputChunk(InputChunk {
                name: name.to_owned(),
                offset,
                bytes: vec![0u8; len],
            })),
        }
    }

    fn output(name: &str, len: usize) -> DataLinkMessage {
        DataLinkMessage {
            op: Some(Op::OutputChunk(OutputChunk {
                name: name.to_owned(),
                bytes: vec![0u8; len],
            })),
        }
    }

    #[test]
    fn a_chunk_at_both_limits_is_accepted() {
        let longest = "n".repeat(MAX_CHUNK_NAME_BYTES);
        assert_eq!(input(&longest, 0, MAX_CHUNK_BYTES).validate(), Ok(()));
        assert_eq!(output(&longest, MAX_CHUNK_BYTES).validate(), Ok(()));
    }

    #[test]
    fn a_chunk_over_the_byte_limit_is_refused_in_both_directions() {
        let over = DataLinkViolation::ChunkTooLarge {
            len: MAX_CHUNK_BYTES + 1,
        };
        assert_eq!(input("in", 0, MAX_CHUNK_BYTES + 1).validate(), Err(over));
        assert_eq!(output("out", MAX_CHUNK_BYTES + 1).validate(), Err(over));
    }

    #[test]
    fn a_name_over_the_length_limit_is_refused_in_both_directions() {
        let name = "n".repeat(MAX_CHUNK_NAME_BYTES + 1);
        let over = DataLinkViolation::NameTooLong {
            len: MAX_CHUNK_NAME_BYTES + 1,
        };
        assert_eq!(input(&name, 0, 1).validate(), Err(over));
        assert_eq!(output(&name, 1).validate(), Err(over));
    }

    #[test]
    fn a_plain_relative_name_is_accepted() {
        for name in [
            "in",
            "in/a.txt",
            "in/dir/deep/file",
            "out/.hidden",
            "a b/c d",
            "in/..a",
            "in/a..",
            "in/.a",
        ] {
            assert_eq!(input(name, 0, 1).validate(), Ok(()), "{name:?}");
            assert_eq!(output(name, 1).validate(), Ok(()), "{name:?}");
        }
    }

    #[test]
    fn a_name_that_could_leave_the_destination_is_refused_in_both_directions() {
        use DataLinkViolation as V;
        for (name, why) in [
            ("", V::NameEmpty),
            ("/etc/passwd", V::NameAbsolute),
            ("/", V::NameAbsolute),
            ("..", V::NameComponent),
            ("../x", V::NameComponent),
            ("in/../x", V::NameComponent),
            ("in/..", V::NameComponent),
            (".", V::NameComponent),
            ("in/./x", V::NameComponent),
            ("in//x", V::NameComponent),
            ("in/x/", V::NameComponent),
            ("in\0x", V::NameNul),
            ("in/x\0", V::NameNul),
        ] {
            assert_eq!(input(name, 0, 1).validate(), Err(why), "input {name:?}");
            assert_eq!(output(name, 1).validate(), Err(why), "output {name:?}");
        }
    }

    #[test]
    fn an_input_offset_plus_length_that_overflows_is_refused() {
        assert_eq!(
            input("in", u64::MAX, 1).validate(),
            Err(DataLinkViolation::OffsetOverflow)
        );
        assert_eq!(
            input("in", u64::MAX - 1, 2).validate(),
            Err(DataLinkViolation::OffsetOverflow)
        );
        assert_eq!(input("in", u64::MAX - 1, 1).validate(), Ok(()));
        assert_eq!(input("in", u64::MAX, 0).validate(), Ok(()), "no bytes, no overflow");
    }

    #[test]
    fn the_control_messages_are_accepted_and_an_empty_one_is_not() {
        let end = |op| DataLinkMessage { op: Some(op) };
        assert_eq!(end(Op::InputEnd(Default::default())).validate(), Ok(()));
        assert_eq!(end(Op::OutputEnd(Default::default())).validate(), Ok(()));
        assert_eq!(
            end(Op::TransferError(TransferError {
                reason: "disk full".to_owned()
            }))
            .validate(),
            Ok(())
        );
        assert_eq!(DataLinkMessage { op: None }.validate(), Err(DataLinkViolation::Empty));
    }

    /// The codec does not enforce the limits, which is why the receiver must: a frame of up to 1 MiB decodes to a
    /// chunk four times the cap.
    #[test]
    fn a_decoded_oversized_chunk_is_refused() -> anyhow::Result<()> {
        use prost::Message;
        let wire = input("in", 0, 4 * MAX_CHUNK_BYTES - 64).encode_to_vec();
        let decoded = DataLinkMessage::decode(wire.as_slice())?;
        assert!(matches!(
            decoded.validate(),
            Err(DataLinkViolation::ChunkTooLarge { .. })
        ));
        Ok(())
    }

    /// A violation is logged and answered on the link, so it never repeats the peer's name or bytes.
    #[test]
    fn a_violation_never_echoes_the_peers_name() {
        let secret = "SECRET-NAME";
        let err = input(&format!("/{secret}"), 0, 1).validate().expect_err("absolute");
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains(secret), "{shown}");
    }
}
