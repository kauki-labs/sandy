//! The proxy's answer to one CONNECT: an HTTP status and a one-line reason.

use std::fmt;

/// The statuses the proxy answers with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// The tunnel is open.
    Ok = 200,
    /// The request head, port, or host is malformed.
    BadRequest = 400,
    /// The target is not allowed.
    Forbidden = 403,
    /// The method is not `CONNECT`.
    MethodNotAllowed = 405,
    /// Resolution or connection failed.
    BadGateway = 502,
    /// Resolution or connection timed out.
    GatewayTimeout = 504,
}

impl Status {
    /// The numeric HTTP status code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    const fn phrase(self) -> &'static str {
        match self {
            Self::Ok => "Connection Established",
            Self::BadRequest => "Bad Request",
            Self::Forbidden => "Forbidden",
            Self::MethodNotAllowed => "Method Not Allowed",
            Self::BadGateway => "Bad Gateway",
            Self::GatewayTimeout => "Gateway Timeout",
        }
    }
}

/// A status plus a one-line reason that names the target.
///
/// The reason never carries raw request bytes: a target that fails the host
/// grammar is described as `malformed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The status to answer with.
    pub status: Status,
    /// A single line, safe to log and to write into a response.
    pub reason: String,
}

impl Verdict {
    /// Build a verdict from a status and a reason.
    pub fn new(status: Status, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
        }
    }

    /// The HTTP/1.1 response for this verdict. A `200` has no body.
    #[must_use]
    pub fn to_response(&self) -> Vec<u8> {
        let code = self.status.code();
        let phrase = self.status.phrase();
        if self.status == Status::Ok {
            return format!("HTTP/1.1 {code} {phrase}\r\n\r\n").into_bytes();
        }
        let body = format!("{}\n", self.reason);
        format!(
            "HTTP/1.1 {code} {phrase}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: \
             close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.status.code(), self.reason)
    }
}
