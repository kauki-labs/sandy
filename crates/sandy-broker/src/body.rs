//! The response body: a whole buffer for the JSON API, or a channel-fed stream for attach.

use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use http_body_util::Full;
use hyper::body::{Body as HttpBody, Bytes, Frame};
use tokio::sync::mpsc;

/// A response body. The stream variant ends when its sender drops, and the
/// sender sees the receiver drop when the client hangs up.
pub(crate) enum Body {
    /// One buffered payload.
    Full(Full<Bytes>),
    /// Chunks sent by a producer task, one frame each.
    Stream(mpsc::Receiver<Bytes>),
}

impl HttpBody for Body {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.get_mut() {
            Self::Full(full) => Pin::new(full).poll_frame(cx),
            Self::Stream(rx) => rx.poll_recv(cx).map(|chunk| chunk.map(|c| Ok(Frame::data(c)))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Full(full) => full.is_end_stream(),
            Self::Stream(_) => false,
        }
    }
}
