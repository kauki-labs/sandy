//! Behavioural contract for `InMem` (issue #107).
//!
//! The shared `channel_backend_suite` already pins every rule the issue asks
//! for (dedup-keeps-first, sequence order under arrival skew, bounded fetch,
//! replay-then-follow with no gap, `MissingMsgId` rejection), so passing it is
//! the primary conformance check. The two tests below cover what a real
//! concurrent backend must get right that a sequential toy fake cannot expose.

use std::time::Duration;

use anyhow::Context as _;
use futures_util::{Stream, StreamExt as _};
use sandy_fabric::{
    channel_backend::{ChannelBackend, ChannelBackendError, MSG_ID_KEY},
    contract::channel_backend_suite,
};
use sandy_fabric_local::inmem::InMem;
use sandy_proto::{CONTENT_TYPE_TEXT, Envelope, MessageType, PeerMsg};

fn deadline() -> tokio::time::Sleep {
    tokio::time::sleep(Duration::from_secs(2))
}

fn envelope(sequence: u64, id: &str) -> Envelope {
    Envelope {
        sequence,
        content_type: CONTENT_TYPE_TEXT.to_owned(),
        payload: id.as_bytes().to_vec(),
        metadata: [(MSG_ID_KEY.to_owned(), id.to_owned())].into(),
        message_type: Some(MessageType::PeerMsg(PeerMsg {})),
    }
}

/// `InMem` passes the full `ChannelBackend` contract suite.
#[tokio::test]
async fn passes_the_channel_backend_suite() -> anyhow::Result<()> {
    channel_backend_suite(InMem::default, deadline).await.context("InMem")
}

/// Concurrent appends of distinct envelopes race on the same backend; none are
/// lost, and the stored log stays sequence-ordered regardless of arrival order.
#[tokio::test]
async fn concurrent_appends_do_not_lose_entries() -> anyhow::Result<()> {
    let backend = InMem::default();
    let tasks = (0..50u64).map(|i| {
        let backend = backend.clone();
        tokio::spawn(async move { backend.append(envelope(i, &format!("id-{i}"))).await })
    });
    for task in tasks {
        task.await.context("join a concurrent append")?.context("append")?;
    }

    let all = backend.fetch(0).await.context("fetch")?;
    assert_eq!(all.len(), 50, "every concurrent append is stored, none lost to a race");
    let sequences: Vec<_> = all.iter().map(|e| e.sequence).collect();
    assert_eq!(
        sequences,
        (0..50).collect::<Vec<_>>(),
        "fetch stays sequence-ordered despite concurrent arrival order"
    );
    Ok(())
}

async fn next_seq(
    stream: &mut (impl Stream<Item = Result<Envelope, ChannelBackendError>> + Unpin),
) -> anyhow::Result<u64> {
    let item = tokio::time::timeout(Duration::from_secs(2), stream.next())
        .await
        .context("stream did not yield before the deadline")?
        .context("stream ended unexpectedly")?;
    Ok(item.context("backend error")?.sequence)
}

/// Two independent `stream_from` subscribers track their own cursors: reading
/// from one does not advance or skip entries for the other.
#[tokio::test]
async fn independent_stream_subscribers_do_not_cross_cursors() -> anyhow::Result<()> {
    let backend = InMem::default();
    backend.append(envelope(1, "a")).await.context("append 1")?;
    backend.append(envelope(2, "b")).await.context("append 2")?;

    let mut from_zero = backend.stream_from(0);
    let mut from_two = backend.stream_from(2);

    assert_eq!(next_seq(&mut from_zero).await?, 1, "from_zero starts at its own cursor");
    assert_eq!(
        next_seq(&mut from_two).await?,
        2,
        "from_two starts at its own cursor, unaffected by from_zero"
    );
    assert_eq!(
        next_seq(&mut from_zero).await?,
        2,
        "from_zero's second read is unaffected by from_two"
    );

    backend.append(envelope(3, "c")).await.context("append 3")?;
    assert_eq!(next_seq(&mut from_zero).await?, 3, "from_zero follows the live append");
    assert_eq!(
        next_seq(&mut from_two).await?,
        3,
        "from_two follows the live append independently"
    );
    Ok(())
}
