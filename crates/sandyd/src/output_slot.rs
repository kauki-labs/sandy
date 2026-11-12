//! The per-job rendezvous between the data link that receives a job's outputs and the result relay that records the
//! job's terminal status (#482 decision 22, slice 6c-2).
//!
//! The host sends the outputs before it reports the result, but the two travel on different streams, so either can be
//! seen first. A succeeded job whose outputs are owed is terminal only once the receive says so.

use std::time::Duration;

use tokio::sync::watch;

use crate::data_link_recv::Received;

/// What the receive of a job's outputs has come to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputsState {
    /// Nothing has finished yet.
    Pending,
    /// Every output arrived and is in place.
    Received(Received),
    /// The receive failed, or never happened. The text is fixed, never a peer-chosen byte.
    Failed(String),
}

/// One job's [`OutputsState`], written once by the data link and read by the result relay.
#[derive(Debug)]
pub struct OutputsSlot {
    state: watch::Sender<OutputsState>,
}

impl Default for OutputsSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputsSlot {
    /// A slot with nothing decided.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: watch::Sender::new(OutputsState::Pending),
        }
    }

    /// Record how the receive ended. The first outcome stands: a later one (a second claim of the link cannot happen,
    /// but a late failure after a success could be raced in) never overturns it.
    pub fn publish(&self, outcome: OutputsState) {
        self.state.send_if_modified(|state| {
            if *state == OutputsState::Pending && outcome != OutputsState::Pending {
                *state = outcome;
                true
            } else {
                false
            }
        });
    }

    /// Wait for the receive to end, at most `within`. The state at that point, if it is still pending, is a failure:
    /// the outputs did not arrive in time.
    pub async fn wait(&self, within: Duration) -> OutputsState {
        let mut rx = self.state.subscribe();
        let decided = tokio::time::timeout(within, rx.wait_for(|state| *state != OutputsState::Pending)).await;
        match decided {
            Ok(Ok(state)) => state.clone(),
            // Published, so the receive that may still be waiting for a first frame gives up too.
            Ok(Err(_)) | Err(_) => {
                self.publish(OutputsState::Failed("the outputs did not arrive in time".to_owned()));
                // The first outcome stands: a receive that finished just now wins over the timeout.
                self.state.borrow().clone()
            }
        }
    }

    /// Resolve once the slot is decided, by the receive or by the job ending. No time limit: the caller bounds it.
    pub async fn decided(&self) {
        let mut rx = self.state.subscribe();
        let _ = rx.wait_for(|state| *state != OutputsState::Pending).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn a_published_outcome_is_seen_by_a_later_wait() {
        let slot = OutputsSlot::new();
        slot.publish(OutputsState::Received(Received { files: 2, bytes: 9 }));
        assert_eq!(
            slot.wait(SHORT).await,
            OutputsState::Received(Received { files: 2, bytes: 9 })
        );
    }

    #[tokio::test]
    async fn a_wait_that_started_first_is_woken_by_the_publish() {
        let slot = std::sync::Arc::new(OutputsSlot::new());
        let waiting = tokio::spawn({
            let slot = std::sync::Arc::clone(&slot);
            async move { slot.wait(Duration::from_secs(30)).await }
        });
        tokio::task::yield_now().await;
        slot.publish(OutputsState::Failed("link closed".to_owned()));
        assert_eq!(
            waiting.await.expect("the waiter ran"),
            OutputsState::Failed("link closed".to_owned())
        );
    }

    #[tokio::test]
    async fn the_first_outcome_stands() {
        let slot = OutputsSlot::new();
        slot.publish(OutputsState::Received(Received { files: 1, bytes: 1 }));
        slot.publish(OutputsState::Failed("late".to_owned()));
        assert_eq!(
            slot.wait(SHORT).await,
            OutputsState::Received(Received { files: 1, bytes: 1 })
        );
    }

    #[tokio::test]
    async fn an_undecided_slot_fails_when_the_wait_runs_out() {
        let slot = OutputsSlot::new();
        assert!(matches!(
            slot.wait(Duration::from_millis(50)).await,
            OutputsState::Failed(_)
        ));
    }
}
