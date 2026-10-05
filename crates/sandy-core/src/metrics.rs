//! Run-state observability metrics (Phase D, D.4 / D-REQ-5).
//!
//! A small owned metrics box with named counters and a gauge that MUST move when
//! a run changes state. Presence alone is not observability: a counter that never
//! moves is a dead signal (the `metric_present_but_dead_fails` adversarial), so
//! the type is built to be asserted both present *and* moving.

/// A run's lifecycle phase — the input whose movement the metrics track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPhase {
    /// Accepted, not yet booted.
    Pending,
    /// Booted and executing.
    Running,
    /// Terminal: guest exited 0 and outputs were collected.
    Succeeded,
    /// Terminal: a task or infra fault.
    Failed,
    /// Terminal: cancelled before a guest result.
    Cancelled,
}

/// Owned counters and gauge for a run's state transitions (D-REQ-5).
///
/// The running gauge rises when a run enters [`RunPhase::Running`] and falls when
/// it leaves; the terminal counters and the transitions total only ever rise.
/// Fields are private; the getters are the observable surface.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunMetrics {
    running: i64,
    transitions_total: u64,
    succeeded_total: u64,
    failed_total: u64,
    cancelled_total: u64,
}

impl RunMetrics {
    /// A zeroed metrics box.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a state transition, moving the gauge and counters (D-REQ-5).
    ///
    /// Entering [`RunPhase::Running`] raises the running gauge and leaving it
    /// lowers the gauge; a terminal `to` bumps its counter; every call bumps the
    /// transitions total.
    pub fn on_transition(&mut self, from: RunPhase, to: RunPhase) {
        self.transitions_total += 1;

        let entering_running = matches!(to, RunPhase::Running) && !matches!(from, RunPhase::Running);
        let leaving_running = matches!(from, RunPhase::Running) && !matches!(to, RunPhase::Running);
        if entering_running {
            self.running += 1;
        } else if leaving_running && self.running > 0 {
            // A count of in-flight runs is never negative: an unpaired leave (a
            // Running→terminal with no matching enter) holds at zero rather than
            // underflowing the gauge.
            self.running -= 1;
        }

        match to {
            RunPhase::Succeeded => self.succeeded_total += 1,
            RunPhase::Failed => self.failed_total += 1,
            RunPhase::Cancelled => self.cancelled_total += 1,
            _ => {}
        }
    }

    /// Current number of runs in [`RunPhase::Running`] (a gauge).
    #[must_use]
    pub fn running_gauge(&self) -> i64 {
        self.running
    }

    /// Total state transitions recorded (a monotonic counter).
    #[must_use]
    pub fn transitions_total(&self) -> u64 {
        self.transitions_total
    }

    /// Total runs that reached [`RunPhase::Succeeded`].
    #[must_use]
    pub fn succeeded_total(&self) -> u64 {
        self.succeeded_total
    }

    /// Total runs that reached [`RunPhase::Failed`].
    #[must_use]
    pub fn failed_total(&self) -> u64 {
        self.failed_total
    }

    /// Total runs that reached [`RunPhase::Cancelled`].
    #[must_use]
    pub fn cancelled_total(&self) -> u64 {
        self.cancelled_total
    }
}

#[cfg(test)]
mod tests {
    use super::{RunMetrics, RunPhase};

    /// D-REQ-5 (positive): the named signals move when the run's state moves —
    /// the running gauge rises on start and falls on finish, and the succeeded
    /// counter rises on a successful terminal transition.
    #[test]
    fn observability_signal_moves() {
        let mut m = RunMetrics::new();
        m.on_transition(RunPhase::Pending, RunPhase::Running);
        assert_eq!(m.running_gauge(), 1, "running gauge must rise on start");
        m.on_transition(RunPhase::Running, RunPhase::Succeeded);
        assert_eq!(m.running_gauge(), 0, "running gauge must fall on finish");
        assert_eq!(m.succeeded_total(), 1, "succeeded counter must rise on success");
    }

    /// D-REQ-5: a cancellation is observable on its own counter — a terminal
    /// `Cancelled` lowers the running gauge and moves `cancelled_total`, distinct
    /// from succeeded/failed.
    #[test]
    fn cancellation_moves_its_own_counter() {
        let mut m = RunMetrics::new();
        m.on_transition(RunPhase::Pending, RunPhase::Running);
        m.on_transition(RunPhase::Running, RunPhase::Cancelled);
        assert_eq!(m.running_gauge(), 0, "running gauge must fall on cancellation");
        assert_eq!(m.cancelled_total(), 1, "cancelled counter must rise on cancellation");
        assert_eq!(m.succeeded_total(), 0, "a cancellation is not a success");
        assert_eq!(m.failed_total(), 0, "a cancellation is not a failure");
    }

    /// D-REQ-5 (adversarial): a metric that exists but never moves is dead. The
    /// transitions counter must actually change across a transition — a
    /// never-moving counter fails this, not just the presence check.
    #[test]
    fn metric_present_but_dead_fails() {
        let mut m = RunMetrics::new();
        let before = m.transitions_total();
        m.on_transition(RunPhase::Pending, RunPhase::Running);
        let after = m.transitions_total();
        assert_ne!(before, after, "a transitions counter that never moves is a dead metric");
    }

    /// An unpaired leave (a `Running` → terminal with no matching enter) must not
    /// drive the in-flight gauge negative — a count of running runs is never below
    /// zero. Regression: the leave branch used to decrement unconditionally.
    #[test]
    fn unbalanced_leave_does_not_underflow_gauge() {
        let mut m = RunMetrics::new();
        m.on_transition(RunPhase::Running, RunPhase::Succeeded);
        assert_eq!(
            m.running_gauge(),
            0,
            "an unpaired leave must hold the gauge at zero, not -1"
        );
    }
}
