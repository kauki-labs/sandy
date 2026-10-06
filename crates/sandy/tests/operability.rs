//! Operability signals: run-state metrics and staging GC retention.
//!
//! Exercises the two `sandy` operability surfaces from a consumer's view —
//! the run metrics must MOVE when a run changes state (presence alone is not
//! observability), and the GC plan must evict beyond the keep-last-N window
//! while never evicting a referenced image.

use std::{
    collections::HashSet,
    time::{Duration, SystemTime},
};

use sandy::{RunMetrics, RunPhase, StagedImage, plan_eviction};

/// The running gauge rises on start and falls on finish, and a terminal
/// transition moves its own counter and the transitions total.
#[test]
fn the_metrics_move_when_the_run_moves() {
    let mut m = RunMetrics::new();
    let before = m.transitions_total();

    m.on_transition(RunPhase::Pending, RunPhase::Running);
    assert_eq!(m.running_gauge(), 1, "gauge rises on start");

    m.on_transition(RunPhase::Running, RunPhase::Succeeded);
    assert_eq!(m.running_gauge(), 0, "gauge falls on finish");
    assert_eq!(m.succeeded_total(), 1, "the succeeded counter moves");
    assert!(
        m.transitions_total() > before,
        "a never-moving transitions counter is a dead metric"
    );
}

/// An unpaired leave (a `Running` -> terminal with no matching enter) holds the
/// in-flight gauge at zero rather than driving it negative.
#[test]
fn an_unpaired_leave_does_not_underflow_the_gauge() {
    let mut m = RunMetrics::new();
    m.on_transition(RunPhase::Running, RunPhase::Succeeded);
    assert_eq!(m.running_gauge(), 0, "a count of in-flight runs is never negative");
}

fn image(id: &str, secs: u64) -> StagedImage {
    StagedImage {
        id: id.to_string(),
        staged_at: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
    }
}

/// With nothing referenced, the newest N survive and everything older is
/// evicted.
#[test]
fn gc_keeps_the_newest_n_and_evicts_the_rest() {
    let images = [image("a", 1), image("b", 2), image("c", 3)];
    let evict = plan_eviction(&images, 1, &HashSet::new());
    assert!(evict.contains(&"a".to_string()), "oldest is evicted: {evict:?}");
    assert!(evict.contains(&"b".to_string()), "second-oldest is evicted: {evict:?}");
    assert!(!evict.contains(&"c".to_string()), "the newest is kept: {evict:?}");
}

/// A referenced image is never evicted, even when it falls outside the
/// keep-last-N window.
#[test]
fn gc_never_evicts_a_referenced_image() {
    let images = [image("a", 1), image("b", 2), image("c", 3)];
    let referenced = HashSet::from(["a".to_string()]);
    let evict = plan_eviction(&images, 1, &referenced);
    assert!(
        !evict.contains(&"a".to_string()),
        "a referenced id survives even when old: {evict:?}"
    );
}
