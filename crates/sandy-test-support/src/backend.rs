//! [`FakeBackend`]: an in-memory [`VirtualizationBackend`] test double.

use std::sync::{Mutex, PoisonError};

use sandy_api::{
    backend::{BackendError, BoxState, Outcome, RunSpec, SandboxKind, VirtualizationBackend},
    egress::AllowList,
};

/// An in-memory [`VirtualizationBackend`] test double.
///
/// Script a run outcome with [`FakeBackend::with_outcome`] /
/// [`FakeBackend::with_error`], the running-box set with
/// [`FakeBackend::with_boxes`], the reported [`SandboxKind`] with
/// [`FakeBackend::with_kind`], and inspect teardown calls with
/// [`FakeBackend::killed`].
#[derive(Debug)]
pub struct FakeBackend {
    /// The scripted result of the next [`VirtualizationBackend::run`] call. Set once by the
    /// by-value builders, then only read, so it needs no interior mutability.
    run_result: Option<Result<Outcome, BackendError>>,
    /// The boxes [`VirtualizationBackend::boxes`] should report.
    boxes: Vec<BoxState>,
    /// The [`SandboxKind`] [`VirtualizationBackend::kind`] reports; `Vm` by default, matching
    /// the trait's own default for every real backend but the process one.
    kind: SandboxKind,
    /// Box ids passed to [`VirtualizationBackend::kill`], in call order — the one field
    /// mutated through `&self`, so the only one behind a lock.
    killed: Mutex<Vec<String>>,
    /// The egress policy each [`VirtualizationBackend::run`] call carried, in call order; its
    /// length is the number of runs, so an empty list proves nothing booted.
    run_egress: Mutex<Vec<Option<AllowList>>>,
}

impl Default for FakeBackend {
    fn default() -> Self {
        Self {
            run_result: None,
            boxes: Vec::new(),
            kind: SandboxKind::Vm,
            killed: Mutex::new(Vec::new()),
            run_egress: Mutex::new(Vec::new()),
        }
    }
}

impl FakeBackend {
    /// A backend with no scripted outcome and no running boxes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the [`Outcome`] the next [`VirtualizationBackend::run`] returns.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.run_result = Some(Ok(outcome));
        self
    }

    /// Script a [`BackendError`] for the next [`VirtualizationBackend::run`] call.
    #[must_use]
    pub fn with_error(mut self, error: BackendError) -> Self {
        self.run_result = Some(Err(error));
        self
    }

    /// Script the boxes [`VirtualizationBackend::boxes`] reports.
    #[must_use]
    pub fn with_boxes(mut self, boxes: Vec<BoxState>) -> Self {
        self.boxes = boxes;
        self
    }

    /// Script the [`SandboxKind`] [`VirtualizationBackend::kind`] reports.
    #[must_use]
    pub fn with_kind(mut self, kind: SandboxKind) -> Self {
        self.kind = kind;
        self
    }

    /// The [`RunSpec::egress`] of each [`VirtualizationBackend::run`] call, in order. Empty
    /// when `run` was never reached.
    #[must_use]
    pub fn run_egress(&self) -> Vec<Option<AllowList>> {
        self.run_egress.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    /// The box ids [`VirtualizationBackend::kill`] has been called with, in order.
    #[must_use]
    pub fn killed(&self) -> Vec<String> {
        self.killed.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
}

impl VirtualizationBackend for FakeBackend {
    fn run(&self, spec: &RunSpec) -> Result<Outcome, BackendError> {
        self.run_egress
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(spec.egress.cloned());
        self.run_result
            .clone()
            .unwrap_or_else(|| Err(BackendError::Protocol("no scripted run outcome".to_string())))
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        self.killed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(box_id.to_string());
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self.boxes.clone())
    }

    fn kind(&self) -> SandboxKind {
        self.kind
    }
}
