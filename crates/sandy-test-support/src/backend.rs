//! [`FakeBackend`]: an in-memory [`VmBackend`] test double.

use std::sync::Mutex;

use sandy_api::backend::{BackendError, BoxState, Outcome, RunSpec, VmBackend};

/// An in-memory [`VmBackend`] test double.
///
/// Script a run outcome with [`FakeBackend::with_outcome`] /
/// [`FakeBackend::with_error`], the running-box set with
/// [`FakeBackend::with_boxes`], and inspect teardown calls with
/// [`FakeBackend::killed`].
#[derive(Debug, Default)]
pub struct FakeBackend {
    /// The scripted result of the next [`VmBackend::run`] call. Set once by the
    /// by-value builders, then only read, so it needs no interior mutability.
    run_result: Option<Result<Outcome, BackendError>>,
    /// The boxes [`VmBackend::boxes`] should report.
    boxes: Vec<BoxState>,
    /// Box ids passed to [`VmBackend::kill`], in call order — the one field
    /// mutated through `&self`, so the only one behind a lock.
    killed: Mutex<Vec<String>>,
}

impl FakeBackend {
    /// A backend with no scripted outcome and no running boxes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Script the [`Outcome`] the next [`VmBackend::run`] returns.
    #[must_use]
    pub fn with_outcome(mut self, outcome: Outcome) -> Self {
        self.run_result = Some(Ok(outcome));
        self
    }

    /// Script a [`BackendError`] for the next [`VmBackend::run`] call.
    #[must_use]
    pub fn with_error(mut self, error: BackendError) -> Self {
        self.run_result = Some(Err(error));
        self
    }

    /// Script the boxes [`VmBackend::boxes`] reports.
    #[must_use]
    pub fn with_boxes(mut self, boxes: Vec<BoxState>) -> Self {
        self.boxes = boxes;
        self
    }

    /// The box ids [`VmBackend::kill`] has been called with, in order.
    #[must_use]
    pub fn killed(&self) -> Vec<String> {
        self.killed.lock().expect("killed lock poisoned").clone()
    }
}

impl VmBackend for FakeBackend {
    fn run(&self, _spec: &RunSpec) -> Result<Outcome, BackendError> {
        self.run_result
            .clone()
            .unwrap_or_else(|| Err(BackendError::Protocol("no scripted run outcome".to_string())))
    }

    fn kill(&self, box_id: &str) -> Result<(), BackendError> {
        self.killed
            .lock()
            .expect("killed lock poisoned")
            .push(box_id.to_string());
        Ok(())
    }

    fn boxes(&self) -> Result<Vec<BoxState>, BackendError> {
        Ok(self.boxes.clone())
    }
}
