//! Collect the files a backend wrote to a job's declared output destinations, for both the envelope (`OutputRef`) and
//! the audit receipt (`OutputSizeRef`, #361). The listing itself is `sandy::outputs`, shared with `sandyd`.

use sandy::{ContentDigests, OutputRef, OutputSizeRef};

use crate::plan::JobPlan;

fn declared(plan: &JobPlan) -> Vec<sandy::DeclaredOutput<'_>> {
    plan.outputs
        .iter()
        .map(|output| (output.name.as_deref(), output.dest.as_path()))
        .collect()
}

/// The envelope's `outputs` for `plan`.
pub(super) fn collect_output_refs(plan: &JobPlan) -> Vec<OutputRef> {
    sandy::collect_output_refs(&declared(plan))
}

/// The receipt's `guest_reported.outputs` for `plan`, with the backend's digests (#373) joined by path.
pub(super) fn collect_output_size_refs(plan: &JobPlan, digests: Option<&ContentDigests>) -> Vec<OutputSizeRef> {
    sandy::collect_output_size_refs(&declared(plan), digests)
}
