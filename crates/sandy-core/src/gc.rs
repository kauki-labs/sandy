//! Staging GC / retention policy (Phase D, D.4 / D-REQ-4).
//!
//! The operable default: keep the newest N staged images plus anything a running
//! sandbox still references; evict the rest. A referenced image is NEVER evicted,
//! even when it is old (the `gc_evict_referenced_blocked` adversarial).

use std::{collections::HashSet, time::SystemTime};

/// A staged image eligible for garbage collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedImage {
    /// The image's stable id (the retain key GC matches against).
    pub id: String,
    /// When the image was staged; orders newest-first for keep-last-N.
    pub staged_at: SystemTime,
}

/// Plan which staged image ids to evict under the keep-last-N + referenced policy
/// (D-REQ-4).
///
/// Keeps the newest `keep_last_n` images by [`StagedImage::staged_at`] and every
/// id in `referenced`; returns the ids to evict. A referenced id is never in the
/// result, even when it falls outside the newest N.
#[must_use]
pub fn plan_eviction(images: &[StagedImage], keep_last_n: usize, referenced: &HashSet<String>) -> Vec<String> {
    let mut newest_first: Vec<&StagedImage> = images.iter().collect();
    newest_first.sort_by_key(|image| std::cmp::Reverse(image.staged_at));
    newest_first
        .into_iter()
        // The newest `keep_last_n` survive unconditionally...
        .skip(keep_last_n)
        // ...and a referenced id is never evicted, even when it falls past the window.
        .filter(|image| !referenced.contains(&image.id))
        .map(|image| image.id.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashSet,
        time::{Duration, SystemTime},
    };

    use super::{StagedImage, plan_eviction};

    /// A staged image at `secs` past the epoch — higher `secs` is newer.
    fn img(id: &str, secs: u64) -> StagedImage {
        StagedImage {
            id: id.to_string(),
            staged_at: SystemTime::UNIX_EPOCH + Duration::from_secs(secs),
        }
    }

    /// D-REQ-4: with keep-last-N and nothing referenced, the newest N survive and
    /// everything older is evicted.
    #[test]
    fn gc_evict_beyond_keep_n() {
        let images = [img("a", 1), img("b", 2), img("c", 3)];
        let evict = plan_eviction(&images, 1, &HashSet::new());
        assert!(evict.contains(&"a".to_string()), "oldest must be evicted: {evict:?}");
        assert!(
            evict.contains(&"b".to_string()),
            "second-oldest must be evicted: {evict:?}"
        );
        assert!(
            !evict.contains(&"c".to_string()),
            "newest (kept) must not be evicted: {evict:?}"
        );
    }

    /// D-REQ-4 (MUST NOT): a referenced id is never evicted, even when it is older
    /// than the keep-last-N window.
    #[test]
    fn gc_evict_referenced_blocked() {
        let images = [img("a", 1), img("b", 2), img("c", 3)];
        let mut referenced = HashSet::new();
        referenced.insert("a".to_string());
        let evict = plan_eviction(&images, 1, &referenced);
        assert!(
            !evict.contains(&"a".to_string()),
            "a referenced id must never be evicted, even if old: {evict:?}"
        );
    }
}
