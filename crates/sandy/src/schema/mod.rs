//! Versioned, serialized journal schema types.
//!
//! The on-disk journal record and its enum live here, split by schema version
//! so a future format can be added as a sibling module without disturbing the
//! behavioral [`Journal`](crate::journal::Journal) impl.

pub mod v1;
