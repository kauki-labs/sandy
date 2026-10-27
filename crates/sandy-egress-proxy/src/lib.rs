//! The per-run egress proxy's pure core: CONNECT parsing, the allow-list
//! match, and the address filter. See `docs/decisions/egress-proxy.md`.
//!
//! The core does no I/O. The binary owns sockets, resolution, and timeouts.

mod allow;
mod decide;
mod filter;
mod head;
mod verdict;

pub use allow::{Policy, PolicyError};
pub use decide::{ResolveError, Resolver, decide};
pub use filter::filter_addrs;
pub use head::{HeadRead, Host, MAX_HEAD, Target, parse_head, read_head};
pub use verdict::{Status, Verdict};
