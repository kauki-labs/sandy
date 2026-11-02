//! sandy-mcp: a thin MCP stdio frontend over the sandyd broker API.
//!
//! One tool call is one API request; the server holds no state and has no
//! dispatch logic (`docs/decisions/sandyd.md` section 7). It depends on the
//! API tier only, never on `sandy-control-proto`.

mod api;
mod guard;
mod server;
mod tools;

pub use api::Api;
pub use server::{Server, serve_stdio};
