//! `sandy-agent`: the sandbox agent as its own OS process (#216).
//!
//! Usage: `sandy-agent -- <job> [args...]`, launched by the process backend
//! with its agent link on stdin ([`AGENT_LINK_FD`](sandy_fabric_local) is fd 0).

fn main() {
    eprintln!("sandy-agent: not implemented");
    std::process::abort();
}
