//! `sandy run --flake`/`sandy daemon submit --flake`'s own thin call site
//! over `sandy-guest-template`'s resolution logic (#325/#332): the real work
//! (template-kind detection, the guest-wrapper build+eval) was extracted to
//! that shared crate so `sandy-host-executor`'s remote VM dispatch can call
//! the identical logic against its own host. This module only re-exports the
//! shared types unchanged and injects sandy-cli's own macOS vfkit-prereq
//! check — the one piece of the original logic that reached into a
//! `sandy-cli`-local module (`doctor`), which the shared crate cannot depend
//! on.

pub use sandy_guest_template::{ResolvedTemplate, TemplateKind, parse_kind};

/// [`sandy_guest_template::resolve_flake_template`], with this crate's own
/// macOS vfkit-prereq check (`doctor::mac_prereq_result`/`detect_mac_prereq`)
/// wired in — the exact check `sandy doctor` itself runs on macOS. Unchanged
/// call-site shape for `main.rs`'s `run --flake` and `daemon submit --flake`
/// arms: this is a pure extraction (#332), not a behavior change.
///
/// # Errors
/// See [`sandy_guest_template::resolve_flake_template`].
pub fn resolve_flake_template(
    flake_ref: &str,
    kind: Option<&str>,
    attr: Option<&str>,
    from_devshell: bool,
) -> anyhow::Result<ResolvedTemplate> {
    sandy_guest_template::resolve_flake_template(
        flake_ref,
        kind,
        attr,
        from_devshell,
        || crate::doctor::mac_prereq_result(crate::doctor::detect_mac_prereq()).map(|refusal| refusal.message),
        // `None`: unbounded, exactly today's behavior — the new deadline
        // (#332, CodeRabbit finding on PR #333) is for the REMOTE
        // host-executor's dispatch loop, which `sandy run --flake`/`daemon
        // submit --flake` never go through.
        None,
    )
}
