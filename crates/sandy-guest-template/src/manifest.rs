//! The `flake/v1` dispatch manifest (#332): a flake-templated VM job's
//! `Dispatch.manifest` bytes, mirroring `sandy run --flake`'s own CLI shape
//! (`--flake`/`--attr`/`--kind`, a trailing `-- CMD ARGS...`) so
//! `sandy daemon submit --flake` encodes exactly what a remote host-executor's
//! `SandboxKind::Vm` branch decodes — ship the flake REFERENCE, never a
//! prebuilt topology: the executor resolves it against its OWN host (ground
//! truth confirmed on #332: a topology built on the submitting Mac is useless
//! on an x86_64-linux executor).

use serde::{Deserialize, Serialize};

/// The `Dispatch.manifest_encoding` tag a `flake/v1` manifest carries.
pub const MANIFEST_ENCODING_FLAKE_V1: &str = "flake/v1";

/// A `flake/v1` manifest's decoded shape: everything
/// [`crate::resolve_flake_template`] needs, plus the guest command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlakeManifestV1 {
    /// The flake reference `--flake` named (a path, `github:…`, or any other
    /// `nix` installable flake-ref syntax) — resolved by the EXECUTOR against
    /// its own host, never built here.
    pub flake: String,
    /// `--kind`'s override, if given; `None` auto-detects (mirrors `sandy run
    /// --flake`'s own default).
    pub kind: Option<String>,
    /// `--attr`'s override, if given; `None` uses `resolve_flake_template`'s
    /// own default (`"default"`).
    pub attr: Option<String>,
    /// The trailing `-- CMD ARGS...` guest command; empty means "boot the
    /// template's default command" (same convention as `JobPlan::command`).
    pub command: Vec<String>,
    /// The scrollback/transcript line bound for the job's interactive
    /// session (epic #340, phase 6): both tmux's own `history-limit` for
    /// live reattach and the cap on the archived transcript delivered back
    /// once the job ends use this same number. `#[serde(default)]` so a
    /// manifest encoded before this field existed still decodes — the
    /// default matches what a consumer should assume absent any override.
    #[serde(default = "default_history_lines")]
    pub history_lines: u32,
}

/// [`FlakeManifestV1::history_lines`]'s default (10,000) — also `sandy
/// daemon submit --flake`'s own `--history-lines` CLI default, so an
/// unencoded-field manifest and an explicit-default submission produce
/// identical bytes.
#[must_use]
pub fn default_history_lines() -> u32 {
    10_000
}

/// Encode a [`FlakeManifestV1`] as the JSON bytes `Dispatch.manifest` carries
/// under [`MANIFEST_ENCODING_FLAKE_V1`].
///
/// # Errors
/// Never fails in practice (every field is a plain string/`Vec<String>`), but
/// surfaces `serde_json`'s own error rather than panicking.
pub fn encode_flake_manifest(manifest: &FlakeManifestV1) -> Result<Vec<u8>, serde_json::Error> {
    serde_json::to_vec(manifest)
}

/// Decode a `flake/v1` manifest's bytes back into a [`FlakeManifestV1`].
///
/// # Errors
/// `serde_json`'s own error if the bytes are not valid JSON, or not this
/// shape.
pub fn decode_flake_manifest(bytes: &[u8]) -> Result<FlakeManifestV1, serde_json::Error> {
    serde_json::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flake_manifest_round_trips_through_json() -> Result<(), serde_json::Error> {
        let manifest = FlakeManifestV1 {
            flake: "github:acme/guest".to_owned(),
            kind: Some("nixos-module".to_owned()),
            attr: Some("default".to_owned()),
            command: vec!["sh".to_owned()],
            history_lines: 5_000,
        };
        let bytes = encode_flake_manifest(&manifest)?;
        assert_eq!(decode_flake_manifest(&bytes)?, manifest);
        Ok(())
    }

    /// `kind`/`attr` are optional and an empty command means "boot the
    /// template's default" — the minimal `--flake <ref>` invocation with no
    /// overrides and no trailing command.
    #[test]
    fn kind_attr_and_command_are_optional() -> Result<(), serde_json::Error> {
        let manifest = FlakeManifestV1 {
            flake: "./fixture".to_owned(),
            kind: None,
            attr: None,
            command: Vec::new(),
            history_lines: default_history_lines(),
        };
        let bytes = encode_flake_manifest(&manifest)?;
        assert_eq!(decode_flake_manifest(&bytes)?, manifest);
        Ok(())
    }

    /// Malformed bytes are refused, not silently defaulted.
    #[test]
    fn malformed_bytes_are_refused() {
        assert!(decode_flake_manifest(b"not json").is_err());
    }

    /// A manifest encoded before `history_lines` existed (no field in the
    /// JSON at all) must still decode, defaulting to 10,000 — the whole
    /// point of `#[serde(default)]` here: a not-yet-redeployed host-executor
    /// or an older CLI must never fail to decode an otherwise-valid
    /// `flake/v1` manifest.
    #[test]
    fn a_manifest_with_no_history_lines_field_defaults_to_ten_thousand() -> Result<(), serde_json::Error> {
        let legacy_json = br#"{"flake":"./fixture","kind":null,"attr":null,"command":[]}"#;
        let decoded = decode_flake_manifest(legacy_json)?;
        assert_eq!(decoded.history_lines, 10_000);
        Ok(())
    }
}
