//! Inert development package wire contract, retained in ordinary v2 builds.
//! Canonical decoding and inspection do not imply runtime availability.
//! Only package-cel-dev compiles the checked guest adapter.

use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PROVIDER: &str = "host.cel-scalar-dev/1";
pub const LANGUAGE: &str = "cel-subset@1";
pub const PROFILE: &str = "native.cel-scalar-dev/1";
pub const MAX_BINDINGS: usize = 16;
pub const MAX_EXPRESSION_BYTES: usize = 1024;
pub const MAX_SOURCE_BYTES: usize = 16 * 1024;
pub const MAX_STRING_BYTES: usize = 1024;
pub const MAX_RESULT_BYTES: usize = 8192;
const UNAVAILABLE: &str =
    "CEL development package operations require the explicit package-cel-dev feature";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableDeclaration {
    pub language: String,
    pub profile: String,
    /// Exact UTF-8 bytes, never trimmed or normalized.
    pub expression: String,
    pub bindings: Vec<ScalarBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScalarBinding {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ScalarType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    Int,
    Double,
    Bool,
    String,
}

impl ExecutableDeclaration {
    pub fn validate_shape(&self) -> Result<()> {
        if self.language != LANGUAGE || self.profile != PROFILE {
            return Err(Error::engine(
                "unsupported CEL development language or profile",
            ));
        }
        if self.expression.is_empty() || self.expression.len() > MAX_EXPRESSION_BYTES {
            return Err(Error::engine(
                "CEL development expression must be 1..=1024 bytes",
            ));
        }
        if self.bindings.len() > MAX_BINDINGS {
            return Err(Error::engine(
                "CEL development profile allows at most 16 bindings",
            ));
        }
        let mut names = BTreeSet::new();
        for binding in &self.bindings {
            let name = &binding.name;
            if name.is_empty()
                || name.len() > 64
                || !name.bytes().enumerate().all(|(i, c)| {
                    c == b'_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())
                })
                || !names.insert(name)
            {
                return Err(Error::engine(
                    "CEL binding names must be unique ASCII identifiers of 1..=64 bytes",
                ));
            }
        }
        Ok(())
    }
}

/// Returned execution metadata, never admission evidence. Interpreter identifies
/// the checked guest adapter; policy/interim come from its actual report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionReceipt {
    pub language: String,
    pub interpreter: String,
    pub policy: String,
    pub interim: bool,
    pub profile: String,
    pub expression_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<GuestExecutionReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GuestExecutionReceipt {
    pub abi: String,
    pub module_sha256: String,
    pub source_sha256: String,
    pub build_manifest_sha256: String,
    pub runtime: String,
    pub configuration: String,
    pub fuel_budget: u64,
    pub fuel_used: u64,
    pub deadline_ms: u64,
    pub phase: String,
    pub limits: serde_json::Value,
}

/// Runtime admission is separate from structural manifest validation.
pub(crate) fn require_enabled() -> Result<()> {
    if cfg!(feature = "package-cel-dev") {
        Ok(())
    } else {
        Err(Error::engine(UNAVAILABLE))
    }
}

#[cfg(feature = "package-cel-dev")]
mod runtime;
#[cfg(feature = "package-cel-dev")]
pub(crate) use runtime::{admit, provider_schema, run};

#[cfg(not(feature = "package-cel-dev"))]
pub(crate) async fn admit(_manifest: &crate::package_manifest::PackageManifest) -> Result<()> {
    require_enabled()
}

#[cfg(not(feature = "package-cel-dev"))]
pub(crate) async fn run(
    _declaration: ExecutableDeclaration,
    _source: String,
) -> Result<(serde_json::Value, ExecutionReceipt)> {
    Err(Error::engine(UNAVAILABLE))
}

#[cfg(all(test, not(feature = "package-cel-dev")))]
mod shipping_tests;

// Development runtime tests share the bounded worker admission budget.
#[cfg(all(test, feature = "package-cel-dev"))]
pub(crate) static RUNTIME_TEST: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
