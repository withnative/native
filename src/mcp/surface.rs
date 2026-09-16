//! Process-lifetime MCP product selection.
//!
//! This is deliberately a startup-only operator control. It is not an
//! account preference and must never be exposed through MCP or settings APIs.

use std::collections::BTreeSet;
use std::str::FromStr;

/// Deployment-level opt-in for experimental MCP executors.
///
/// `NATIVE_CE_EXPERIMENTAL_EXECUTORS` is a comma-separated allowlist read once
/// at process startup. Unset or empty means no experimental executors: the
/// advertised catalogue is byte-identical to the stable-only surface. The only
/// recognised value is [`EXPERIMENTAL_FRESHNESS_EXECUTOR`]; any other name
/// fails startup (fail closed), naming the variable and the offending value.
pub const EXPERIMENTAL_EXECUTORS_ENV: &str = "NATIVE_CE_EXPERIMENTAL_EXECUTORS";

/// The only experimental executor the allowlist recognises: the
/// feature-gated context-freshness development probe backed by the
/// build-enabled legacy tool `experimental_freshness_agent_intent`.
pub const EXPERIMENTAL_FRESHNESS_EXECUTOR: &str = "experimental_freshness";

/// Parsed value of [`EXPERIMENTAL_EXECUTORS_ENV`]. Prefer this over passing
/// raw strings: parsing (and its fail-closed unknown-name refusal) happens
/// once at startup, and catalogue builders receive an authoritative set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExperimentalExecutors {
    names: BTreeSet<String>,
}

impl ExperimentalExecutors {
    /// No experimental executors: the stable-only catalogue, byte-identical
    /// to the surface shipped before this opt-in existed.
    pub fn empty() -> Self {
        Self {
            names: BTreeSet::new(),
        }
    }

    /// Parse the raw environment value. `None` (unset) and blank entries mean
    /// "no experimental executors". Entries are whitespace-trimmed and empty
    /// entries ignored; duplicates are tolerated. Any other name is an error
    /// naming the variable and the offending value.
    pub fn from_env_value(raw: Option<String>) -> Result<Self, String> {
        let Some(raw) = raw else {
            return Ok(Self::empty());
        };
        let mut names = BTreeSet::new();
        for entry in raw.split(',') {
            let name = entry.trim();
            if name.is_empty() {
                continue;
            }
            if name != EXPERIMENTAL_FRESHNESS_EXECUTOR {
                return Err(format!(
                    "{EXPERIMENTAL_EXECUTORS_ENV} names an unrecognised experimental executor ({name}): only {EXPERIMENTAL_FRESHNESS_EXECUTOR} is recognised"
                ));
            }
            names.insert(name.to_string());
        }
        Ok(Self { names })
    }

    /// Whether `name` was allowlisted.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Whether the allowlist admits nothing (unset, empty, or blank).
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// The one MCP product selected for the lifetime of a server process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum McpSurfaceMode {
    /// The stable permission-shaped executor catalogue.
    #[default]
    Executor,
    /// Hidden emergency rollback to the original tool registry surface.
    Legacy,
}

impl McpSurfaceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Executor => "executor",
            Self::Legacy => "legacy",
        }
    }
}

impl std::fmt::Display for McpSurfaceMode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for McpSurfaceMode {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "executor" => Ok(Self::Executor),
            "legacy" => Ok(Self::Legacy),
            _ => Err("expected executor or legacy"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_is_the_only_default_and_values_are_exact() {
        assert_eq!(McpSurfaceMode::default(), McpSurfaceMode::Executor);
        assert_eq!("executor".parse(), Ok(McpSurfaceMode::Executor));
        assert_eq!("legacy".parse(), Ok(McpSurfaceMode::Legacy));
        for invalid in ["", "complete", "focused", "EXECUTOR", " legacy"] {
            assert!(invalid.parse::<McpSurfaceMode>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn experimental_executors_allowlist_is_off_by_default_and_fails_closed() {
        assert!(ExperimentalExecutors::from_env_value(None)
            .unwrap()
            .is_empty());
        assert!(ExperimentalExecutors::from_env_value(Some(String::new()))
            .unwrap()
            .is_empty());
        assert!(ExperimentalExecutors::from_env_value(Some("  , ,".into()))
            .unwrap()
            .is_empty());
        let allowlisted =
            ExperimentalExecutors::from_env_value(Some(" experimental_freshness ,,".into()))
                .unwrap();
        assert!(allowlisted.contains(EXPERIMENTAL_FRESHNESS_EXECUTOR));
        // Duplicates are tolerated.
        let duplicated = ExperimentalExecutors::from_env_value(Some(
            "experimental_freshness, experimental_freshness".into(),
        ))
        .unwrap();
        assert_eq!(allowlisted, duplicated);
        let error =
            ExperimentalExecutors::from_env_value(Some("experimental_nope".into())).unwrap_err();
        assert!(error.contains(EXPERIMENTAL_EXECUTORS_ENV), "{error}");
        assert!(error.contains("experimental_nope"), "{error}");
    }
}
