//! Process-lifetime MCP product selection.
//!
//! This is deliberately a startup-only operator control. It is not an
//! account preference and must never be exposed through MCP or settings APIs.

use std::str::FromStr;

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
}
