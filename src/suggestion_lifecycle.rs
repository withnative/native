//! Caller-authored suggestion lifecycle normalization and transition rules.
//!
//! Active membership remains data-governed by `suggestion-lifecycle`; this
//! module owns only the product rule that suggestions are authored `open` and
//! terminal states are written by `resolve_suggestions`.

use crate::error::{Error, Result};

pub(crate) fn validate_create(tool: &str, lifecycle: Option<&str>) -> Result<()> {
    if lifecycle != Some("open") {
        return Err(Error::engine(format!(
            "{tool}: Annotation:suggestion must be authored with lifecycle 'open'; terminal transitions belong to resolve_suggestions"
        )));
    }
    Ok(())
}

/// Validate an ordinary update after active vocabulary membership has been
/// checked for every explicit non-null destination.
pub(crate) fn validate_update(
    tool: &str,
    current_is_suggestion: bool,
    resulting_is_suggestion: bool,
    current_lifecycle: Option<&str>,
    resulting_lifecycle: Option<&str>,
    lifecycle_touched: bool,
    current_lifecycle_is_active: bool,
) -> Result<()> {
    if !resulting_is_suggestion {
        return Ok(());
    }

    if !current_is_suggestion {
        if resulting_lifecycle != Some("open") {
            return Err(Error::engine(format!(
                "{tool}: entering Annotation:suggestion requires lifecycle 'open'"
            )));
        }
        return Ok(());
    }

    if !lifecycle_touched {
        return Ok(());
    }
    let Some(resulting) = resulting_lifecycle else {
        return Err(Error::engine(format!(
            "{tool}: Annotation:suggestion lifecycle cannot be cleared"
        )));
    };
    if current_lifecycle == Some(resulting) {
        return Ok(());
    }
    if current_is_suggestion && !current_lifecycle_is_active && resulting == "open" {
        return Ok(());
    }
    Err(Error::engine(format!(
        "{tool}: ordinary updates cannot resolve or reopen Annotation:suggestion; terminal transitions belong to resolve_suggestions"
    )))
}
