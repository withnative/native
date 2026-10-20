//! Opt-in, read-only filesystem projection. Source selection, rendering and
//! publication are separate: only the source collector has an engine handle.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod kernel_v2;
mod publisher;
mod render;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(crate) use publisher::Publisher;

pub(crate) const VERSION: &str = "native.markdown-vault.v1";

/// Byte budgets for single-line vault diagnostics. The bounded stderr
/// contract allows 256 bytes per line, so embedded paths and error details
/// are escaped and truncated (see `diag_field`) to keep each site's worst
/// case within budget: notice 157 + path, guard 201 + root, update-failed
/// 86 + detail, init-failed 96 + detail.
pub(crate) const DIAG_PATH_MAX: usize = 80;
pub(crate) const DIAG_ROOT_MAX: usize = 48;
pub(crate) const DIAG_ERROR_MAX: usize = 128;

/// Render one vault diagnostic field on a single bounded line. Everything
/// outside printable ASCII (including newlines and other control characters)
/// is escaped, then the result is truncated to `max` bytes, so a hostile or
/// merely long path can neither break the line nor blow the byte budget.
pub(crate) fn diag_field(value: &impl std::fmt::Display, max: usize) -> String {
    let mut out = String::new();
    for c in format!("{value}").chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(c),
            c => out.push_str(&format!("\\u{:04x}", c as u32)),
        }
    }
    out.truncate(max);
    out
}

/// A complete caller-visible snapshot at one act, not a paginated MCP response.
/// Keep this format-neutral: a deliverable may combine several source records.
#[derive(Clone, Debug, Default)]
pub(crate) struct SourceSnapshot {
    pub origin: String,
    pub account: String,
    pub act: i64,
    pub generation: String,
    pub freshness: Value,
    pub records: BTreeMap<String, SourceRecord>,
    pub links: Vec<SourceLink>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct SourceRecord {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: Option<String>,
    pub name: Option<String>,
    pub body: Option<String>,
    pub home_id: Option<String>,
    pub archived: bool,
    pub metadata: BTreeMap<String, Value>,
    pub facets: BTreeMap<String, Value>,
    pub anchors: Vec<Value>,
}

impl SourceRecord {
    fn included(&self) -> bool {
        !self.archived && self.record_type != "Configuration"
    }
    fn folder(&self) -> bool {
        self.record_type == "Collection" && self.kind.as_deref() == Some("folder")
    }
    fn comment(&self) -> bool {
        self.record_type == "Annotation" && self.kind.as_deref() == Some("comment")
    }
    fn title(&self) -> String {
        self.name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| {
                format!(
                    "{} {} {}",
                    self.record_type,
                    self.kind.as_deref().unwrap_or(""),
                    short(&self.id)
                )
            })
    }
}

pub(crate) fn short(id: &str) -> &str {
    if id.starts_with("native:") {
        return id;
    }
    &id[..id.char_indices().nth(7).map(|(n, _)| n).unwrap_or(id.len())]
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct SourceLink {
    pub source_id: String,
    pub target_id: String,
    pub relationship: String,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct Allocation {
    pub title: String,
    pub home: Option<String>,
    pub stem: String,
}

pub(crate) struct Output {
    pub bytes: Vec<u8>,
    /// All structured inputs (including link endpoints, ancestors, comments).
    /// Losing any contributor invalidates even a locally edited deliverable.
    pub contributors: BTreeSet<String>,
}

pub(crate) struct Rendered {
    pub files: BTreeMap<String, Output>,
    pub allocations: BTreeMap<String, Allocation>,
    pub directories: BTreeMap<String, BTreeSet<String>>,
}

#[cfg(test)]
mod tests;

impl SourceSnapshot {
    pub(crate) fn status_only(&self) -> Self {
        Self {
            origin: self.origin.clone(),
            account: self.account.clone(),
            act: self.act,
            generation: self.generation.clone(),
            freshness: self.freshness.clone(),
            ..Default::default()
        }
    }
}

pub(crate) fn needs_projection(
    last: Option<&SourceSnapshot>,
    head: i64,
    generation: &str,
    audit_elapsed: std::time::Duration,
) -> bool {
    last.is_none_or(|s| s.act != head || s.generation != generation)
        || audit_elapsed >= std::time::Duration::from_secs(300)
}
