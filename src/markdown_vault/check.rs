//! Pure, deliberately narrow v0 grammar for prospective vault edits.
//! Nothing here owns a workspace handle or performs a write.
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Severity {
    Error,
    Warning,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Diagnostic {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub severity: Severity,
    pub code: String,
    pub message: String,
    pub next_step: String,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum FileState {
    Unchanged,
    ModifiedValid,
    ModifiedInvalid,
    LocalOnly,
    BaseMovedOn,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct FileReport {
    pub path: String,
    pub state: FileState,
    pub record_id: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
    pub intents: Vec<Intent>,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Intent {
    SetName {
        record_id: String,
        name: String,
    },
    SetSummary {
        record_id: String,
        summary: String,
    },
    MergeBody {
        record_id: String,
        base_text: String,
        my_text: String,
        base_version: Option<String>,
    },
    AddLink {
        source_id: String,
        target_id: String,
        relationship: String,
    },
}
#[derive(Clone, Debug)]
pub(crate) struct LinkTarget {
    pub record_id: String,
    pub path: String,
    pub name: String,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct LinkIndex {
    pub entries: Vec<LinkTarget>,
    /// True only when the caller can establish that its link catalog is fresh.
    pub fresh: bool,
}
struct Parsed<'a> {
    fields: BTreeMap<String, (Value, usize)>,
    body: &'a str,
    body_line: usize,
    suffix: &'a str,
}
const MARKER: &str = "\n\n<!-- native:generated links -->\n";
fn diag(path: &str, line: usize, code: &str, message: &str, next_step: &str) -> Diagnostic {
    Diagnostic {
        path: path.into(),
        line,
        column: 1,
        severity: Severity::Error,
        code: code.into(),
        message: message.into(),
        next_step: next_step.into(),
    }
}
fn split_field(line: &str) -> Option<(&str, &str)> {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            quoted = !quoted;
        }
        if c == ':' && !quoted {
            return Some((&line[..i], line[i + 1..].trim()));
        }
    }
    None
}
fn scalar(s: &str) -> Option<Value> {
    if let Ok(v) = serde_json::from_str(s) {
        return Some(v);
    }
    // This is a bounded subset, not a permissive YAML interpreter. Block YAML,
    // tags, anchors, aliases and flow collections must never silently become text.
    if s.is_empty()
        || s.starts_with(['"', '\'', '[', '{', '|', '>', '&', '*', '!'])
        || s.contains(" #")
        || s.contains(": ")
    {
        return None;
    }
    Some(Value::String(s.into()))
}
fn parse<'a>(path: &str, text: &'a str) -> Result<Parsed<'a>, Diagnostic> {
    let Some(rest) = text.strip_prefix("---\n") else {
        return Err(diag(
            path,
            1,
            "frontmatter",
            "Expected opening frontmatter delimiter.",
            "Restore the projected frontmatter.",
        ));
    };
    let Some(end) = rest.find("\n---\n") else {
        return Err(diag(
            path,
            1,
            "frontmatter",
            "Missing closing frontmatter delimiter.",
            "Close frontmatter with --- on its own line.",
        ));
    };
    let mut fields = BTreeMap::new();
    for (n, line) in rest[..end].lines().enumerate() {
        let line_no = n + 2;
        let Some((key, value)) = split_field(line) else {
            return Err(diag(
                path,
                line_no,
                "frontmatter",
                "Only one scalar or JSON value per frontmatter line is supported.",
                "Use key: value; quote complex values with JSON syntax.",
            ));
        };
        let key = if key.trim().starts_with('"') {
            serde_json::from_str::<String>(key.trim()).ok()
        } else {
            Some(key.trim().to_owned())
        };
        let Some(key) = key.filter(|k| !k.is_empty()) else {
            return Err(diag(
                path,
                line_no,
                "frontmatter",
                "Malformed frontmatter key.",
                "Use a plain or JSON quoted key.",
            ));
        };
        if fields.contains_key(&key) {
            return Err(diag(
                path,
                line_no,
                "duplicate_key",
                "Duplicate frontmatter key.",
                "Keep each frontmatter key exactly once.",
            ));
        }
        let Some(value) = scalar(value) else {
            return Err(diag(
                path,
                line_no,
                "frontmatter",
                "Unsupported or malformed frontmatter value.",
                "Use a single-line JSON value or a plain scalar; block YAML is unsupported.",
            ));
        };
        fields.insert(key, (value, line_no));
    }
    let after = &rest[end + 5..];
    let Some(content) = after.strip_prefix('\n') else {
        return Err(diag(
            path,
            rest[..end].lines().count() + 3,
            "body_boundary",
            "Missing blank line after frontmatter.",
            "Restore the blank line after the closing --- delimiter.",
        ));
    };
    let Some(marker) = content.rfind(MARKER) else {
        return Err(diag(
            path,
            text.lines().count().max(1),
            "generated_section",
            "Generated Links boundary is missing.",
            "Restore the generated Links and Comments suffix from the published copy.",
        ));
    };
    let body_line = rest[..end].lines().count() + 4;
    Ok(Parsed {
        fields,
        body: &content[..marker],
        body_line,
        suffix: &content[marker..],
    })
}
// Fenced code blocks and inline code are literal Markdown, not link requests.
fn code_ranges(text: &str) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    let mut fence: Option<(u8, usize)> = None;
    let mut offset = 0;
    for line in text.split_inclusive('\n') {
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        let byte = trimmed.as_bytes().first().copied().unwrap_or(0);
        let run = trimmed.bytes().take_while(|b| *b == byte).count();
        if let Some((kind, length)) = fence {
            ranges.push(offset..offset + line.len());
            if indent <= 3 && byte == kind && run >= length && trimmed[run..].trim().is_empty() {
                fence = None;
            }
        } else if indent <= 3 && matches!(byte, b'`' | b'~') && run >= 3 {
            fence = Some((byte, run));
            ranges.push(offset..offset + line.len());
        } else if indent >= 4 {
            ranges.push(offset..offset + line.len());
        } else {
            let mut cursor = 0;
            while let Some(start) = line[cursor..].find('`') {
                let start = cursor + start;
                let length = line[start..].bytes().take_while(|b| *b == b'`').count();
                let delimiter = &line[start..start + length];
                if let Some(end) = line[start + length..].find(delimiter) {
                    let end = start + length + end + length;
                    ranges.push(offset + start..offset + end);
                    cursor = end;
                } else {
                    cursor = start + length;
                }
            }
        }
        offset += line.len();
    }
    ranges
}
fn wikilinks(text: &str) -> Vec<(String, usize, usize)> {
    let code = code_ranges(text);
    let mut out = Vec::new();
    let mut offset = 0;
    while let Some(start) = text[offset..].find("[[") {
        let start = offset + start;
        let escaped = text[..start]
            .bytes()
            .rev()
            .take_while(|b| *b == b'\\')
            .count()
            % 2
            == 1;
        if escaped || code.iter().any(|range| range.contains(&start)) {
            offset = start + 2;
            continue;
        }
        let Some(end) = text[start + 2..].find("]]") else {
            break;
        };
        let end = start + 2 + end;
        let target = text[start + 2..end]
            .split('|')
            .next()
            .unwrap_or("")
            .split('#')
            .next()
            .unwrap_or("")
            .trim();
        let line = text[..start].bytes().filter(|b| *b == b'\n').count();
        let column = text[..start]
            .rsplit('\n')
            .next()
            .unwrap_or("")
            .chars()
            .count()
            + 1;
        if !target.is_empty() {
            out.push((target.into(), line, column));
        }
        offset = end + 2;
    }
    out
}
fn normalized_path(path: &str) -> Option<String> {
    let mut segments = Vec::new();
    for segment in path.trim_start_matches('/').split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop()?;
            }
            _ => segments.push(segment),
        }
    }
    let joined = segments.join("/");
    Some(joined.strip_suffix(".md").unwrap_or(&joined).to_owned())
}
fn resolve(index: &LinkIndex, path: &str, target: &str) -> BTreeSet<String> {
    let normalized = normalized_path(target);
    let relative = path
        .rsplit_once('/')
        .and_then(|(dir, _)| normalized_path(&format!("{dir}/{target}")));
    let mut matches = BTreeSet::new();
    for entry in &index.entries {
        let entry_path = normalized_path(&entry.path);
        let id_match =
            entry.record_id == target || (target.len() >= 7 && entry.record_id.starts_with(target));
        let path_match = normalized.is_some()
            && (entry_path == normalized || (target.contains('/') && entry_path == relative));
        let name_match = !target.contains('/') && entry.name == target;
        if id_match || path_match || name_match {
            matches.insert(entry.record_id.clone());
        }
    }
    matches
}
fn resolve_checked(
    index: &LinkIndex,
    path: &str,
    target: &str,
    line: usize,
    column: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<String> {
    let matches = resolve(index, path, target);
    if matches.len() == 1 {
        return matches.into_iter().next();
    }
    let ambiguous = matches.len() > 1;
    let mut d = diag(
        path,
        line,
        if ambiguous {
            "ambiguous_link"
        } else {
            "unresolved_link"
        },
        &format!(
            "Wikilink target {target:?} {} in the local catalog.",
            if ambiguous {
                "is ambiguous"
            } else {
                "was not found"
            }
        ),
        "Use a unique vault-relative path or record ID; refresh the catalog if needed.",
    );
    d.column = column;
    if !index.fresh {
        d.severity = Severity::Warning;
        d.message
            .push_str(" Catalog freshness is not established; resolution is provisional.");
    }
    diagnostics.push(d);
    None
}
fn whole_wikilink(value: &str) -> bool {
    value
        .strip_prefix("[[")
        .and_then(|s| s.strip_suffix("]]"))
        .is_some_and(|inner| !inner.contains(['[', ']', '\n', '\r']) && !inner.trim().is_empty())
        && wikilinks(value).len() == 1
}
fn artifact_companion(base: &Parsed<'_>) -> bool {
    base.fields
        .get("facet.runtime")
        .or_else(|| base.fields.get("facet.artifact_runtime"))
        .and_then(|(value, _)| value.as_str())
        .is_some_and(|runtime| {
            matches!(
                runtime,
                "native.html.v1" | "native.mdx.v2" | "native.board.v1"
            )
        })
}
fn relation(value: &Value) -> Option<Vec<String>> {
    let values = value.as_array()?;
    let mut result = Vec::new();
    for value in values {
        let value = value.as_str()?;
        if !whole_wikilink(value) {
            return None;
        }
        result.push(value.to_owned());
    }
    // An empty metadata array is not enough to establish a relationship schema.
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// Metadata can also contain arrays of wikilinks. A published generated Links
// entry must establish the relationship; arrays alone never authorize edits.
fn relationship_name(base: &Parsed<'_>, key: &str, values: &[String]) -> Option<String> {
    // Prefer a collision-prefixed property over a same-named metadata field.
    if base.fields.contains_key(&format!("relationship:{key}")) {
        return None;
    }
    let mut candidates = BTreeSet::new();
    for line in base.suffix.lines() {
        let Some((name, _)) = line.strip_prefix("- ").and_then(|s| s.split_once(": ")) else {
            continue;
        };
        let mut field = name.to_owned();
        while field.len() <= key.len() {
            if field == key {
                let prefix = format!("- {name}: ");
                if values.iter().all(|value| {
                    base.suffix.lines().any(|line| {
                        line.strip_prefix(prefix.as_str()).is_some_and(|tail| {
                            tail == value
                                || tail
                                    .strip_prefix(value.as_str())
                                    .is_some_and(|rest| rest.starts_with(" — "))
                        })
                    })
                }) {
                    candidates.insert(name.to_owned());
                }
                break;
            }
            field = format!("relationship:{field}");
        }
    }
    if candidates.len() == 1 {
        candidates.into_iter().next()
    } else {
        None
    }
}

pub(crate) fn check_file(path: &str, base: &str, edited: &str, index: &LinkIndex) -> FileReport {
    let mut report = FileReport {
        path: path.into(),
        state: FileState::Unchanged,
        record_id: None,
        diagnostics: vec![],
        intents: vec![],
    };
    let unchanged = base == edited;
    if !unchanged {
        report.state = FileState::ModifiedValid;
    }
    let base = match parse(path, base) {
        Ok(p) => p,
        Err(_)
            if unchanged
                && !base.lines().any(|line| {
                    split_field(line).is_some_and(|(key, _)| matches!(key.trim(), "id" | "\"id\""))
                }) =>
        {
            return report
        }
        Err(_) => {
            report.state = FileState::ModifiedInvalid;
            report.diagnostics.push(diag(
                path,
                1,
                "unsupported_projection",
                "This generated file has no supported single-record edit grammar.",
                "Edit an ordinary projected record note; aggregates and companions are read-only.",
            ));
            return report;
        }
    };
    let Some(id) = base.fields.get("id").and_then(|(v, _)| v.as_str()) else {
        if unchanged {
            return report;
        }
        report.state = FileState::ModifiedInvalid;
        report.diagnostics.push(diag(
            path,
            1,
            "unsupported_projection",
            "This file is not a single-record note.",
            "Edit an ordinary projected record note.",
        ));
        return report;
    };
    report.record_id = Some(id.into());
    let edited = match parse(path, edited) {
        Ok(p) => p,
        Err(d) => {
            report.state = FileState::ModifiedInvalid;
            report.diagnostics.push(d);
            return report;
        }
    };
    if unchanged {
        return report;
    }
    if base.suffix != edited.suffix {
        let common_newlines = base
            .suffix
            .bytes()
            .zip(edited.suffix.bytes())
            .take_while(|(a, b)| a == b)
            .filter(|(_, b)| *b == b'\n')
            .count();
        let line = edited.body_line
            + edited.body.bytes().filter(|b| *b == b'\n').count()
            + common_newlines;
        report.diagnostics.push(diag(path, line, "generated_section", "Generated Links or Comments were edited.", "Restore the generated suffix; express relationship additions in existing frontmatter arrays."));
    }
    let keys: BTreeSet<_> = base.fields.keys().chain(edited.fields.keys()).collect();
    for key in keys {
        let old = base.fields.get(key);
        let new = edited.fields.get(key);
        if old.map(|(v, _)| v) == new.map(|(v, _)| v) {
            continue;
        }
        let line = new.or(old).map_or(1, |(_, line)| *line);
        let new_value = new.map(|(v, _)| v);
        if matches!(key.as_str(), "name" | "summary") {
            if let Some(value) = new_value
                .and_then(Value::as_str)
                .filter(|s| !s.trim().is_empty() || key == "summary")
            {
                report.intents.push(if key == "name" {
                    Intent::SetName {
                        record_id: id.into(),
                        name: value.into(),
                    }
                } else {
                    Intent::SetSummary {
                        record_id: id.into(),
                        summary: value.into(),
                    }
                });
            } else {
                report.diagnostics.push(diag(
                    path,
                    line,
                    "invalid_scalar",
                    "Writable name/summary must be strings; name cannot be empty.",
                    "Use a quoted string and retain the property.",
                ));
            }
        } else if let Some(old_links) = old
            .and_then(|(v, _)| relation(v))
            .filter(|values| relationship_name(&base, key, values).is_some())
        {
            let new_links = new_value.and_then(Value::as_array).and_then(|v| {
                v.iter()
                    .map(|v| v.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            });
            match new_links {
                Some(new_links) if old_links.iter().all(|v| new_links.contains(v)) => {
                    let mut seen = BTreeSet::new();
                    for value in new_links.iter().filter(|v| !old_links.contains(v)) {
                        let links = wikilinks(value);
                        if !whole_wikilink(value) {
                            report.diagnostics.push(diag(
                                path,
                                line,
                                "invalid_relationship",
                                "Relationship additions must be whole wikilinks.",
                                "Use a JSON array of quoted [[path|title]] values.",
                            ));
                            continue;
                        }
                        if value[2..value.len() - 2]
                            .split('|')
                            .next()
                            .is_some_and(|target| target.contains('#'))
                        {
                            report.diagnostics.push(diag(
                                path,
                                line,
                                "unsupported_relationship_anchor",
                                "Relationship additions cannot target a heading or embedded-record anchor.",
                                "Use a standalone record target without a #fragment.",
                            ));
                            continue;
                        }
                        if let Some(target_id) = resolve_checked(
                            index,
                            path,
                            &links[0].0,
                            line,
                            1,
                            &mut report.diagnostics,
                        ) {
                            if seen.insert(target_id.clone()) {
                                report.intents.push(Intent::AddLink {
                                    source_id: id.into(),
                                    target_id,
                                    relationship: relationship_name(&base, key, &old_links)
                                        .expect("checked relationship"),
                                });
                            }
                        }
                    }
                }
                _ => report.diagnostics.push(diag(
                    path,
                    line,
                    "relationship_removal",
                    "Existing relationships cannot be removed or replaced by this grammar.",
                    "Retain all published relationship values and append new wikilinks.",
                )),
            }
        } else {
            report.diagnostics.push(diag(path, line, if key.starts_with("facet.") { "unsupported_facet" } else { "readonly_property" }, &format!("Property {key:?} is read-only or outside the v0 writable grammar."), "Restore this property; only name, summary and additions to existing relationship arrays are supported."));
        }
    }
    if base.body != edited.body {
        if artifact_companion(&base) {
            report.diagnostics.push(diag(
                path,
                edited.body_line,
                "artifact_companion",
                "Artifact companion content is read-only.",
                "Edit a supported ordinary record note instead.",
            ));
        } else {
            let existing: BTreeSet<_> = wikilinks(base.body)
                .into_iter()
                .map(|(s, _, _)| s)
                .collect();
            for (target, line, column) in wikilinks(edited.body) {
                if !existing.contains(&target) {
                    resolve_checked(
                        index,
                        path,
                        &target,
                        edited.body_line + line,
                        column,
                        &mut report.diagnostics,
                    );
                }
            }
            report.intents.push(Intent::MergeBody {
                record_id: id.into(),
                base_text: base.body.into(),
                my_text: edited.body.into(),
                base_version: None,
            });
        }
    }
    if report
        .diagnostics
        .iter()
        .any(|d| d.severity == Severity::Error)
    {
        report.state = FileState::ModifiedInvalid;
        report.intents.clear();
    }
    report
}

#[cfg(test)]
mod tests;
