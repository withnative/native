use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::schema::{change_summary_output_schema, ChangeSummary, ChangeSummaryRendererIdentity};
use crate::error::{Error, Result};

pub const CHANGE_SUMMARY_RENDERER_ID: &str = "native.change-summary.markdown.renderer";
pub const CHANGE_SUMMARY_RENDERER_REVISION: &str = "1";
pub const CHANGE_SUMMARY_RENDERER_SHA256: &str =
    "110924767e9186810bb4bc9a08a8807ce78dfc6f7e7e24ffe9d8f075284b2c0d";
pub const CHANGE_SUMMARY_MAX_RENDERED_CHARACTERS: usize = 131_072;
pub const CHANGE_SUMMARY_MAX_RENDERED_BYTES: usize = 131_072;

/// Normative renderer description. Its byte digest is pinned by the recipe.
pub const CHANGE_SUMMARY_RENDERER_SPEC: &str = "native.change-summary.markdown.renderer/v1\n\
input: semantically validated and canonicalized native.change-summary.v1\n\
unicode: Unicode 15.1 White_Space set U+0009..U+000D,U+0020,U+0085,U+00A0,U+1680,U+2000..U+200A,U+2028,U+2029,U+202F,U+205F,U+3000\n\
normalization: collapse each maximal White_Space run to one U+0020 and remove leading/trailing White_Space\n\
escaping: prefix U+005C before each U+005C,U+0060,U+002A,U+005F,U+005B,U+005D,U+003C,U+003E,U+0023; preserve every other scalar\n\
template: '# {title}\\n\\n{overview}\\n\\n## Change\\n\\n### {heading}\\n\\n{summary}\\n\\n## Why it matters\\n\\n{materiality}\\n\\n### Materiality references\\n\\n{materiality_rows}\\n\\n## Suggested links\\n\\n### WorkItems\\n\\n{work_item_rows}\\n\\n### Outcomes\\n\\n{outcome_rows}\\n'\n\
materiality row: '- {record_id} — {rationale}\\n'\n\
suggestion row: '- {record_id} via {relationship} — {rationale}\\n'\n\
empty rows: '- None.\\n'\n\
ordering: consume already canonical array order without reordering\n\
line endings: U+000A only; exactly one terminal U+000A\n\
limits: at most 131072 Unicode scalar values and 131072 UTF-8 bytes after normalization and escaping\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryRenderedOutput {
    pub body: String,
    pub renderer: ChangeSummaryRendererIdentity,
}

pub fn change_summary_renderer_sha256() -> String {
    let digest = format!(
        "{:x}",
        Sha256::digest(CHANGE_SUMMARY_RENDERER_SPEC.as_bytes())
    );
    debug_assert_eq!(digest, CHANGE_SUMMARY_RENDERER_SHA256);
    digest
}

pub fn change_summary_renderer_identity() -> ChangeSummaryRendererIdentity {
    ChangeSummaryRendererIdentity {
        id: CHANGE_SUMMARY_RENDERER_ID.into(),
        revision: CHANGE_SUMMARY_RENDERER_REVISION.into(),
        spec_sha256: CHANGE_SUMMARY_RENDERER_SHA256.into(),
    }
}

fn unicode_whitespace_v15_1(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000d}'
            | '\u{0020}'
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

fn prose(value: &str) -> String {
    let mut collapsed = String::with_capacity(value.len());
    let mut pending_space = false;
    for character in value.chars() {
        if unicode_whitespace_v15_1(character) {
            pending_space = !collapsed.is_empty();
        } else {
            if pending_space {
                collapsed.push(' ');
                pending_space = false;
            }
            collapsed.push(character);
        }
    }
    let mut escaped = String::with_capacity(collapsed.len());
    for character in collapsed.chars() {
        if matches!(
            character,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '#'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

/// Render an already validated result. Validation remains a separate operation
/// because it needs the authoritative context resolver; rendering is pure.
pub fn render_change_summary(summary: &ChangeSummary) -> Result<String> {
    let [item] = summary.items.as_slice() else {
        return Err(Error::engine(
            "change-summary renderer requires exactly one validated item",
        ));
    };
    if summary.renderer != change_summary_renderer_identity() {
        return Err(Error::engine(
            "change-summary renderer identity does not match this implementation",
        ));
    }
    let mut output = String::new();
    writeln!(output, "# {}\n", prose(&summary.title)).expect("String writes cannot fail");
    writeln!(output, "{}\n", prose(&summary.overview)).expect("String writes cannot fail");
    output.push_str("## Change\n\n");
    writeln!(output, "### {}\n", prose(&item.heading)).expect("String writes cannot fail");
    writeln!(output, "{}\n", prose(&item.summary)).expect("String writes cannot fail");
    output.push_str("## Why it matters\n\n");
    writeln!(output, "{}\n", prose(&item.materiality.summary)).expect("String writes cannot fail");
    output.push_str("### Materiality references\n\n");
    if item.materiality.references.is_empty() {
        output.push_str("- None.\n");
    } else {
        for reference in &item.materiality.references {
            writeln!(
                output,
                "- {} — {}",
                prose(&reference.record_id),
                prose(&reference.rationale)
            )
            .expect("String writes cannot fail");
        }
    }
    output.push_str("\n## Suggested links\n\n### WorkItems\n\n");
    if item.link_suggestions.work_items.is_empty() {
        output.push_str("- None.\n");
    } else {
        for suggestion in &item.link_suggestions.work_items {
            writeln!(
                output,
                "- {} via {} — {}",
                prose(&suggestion.record_id),
                prose(&suggestion.relationship),
                prose(&suggestion.rationale)
            )
            .expect("String writes cannot fail");
        }
    }
    output.push_str("\n### Outcomes\n\n");
    if item.link_suggestions.outcomes.is_empty() {
        output.push_str("- None.\n");
    } else {
        for suggestion in &item.link_suggestions.outcomes {
            writeln!(
                output,
                "- {} via {} — {}",
                prose(&suggestion.record_id),
                prose(&suggestion.relationship),
                prose(&suggestion.rationale)
            )
            .expect("String writes cannot fail");
        }
    }
    if output.chars().count() > CHANGE_SUMMARY_MAX_RENDERED_CHARACTERS
        || output.len() > CHANGE_SUMMARY_MAX_RENDERED_BYTES
    {
        return Err(Error::engine(
            "change-summary rendered output exceeds its character or UTF-8 byte contract",
        ));
    }
    Ok(output)
}

pub fn render_change_summary_output(
    summary: &ChangeSummary,
) -> Result<ChangeSummaryRenderedOutput> {
    let output = ChangeSummaryRenderedOutput {
        body: render_change_summary(summary)?,
        renderer: change_summary_renderer_identity(),
    };
    let value = serde_json::to_value(&output)?;
    let validator = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(&change_summary_output_schema())
        .map_err(|_| Error::engine("change-summary output contract is invalid"))?;
    validator.validate(&value).map_err(|_| {
        Error::engine("change-summary rendered output does not satisfy its pinned contract")
    })?;
    Ok(output)
}
