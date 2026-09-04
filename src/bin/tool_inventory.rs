//! The tool surface's inventory, rendered from the registry rather than typed.
//!
//! `docs/tool-surface.md` carried five hand-written counts that disagreed with
//! each other and with the code (`32 enumerated · 27 shipping`, `~19 of the 31
//! tools`, `all 26 v1 tools`). A count in prose is a cache with no invalidation:
//! it is written once, at the moment a forecast is made, and nothing afterwards
//! makes it wrong out loud. This binary is the invalidation — `--check` fails
//! the build the way `tool-types` and `kind-types` already do, so the inventory
//! cannot drift from the registry without CI saying so.
//!
//! Scope is deliberately narrow: **what exists, and one line on each**. Bounds,
//! contracts and the reasoning behind them are not here. Contracts belong next
//! to the code that enforces them; reasoning belongs in the Native HQ decision
//! records the prose doc cites. Generating either would only move the cache.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use native_ce::export::LocalSnapshotSource;
use native_ce::mcp::register_membership_tool_schema;
use native_ce::mcp::render::has_renderer;
use native_ce::mcp::{
    descriptor_projection_bytes, lens_descriptor_projection, register_builtin_tools,
    register_snapshot_tool, register_surface_tools, validate_lens_profile_budgets, ExposureProfile,
    ToolRegistry,
};
use native_ce::{Error, Result};

const GENERATED_PATH: &str = "docs/tool-surface.generated.md";
const REGENERATE_COMMAND: &str = "cargo run --features dev-tools --bin tool-inventory";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Write,
    Check,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DescriptorComponents {
    envelope: usize,
    name_title: usize,
    tool_description: usize,
    schema_structure: usize,
    schema_annotations: usize,
    app_metadata: usize,
}

impl DescriptorComponents {
    fn total(self) -> usize {
        self.envelope
            + self.name_title
            + self.tool_description
            + self.schema_structure
            + self.schema_annotations
            + self.app_metadata
    }

    fn add(&mut self, other: Self) {
        self.envelope += other.envelope;
        self.name_title += other.name_title;
        self.tool_description += other.tool_description;
        self.schema_structure += other.schema_structure;
        self.schema_annotations += other.schema_annotations;
        self.app_metadata += other.app_metadata;
    }
}

#[derive(Clone, Debug)]
struct Repetition {
    kind: &'static str,
    preview: String,
    occurrences: usize,
    bytes_each: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("tool-inventory: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mode = parse_args(std::env::args().skip(1))?;
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GENERATED_PATH);
    run_at(mode, &path)
}

#[allow(dead_code)] // Called when this source is included by tool-types --check-all.
pub(crate) fn check_generated() -> Result<()> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GENERATED_PATH);
    run_at(Mode::Check, &path)
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Mode> {
    let args = args.into_iter().collect::<Vec<_>>();
    match args.as_slice() {
        [] => Ok(Mode::Write),
        [arg] if arg == "--check" => Ok(Mode::Check),
        _ => Err(Error::engine(format!(
            "unexpected arguments: {}; expected no arguments or `--check`",
            args.iter()
                .map(|arg| format!("`{arg}`"))
                .collect::<Vec<_>>()
                .join(" ")
        ))),
    }
}

fn run_at(mode: Mode, path: &Path) -> Result<()> {
    let expected = render()?;
    match mode {
        Mode::Write => write(path, &expected),
        Mode::Check => check(path, &expected),
    }
}

/// The registry the server actually serves, assembled exactly as `tool-types`
/// assembles it. The two generators must see the same surface or the inventory
/// would describe a surface no transport exposes.
fn registry() -> Result<ToolRegistry> {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry)?;
    register_surface_tools(&mut registry)?;
    register_snapshot_tool(
        &mut registry,
        std::sync::Arc::new(LocalSnapshotSource::new()),
    )?;
    register_membership_tool_schema(&mut registry)?;
    Ok(registry)
}

/// First sentence, whitespace-collapsed, pipes escaped for the table cell.
///
/// Tool descriptions are multi-line Rust string literals whose line breaks are
/// an artifact of source formatting, never of meaning. Truncating at the first
/// sentence keeps one row to one line: the rows answer *what is this*, and the
/// full description is one `tools/list` call away for anything more.
fn summary(description: &str) -> String {
    let collapsed = description.split_whitespace().collect::<Vec<_>>().join(" ");
    let end = collapsed
        .find(". ")
        .map(|index| index + 1)
        .unwrap_or(collapsed.len());
    // Escape backslashes first: an existing `\\|` must become `\\\\\\|`, or
    // Markdown consumes the first backslash while the pipe still ends the cell.
    collapsed[..end].replace('\\', "\\\\").replace('|', "\\|")
}

fn compact_len(value: &Value) -> usize {
    serde_json::to_vec(value)
        .expect("tool descriptors are JSON values")
        .len()
}

fn without_schema_annotations(value: &Value) -> Value {
    const ANNOTATIONS: &[&str] = &[
        "title",
        "description",
        "default",
        "deprecated",
        "readOnly",
        "writeOnly",
        "examples",
    ];
    match value {
        Value::Array(values) => {
            Value::Array(values.iter().map(without_schema_annotations).collect())
        }
        Value::Object(object) => Value::Object(
            object
                .iter()
                .filter(|(key, _)| !ANNOTATIONS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), without_schema_annotations(value)))
                .collect(),
        ),
        value => value.clone(),
    }
}

fn descriptor_components(descriptor: &Value) -> DescriptorComponents {
    let descriptor = descriptor.as_object().expect("descriptor object");
    let mut assembled = Map::new();
    let mut current = compact_len(&Value::Object(assembled.clone()));
    let mut components = DescriptorComponents {
        envelope: current,
        ..DescriptorComponents::default()
    };

    for (key, value) in descriptor {
        if key == "inputSchema" {
            let structural = without_schema_annotations(value);
            assembled.insert(key.clone(), structural);
            let structural_len = compact_len(&Value::Object(assembled.clone()));
            components.schema_structure += structural_len - current;
            current = structural_len;

            assembled.insert(key.clone(), value.clone());
            let full_len = compact_len(&Value::Object(assembled.clone()));
            components.schema_annotations += full_len - current;
            current = full_len;
            continue;
        }

        assembled.insert(key.clone(), value.clone());
        let next = compact_len(&Value::Object(assembled.clone()));
        let delta = next - current;
        match key.as_str() {
            "name" | "title" => components.name_title += delta,
            "description" => components.tool_description += delta,
            "_meta" => components.app_metadata += delta,
            _ => components.envelope += delta,
        }
        current = next;
    }

    assert_eq!(
        components.total(),
        compact_len(&Value::Object(descriptor.clone()))
    );
    components
}

fn projection_components(tools: &[native_ce::mcp::AdvertisedTool]) -> DescriptorComponents {
    let mut components = DescriptorComponents::default();
    for tool in tools {
        components.add(descriptor_components(&tool.descriptor));
    }
    // The exact array framing: two brackets plus one comma between descriptors.
    components.envelope += if tools.is_empty() { 2 } else { tools.len() + 1 };
    assert_eq!(components.total(), descriptor_projection_bytes(tools));
    components
}

fn write_component_row(
    output: &mut String,
    surface: &str,
    tools: &[native_ce::mcp::AdvertisedTool],
) {
    let components = projection_components(tools);
    writeln!(
        output,
        "| {surface} | {} | {} | {} | {} | {} | {} | {} | {} |",
        tools.len(),
        components.name_title,
        components.tool_description,
        components.schema_structure,
        components.schema_annotations,
        components.app_metadata,
        components.envelope,
        components.total(),
    )
    .expect("write String");
}

fn preview(value: &str) -> String {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut preview = collapsed.chars().take(96).collect::<String>();
    if collapsed.chars().count() > 96 {
        preview.push('…');
    }
    preview.replace('|', "\\|")
}

fn record_repetition(
    repetitions: &mut HashMap<String, Repetition>,
    kind: &'static str,
    serialized: String,
    display: String,
    bytes_each: usize,
) {
    let key = format!("{kind}\0{serialized}");
    repetitions
        .entry(key)
        .and_modify(|entry| entry.occurrences += 1)
        .or_insert(Repetition {
            kind,
            preview: preview(&display),
            occurrences: 1,
            bytes_each,
        });
}

fn collect_description_repetitions(value: &Value, repetitions: &mut HashMap<String, Repetition>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_description_repetitions(value, repetitions);
            }
        }
        Value::Object(object) => {
            for (key, value) in object {
                if key == "description" {
                    if let Some(description) = value.as_str().filter(|value| value.len() >= 32) {
                        let serialized = serde_json::to_string(description)
                            .expect("description strings serialize");
                        record_repetition(
                            repetitions,
                            "description",
                            serialized.clone(),
                            description.into(),
                            serialized.len(),
                        );
                    }
                }
                collect_description_repetitions(value, repetitions);
            }
        }
        _ => {}
    }
}

fn collect_fragment_repetitions(value: &Value, repetitions: &mut HashMap<String, Repetition>) {
    match value {
        Value::Array(values) => {
            for value in values {
                collect_fragment_repetitions(value, repetitions);
            }
        }
        Value::Object(object) => {
            let serialized = serde_json::to_string(value).expect("schema fragments serialize");
            if serialized.len() >= 80 {
                record_repetition(
                    repetitions,
                    "schema fragment",
                    serialized.clone(),
                    serialized.clone(),
                    serialized.len(),
                );
            }
            for value in object.values() {
                collect_fragment_repetitions(value, repetitions);
            }
        }
        _ => {}
    }
}

fn repeated_items(tools: &[native_ce::mcp::AdvertisedTool]) -> Vec<Repetition> {
    let mut repetitions = HashMap::new();
    for tool in tools {
        collect_description_repetitions(&tool.descriptor, &mut repetitions);
        if let Some(schema) = tool.descriptor.get("inputSchema") {
            collect_fragment_repetitions(schema, &mut repetitions);
        }
    }
    let mut repetitions = repetitions
        .into_values()
        .filter(|entry| entry.occurrences > 1)
        .collect::<Vec<_>>();
    repetitions.sort_by_key(|entry| {
        std::cmp::Reverse((entry.occurrences * entry.bytes_each, entry.bytes_each))
    });
    repetitions
}

fn write_repetition_table(
    output: &mut String,
    title: &str,
    tools: &[native_ce::mcp::AdvertisedTool],
) {
    writeln!(output, "### {title}\n").expect("write String");
    output.push_str("| Kind | Occurrences | Bytes each | Wire bytes | Repeated excess | Preview |\n|---|---:|---:|---:|---:|---|\n");
    for entry in repeated_items(tools).into_iter().take(15) {
        writeln!(
            output,
            "| {} | {} | {} | {} | {} | {} |",
            entry.kind,
            entry.occurrences,
            entry.bytes_each,
            entry.occurrences * entry.bytes_each,
            (entry.occurrences - 1) * entry.bytes_each,
            entry.preview,
        )
        .expect("write String");
    }
    output.push('\n');
}

fn render() -> Result<Vec<u8>> {
    let registry = registry()?;
    registry.validate_profile_budgets()?;
    validate_lens_profile_budgets(&registry)?;
    let tools = registry.specs().collect::<Vec<_>>();
    let ordinary_focused = registry.descriptor_projection(ExposureProfile::Focused);
    let ordinary_complete = registry.descriptor_projection(ExposureProfile::Complete);
    let lens_focused = lens_descriptor_projection(&registry, ExposureProfile::Focused)?;
    let lens_complete = lens_descriptor_projection(&registry, ExposureProfile::Complete)?;
    let ordinary_focused_bytes = ordinary_focused
        .iter()
        .map(|tool| (tool.name.as_str(), tool.descriptor_bytes()))
        .collect::<HashMap<_, _>>();
    let ordinary_complete_bytes = ordinary_complete
        .iter()
        .map(|tool| (tool.name.as_str(), tool.descriptor_bytes()))
        .collect::<HashMap<_, _>>();

    let mut output =
        String::from(
            "<!-- Generated by `cargo run --features dev-tools --bin tool-inventory`; do not edit. -->\n\n",
        );
    output.push_str("# native-ce legacy direct-tool inventory\n\n");
    let rendered = tools.iter().filter(|tool| has_renderer(&tool.name)).count();
    writeln!(output, "This inventory covers only the legacy transport that advertises each registered operation as a direct tool. It does not describe the contract-derived executor catalogue.\n\n**{} tools** are registered in the legacy complete surface; {rendered} have a text renderer. The legacy default complete profile advertises all of them. Focused and custom filtering are intentionally lossy: hidden tools can be undiscoverable and visible workflows can lose dependencies. Filtering does not change exact-name dispatch or authorization.\n", tools.len()).expect("write String");
    for profile in ExposureProfile::ALL {
        writeln!(
            output,
            "- **{}**: {} tools, {} compact UTF-8 bytes",
            profile.as_str(),
            registry.specs_for_profile(profile).count(),
            registry.descriptor_array_bytes(profile),
        )
        .expect("write String");
    }
    output.push_str("\nTotals are the exact compact JSON `result.tools` arrays. Per-tool bytes below are descriptor deltas before array commas/brackets.\n\n");
    output.push_str("## Descriptor byte composition\n\nSchema annotations are the recursively removed JSON Schema annotation keywords `title`, `description`, `default`, `deprecated`, `readOnly`, `writeOnly`, and `examples`. Structure is the exact remaining `inputSchema`; envelope includes JSON object/array framing and any uncategorized top-level fields. Every row sums exactly to the production compact descriptor array.\n\n");
    output.push_str("| Surface | Tools | Name/title | Tool descriptions | Schema structure | Schema annotations | App metadata | Envelope | Total |\n|---|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    write_component_row(&mut output, "legacy ordinary focused", &ordinary_focused);
    write_component_row(&mut output, "legacy ordinary complete", &ordinary_complete);
    write_component_row(&mut output, "legacy lens focused", &lens_focused);
    write_component_row(&mut output, "legacy lens complete", &lens_complete);
    output.push_str("\n## Largest exact repetitions\n\n`Wire bytes` counts every serialized occurrence; `Repeated excess` subtracts one canonical occurrence. Schema fragments are same-document object fragments of at least 80 compact bytes and may overlap larger repeated parents, so this is a diagnostic ranking rather than an additive savings forecast.\n\n");
    write_repetition_table(&mut output, "Legacy ordinary complete", &ordinary_complete);
    write_repetition_table(
        &mut output,
        "Legacy federated lens complete",
        &lens_complete,
    );

    output.push_str("## Per-tool inventory\n\n");
    output.push_str("| Tool | Family | Admission | Focused | Complete bytes | Focused bytes | Renders | Summary |\n|---|---|---|---:|---:|---:|---|---|\n");
    for tool in &tools {
        writeln!(
            output,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} |",
            tool.name,
            tool.exposure.family.as_str(),
            tool.exposure.admission_reason.as_str(),
            if tool.exposure.focused { "yes" } else { "—" },
            ordinary_complete_bytes[tool.name.as_str()],
            ordinary_focused_bytes
                .get(tool.name.as_str())
                .map(usize::to_string)
                .unwrap_or_else(|| "—".to_string()),
            if has_renderer(&tool.name) {
                "yes"
            } else {
                "—"
            },
            summary(&tool.description)
        )
        .expect("write String");
    }

    output.push_str("\n## Federated lens projection\n\nLens discovery overlays composite references and routing arguments, then adds the explicitly classified lens-only `materialize_record` capability. These are the actual lens `result.tools` bytes.\n\n");
    for (profile, projection) in [
        (ExposureProfile::Focused, &lens_focused),
        (ExposureProfile::Complete, &lens_complete),
    ] {
        writeln!(
            output,
            "- **{}**: {} tools, {} compact UTF-8 bytes",
            profile.as_str(),
            projection.len(),
            descriptor_projection_bytes(projection),
        )
        .expect("write String");
    }
    let focused_bytes = lens_focused
        .iter()
        .map(|tool| (tool.name.as_str(), tool.descriptor_bytes()))
        .collect::<HashMap<_, _>>();
    output.push_str("\n| Tool | Family | Admission | Focused | Complete bytes | Focused bytes |\n|---|---|---|---:|---:|---:|\n");
    for tool in &lens_complete {
        writeln!(
            output,
            "| `{}` | {} | {} | {} | {} | {} |",
            tool.name,
            tool.exposure.family.as_str(),
            tool.exposure.admission_reason.as_str(),
            if tool.exposure.focused { "yes" } else { "—" },
            tool.descriptor_bytes(),
            focused_bytes
                .get(tool.name.as_str())
                .map(usize::to_string)
                .unwrap_or_else(|| "—".into()),
        )
        .expect("write String");
    }

    Ok(output.into_bytes())
}

fn write(path: &Path, expected: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, expected)?;
    Ok(())
}

fn check(path: &Path, expected: &[u8]) -> Result<()> {
    let actual = match fs::read(path) {
        Ok(actual) => actual,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(drift_error());
        }
        Err(error) => return Err(error.into()),
    };
    if actual != expected {
        return Err(drift_error());
    }
    Ok(())
}

fn drift_error() -> Error {
    Error::engine(format!(
        "generated tool inventory is stale or missing: {GENERATED_PATH}\n\
         run `{REGENERATE_COMMAND}` to regenerate it, then commit {GENERATED_PATH}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_collapses_source_line_breaks() {
        assert_eq!(
            summary("Declare this run's current\n         intent. Re-declaring is safe."),
            "Declare this run's current intent."
        );
    }

    #[test]
    fn summary_keeps_a_single_sentence_whole() {
        assert_eq!(summary("One sentence only"), "One sentence only");
    }

    #[test]
    fn summary_escapes_table_pipes() {
        assert_eq!(summary("Reads a | b"), "Reads a \\| b");
    }

    #[test]
    fn summary_escapes_backslashes_before_table_pipes() {
        assert_eq!(summary(r"Reads a \| b"), r"Reads a \\\| b");
    }

    #[test]
    fn parse_args_accepts_check_and_nothing_else() {
        assert_eq!(parse_args([]).unwrap(), Mode::Write);
        assert_eq!(parse_args(["--check".to_string()]).unwrap(), Mode::Check);
        assert!(parse_args(["--wat".to_string()]).is_err());
    }

    #[test]
    fn descriptor_components_are_exact_and_separate_schema_annotations() {
        let descriptor = serde_json::json!({
            "name": "example",
            "description": "Top-level tool description",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "Field guidance",
                        "default": "example"
                    }
                },
                "required": ["value"],
                "additionalProperties": false
            },
            "_meta": { "ui/resourceUri": "ui://native-ce/example.html" }
        });
        let components = descriptor_components(&descriptor);

        assert_eq!(components.total(), compact_len(&descriptor));
        assert!(components.name_title > 0);
        assert!(components.tool_description > 0);
        assert!(components.schema_structure > 0);
        assert!(components.schema_annotations > 0);
        assert!(components.app_metadata > 0);
        assert!(components.envelope > 0);
    }

    #[test]
    fn repeated_description_ranking_counts_exact_serialized_values() {
        let description = "The same sufficiently long field guidance appears twice.";
        let descriptor = serde_json::json!({
            "properties": {
                "one": { "type": "string", "description": description },
                "two": { "type": "string", "description": description }
            }
        });
        let mut repetitions = HashMap::new();
        collect_description_repetitions(&descriptor, &mut repetitions);
        let repeated = repetitions
            .into_values()
            .find(|entry| entry.occurrences == 2)
            .expect("repeated description");

        assert_eq!(repeated.kind, "description");
        assert_eq!(
            repeated.bytes_each,
            serde_json::to_string(description).unwrap().len()
        );
    }

    #[test]
    fn check_reports_drift_with_the_regenerate_command() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tool-surface.generated.md");
        let error = run_at(Mode::Check, &path).expect_err("missing file is drift");
        assert!(error.to_string().contains(REGENERATE_COMMAND));

        fs::write(&path, b"stale").expect("overwrite");
        assert!(run_at(Mode::Check, &path).is_err());
    }

    #[test]
    fn write_is_reproducible_and_immediately_passes_check() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join("tool-surface.generated.md");

        run_at(Mode::Write, &path).expect("first write");
        let first = fs::read(&path).expect("read first output");
        run_at(Mode::Write, &path).expect("second write");
        let second = fs::read(&path).expect("read second output");

        assert_eq!(first, second);
        run_at(Mode::Check, &path).expect("freshly written output is current");
    }

    #[test]
    fn committed_inventory_matches_the_current_registry() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(GENERATED_PATH);
        run_at(Mode::Check, &path).expect("regenerate and commit the tool inventory");
    }

    /// The inventory exists to stop counts drifting, so the count itself is the
    /// one thing worth asserting against the registry rather than a fixture.
    #[test]
    fn rendered_count_matches_the_registry() {
        let expected = registry().expect("registry").specs().count();
        let rendered = String::from_utf8(render().expect("render")).expect("utf8");
        assert!(rendered.contains(&format!("**{expected} tools**")));
        assert!(rendered.contains("| `set_intent` |"));
    }

    #[test]
    fn render_preserves_the_registry_surface_order() {
        let registry = registry().expect("registry");
        let expected = registry
            .specs()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>();
        let rendered = String::from_utf8(render().expect("render")).expect("utf8");
        let actual = rendered
            .lines()
            .take_while(|line| *line != "## Federated lens projection")
            .filter_map(|line| line.strip_prefix("| `"))
            .filter_map(|line| line.split_once("` |"))
            .map(|(name, _)| name)
            .collect::<Vec<_>>();

        assert_eq!(actual, expected);
    }

    #[test]
    fn render_reports_every_profile_and_the_lens_only_capability() {
        let rendered = String::from_utf8(render().expect("render")).expect("utf8");
        // Both profiles are asserted with their own counts. The ordinary and
        // lens surfaces differ by exactly the lens-only tool, so repeating one
        // pair of strings for both sections — as this test used to — passes on
        // whichever section happens to match and checks neither deliberately.
        assert!(rendered.contains("- **focused**: 27 tools,"));
        assert!(rendered.contains("- **complete**: 74 tools,"));
        assert!(rendered.contains("| `manage_memberships` | identity | atomicity | — |"));
        assert!(rendered.contains("## Federated lens projection"));
        assert!(rendered.contains("- **focused**: 28 tools,"));
        assert!(rendered.contains("- **complete**: 75 tools,"));
        assert!(rendered.contains("| `materialize_record` | identity | atomicity | yes |"));
    }
}
