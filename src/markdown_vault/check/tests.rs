use super::*;

fn note(fields: &str, body: &str) -> String {
    format!("---\n\"id\": \"record-one\"\n\"name\": \"Original\"\n{fields}---\n\n{body}\n\n<!-- native:generated links -->\n## Links\n")
}
fn index(fresh: bool) -> LinkIndex {
    LinkIndex {
        fresh,
        entries: vec![
            LinkTarget {
                record_id: "target-one".into(),
                path: "Root/Target.md".into(),
                name: "Target".into(),
            },
            LinkTarget {
                record_id: "target-two".into(),
                path: "Elsewhere/Target.md".into(),
                name: "Target".into(),
            },
        ],
    }
}
#[test]
fn unchanged_is_noop_even_for_unparsed_aggregate() {
    let r = check_file("Messages/a.md", "unparsed", "unparsed", &index(true));
    assert_eq!(r.state, FileState::Unchanged);
    assert!(r.intents.is_empty());
    assert!(r.diagnostics.is_empty());
}
#[test]
fn body_intent_retains_exact_base_and_no_invented_record_version() {
    let base = note("", "old\n\nparagraph\n");
    let edit = note("", "new\n\nparagraph\n");
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert!(r.diagnostics.is_empty());
    assert!(
        matches!(&r.intents[..], [Intent::MergeBody { base_text, my_text, base_version: None, .. }] if base_text == "old\n\nparagraph\n" && my_text == "new\n\nparagraph\n")
    );
}
#[test]
fn name_and_summary_are_typed_scalar_intents() {
    let base = note("", "body");
    let edit = note("summary: \"short\"\n", "body").replace("\"Original\"", "New title");
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert_eq!(r.intents.len(), 2);
    assert!(matches!(&r.intents[0], Intent::SetName { name, .. } if name == "New title"));
    assert!(matches!(&r.intents[1], Intent::SetSummary { summary, .. } if summary == "short"));
}
#[test]
fn readonly_changes_invalidate_all_other_intents() {
    let base = note("", "body");
    let edit = note("", "edited").replace("record-one", "another-id");
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert_eq!(r.state, FileState::ModifiedInvalid);
    assert!(r.intents.is_empty());
    assert_eq!(r.diagnostics[0].code, "readonly_property");
}
#[test]
fn duplicate_and_malformed_frontmatter_are_located() {
    let base = note("", "body");
    for (field, code) in [
        ("name: second\n", "duplicate_key"),
        ("summary: [broken\n", "frontmatter"),
        ("summary: |\n  block\n", "frontmatter"),
    ] {
        let r = check_file("Root/A.md", &base, &note(field, "body"), &index(true));
        assert_eq!(r.diagnostics[0].line, 4);
        assert_eq!(r.diagnostics[0].path, "Root/A.md");
        assert_eq!(r.diagnostics[0].code, code);
        assert!(!r.diagnostics[0].next_step.is_empty());
        assert!(r.intents.is_empty());
    }
}
#[test]
fn generated_suffix_is_readonly() {
    let base = note("", "body");
    let edit = base.replace("## Links", "## Mine");
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert_eq!(r.diagnostics[0].code, "generated_section");
    assert!(r.intents.is_empty());
}
#[test]
fn new_wikilinks_resolve_paths_and_reject_ambiguity() {
    let base = note("", "body");
    let good = check_file(
        "Root/A.md",
        &base,
        &note("", "[[Root/Target|display]]"),
        &index(true),
    );
    assert!(good.diagnostics.is_empty());
    assert_eq!(good.intents.len(), 1); // inline links never infer an AddLink
    let ambiguous = check_file("Root/A.md", &base, &note("", "[[Target]]"), &index(true));
    assert_eq!(ambiguous.diagnostics[0].code, "ambiguous_link");
    assert!(ambiguous.intents.is_empty());
    let missing = check_file("Root/A.md", &base, &note("", "[[Missing]]"), &index(true));
    assert_eq!(missing.diagnostics[0].code, "unresolved_link");
    assert_eq!(missing.diagnostics[0].severity, Severity::Error);
}
#[test]
fn stale_catalog_warns_and_retains_body_preview() {
    let r = check_file(
        "A.md",
        &note("", "body"),
        &note("", "[[Missing]]"),
        &index(false),
    );
    assert_eq!(r.diagnostics[0].severity, Severity::Warning);
    assert!(matches!(&r.intents[..], [Intent::MergeBody { .. }]));
}
#[test]
fn existing_dangling_body_links_do_not_poison_edits() {
    let r = check_file(
        "A.md",
        &note("", "[[Missing]]"),
        &note("", "[[Missing]]\nmore"),
        &index(true),
    );
    assert!(r.diagnostics.is_empty());
    assert_eq!(r.intents.len(), 1);
}
#[test]
fn unicode_locations_are_character_columns() {
    let r = check_file(
        "A.md",
        &note("", "old"),
        &note("", "é🎉 [[Missing]]"),
        &index(true),
    );
    assert_eq!(r.diagnostics[0].line, 6);
    assert_eq!(r.diagnostics[0].column, 4);
}
#[test]
fn relationship_addition_is_typed_and_removal_is_refused() {
    let fields = "\"relates_to\": [\"[[Root/Target|Target]]\"]\n";
    let mut base = note(fields, "body");
    base.push_str("- relates_to: [[Root/Target|Target]]\n");
    let edit = base.replace(
        "[\"[[Root/Target|Target]]\"]",
        "[\"[[Root/Target|Target]]\",\"[[Elsewhere/Target]]\"]",
    );
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
    assert!(
        matches!(&r.intents[..], [Intent::AddLink { target_id, relationship, .. }] if target_id == "target-two" && relationship == "relates_to")
    );
    let removed = base.replace("[\"[[Root/Target|Target]]\"]", "[]");
    assert_eq!(
        check_file("Root/A.md", &base, &removed, &index(true)).diagnostics[0].code,
        "relationship_removal"
    );
}
#[test]
fn arbitrary_metadata_link_arrays_are_not_relationship_authority() {
    let base = note("\"custom\": [\"[[Root/Target]]\"]\n", "body");
    let edit = base.replace(
        "[\"[[Root/Target]]\"]",
        "[\"[[Root/Target]]\",\"[[Elsewhere/Target]]\"]",
    );
    let r = check_file("A.md", &base, &edit, &index(true));
    assert_eq!(r.diagnostics[0].code, "readonly_property");
}
#[test]
fn unsupported_facets_are_explicit() {
    let base = note("\"facet.status\": \"open\"\n", "body");
    let edit = base.replace("\"open\"", "\"closed\"");
    let r = check_file("A.md", &base, &edit, &index(true));
    assert_eq!(r.diagnostics[0].code, "unsupported_facet");
}
#[test]
fn freshly_rendered_projection_has_zero_intents() {
    use crate::markdown_vault::{SourceRecord, SourceSnapshot};
    let mut source = SourceSnapshot::default();
    source.records.insert(
        "native:root".into(),
        SourceRecord {
            id: "native:root".into(),
            name: Some("Root".into()),
            record_type: "Collection".into(),
            kind: Some("folder".into()),
            ..Default::default()
        },
    );
    source.records.insert(
        "record-one".into(),
        SourceRecord {
            id: "record-one".into(),
            name: Some("Original".into()),
            record_type: "Document".into(),
            body: Some("body\n".into()),
            ..Default::default()
        },
    );
    let rendered = crate::markdown_vault::render::render(&source, &BTreeMap::new()).unwrap();
    for (path, output) in rendered.files {
        let text = String::from_utf8(output.bytes).unwrap();
        let r = check_file(&path, &text, &text, &index(true));
        assert!(r.intents.is_empty());
        assert!(r.diagnostics.is_empty());
    }
}
#[test]
fn unchanged_ordinary_note_is_parsed_and_identified() {
    let text = note("", "body");
    let r = check_file("A.md", &text, &text, &index(true));
    assert_eq!(r.record_id.as_deref(), Some("record-one"));
    assert_eq!(r.state, FileState::Unchanged);
    let malformed = text.replace("\"name\": \"Original\"", "\"name\": [broken");
    assert_eq!(
        check_file("A.md", &malformed, &malformed, &index(true)).state,
        FileState::ModifiedInvalid
    );
}
#[test]
fn code_examples_and_escaped_links_are_literal() {
    let body = "```md\n[[Missing]]\n```\n`[[Also missing]]`\n\\[[Escaped]]";
    let r = check_file("A.md", &note("", "old"), &note("", body), &index(true));
    assert!(r.diagnostics.is_empty(), "{:?}", r.diagnostics);
    assert_eq!(r.intents.len(), 1);
}
#[test]
fn relationship_prefix_in_actual_name_is_preserved() {
    let fields = "\"relationship:custom\": [\"[[Root/Target|Target]]\"]\n";
    let mut base = note(fields, "body");
    base.push_str("- relationship:custom: [[Root/Target|Target]]\n");
    let edit = base.replace(
        "[\"[[Root/Target|Target]]\"]",
        "[\"[[Root/Target|Target]]\",\"[[Elsewhere/Target]]\"]",
    );
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert!(
        matches!(&r.intents[..], [Intent::AddLink { relationship, .. }] if relationship == "relationship:custom")
    );
}
#[test]
fn repeated_markdown_suffixes_resolve_to_distinct_explicit_paths() {
    let catalog = LinkIndex {
        fresh: true,
        entries: vec![
            LinkTarget {
                record_id: "single-suffix".into(),
                path: "Root/Foo.md".into(),
                name: "Foo".into(),
            },
            LinkTarget {
                record_id: "double-suffix".into(),
                path: "Root/Foo.md.md".into(),
                name: "Foo.md".into(),
            },
        ],
    };
    assert_eq!(
        resolve(&catalog, "Root/A.md", "Root/Foo.md"),
        BTreeSet::from(["single-suffix".into()])
    );
    assert_eq!(
        resolve(&catalog, "Root/A.md", "Root/Foo.md.md"),
        BTreeSet::from(["double-suffix".into()])
    );
}
#[test]
fn malformed_relationship_wikilinks_do_not_produce_link_intents() {
    let fields = "\"relates_to\": [\"[[Root/Target|Target]]\"]\n";
    let mut base = note(fields, "body");
    base.push_str("- relates_to: [[Root/Target|Target]]\n");
    for malformed in [
        "[[Elsewhere/Target]] trailing]]",
        "[[Elsewhere/[Target]]]",
        "[[Elsewhere/Target\n]]",
    ] {
        let edit = base.replace(
            "[\"[[Root/Target|Target]]\"]",
            &serde_json::to_string(&vec!["[[Root/Target|Target]]", malformed]).unwrap(),
        );
        let r = check_file("Root/A.md", &base, &edit, &index(true));
        assert_eq!(r.state, FileState::ModifiedInvalid, "{malformed}");
        assert!(r.intents.is_empty(), "{malformed}");
        assert_eq!(r.diagnostics[0].code, "invalid_relationship", "{malformed}");
    }
}
#[test]
fn authored_open_artifact_link_does_not_make_a_note_readonly() {
    let base = note("", "[Open artifact](<example.html>)");
    let edit = note("", "[Open artifact](<example.html>)\nAuthored text");
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert!(r.diagnostics.is_empty());
    assert!(matches!(&r.intents[..], [Intent::MergeBody { .. }]));
}
#[test]
fn artifact_runtime_metadata_protects_companion_body() {
    for runtime_key in ["facet.runtime", "facet.artifact_runtime"] {
        let fields = format!("\"{runtime_key}\": \"native.html.v1\"\n");
        let base = note(&fields, "[Open artifact](<example.html>)");
        let edit = note(&fields, "edited");
        let r = check_file("Root/A.md", &base, &edit, &index(true));
        assert_eq!(r.diagnostics[0].code, "artifact_companion");
        assert!(r.intents.is_empty());
    }
}
#[test]
fn relationship_anchor_additions_never_target_the_parent_record() {
    let fields = "\"relates_to\": [\"[[Root/Target|Target]]\"]\n";
    let mut base = note(fields, "body");
    base.push_str("- relates_to: [[Root/Target|Target]]\n");
    let edit = base.replace(
        "[\"[[Root/Target|Target]]\"]",
        "[\"[[Root/Target|Target]]\",\"[[Elsewhere/Target#comment-id|Comment]]\"]",
    );
    let r = check_file("Root/A.md", &base, &edit, &index(true));
    assert_eq!(r.diagnostics[0].code, "unsupported_relationship_anchor");
    assert_eq!(r.state, FileState::ModifiedInvalid);
    assert!(r.intents.is_empty());
    // An existing anchor is retained as published; an unrelated body edit is safe.
    let existing = base.replace("Root/Target|Target", "Root/Target#existing-comment|Comment");
    let edited_body = existing.replace("\n\nbody\n\n", "\n\nnew body\n\n");
    let retained = check_file("Root/A.md", &existing, &edited_body, &index(true));
    assert!(retained.diagnostics.is_empty());
    assert!(matches!(&retained.intents[..], [Intent::MergeBody { .. }]));
}
