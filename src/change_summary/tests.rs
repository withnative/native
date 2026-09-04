use std::collections::HashMap;

use serde_json::{json, Value};

use super::*;
use crate::error::Result;

#[derive(Clone, Default)]
struct FixtureResolver {
    events: HashMap<String, ChangeSummarySourceEvent>,
    records: HashMap<String, ChangeSummaryContextRecord>,
}

impl ChangeSummaryResolver for FixtureResolver {
    fn source_event(&self, event_id: &str) -> Result<Option<ChangeSummarySourceEvent>> {
        Ok(self.events.get(event_id).cloned())
    }

    fn context_record(&self, record_id: &str) -> Result<Option<ChangeSummaryContextRecord>> {
        Ok(self.records.get(record_id).cloned())
    }
}

fn resolver() -> FixtureResolver {
    let events = [
        ("event:one", 10, "scout-chair-000001", '1', "source:one"),
        ("event:two", 20, "scout-chair-000002", '2', "source:two"),
        ("event:three", 30, "scout-chair-000003", '3', "source:three"),
    ]
    .into_iter()
    .map(|(event_id, event_seq, run_key, digest, record_id)| {
        (
            event_id.into(),
            ChangeSummarySourceEvent {
                event_id: event_id.into(),
                event_seq,
                run_key: run_key.into(),
                sha256: digest.to_string().repeat(64),
                record_id: record_id.into(),
                record_type: "Document".into(),
                record_kind: "note".into(),
                record_is_live: true,
                audience_can_view: true,
            },
        )
    })
    .collect();
    let records = [
        (
            "context:decision",
            "Resolution",
            "decision",
            true,
            "body:decision",
            '4',
        ),
        (
            "outcome:one",
            "Outcome",
            "impact",
            true,
            "body:outcome",
            '5',
        ),
        ("work:one", "WorkItem", "task", false, "body:work", '6'),
    ]
    .into_iter()
    .map(
        |(record_id, record_type, record_kind, is_realised, body_event, digest)| {
            (
                record_id.into(),
                ChangeSummaryContextRecord {
                    record_id: record_id.into(),
                    record_type: record_type.into(),
                    record_kind: record_kind.into(),
                    record_is_live: true,
                    audience_can_view: true,
                    is_realised,
                    current_body_event_id: body_event.into(),
                    current_body_sha256: digest.to_string().repeat(64),
                },
            )
        },
    )
    .collect();
    FixtureResolver { events, records }
}

fn query() -> ChangeSummaryQuery {
    ChangeSummaryQuery {
        selection: ChangeSummarySelection {
            schema: CHANGE_SUMMARY_SELECTION_SCHEMA.into(),
            source_event_ids: vec!["event:one".into(), "event:two".into(), "event:three".into()],
        },
        scope: ChangeSummaryScope {
            schema: CHANGE_SUMMARY_SCOPE_SCHEMA.into(),
            context_record_ids: vec![
                "context:decision".into(),
                "outcome:one".into(),
                "work:one".into(),
            ],
        },
    }
}

fn manifest() -> ChangeSummaryInputManifest {
    let fixture = resolver();
    let query = query();
    let mut inputs = Vec::new();
    for (ordinal, event_id) in query.selection.source_event_ids.iter().enumerate() {
        let event = fixture.events.get(event_id).unwrap();
        inputs.push(ChangeSummaryManifestInput {
            ordinal: ordinal as u32,
            input_role: "source".into(),
            input_kind: "content_event".into(),
            portable_id: event.event_id.clone(),
            sha256: event.sha256.clone(),
            record_id: event.record_id.clone(),
        });
    }
    for (offset, record_id) in query.scope.context_record_ids.iter().enumerate() {
        let record = fixture.records.get(record_id).unwrap();
        inputs.push(ChangeSummaryManifestInput {
            ordinal: (offset + 3) as u32,
            input_role: "context".into(),
            input_kind: "record_body".into(),
            portable_id: record.current_body_event_id.clone(),
            sha256: record.current_body_sha256.clone(),
            record_id: record.record_id.clone(),
        });
    }
    ChangeSummaryInputManifest { inputs }
}

fn citation(input: &ChangeSummaryManifestInput) -> Value {
    json!({
        "ordinal":input.ordinal,
        "input_role":input.input_role,
        "input_kind":input.input_kind,
        "portable_id":input.portable_id,
        "sha256":input.sha256,
    })
}

fn result_value() -> Value {
    let citations = manifest().inputs.iter().map(citation).collect::<Vec<_>>();
    json!({
        "schema":"native.change-summary.v1",
        "effective_work_interval":{
            "started_at":"2026-08-01T09:00:00.000Z",
            "ended_at":"2026-08-03T17:30:00.000Z"
        },
        "renderer":{
            "id":CHANGE_SUMMARY_RENDERER_ID,
            "revision":CHANGE_SUMMARY_RENDERER_REVISION,
            "spec_sha256":CHANGE_SUMMARY_RENDERER_SHA256
        },
        "source_groups":[
            {"run_key":"scout-chair-000001","source_ordinal":0},
            {"run_key":"scout-chair-000002","source_ordinal":1},
            {"run_key":"scout-chair-000003","source_ordinal":2}
        ],
        "title":"A safer release path",
        "overview":"Three implementation runs converged on one shippable result.",
        "items":[{
            "heading":"Gate release on explicit confirmation",
            "summary":"The draft, confirmation, and query paths now share one traceable contract.",
            "citations":citations,
            "materiality":{
                "summary":"This keeps semantic shipping judgement explicit while preserving the source evidence.",
                "references":[{
                    "record_id":"context:decision",
                    "rationale":"Records the decision that confirmation is explicit."
                }]
            },
            "link_suggestions":{
                "work_items":[{
                    "record_id":"work:one",
                    "relationship":"implements",
                    "rationale":"This work item owns the implementation."
                }],
                "outcomes":[{
                    "record_id":"outcome:one",
                    "relationship":"relates_to",
                    "rationale":"The change contributes to this realised impact."
                }]
            }
        }]
    })
}

fn validate(value: &Value, resolver: &FixtureResolver) -> Result<ChangeSummary> {
    decode_and_validate_change_summary(value, &query(), &manifest(), resolver)
}

#[test]
fn exact_result_query_manifest_and_output_contracts_validate() {
    let resolver = resolver();
    validate_change_summary_query(&query(), &resolver).unwrap();
    validate_change_summary_manifest(&query(), &manifest(), &resolver).unwrap();
    let result = validate(&result_value(), &resolver).unwrap();
    assert_eq!(result.items[0].citations.len(), 6);
    assert_eq!(result.source_groups.len(), 3);
    let rendered = render_change_summary_output(&result).unwrap();
    assert_eq!(rendered.renderer, change_summary_renderer_identity());
}

#[test]
fn canonicalization_sorts_structural_sets_and_pins_bytes_without_changing_prose() {
    let resolver = resolver();
    let mut scrambled = result_value();
    scrambled["source_groups"].as_array_mut().unwrap().reverse();
    scrambled["items"][0]["citations"]
        .as_array_mut()
        .unwrap()
        .reverse();
    let original_summary = scrambled["items"][0]["summary"].clone();
    let canonical =
        canonicalize_and_validate_change_summary(&scrambled, &query(), &manifest(), &resolver)
            .unwrap();
    assert_eq!(canonical.result.items[0].summary, original_summary);
    assert_eq!(canonical.result.source_groups[0].source_ordinal, 0);
    assert_eq!(canonical.result.items[0].citations[0].ordinal, 0);
    assert_eq!(canonical.sha256.len(), 64);
    assert_eq!(
        serde_json::from_str::<Value>(&canonical.canonical_json).unwrap(),
        serde_json::to_value(&canonical.result).unwrap()
    );
    let direct =
        canonicalize_and_validate_change_summary(&result_value(), &query(), &manifest(), &resolver)
            .unwrap();
    assert_eq!(canonical.sha256, direct.sha256);
}

#[test]
fn result_schema_is_closed_and_renderer_identity_is_exact() {
    let mut extra = result_value();
    extra["unexpected"] = json!(true);
    assert!(validate_change_summary_result_schema(&extra).is_err());

    let mut renderer = result_value();
    renderer["renderer"]["revision"] = json!("2");
    assert!(validate(&renderer, &resolver()).is_err());
}

#[test]
fn effective_work_interval_is_canonical_positive_and_bounded() {
    for (started, ended) in [
        ("2026-08-01T09:00:00Z", "2026-08-01T10:00:00.000Z"),
        ("2026-08-01T10:00:00.000Z", "2026-08-01T09:00:00.000Z"),
        ("2025-01-01T00:00:00.000Z", "2026-08-01T00:00:00.000Z"),
        (
            "2026-08-01T09:00:00.000+00:00",
            "2026-08-01T10:00:00.000+00:00",
        ),
    ] {
        let mut value = result_value();
        value["effective_work_interval"]["started_at"] = json!(started);
        value["effective_work_interval"]["ended_at"] = json!(ended);
        assert!(validate(&value, &resolver()).is_err(), "{started}..{ended}");
    }
}

#[test]
fn citations_must_exactly_match_and_cover_the_immutable_manifest() {
    let resolver = resolver();
    let mut swapped = result_value();
    let first_id = swapped["items"][0]["citations"][0]["portable_id"].clone();
    swapped["items"][0]["citations"][0]["portable_id"] =
        swapped["items"][0]["citations"][1]["portable_id"].clone();
    swapped["items"][0]["citations"][1]["portable_id"] = first_id;
    assert!(validate(&swapped, &resolver).is_err());

    let mut missing = result_value();
    missing["items"][0]["citations"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    assert!(validate(&missing, &resolver).is_err());

    let mut digest = result_value();
    digest["items"][0]["citations"][0]["sha256"] = json!("f".repeat(64));
    assert!(validate(&digest, &resolver).is_err());

    let mut ordinal = result_value();
    ordinal["items"][0]["citations"][0]["ordinal"] = json!(8);
    assert!(validate(&ordinal, &resolver).is_err());

    let mut extra = result_value();
    let duplicate = extra["items"][0]["citations"][0].clone();
    extra["items"][0]["citations"]
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    assert!(
        canonicalize_and_validate_change_summary(&extra, &query(), &manifest(), &resolver).is_err()
    );
}

#[test]
fn source_groups_use_authoritative_valid_full_run_keys_and_cited_ordinals() {
    let mut wrong_group = result_value();
    wrong_group["source_groups"][0]["run_key"] = json!("scout-chair-000002");
    assert!(validate(&wrong_group, &resolver()).is_err());

    let mut wrong_ordinal = result_value();
    wrong_ordinal["source_groups"][0]["source_ordinal"] = json!(5);
    assert!(validate(&wrong_ordinal, &resolver()).is_err());

    let mut invalid_evidence = resolver();
    invalid_evidence
        .events
        .get_mut("event:one")
        .unwrap()
        .run_key = "run:one".into();
    assert!(validate(&result_value(), &invalid_evidence).is_err());
}

#[test]
fn context_suggestions_require_live_authorized_governed_evidence_and_citations() {
    let mut non_impact = resolver();
    non_impact
        .records
        .get_mut("outcome:one")
        .unwrap()
        .record_kind = "milestone".into();
    assert!(validate(&result_value(), &non_impact).is_err());

    let mut fabricated_type = resolver();
    fabricated_type
        .records
        .get_mut("work:one")
        .unwrap()
        .record_type = "Outcome".into();
    assert!(validate(&result_value(), &fabricated_type).is_err());

    let mut deleted = resolver();
    deleted.records.get_mut("work:one").unwrap().record_is_live = false;
    assert!(validate(&result_value(), &deleted).is_err());

    let mut unauthorized = resolver();
    unauthorized
        .records
        .get_mut("outcome:one")
        .unwrap()
        .audience_can_view = false;
    assert!(validate(&result_value(), &unauthorized).is_err());

    let mut ambient = result_value();
    ambient["items"][0]["citations"]
        .as_array_mut()
        .unwrap()
        .remove(5);
    assert!(validate(&ambient, &resolver()).is_err());
}

#[test]
fn query_constructor_orders_sources_and_context_and_rejects_invalid_evidence() {
    let fixture = resolver();
    let canonical = ChangeSummaryQuery::canonical(
        vec!["event:three".into(), "event:one".into(), "event:two".into()],
        vec![
            "work:one".into(),
            "context:decision".into(),
            "outcome:one".into(),
        ],
        &fixture,
    )
    .unwrap();
    assert_eq!(
        canonical.selection.source_event_ids,
        vec!["event:one", "event:two", "event:three"]
    );
    assert_eq!(
        canonical.scope.context_record_ids,
        query().scope.context_record_ids
    );

    let mut unavailable = resolver();
    unavailable
        .events
        .get_mut("event:two")
        .unwrap()
        .record_is_live = false;
    assert!(validate_change_summary_query(&query(), &unavailable).is_err());
}

#[test]
fn markdown_renderer_has_byte_exact_output_and_pinned_output_identity() {
    let result = validate(&result_value(), &resolver()).unwrap();
    assert_eq!(
        render_change_summary(&result).unwrap(),
        "# A safer release path\n\n\
Three implementation runs converged on one shippable result.\n\n\
## Change\n\n\
### Gate release on explicit confirmation\n\n\
The draft, confirmation, and query paths now share one traceable contract.\n\n\
## Why it matters\n\n\
This keeps semantic shipping judgement explicit while preserving the source evidence.\n\n\
### Materiality references\n\n\
- context:decision — Records the decision that confirmation is explicit.\n\n\
## Suggested links\n\n\
### WorkItems\n\n\
- work:one via implements — This work item owns the implementation.\n\n\
### Outcomes\n\n\
- outcome:one via relates\\_to — The change contributes to this realised impact.\n"
    );
    assert_eq!(
        change_summary_renderer_sha256(),
        CHANGE_SUMMARY_RENDERER_SHA256
    );
}

#[test]
fn renderer_normalizes_pinned_unicode_whitespace_and_rejects_expansion_limits() {
    let mut value = result_value();
    value["overview"] = json!("line\u{3000}one\n\n## injected");
    let result = validate(&value, &resolver()).unwrap();
    assert!(render_change_summary(&result)
        .unwrap()
        .contains("line one \\#\\# injected"));

    let mut enormous = result;
    let item = &mut enormous.items[0];
    let id = |index: usize| format!("{}{:02}", "*".repeat(250), index);
    item.materiality.references = (0..16)
        .map(|index| ChangeSummaryMaterialityReference {
            record_id: id(index),
            rationale: "💥".repeat(1000),
        })
        .collect();
    item.link_suggestions.work_items = (0..16)
        .map(|index| ChangeSummaryLinkSuggestion {
            record_id: id(index + 16),
            relationship: "implements".into(),
            rationale: "*".repeat(1000),
        })
        .collect();
    item.link_suggestions.outcomes = (0..16)
        .map(|index| ChangeSummaryLinkSuggestion {
            record_id: id(index + 32),
            relationship: "relates_to".into(),
            rationale: "💥".repeat(1000),
        })
        .collect();
    assert!(render_change_summary(&enormous).is_err());
}

#[test]
fn canonical_recipe_pins_contracts_budget_and_zero_repair_ordering_instructions() {
    let definition = change_summary_recipe_definition().unwrap();
    crate::recipe::validate_recipe_definition(&definition).unwrap();
    assert_eq!(CHANGE_SUMMARY_RECIPE_PROGRAM.record_type, "Program");
    assert_eq!(CHANGE_SUMMARY_RECIPE_PROGRAM.kind, "recipe");
    assert_eq!(
        definition.query_contract.id,
        CHANGE_SUMMARY_QUERY_CONTRACT_ID
    );
    assert_eq!(
        definition.result_contract.id,
        CHANGE_SUMMARY_RESULT_CONTRACT_ID
    );
    assert_eq!(
        definition.output_contract.id,
        CHANGE_SUMMARY_OUTPUT_CONTRACT_ID
    );
    assert_eq!(definition.renderer.sha256, CHANGE_SUMMARY_RENDERER_SHA256);
    assert!(definition.contextual_inputs.is_empty());
    assert_eq!(definition.budgets.defaults.max_input_items, 19);
    assert_eq!(definition.budgets.defaults.max_output_bytes, 131_072);
    assert_eq!(definition.repair_policy.max_repairs, 0);
    assert!(definition.instructions.text.contains("sort citations"));
}
