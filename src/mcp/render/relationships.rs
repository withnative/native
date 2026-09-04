//! Text rendering for the `manage_relationships` capability family.

use super::*;

const RELATIONSHIP_WRITE_RECOVERY: &str = "Exact response remains in structuredContent; do not repeat a possibly non-idempotent relationship write solely to obtain another format. For a future write, request format:\"json\" on the original call.";

pub(super) fn render_manage_relationships(value: &Value) -> String {
    let Some(object) = value.as_object() else {
        return format!(
            "Relationship result is malformed and was not interpreted; {RELATIONSHIP_WRITE_RECOVERY}\n"
        );
    };
    let Some(action) = object.get("action").and_then(Value::as_str) else {
        return format!(
            "Relationship action is missing or malformed and no outcome was inferred; {RELATIONSHIP_WRITE_RECOVERY}\n"
        );
    };
    match action {
        "assert" | "contest" | "add_evidence" | "retract" => {
            render_relationship_write_receipt(value, action)
        }
        "read" | "why" => render_relationship_read(value, action),
        "find" => render_relationship_find(value),
        _ => format!(
            "Relationship action {} is unsupported and no outcome was inferred; {RELATIONSHIP_WRITE_RECOVERY}\n",
            inline_json(&json!(action))
        ),
    }
}

fn render_relationship_write_component(
    out: &mut String,
    prefix: &str,
    value: &Value,
    remaining: &mut usize,
    cap: usize,
) -> bool {
    if *remaining == 0 {
        return false;
    }
    let encoded = inline_json(value);
    let (preview, shortened) = one_line_preview(&encoded, (*remaining).min(cap));
    *remaining = remaining.saturating_sub(preview.chars().count());
    let suffix = if shortened {
        format!(" (shortened; {RELATIONSHIP_WRITE_RECOVERY})")
    } else {
        String::new()
    };
    let _ = writeln!(out, "{prefix}{preview}{suffix}");
    true
}

fn render_relationship_write_malformed(
    out: &mut String,
    label: &str,
    malformed: Vec<String>,
    remaining: &mut usize,
) {
    if malformed.is_empty() {
        return;
    }
    let _ = render_relationship_write_component(
        out,
        &format!("Malformed {label} fields omitted without interpretation: "),
        &json!(malformed),
        remaining,
        1_000,
    );
    let _ = writeln!(out, "{RELATIONSHIP_WRITE_RECOVERY}");
}

fn render_relationship_write_unknowns(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
    remaining: &mut usize,
) {
    let unknown = unknown_object_keys(value, known);
    if unknown.is_empty() {
        return;
    }
    let _ = render_relationship_write_component(
        out,
        &format!("Additional {label} fields omitted from text: "),
        &json!(unknown),
        remaining,
        1_000,
    );
    let _ = writeln!(out, "{RELATIONSHIP_WRITE_RECOVERY}");
}

fn render_relationship_write_object_array(
    out: &mut String,
    label: &str,
    values: &[Value],
    remaining: &mut usize,
    known: impl Fn(&str) -> bool + Copy,
    valid: impl Fn(&str, &Value) -> bool + Copy,
) {
    let mut rendered = 0usize;
    let mut malformed = 0usize;
    for value in values.iter().take(RELATIONSHIP_DETAIL_ITEM_LIMIT) {
        if !value.is_object() {
            malformed += 1;
            continue;
        }
        let (projection, malformed_fields) = typed_context_projection(value, known, valid);
        if render_relationship_write_component(
            out,
            &format!("{label}: "),
            &projection,
            remaining,
            750,
        ) {
            rendered += 1;
        }
        render_relationship_write_malformed(out, label, malformed_fields, remaining);
        render_relationship_write_unknowns(out, label, value, known, remaining);
    }
    if rendered + malformed < values.len() || malformed > 0 {
        let _ = writeln!(
            out,
            "{label} detail: {rendered} rendered, {malformed} malformed, {} omitted from text; {RELATIONSHIP_WRITE_RECOVERY}",
            values.len().saturating_sub(rendered + malformed),
        );
    }
}

fn render_relationship_write_receipt(value: &Value, action: &str) -> String {
    const RECEIPT_BUDGET: usize = 8_000;
    let expected_status = match action {
        "assert" => "asserted",
        "contest" => "contested",
        "add_evidence" => "evidence_added",
        "retract" => "retracted",
        _ => unreachable!("write actions are closed above"),
    };
    if value.get("status").and_then(Value::as_str) != Some(expected_status) {
        return format!(
            "Relationship {action} receipt has a missing or contradictory status and no write outcome was inferred; {RELATIONSHIP_WRITE_RECOVERY}\n"
        );
    }
    let required_strings = [
        "relationship_origin_db_id",
        "relationship_id",
        "assertion_issuer_origin_db_id",
        "assertion_id",
    ];
    let output_events = value.get("output_events").and_then(Value::as_array);
    let attestation_ids = value
        .get("action_attestation_ids")
        .and_then(Value::as_array);
    let required_shape = required_strings
        .iter()
        .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
        && value
            .get("relationship_revision")
            .is_some_and(relationship_positive_integer)
        && value
            .get("assertion_stream_version")
            .is_some_and(relationship_positive_integer)
        && output_events.is_some_and(|events| {
            !events.is_empty()
                && events.iter().all(|event| {
                    event.get("domain").and_then(Value::as_str) == Some("relationship")
                        && event
                            .get("issuer_origin_db_id")
                            .is_some_and(relationship_nonblank_string)
                        && event
                            .get("event_id")
                            .is_some_and(relationship_nonblank_string)
                })
        })
        && attestation_ids
            .is_some_and(|ids| !ids.is_empty() && ids.iter().all(relationship_nonblank_string))
        && (action != "add_evidence"
            || value
                .get("evidence_id")
                .is_some_and(relationship_nonblank_string));
    if !required_shape {
        return format!(
            "Relationship {action} receipt is missing required coordinates, revisions, output events, or attestation IDs and no write outcome was inferred; {RELATIONSHIP_WRITE_RECOVERY}\n"
        );
    }
    let (mut receipt, malformed) = typed_context_projection(
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "status"
                    | "relationship_origin_db_id"
                    | "relationship_id"
                    | "relationship_revision"
                    | "assertion_issuer_origin_db_id"
                    | "assertion_id"
                    | "assertion_stream_version"
                    | "output_events"
                    | "action_attestation_ids"
                    | "run_context"
            ) || (action == "add_evidence" && key == "evidence_id")
        },
        |key, field| match key {
            "relationship_revision" | "assertion_stream_version" => {
                relationship_positive_integer(field)
            }
            "output_events" => field.is_array(),
            "action_attestation_ids" => field
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            "run_context" => true,
            _ => field.is_string(),
        },
    );
    receipt
        .as_object_mut()
        .expect("projection object")
        .remove("output_events");
    receipt
        .as_object_mut()
        .expect("projection object")
        .remove("run_context");
    let mut out = format!("Relationship {action} write receipt.\n");
    let mut remaining = RECEIPT_BUDGET;
    render_relationship_write_component(
        &mut out,
        "Receipt fields: ",
        &receipt,
        &mut remaining,
        3_000,
    );
    render_relationship_write_malformed(&mut out, "write receipt", malformed, &mut remaining);

    if let Some(events) = output_events {
        let _ = writeln!(out, "Output events returned: {}.", events.len());
        render_relationship_write_object_array(
            &mut out,
            "output event",
            events,
            &mut remaining,
            |key| matches!(key, "domain" | "issuer_origin_db_id" | "event_id"),
            |_, field| field.is_string(),
        );
    }
    render_relationship_write_unknowns(
        &mut out,
        "write receipt",
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "status"
                    | "relationship_origin_db_id"
                    | "relationship_id"
                    | "relationship_revision"
                    | "assertion_issuer_origin_db_id"
                    | "assertion_id"
                    | "assertion_stream_version"
                    | "output_events"
                    | "action_attestation_ids"
                    | "run_context"
            ) || (action == "add_evidence" && key == "evidence_id")
        },
        &mut remaining,
    );
    if remaining == 0 {
        out.push_str("Relationship write-receipt text budget reached its limit.\n");
    }
    let _ = writeln!(out, "{RELATIONSHIP_WRITE_RECOVERY}");
    out
}

fn render_relationship_read(value: &Value, action: &str) -> String {
    const SUMMARY_BUDGET: usize = 4_000;
    const ASSERTION_BUDGET: usize = 18_000;
    const PROVENANCE_BUDGET: usize = 10_000;

    let endpoints = value.get("endpoints").and_then(Value::as_array);
    let effective = value.get("effective").filter(|field| field.is_object());
    let assertions = value.get("assertions").and_then(Value::as_array);
    let provenance = value
        .get("authorized_action_provenance")
        .and_then(Value::as_array);
    let required_metadata = [
        "relationship_origin_db_id",
        "relationship_id",
        "relationship_type",
        "type_definition_id",
        "canonical_proposition_key",
    ]
    .into_iter()
    .all(|key| value.get(key).is_some_and(relationship_nonblank_string));
    if !required_metadata
        || !endpoints.is_some_and(|items| {
            !items.is_empty() && items.iter().all(relationship_read_endpoint_valid)
        })
        || !effective.is_some_and(relationship_read_effective_valid)
        || !assertions.is_some_and(|items| {
            !items.is_empty() && items.iter().all(relationship_read_assertion_valid)
        })
        || (action == "why" && provenance.is_none())
    {
        return format!(
            "Relationship {action} result is missing required containers and was not interpreted; {READ_JSON_RECOVERY}\n"
        );
    }

    let mut out = format!("Relationship {action}.\n");
    let mut summary_remaining = SUMMARY_BUDGET;
    let (mut metadata, malformed_metadata) = typed_context_projection(
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "relationship_origin_db_id"
                    | "relationship_id"
                    | "relationship_type"
                    | "type_definition_id"
                    | "canonical_proposition_key"
                    | "endpoints"
                    | "effective"
                    | "assertions"
                    | "authorized_action_provenance"
                    | "run_context"
            )
        },
        |key, field| match key {
            "endpoints" | "assertions" | "authorized_action_provenance" => field.is_array(),
            "effective" | "run_context" => field.is_object(),
            _ => field.is_string(),
        },
    );
    for key in [
        "endpoints",
        "effective",
        "assertions",
        "authorized_action_provenance",
        "run_context",
    ] {
        metadata
            .as_object_mut()
            .expect("projection object")
            .remove(key);
    }
    render_bounded_context_component(
        &mut out,
        "Relationship: ",
        &metadata,
        &mut summary_remaining,
        2_000,
    );
    render_context_malformed_fields(
        &mut out,
        "relationship metadata",
        malformed_metadata,
        &mut summary_remaining,
    );
    let endpoints = endpoints.expect("validated above");
    let _ = writeln!(out, "Endpoints returned: {}.", endpoints.len());
    render_relationship_object_array(
        &mut out,
        "endpoint",
        endpoints,
        &mut summary_remaining,
        600,
        |key| {
            matches!(
                key,
                "role" | "portable_ref" | "record_type" | "record_kind" | "record_id"
            )
        },
        |_, field| string_or_null(field),
    );
    render_relationship_effective(
        &mut out,
        effective.expect("validated above"),
        &mut summary_remaining,
    );

    let assertions = assertions.expect("validated above");
    let _ = writeln!(out, "Assertions returned: {}.", assertions.len());
    let mut assertion_remaining = ASSERTION_BUDGET;
    let mut assertion_nested = RelationshipNestedDetail::new();
    let mut rendered = 0usize;
    let mut malformed = 0usize;
    for assertion in assertions.iter().take(RELATIONSHIP_DETAIL_ITEM_LIMIT) {
        if !assertion.is_object() {
            malformed += 1;
            continue;
        }
        if render_relationship_assertion(
            &mut out,
            assertion,
            &mut assertion_remaining,
            &mut assertion_nested,
        ) {
            rendered += 1;
        }
    }
    if rendered + malformed < assertions.len() || malformed > 0 {
        let _ = writeln!(
            out,
            "Assertion detail: {rendered} rendered, {malformed} malformed, {} omitted from text; {READ_JSON_RECOVERY}",
            assertions.len().saturating_sub(rendered + malformed)
        );
    }
    if assertion_nested.malformed > 0 || assertion_nested.omitted > 0 {
        let _ = writeln!(
            out,
            "Assertion nested detail: {} rendered, {} malformed, {} omitted from text; {READ_JSON_RECOVERY}",
            assertion_nested.rendered, assertion_nested.malformed, assertion_nested.omitted
        );
    }
    if assertion_nested.payload_omitted {
        out.push_str("Assertion-event payload values are omitted from text; ");
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }

    if action == "why" {
        let provenance = provenance.expect("validated above");
        let _ = writeln!(
            out,
            "Authorized action provenance receipts returned: {}.",
            provenance.len()
        );
        let mut provenance_remaining = PROVENANCE_BUDGET;
        let mut provenance_detail = RelationshipProvenanceDetail::new();
        for (index, receipt) in provenance.iter().enumerate() {
            if provenance_detail.remaining == 0 {
                provenance_detail.omitted += provenance.len().saturating_sub(index);
                break;
            }
            provenance_detail.remaining -= 1;
            if !receipt.is_object() || !relationship_provenance_valid(receipt) {
                provenance_detail.malformed += 1;
                continue;
            }
            if render_relationship_provenance(
                &mut out,
                receipt,
                &mut provenance_remaining,
                &mut provenance_detail,
            ) {
                provenance_detail.rendered += 1;
            } else {
                provenance_detail.omitted += 1;
            }
        }
        if provenance_detail.malformed > 0 || provenance_detail.omitted > 0 {
            let _ = writeln!(
                out,
                "Provenance receipt/output detail: {} rendered, {} malformed, {} omitted from text; {READ_JSON_RECOVERY}",
                provenance_detail.rendered,
                provenance_detail.malformed,
                provenance_detail.omitted
            );
        }
    }

    render_relationship_unknowns(
        &mut out,
        "relationship read",
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "relationship_origin_db_id"
                    | "relationship_id"
                    | "relationship_type"
                    | "type_definition_id"
                    | "canonical_proposition_key"
                    | "endpoints"
                    | "effective"
                    | "assertions"
                    | "run_context"
            ) || (action == "why" && key == "authorized_action_provenance")
        },
        &mut summary_remaining,
    );
    if summary_remaining == 0 || assertion_remaining == 0 {
        let _ = writeln!(
            out,
            "Relationship {action} text detail budget reached its limit; {READ_JSON_RECOVERY}"
        );
    }
    out
}

fn render_relationship_find(value: &Value) -> String {
    const RESULT_BUDGET: usize = 16_000;
    let endpoint = value.get("endpoint").filter(|field| field.is_object());
    let results = value.get("results").and_then(Value::as_array);
    let returned = value.get("returned").and_then(Value::as_u64);
    let limit = value.get("limit").and_then(Value::as_i64);
    let offset = value.get("offset").and_then(Value::as_i64);
    let has_more = value.get("has_more").and_then(Value::as_bool);
    let scan_limit_reached = value.get("scan_limit_reached").and_then(Value::as_bool);
    let Some((endpoint, results, returned, limit, offset, has_more, scan_limit_reached)) = endpoint
        .zip(results)
        .zip(returned)
        .zip(limit)
        .zip(offset)
        .zip(has_more)
        .zip(scan_limit_reached)
        .map(
            |((((((endpoint, results), returned), limit), offset), has_more), scan)| {
                (endpoint, results, returned, limit, offset, has_more, scan)
            },
        )
    else {
        return format!(
            "Relationship find result is missing or malformed and no page claim was inferred; {READ_JSON_RECOVERY}\n"
        );
    };
    let controls_valid = returned == results.len() as u64
        && (1..=200).contains(&limit)
        && offset >= 0
        && offset.checked_add(limit).is_some_and(|end| end <= 2_000)
        && returned <= limit as u64
        && (!has_more || (returned > 0 && returned == limit as u64))
        && relationship_find_scope_valid(endpoint)
        && results.iter().all(relationship_find_result_valid);
    if !controls_valid {
        return format!(
            "Relationship find page controls are contradictory and no page claim was inferred; {READ_JSON_RECOVERY}\n"
        );
    }

    let mut out = "Relationship find.\n".to_string();
    let mut endpoint_budget = 1_000;
    render_relationship_object(
        &mut out,
        "find endpoint",
        endpoint,
        &mut endpoint_budget,
        750,
        |key| matches!(key, "record_id" | "resolved_from"),
        |_, field| field.is_string(),
    );
    let _ = writeln!(
        out,
        "Page: {returned} result(s) returned · offset {offset} · limit {limit} · has_more={has_more} · scan_limit_reached={scan_limit_reached}."
    );
    if has_more {
        let next_offset = offset.saturating_add(returned as i64);
        let _ = writeln!(
            out,
            "More visible results are known; re-call find with the same filters and offset {next_offset}."
        );
    }
    if scan_limit_reached {
        out.push_str("The bounded candidate scan reached its limit; additional visible matches may exist even if has_more is false.\n");
    }

    let mut result_remaining = RESULT_BUDGET;
    let mut rendered = 0usize;
    let mut malformed = 0usize;
    for result in results.iter().take(RELATIONSHIP_DETAIL_ITEM_LIMIT) {
        if !result.is_object() {
            malformed += 1;
            continue;
        }
        if render_relationship_find_result(&mut out, result, &mut result_remaining) {
            rendered += 1;
        }
    }
    if rendered + malformed < results.len() || malformed > 0 {
        let _ = writeln!(
            out,
            "Find-result detail: {rendered} rendered, {malformed} malformed, {} omitted from text; {READ_JSON_RECOVERY}",
            results.len().saturating_sub(rendered + malformed)
        );
    }
    render_relationship_unknowns(
        &mut out,
        "relationship find",
        value,
        |key| {
            matches!(
                key,
                "action"
                    | "endpoint"
                    | "results"
                    | "returned"
                    | "limit"
                    | "offset"
                    | "has_more"
                    | "scan_limit_reached"
                    | "run_context"
            )
        },
        &mut endpoint_budget,
    );
    if endpoint_budget == 0 || result_remaining == 0 {
        out.push_str("Relationship-find text detail budget reached its limit; ");
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
    out
}

const RELATIONSHIP_DETAIL_ITEM_LIMIT: usize = 100;

fn relationship_positive_integer(value: &Value) -> bool {
    value.as_u64().is_some_and(|number| number > 0)
}

fn relationship_nonnegative_integer(value: &Value) -> bool {
    value.as_u64().is_some()
}

fn relationship_nonblank_string(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.trim().is_empty())
}

fn relationship_read_endpoint_valid(value: &Value) -> bool {
    ["role", "portable_ref", "record_id"]
        .into_iter()
        .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
}

fn relationship_read_effective_valid(value: &Value) -> bool {
    [
        "state",
        "epistemic_state",
        "reducer_id",
        "assertion_set_digest",
        "recomputed_at",
    ]
    .into_iter()
    .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
        && ["support_count", "contest_count"]
            .into_iter()
            .all(|key| value.get(key).is_some_and(relationship_nonnegative_integer))
        && value
            .get("reducer_version")
            .is_some_and(relationship_positive_integer)
        && value.get("admission_counts").is_some_and(Value::is_object)
        && value
            .get("knowledge_watermark")
            .is_some_and(Value::is_array)
}

fn relationship_read_assertion_valid(value: &Value) -> bool {
    let required = [
        "assertion_issuer_origin_db_id",
        "assertion_id",
        "stance",
        "state",
        "semantic_claimant",
    ]
    .into_iter()
    .all(|key| value.get(key).is_some_and(relationship_nonblank_string));
    let head = value.get("head");
    let local_admission = value.get("local_admission");
    let origin_admission = value.get("origin_admission");
    required
        && head.is_some_and(|head| {
            ["issuer_origin_db_id", "event_id"]
                .into_iter()
                .all(|key| head.get(key).is_some_and(relationship_nonblank_string))
                && head
                    .get("stream_version")
                    .is_some_and(relationship_positive_integer)
        })
        && local_admission.is_some_and(|admission| {
            admission
                .get("state")
                .is_some_and(relationship_nonblank_string)
                && admission.get("class").is_some_and(string_or_null)
        })
        && origin_admission.is_some_and(relationship_origin_admission_valid)
        && value.get("causal_parents").is_some_and(Value::is_array)
        && value
            .get("events")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
        && value.get("evidence").is_some_and(Value::is_array)
}

fn relationship_origin_admission_valid(value: &Value) -> bool {
    [
        "relationship_type_definition",
        "admission_class",
        "admission_rule",
        "authorization_decision_digest",
        "authoring_action_attestation_id",
    ]
    .into_iter()
    .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
        && value
            .get("schema_version")
            .is_some_and(relationship_positive_integer)
        && value.get("authority_anchor").is_some_and(|anchor| {
            ["endpoint_role", "endpoint_ref"]
                .into_iter()
                .all(|key| anchor.get(key).is_some_and(relationship_nonblank_string))
        })
}

fn relationship_find_scope_valid(value: &Value) -> bool {
    ["record_id", "resolved_from"]
        .into_iter()
        .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
}

fn relationship_find_result_valid(value: &Value) -> bool {
    let coordinates = [
        "relationship_origin_db_id",
        "relationship_id",
        "relationship_type",
        "type_definition_id",
        "occurred_at",
    ]
    .into_iter()
    .all(|key| value.get(key).is_some_and(relationship_nonblank_string));
    let endpoint = value.get("endpoint");
    let counterpart = value.get("counterpart");
    let effective = value.get("effective");
    coordinates
        && endpoint.is_some_and(|endpoint| {
            ["record_id", "role"]
                .into_iter()
                .all(|key| endpoint.get(key).is_some_and(relationship_nonblank_string))
        })
        && counterpart.is_some_and(|counterpart| {
            ["role", "record_id", "portable_ref", "name"]
                .into_iter()
                .all(|key| {
                    counterpart
                        .get(key)
                        .is_some_and(relationship_nonblank_string)
                })
        })
        && effective.is_some_and(|effective| {
            ["state", "epistemic_state", "recomputed_at"]
                .into_iter()
                .all(|key| effective.get(key).is_some_and(relationship_nonblank_string))
                && ["support_count", "contest_count"].into_iter().all(|key| {
                    effective
                        .get(key)
                        .is_some_and(relationship_nonnegative_integer)
                })
        })
}

fn render_relationship_unknowns(
    out: &mut String,
    label: &str,
    value: &Value,
    known: impl Fn(&str) -> bool,
    remaining: &mut usize,
) {
    render_context_unknowns(out, label, value, known, remaining);
}

fn render_relationship_object(
    out: &mut String,
    label: &str,
    value: &Value,
    remaining: &mut usize,
    cap: usize,
    known: impl Fn(&str) -> bool + Copy,
    valid: impl Fn(&str, &Value) -> bool + Copy,
) -> bool {
    let (projection, malformed) = typed_context_projection(value, known, valid);
    let rendered =
        render_bounded_context_component(out, &format!("{label}: "), &projection, remaining, cap);
    render_context_malformed_fields(out, label, malformed, remaining);
    if *remaining > 0 {
        render_relationship_unknowns(out, label, value, known, remaining);
    }
    rendered
}

fn render_relationship_object_array(
    out: &mut String,
    label: &str,
    values: &[Value],
    remaining: &mut usize,
    cap: usize,
    known: impl Fn(&str) -> bool + Copy,
    valid: impl Fn(&str, &Value) -> bool + Copy,
) {
    if *remaining == 0 {
        return;
    }
    let mut rendered = 0usize;
    let mut malformed = 0usize;
    for value in values.iter().take(RELATIONSHIP_DETAIL_ITEM_LIMIT) {
        if !value.is_object() {
            malformed += 1;
            continue;
        }
        if render_relationship_object(out, label, value, remaining, cap, known, valid) {
            rendered += 1;
        }
    }
    if rendered + malformed < values.len() || malformed > 0 {
        let _ = writeln!(
            out,
            "{label} detail: {rendered} rendered, {malformed} malformed, {} omitted from text; {READ_JSON_RECOVERY}",
            values.len().saturating_sub(rendered + malformed)
        );
    }
}

fn render_relationship_effective(out: &mut String, value: &Value, remaining: &mut usize) {
    let known = |key: &str| {
        matches!(
            key,
            "state"
                | "epistemic_state"
                | "support_count"
                | "contest_count"
                | "admission_counts"
                | "reducer_id"
                | "reducer_version"
                | "assertion_set_digest"
                | "knowledge_watermark"
                | "recomputed_at"
        )
    };
    let (mut projection, malformed) =
        typed_context_projection(value, known, |key, field| match key {
            "support_count" | "contest_count" => relationship_nonnegative_integer(field),
            "reducer_version" => relationship_positive_integer(field),
            "admission_counts" => field.is_object(),
            "knowledge_watermark" => field.is_array(),
            _ => field.is_string(),
        });
    for key in ["admission_counts", "knowledge_watermark"] {
        projection
            .as_object_mut()
            .expect("projection object")
            .remove(key);
    }
    render_bounded_context_component(out, "Effective projection: ", &projection, remaining, 1_200);
    render_context_malformed_fields(out, "effective projection", malformed, remaining);
    let retained = ["admission_counts", "knowledge_watermark"]
        .into_iter()
        .filter(|key| value.get(key).is_some())
        .collect::<Vec<_>>();
    if !retained.is_empty() {
        let _ = render_bounded_context_component(
            out,
            "Effective fields retained only in exact JSON: ",
            &json!(retained),
            remaining,
            300,
        );
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
    render_relationship_unknowns(out, "effective projection", value, known, remaining);
}

fn render_relationship_assertion(
    out: &mut String,
    value: &Value,
    remaining: &mut usize,
    nested: &mut RelationshipNestedDetail,
) -> bool {
    let known = |key: &str| {
        matches!(
            key,
            "assertion_issuer_origin_db_id"
                | "assertion_id"
                | "stance"
                | "state"
                | "semantic_claimant"
                | "on_behalf_of"
                | "rationale"
                | "valid_from"
                | "valid_until"
                | "causal_parents"
                | "head"
                | "local_admission"
                | "origin_admission"
                | "events"
                | "evidence"
        )
    };
    let (mut projection, malformed) =
        typed_context_projection(value, known, |key, field| match key {
            "causal_parents" | "events" | "evidence" => field.is_array(),
            "head" | "local_admission" | "origin_admission" => field.is_object(),
            _ => string_or_null(field),
        });
    for key in [
        "causal_parents",
        "head",
        "local_admission",
        "origin_admission",
        "events",
        "evidence",
    ] {
        projection
            .as_object_mut()
            .expect("projection object")
            .remove(key);
    }
    for (source, derived) in [
        ("causal_parents", "causal_parent_count"),
        ("events", "event_count"),
        ("evidence", "evidence_count"),
    ] {
        if let Some(items) = value.get(source).and_then(Value::as_array) {
            projection[derived] = json!(items.len());
        }
    }
    let rendered =
        render_bounded_context_component(out, "- assertion ", &projection, remaining, 900);
    render_context_malformed_fields(out, "assertion", malformed, remaining);
    if let Some(head) = value.get("head").filter(|field| field.is_object()) {
        render_relationship_object(
            out,
            "assertion head",
            head,
            remaining,
            500,
            |key| matches!(key, "issuer_origin_db_id" | "event_id" | "stream_version"),
            |key, field| {
                if key == "stream_version" {
                    relationship_positive_integer(field)
                } else {
                    field.is_string()
                }
            },
        );
    }
    if let Some(admission) = value
        .get("local_admission")
        .filter(|field| field.is_object())
    {
        render_relationship_object(
            out,
            "local admission",
            admission,
            remaining,
            400,
            |key| matches!(key, "state" | "class"),
            |_, field| string_or_null(field),
        );
    }
    if let Some(admission) = value
        .get("origin_admission")
        .filter(|field| field.is_object())
    {
        render_relationship_origin_admission(out, admission, remaining);
    }
    if let Some(parents) = value.get("causal_parents").and_then(Value::as_array) {
        render_relationship_assertion_member_array(
            out,
            parents,
            remaining,
            nested,
            RelationshipAssertionMemberSchema {
                label: "causal parent",
                cap: 600,
                known: |key| {
                    matches!(
                        key,
                        "assertion_issuer_origin_db_id"
                            | "assertion_id"
                            | "head_event_issuer_origin_db_id"
                            | "head_event_id"
                            | "head_stream_version"
                    )
                },
                valid: |key, field| {
                    if key == "head_stream_version" {
                        relationship_positive_integer(field)
                    } else {
                        field.is_string()
                    }
                },
                required: relationship_causal_parent_valid,
            },
        );
    }
    if let Some(events) = value.get("events").and_then(Value::as_array) {
        render_relationship_assertion_events(out, events, remaining, nested);
    }
    if let Some(evidence) = value.get("evidence").and_then(Value::as_array) {
        render_relationship_assertion_member_array(
            out,
            evidence,
            remaining,
            nested,
            RelationshipAssertionMemberSchema {
                label: "assertion evidence",
                cap: 500,
                known: |key| matches!(key, "record_id" | "reason"),
                valid: |_, field| string_or_null(field),
                required: relationship_assertion_evidence_valid,
            },
        );
    }
    render_relationship_unknowns(out, "assertion", value, known, remaining);
    rendered
}

fn relationship_causal_parent_valid(value: &Value) -> bool {
    [
        "assertion_issuer_origin_db_id",
        "assertion_id",
        "head_event_issuer_origin_db_id",
        "head_event_id",
    ]
    .into_iter()
    .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
        && value
            .get("head_stream_version")
            .is_some_and(relationship_positive_integer)
}

fn relationship_assertion_event_valid(value: &Value) -> bool {
    ["type", "occurred_at"]
        .into_iter()
        .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
        && value
            .get("stream_version")
            .is_some_and(relationship_positive_integer)
        && value.get("payload").is_some_and(Value::is_object)
}

fn relationship_assertion_evidence_valid(value: &Value) -> bool {
    value
        .get("record_id")
        .is_some_and(relationship_nonblank_string)
        && value.get("reason").is_some_and(string_or_null)
}

struct RelationshipNestedDetail {
    remaining: usize,
    rendered: usize,
    malformed: usize,
    omitted: usize,
    payload_omitted: bool,
}

impl RelationshipNestedDetail {
    fn new() -> Self {
        Self {
            remaining: RELATIONSHIP_DETAIL_ITEM_LIMIT,
            rendered: 0,
            malformed: 0,
            omitted: 0,
            payload_omitted: false,
        }
    }
}

struct RelationshipAssertionMemberSchema {
    label: &'static str,
    cap: usize,
    known: fn(&str) -> bool,
    valid: fn(&str, &Value) -> bool,
    required: fn(&Value) -> bool,
}

fn render_relationship_assertion_member_array(
    out: &mut String,
    values: &[Value],
    remaining: &mut usize,
    nested: &mut RelationshipNestedDetail,
    schema: RelationshipAssertionMemberSchema,
) {
    let attempted = values.len().min(nested.remaining);
    nested.remaining -= attempted;
    nested.omitted += values.len().saturating_sub(attempted);
    for value in values.iter().take(attempted) {
        if !value.is_object() || !(schema.required)(value) {
            nested.malformed += 1;
            continue;
        }
        if render_relationship_object(
            out,
            schema.label,
            value,
            remaining,
            schema.cap,
            schema.known,
            schema.valid,
        ) {
            nested.rendered += 1;
        } else {
            nested.omitted += 1;
        }
    }
}

fn render_relationship_origin_admission(out: &mut String, value: &Value, remaining: &mut usize) {
    let known = |key: &str| {
        matches!(
            key,
            "schema_version"
                | "relationship_type_definition"
                | "admission_class"
                | "authority_anchor"
                | "admission_rule"
                | "authorization_decision_digest"
                | "authoring_action_attestation_id"
        )
    };
    let (mut projection, malformed) = typed_context_projection(value, known, |key, field| {
        if key == "schema_version" {
            relationship_positive_integer(field)
        } else if key == "authority_anchor" {
            field.is_object()
        } else {
            field.is_string()
        }
    });
    projection
        .as_object_mut()
        .expect("projection object")
        .remove("authority_anchor");
    render_bounded_context_component(out, "Origin admission: ", &projection, remaining, 700);
    render_context_malformed_fields(out, "origin admission", malformed, remaining);
    if let Some(anchor) = value
        .get("authority_anchor")
        .filter(|field| field.is_object())
    {
        render_relationship_object(
            out,
            "authority anchor",
            anchor,
            remaining,
            350,
            |key| matches!(key, "endpoint_role" | "endpoint_ref"),
            |_, field| field.is_string(),
        );
    }
    render_relationship_unknowns(out, "origin admission", value, known, remaining);
}

fn render_relationship_assertion_events(
    out: &mut String,
    values: &[Value],
    remaining: &mut usize,
    nested: &mut RelationshipNestedDetail,
) {
    if *remaining == 0 {
        nested.omitted += values.len();
        return;
    }
    let attempted = values.len().min(nested.remaining);
    nested.remaining -= attempted;
    nested.omitted += values.len().saturating_sub(attempted);
    for value in values.iter().take(attempted) {
        if !value.is_object() || !relationship_assertion_event_valid(value) {
            nested.malformed += 1;
            continue;
        }
        let known =
            |key: &str| matches!(key, "stream_version" | "type" | "occurred_at" | "payload");
        let (mut projection, bad) =
            typed_context_projection(value, known, |key, field| match key {
                "stream_version" => relationship_positive_integer(field),
                "payload" => field.is_object(),
                _ => field.is_string(),
            });
        if projection
            .as_object_mut()
            .expect("projection object")
            .remove("payload")
            .is_some()
        {
            projection["payload_available_in_exact_json"] = json!(true);
            nested.payload_omitted = true;
        }
        if render_bounded_context_component(out, "assertion event: ", &projection, remaining, 600) {
            nested.rendered += 1;
        } else {
            nested.omitted += 1;
        }
        render_context_malformed_fields(out, "assertion event", bad, remaining);
        render_relationship_unknowns(out, "assertion event", value, known, remaining);
    }
}

struct RelationshipProvenanceDetail {
    remaining: usize,
    rendered: usize,
    malformed: usize,
    omitted: usize,
}

impl RelationshipProvenanceDetail {
    fn new() -> Self {
        Self {
            remaining: RELATIONSHIP_DETAIL_ITEM_LIMIT,
            rendered: 0,
            malformed: 0,
            omitted: 0,
        }
    }
}

fn relationship_provenance_valid(value: &Value) -> bool {
    value
        .get("attestation")
        .is_some_and(relationship_attestation_core_valid)
}

fn relationship_attestation_core_valid(value: &Value) -> bool {
    [
        "id",
        "executor_kind",
        "trust",
        "operation",
        "action_digest",
        "output_event_set_digest",
        "issuer",
        "issuer_origin_database_id",
        "issued_at",
        "validity",
    ]
    .into_iter()
    .all(|key| value.get(key).is_some_and(relationship_nonblank_string))
        && value
            .get("schema_version")
            .is_some_and(relationship_positive_integer)
        && value
            .get("has_verified_interaction")
            .is_some_and(Value::is_boolean)
        && value.get("intent_digest").is_some_and(string_or_null)
        && value
            .get("outputs")
            .and_then(Value::as_array)
            .is_some_and(|outputs| !outputs.is_empty())
        && value.get("output_event_ids").is_some_and(|ids| {
            ids.as_array()
                .is_some_and(|ids| !ids.is_empty() && ids.iter().all(relationship_nonblank_string))
        })
}

fn relationship_attestation_output_valid(value: &Value) -> bool {
    matches!(
        value.get("domain").and_then(Value::as_str),
        Some("content" | "relationship")
    ) && value
        .get("event_id")
        .is_some_and(relationship_nonblank_string)
}

fn render_relationship_provenance(
    out: &mut String,
    value: &Value,
    remaining: &mut usize,
    detail: &mut RelationshipProvenanceDetail,
) -> bool {
    let known = |key: &str| matches!(key, "attestation" | "why" | "interaction");
    let (projection, malformed) = typed_context_projection(value, known, |_, field| {
        field.is_object() || field.is_null()
    });
    let rendered = render_bounded_context_component(
        out,
        "- provenance envelope ",
        &json!({"sections": projection.as_object().map(Map::len).unwrap_or(0)}),
        remaining,
        250,
    );
    render_context_malformed_fields(out, "provenance envelope", malformed, remaining);
    if let Some(attestation) = value.get("attestation").filter(|field| field.is_object()) {
        render_relationship_attestation(out, attestation, remaining, detail);
    }
    if let Some(why) = value.get("why").filter(|field| field.is_object()) {
        render_relationship_object(
            out,
            "provenance why",
            why,
            remaining,
            650,
            |key| {
                matches!(
                    key,
                    "principal"
                        | "executor_ref_digest"
                        | "delegation_present"
                        | "command_identity_digest"
                )
            },
            |key, field| {
                if key == "delegation_present" {
                    field.is_boolean()
                } else {
                    string_or_null(field)
                }
            },
        );
    }
    if let Some(interaction) = value.get("interaction").filter(|field| field.is_object()) {
        render_relationship_object(
            out,
            "verified interaction",
            interaction,
            remaining,
            900,
            |key| {
                matches!(
                    key,
                    "id" | "scope_digest"
                        | "verifier_digest"
                        | "verified_at"
                        | "evidence_digest"
                        | "retention_class"
                        | "sealed_reference_recorded"
                )
            },
            |key, field| {
                if key == "sealed_reference_recorded" {
                    field.is_boolean()
                } else {
                    string_or_null(field)
                }
            },
        );
    }
    render_relationship_unknowns(out, "provenance envelope", value, known, remaining);
    rendered
}

fn render_relationship_attestation(
    out: &mut String,
    value: &Value,
    remaining: &mut usize,
    detail: &mut RelationshipProvenanceDetail,
) {
    let had_budget = *remaining > 0;
    let known = |key: &str| {
        matches!(
            key,
            "id" | "schema_version"
                | "executor_kind"
                | "has_verified_interaction"
                | "trust"
                | "operation"
                | "action_digest"
                | "output_event_set_digest"
                | "issuer"
                | "issuer_origin_database_id"
                | "issued_at"
                | "intent_digest"
                | "outputs"
                | "output_event_ids"
                | "validity"
        )
    };
    let (mut projection, malformed) =
        typed_context_projection(value, known, |key, field| match key {
            "schema_version" => relationship_positive_integer(field),
            "has_verified_interaction" => field.is_boolean(),
            "outputs" => field.is_array(),
            "output_event_ids" => field
                .as_array()
                .is_some_and(|items| items.iter().all(Value::is_string)),
            "intent_digest" => string_or_null(field),
            _ => field.is_string(),
        });
    let outputs = projection
        .as_object_mut()
        .expect("projection object")
        .remove("outputs");
    if let Some(ids) = projection
        .as_object_mut()
        .expect("projection object")
        .remove("output_event_ids")
    {
        if let Some(items) = ids.as_array() {
            if items.iter().all(Value::is_string) {
                projection["output_event_id_count"] = json!(items.len());
            }
        }
    }
    render_bounded_context_component(out, "Attestation: ", &projection, remaining, 1_000);
    render_context_malformed_fields(out, "attestation", malformed, remaining);
    if let Some(items) = outputs.and_then(|field| field.as_array().cloned()) {
        let attempted = items.len().min(detail.remaining);
        detail.remaining -= attempted;
        detail.omitted += items.len().saturating_sub(attempted);
        for output in items.iter().take(attempted) {
            if !output.is_object() || !relationship_attestation_output_valid(output) {
                detail.malformed += 1;
                continue;
            }
            if render_relationship_object(
                out,
                "attestation output",
                output,
                remaining,
                400,
                |key| matches!(key, "domain" | "event_id"),
                |_, field| field.is_string(),
            ) {
                detail.rendered += 1;
            } else {
                detail.omitted += 1;
            }
        }
    }
    if value.get("output_event_ids").is_some() && had_budget {
        out.push_str("Bare output event IDs are represented by count only; ");
        out.push_str(READ_JSON_RECOVERY);
        out.push('\n');
    }
    render_relationship_unknowns(out, "attestation", value, known, remaining);
}

fn render_relationship_find_result(out: &mut String, value: &Value, remaining: &mut usize) -> bool {
    let known = |key: &str| {
        matches!(
            key,
            "relationship_origin_db_id"
                | "relationship_id"
                | "relationship_type"
                | "type_definition_id"
                | "occurred_at"
                | "endpoint"
                | "counterpart"
                | "effective"
        )
    };
    let (mut projection, malformed) = typed_context_projection(value, known, |key, field| {
        if matches!(key, "endpoint" | "counterpart" | "effective") {
            field.is_object()
        } else {
            field.is_string()
        }
    });
    for key in ["endpoint", "counterpart", "effective"] {
        projection
            .as_object_mut()
            .expect("projection object")
            .remove(key);
    }
    let rendered =
        render_bounded_context_component(out, "- relationship ", &projection, remaining, 700);
    render_context_malformed_fields(out, "find result", malformed, remaining);
    if let Some(endpoint) = value.get("endpoint").filter(|field| field.is_object()) {
        render_relationship_object(
            out,
            "matched endpoint",
            endpoint,
            remaining,
            350,
            |key| matches!(key, "record_id" | "role"),
            |_, field| field.is_string(),
        );
    }
    if let Some(counterpart) = value.get("counterpart").filter(|field| field.is_object()) {
        render_relationship_object(
            out,
            "counterpart",
            counterpart,
            remaining,
            650,
            |key| {
                matches!(
                    key,
                    "role"
                        | "record_id"
                        | "record_type"
                        | "record_kind"
                        | "portable_ref"
                        | "name"
                        | "lifecycle"
                )
            },
            |_, field| string_or_null(field),
        );
    }
    if let Some(effective) = value.get("effective").filter(|field| field.is_object()) {
        render_relationship_object(
            out,
            "result effective",
            effective,
            remaining,
            500,
            |key| {
                matches!(
                    key,
                    "state"
                        | "epistemic_state"
                        | "support_count"
                        | "contest_count"
                        | "recomputed_at"
                )
            },
            |key, field| {
                if matches!(key, "support_count" | "contest_count") {
                    relationship_nonnegative_integer(field)
                } else {
                    field.is_string()
                }
            },
        );
    }
    render_relationship_unknowns(out, "find result", value, known, remaining);
    rendered
}
