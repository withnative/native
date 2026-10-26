//! Counts-only diagnostics. Never copy free-form source values or engine errors.
use super::*;

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RefusalCount {
    pub v1_type: String,
    pub v1_kind: String,
    pub reason_category: String,
    pub shape: String,
    pub count: usize,
}

fn record_type(value: &str) -> &str {
    match value {
        "Document" | "Annotation" | "Message" | "Entity" | "WorkItem" | "Collection" | "Event"
        | "Relation" => value,
        _ => "other",
    }
}
fn record_kind(value: Option<&str>) -> &str {
    match value {
        None | Some("") => "none",
        Some(
            value @ ("attachment" | "comment" | "note" | "artifact" | "folder" | "text" | "task"
            | "epic" | "person" | "channel" | "review" | "review_note" | "review-note"),
        ) => value,
        _ => "other",
    }
}
fn derived(record: &Record) -> bool {
    record.v1_type == "Annotation"
        || (record.v1_type == "Document" && record.kind.as_deref() == Some("attachment"))
}
fn scope(record: &Record) -> &'static str {
    if record.deleted_at.is_some() {
        "deleted"
    } else if record.kind.as_deref() == Some("artifact") {
        "retained_artifact"
    } else if record.v1_type == "Message" {
        "live_message"
    } else if record.v1_type == "Annotation" && record.kind.as_deref() != Some("comment") {
        "non_comment_annotation"
    } else {
        "other"
    }
}
fn reason(reason: &str, record: Option<&Record>) -> String {
    if matches!(
        reason,
        "excluded_deleted" | "excluded_invisible_in_v1" | "inherited_bearer_tombstone"
    ) {
        return reason.into();
    }
    if reason == "record outside current-state importer scope" {
        return format!("outside_scope_{}", record.map(scope).unwrap_or("other"));
    }
    for (needle, category) in [
        (
            "terminal bearer was not imported",
            "terminal_bearer_not_imported",
        ),
        (
            "comment bearer was not imported",
            "terminal_bearer_not_imported",
        ),
        ("exactly one part_of bearer", "invalid_attachment_bearer"),
        (
            "comment bearer is not exactly one",
            "invalid_comment_bearer_chain",
        ),
        (
            "exactly one live part_of chain",
            "invalid_derived_bearer_chain",
        ),
        ("policy visibility mismatch", "policy_visibility_mismatch"),
        (
            "kernel read reconciliation mismatch",
            "kernel_read_reconciliation_mismatch",
        ),
        (
            "kernel current-state import refused",
            "kernel_import_refused",
        ),
        ("source record missing", "source_record_missing"),
        ("owner", "ownership_review"),
        ("comment", "comment_validation"),
        ("attachment", "attachment_validation"),
        ("binding", "instruction_binding_validation"),
        ("link", "link_validation"),
    ] {
        if reason.contains(needle) {
            return category.into();
        }
    }
    "other_refusal".into()
}
fn shape(
    record: &Record,
    records: &BTreeMap<String, Record>,
    bearers: &BTreeMap<String, Vec<String>>,
    outside: &BTreeSet<&str>,
    imported: &BTreeSet<&str>,
) -> String {
    if !derived(record) {
        return "not_derived".into();
    }
    let mut current = record;
    let mut seen = BTreeSet::new();
    for depth in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH {
        if current.deleted_at.is_some() {
            return if depth == 0 {
                "derived_record_tombstoned"
            } else if is_comment_record(record) && is_comment_record(current) {
                "reply_parent_tombstoned"
            } else {
                "bearer_tombstoned"
            }
            .into();
        }
        if !derived(current) {
            return if outside.contains(current.id.as_str()) {
                format!("bearer_outside_scope:{}", scope(current))
            } else if imported.contains(current.id.as_str()) {
                "bearer_imported".into()
            } else {
                "bearer_not_imported:other".into()
            };
        }
        if !seen.insert(current.id.as_str()) {
            return "bearer_chain_cycle".into();
        }
        if depth == crate::authorization::MAX_DERIVED_BEARER_DEPTH {
            return if is_comment_record(record) {
                "comment_chain_depth_exceeded"
            } else {
                "derived_chain_depth_exceeded"
            }
            .into();
        }
        let links = bearers.get(&current.id).map(Vec::as_slice).unwrap_or(&[]);
        let [parent] = links else {
            let category = if current.v1_type == "Document" {
                "attachment"
            } else if is_comment_record(current) {
                "comment"
            } else {
                "annotation"
            };
            return format!("{category}_part_of_count={}", links.len());
        };
        let Some(parent) = records.get(parent) else {
            return "bearer_record_missing".into();
        };
        current = parent;
    }
    unreachable!()
}

pub(super) fn populate(
    report: &mut Report,
    records: &BTreeMap<String, Record>,
    bearers: &BTreeMap<String, Vec<String>>,
    imported: &BTreeSet<&str>,
) {
    let outside = report
        .refusals
        .iter()
        .filter(|r| r.reason == "record outside current-state importer scope")
        .map(|r| r.id.as_str())
        .collect();
    report.refusal_breakdown = breakdown(&report.refusals, records, bearers, &outside, imported);
    report.counted_breakdown = breakdown(&report.counted, records, bearers, &outside, imported);
    report.live_messages_imported = records
        .values()
        .filter(|r| {
            r.v1_type == "Message" && r.deleted_at.is_none() && imported.contains(r.id.as_str())
        })
        .count();
}

fn breakdown(
    issues: &[Issue],
    records: &BTreeMap<String, Record>,
    bearers: &BTreeMap<String, Vec<String>>,
    outside: &BTreeSet<&str>,
    imported: &BTreeSet<&str>,
) -> Vec<RefusalCount> {
    let mut counts = BTreeMap::new();
    for refusal in issues {
        let record = records.get(&refusal.id);
        let key = (
            record
                .map(|r| record_type(&r.v1_type))
                .unwrap_or("non_record")
                .to_owned(),
            record
                .map(|r| record_kind(r.kind.as_deref()))
                .unwrap_or("none")
                .to_owned(),
            reason(&refusal.reason, record),
            record
                .map(|r| shape(r, records, bearers, outside, imported))
                .unwrap_or_else(|| "non_record".into()),
        );
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(
            |((v1_type, v1_kind, reason_category, shape), count)| RefusalCount {
                v1_type,
                v1_kind,
                reason_category,
                shape,
                count,
            },
        )
        .collect()
}

/// Validation can refuse before a source record graph is available.
pub(super) fn without_source(mut report: Report) -> Report {
    populate(
        &mut report,
        &BTreeMap::new(),
        &BTreeMap::new(),
        &BTreeSet::new(),
    );
    report
}

/// Allowlisted projection of the CLI report; legacy report identifiers stay private.
pub fn sanitized_report(report: &serde_json::Value) -> serde_json::Value {
    json!({"schema":"native.v2-import-sanitized.v1",
        "importer_build_sha":report["importer_build_sha"].as_str().filter(|sha| *sha == "dev" || (sha.len()==40 && sha.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))),
        "refusal_breakdown":report["refusal_breakdown"],
        "counted_breakdown":report["counted_breakdown"],
        "excluded_deleted":report["excluded_deleted"],
        "excluded_invisible_in_v1":report["excluded_invisible_in_v1"],
        "excluded_invisible_tombstones_verified":report["excluded_invisible_tombstones_verified"],
        "inherited_bearer_tombstones":report["inherited_bearer_tombstones"],
        "total_refusals":report["refusals"].as_array().map(Vec::len),
        "total_review_items":report["review"].as_array().map(Vec::len),
        "capture_complete":report["capture_complete"],"mismatches":report["mismatches"],
        "live_messages_imported":report["live_messages_imported"],
        "derived_replaced":{"attachments":report["derived_replaced"]["attachments"].as_u64().unwrap_or(0),"annotations":report["derived_replaced"]["annotations"].as_u64().unwrap_or(0)}})
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod tests {
    use super::*;
    fn fixture(id: &str, v1_type: &str, kind: &str, deleted: bool) -> Record {
        serde_json::from_value(json!({"id":id,"v1_type":v1_type,"kind":kind,
            "name":"PRIVATE fixture title","body":"PRIVATE fixture body", "home_id":null,
            "owner_id":"PRIVATE owner", "lifecycle":null,"summary":"PRIVATE summary",
            "persistence":"persistent","maturity":null,"last_activity_at":"2026-01-01",
            "created_at":"2026-01-01","updated_at":"2026-01-01","archived":false,
            "policy_anchor_id":null,"deleted_at":if deleted {Some("2026-01-01")} else {None}}))
        .unwrap()
    }
    #[test]
    fn imported_refusal_report_is_counts_only_and_classifies_bearer_dependencies() {
        let records: BTreeMap<_, _> = [
            fixture("PRIVATE deleted", "Document", "note", true),
            fixture("PRIVATE retained", "Document", "artifact", false),
            fixture("PRIVATE child", "Document", "attachment", false),
            fixture("PRIVATE orphan", "Document", "attachment", false),
            fixture("PRIVATE parent", "Annotation", "comment", true),
            fixture("PRIVATE reply", "Annotation", "comment", false),
            fixture(
                "PRIVATE custom",
                "PRIVATE custom type",
                "PRIVATE email@example.org",
                false,
            ),
            fixture("PRIVATE message", "Message", "text", false),
        ]
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect();
        let bearers = BTreeMap::from([
            ("PRIVATE child".into(), vec!["PRIVATE retained".into()]),
            ("PRIVATE reply".into(), vec!["PRIVATE parent".into()]),
        ]);
        let mut report = Report::default();
        for id in ["PRIVATE deleted", "PRIVATE retained", "PRIVATE custom"] {
            report
                .refusals
                .push(issue(id, "record outside current-state importer scope"));
        }
        report.refusals.push(issue(
            "PRIVATE child",
            "derived terminal bearer was not imported",
        ));
        report
            .counted
            .push(issue("PRIVATE orphan", "excluded_invisible_in_v1"));
        report.excluded_invisible_in_v1 = 1;
        report.refusals.push(issue(
            "PRIVATE reply",
            "comment bearer is not exactly one part_of link",
        ));
        report
            .counted
            .push(issue("PRIVATE deleted", "excluded_deleted"));
        report
            .counted
            .push(issue("PRIVATE reply", "inherited_bearer_tombstone"));
        report.excluded_deleted = 1;
        report.inherited_bearer_tombstones = 1;
        populate(
            &mut report,
            &records,
            &bearers,
            &BTreeSet::from(["PRIVATE message"]),
        );
        let mut raw = serde_json::to_value(&report).unwrap();
        raw["capture_complete"] = json!(false);
        let safe = sanitized_report(&raw);
        let encoded = serde_json::to_string(&safe).unwrap();
        for source in records.values() {
            for secret in [
                source.id.as_str(),
                source.name.as_str(),
                source.body.as_deref().unwrap(),
                source.owner_id.as_deref().unwrap(),
                source.summary.as_deref().unwrap(),
            ] {
                assert!(!encoded.contains(secret));
            }
        }
        assert!(!encoded.contains("PRIVATE"));
        let mut early = Report::default();
        early.refusals.push(issue(
            "PRIVATE validation subject",
            "source identity differs",
        ));
        let early = without_source(early);
        assert_eq!(early.refusal_breakdown.len(), 1);
        assert_eq!(early.refusal_breakdown[0].v1_type, "non_record");
        assert_eq!(early.refusal_breakdown[0].count, 1);
        assert!(!serde_json::to_string(&early.refusal_breakdown)
            .unwrap()
            .contains("PRIVATE"));
        assert_eq!(safe["total_refusals"], 5);
        assert_eq!(safe["excluded_invisible_in_v1"], 1);
        assert_eq!(safe["excluded_deleted"], 1);
        assert_eq!(safe["inherited_bearer_tombstones"], 1);
        assert_eq!(
            report
                .counted_breakdown
                .iter()
                .map(|r| r.count)
                .sum::<usize>(),
            3
        );
        assert_eq!(safe["live_messages_imported"], 1);
        for shape in [
            "bearer_outside_scope:retained_artifact",
            "attachment_part_of_count=0",
            "reply_parent_tombstoned",
        ] {
            assert!(report
                .refusal_breakdown
                .iter()
                .chain(&report.counted_breakdown)
                .any(|r| r.shape == shape && r.count == 1));
        }
        assert_eq!(
            report
                .refusal_breakdown
                .iter()
                .map(|r| r.count)
                .sum::<usize>(),
            report.refusals.len()
        );
        assert!(report
            .refusal_breakdown
            .iter()
            .any(|r| r.reason_category == "outside_scope_deleted"));
        assert!(report
            .refusal_breakdown
            .iter()
            .any(|r| r.reason_category == "outside_scope_retained_artifact"));
    }
    #[test]
    fn imported_refusal_derived_shapes_distinguish_ambiguity_cycle_missing_parent_and_depth() {
        let mut records = BTreeMap::new();
        let mut bearers = BTreeMap::new();
        for depth in 0..=crate::authorization::MAX_DERIVED_BEARER_DEPTH + 1 {
            let id = format!("private-{depth}");
            records.insert(id.clone(), fixture(&id, "Annotation", "comment", false));
            bearers.insert(id, vec![format!("private-{}", depth + 1)]);
        }
        let check = |records: &BTreeMap<String, Record>,
                     bearers: &BTreeMap<String, Vec<String>>| {
            shape(
                &records["private-0"],
                records,
                bearers,
                &BTreeSet::new(),
                &BTreeSet::new(),
            )
        };
        assert_eq!(check(&records, &bearers), "comment_chain_depth_exceeded");
        bearers.insert("private-0".into(), vec!["private-0".into()]);
        assert_eq!(check(&records, &bearers), "bearer_chain_cycle");
        bearers.insert("private-0".into(), vec!["absent".into()]);
        assert_eq!(check(&records, &bearers), "bearer_record_missing");
        bearers.insert(
            "private-0".into(),
            vec!["private-1".into(), "private-2".into()],
        );
        assert_eq!(check(&records, &bearers), "comment_part_of_count=2");
    }
}
