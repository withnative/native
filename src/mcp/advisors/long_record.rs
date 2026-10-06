//! Long-record nudge as an in-process [`Advisor`](super::Advisor).
//!
//! Ports the `decide_task_body_advisory` trigger from the write-path
//! experiment onto the S1 post-commit hook, with configurable milestones.

use std::sync::Arc;

use futures::future::BoxFuture;

use super::manifest::AdvisorManifest;
use super::{AdviceContext, Advisor, Advisory, AdvisoryLevel, ADVISOR_BODY_REVISIONS_CAP};
use crate::error::Result;

/// Default milestones (body characters) ported verbatim from the source
/// `TASK_BODY_ADVISORY_MILESTONES`: doubling bands keep the nudge rare.
pub const DEFAULT_MILESTONES: [usize; 3] = [40_000, 80_000, 160_000];

/// Default minimum body-bearing revisions ported verbatim from the source
/// `TASK_BODY_ADVISORY_MIN_REVISIONS`: short-lived drafts never see it.
pub const DEFAULT_MIN_REVISIONS: usize = 5;

/// Advisory code emitted by [`LongRecordAdvisor`] for a long `WorkItem`/task.
pub const LONG_RECORD_CODE: &str = "task_body_length_advisory";

/// Advisory code emitted for a long `Document`/note body. The note nudge is
/// the same trigger as [`LONG_RECORD_CODE`] with note-appropriate wording.
pub const NOTE_LONG_RECORD_CODE: &str = "note_body_length_advisory";

/// Advisory code for the repeated same-run append signal: a run that makes four
/// or more consecutive same-run append transitions (five body-bearing
/// revisions) in the append window is re-sending a growing body in pieces.
/// The heuristic is body-shape only (strictly longer and a prefix), so a chain
/// of growing `body_set` replacements triggers it too, not just `body_append`.
pub const REPEATED_APPEND_CODE: &str = "body_append_pieces_advisory";

/// How many consecutive same-run append transitions trigger
/// [`REPEATED_APPEND_CODE`]. Each transition is a pair of body-bearing
/// revisions, so this needs five rows: the base revision plus four appends.
pub const REPEATED_APPEND_MIN: i64 = 4;

/// The repeated-append advisory message. It covers both `body_append` uploads
/// and growing `body_set` chains, because the trigger is body shape, not the
/// named operation.
pub const REPEATED_APPEND_MESSAGE: &str = "This document has been re-sent in growing pieces several times; each write re-stores the whole body, so send the finished document once with body_set.";

/// Configurable thresholds for [`LongRecordAdvisor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LongRecordSettings {
    pub milestones: Vec<usize>,
    pub min_revisions: usize,
}

impl Default for LongRecordSettings {
    fn default() -> Self {
        Self {
            milestones: DEFAULT_MILESTONES.to_vec(),
            min_revisions: DEFAULT_MIN_REVISIONS,
        }
    }
}

impl LongRecordSettings {
    /// Parse optional `{"milestones":[..],"min_revisions":n}`.
    /// Missing fields fall back to defaults; invalid shapes warn on
    /// `native::advisors` and return defaults. Milestones sort
    /// ascending and dedupe so banding stays well-defined.
    pub fn from_value(value: &serde_json::Value) -> Self {
        let defaults = Self::default();
        let Some(obj) = value.as_object() else {
            return defaults;
        };
        if obj.is_empty() {
            return defaults;
        }
        let mut milestones = defaults.milestones.clone();
        let mut min_revisions = defaults.min_revisions;
        let mut invalid = false;
        if let Some(raw) = obj.get("milestones") {
            match raw.as_array() {
                Some(items) => {
                    let mut parsed = Vec::with_capacity(items.len());
                    for item in items {
                        match item.as_u64() {
                            Some(n) => parsed.push(n as usize),
                            None => {
                                invalid = true;
                                break;
                            }
                        }
                    }
                    if invalid || parsed.is_empty() {
                        invalid = true;
                    } else {
                        parsed.sort_unstable();
                        parsed.dedup();
                        milestones = parsed;
                    }
                }
                None => invalid = true,
            }
        }
        if let Some(raw) = obj.get("min_revisions") {
            match raw.as_u64() {
                Some(n) => min_revisions = n as usize,
                None => invalid = true,
            }
        }
        if invalid {
            tracing::warn!(
                target: "native::advisors",
                settings = %value,
                "invalid long_record settings; using defaults"
            );
            return Self::default();
        }
        // The hook context caps the revision count at
        // `ADVISOR_BODY_REVISIONS_CAP`; a larger minimum could never fire,
        // so clamp (with a warn) rather than install a dead advisor.
        let cap = ADVISOR_BODY_REVISIONS_CAP as usize;
        if min_revisions > cap {
            tracing::warn!(
                target: "native::advisors",
                min_revisions = min_revisions,
                cap = cap,
                "long_record min_revisions exceeds the context revision cap; clamping"
            );
            min_revisions = cap;
        }
        Self {
            milestones,
            min_revisions,
        }
    }

    /// Alias kept for the task brief's `from_settings` naming.
    pub fn from_settings(value: &serde_json::Value) -> Self {
        Self::from_value(value)
    }
}

/// Band of a body length over the configured milestones: 0 below the
/// first milestone, then one band per milestone reached.
pub fn band(body_chars: usize, settings: &LongRecordSettings) -> usize {
    settings
        .milestones
        .iter()
        .filter(|milestone| body_chars >= **milestone)
        .count()
}

/// Cheap stateless gate: the new body must enter a higher milestone band
/// than the old one. Growth within a band, shrinks and clears never
/// cross, while shrink-then-regrow crosses again.
pub fn milestone_entered(
    old_chars: usize,
    new_chars: usize,
    settings: &LongRecordSettings,
) -> Option<usize> {
    let new_band = band(new_chars, settings);
    if new_band > 0 && new_band > band(old_chars, settings) {
        Some(settings.milestones[new_band - 1])
    } else {
        None
    }
}

/// A due trigger decision: the advisory code, the human message, and the
/// machine-readable numbers (the old warning's `milestone_chars`,
/// `body_chars`, `body_bearing_revisions_at_least`).
pub struct Decision {
    pub code: String,
    pub message: String,
    pub milestone_chars: usize,
    pub body_chars: usize,
    pub revisions: usize,
}

/// Self-contained trigger decision, behaviour-identical to the source
/// `decide_task_body_advisory` at default settings. Returns the decision
/// when due, `None` when suppressed.
pub fn decide(
    record_type: &str,
    kind: Option<&str>,
    old_chars: usize,
    new_chars: usize,
    revisions: usize,
    settings: &LongRecordSettings,
) -> Option<Decision> {
    let (code, subject, closing_noun) = match (record_type, kind) {
        ("WorkItem", Some("task")) => (LONG_RECORD_CODE, "Task body", "artifact"),
        ("Document", Some("note")) => (NOTE_LONG_RECORD_CODE, "Note body", "document"),
        _ => return None,
    };
    let milestone_chars = milestone_entered(old_chars, new_chars, settings)?;
    if revisions < settings.min_revisions {
        return None;
    }
    Some(Decision {
        code: code.to_owned(),
        message: format!(
            "{subject} crossed {milestone_chars} characters ({new_chars} chars after at least {revisions} body-bearing revisions). Advisory only: if a section has its own subject or deliverable, consider moving it to a titled linked record and leaving a concise synthesis here. If linked records already carry those subjects, or this is one coherent {closing_noun}, keep it as is. There is no hard cap and nothing is auto-split.",
        ),
        milestone_chars,
        body_chars: new_chars,
        revisions,
    })
}

/// In-process advisor watching `update_record` on `WorkItem`/`task`.
/// The watch gate is hardcoded (the nudge is a task-body nudge by
/// definition; `decide` gates type/kind again), so a manifest's `watches`
/// only documents the default — `settings` is the live override.
pub struct LongRecordAdvisor {
    id: String,
    version: String,
    manifest_digest: Option<String>,
    settings: LongRecordSettings,
}

impl LongRecordAdvisor {
    pub fn new(settings: LongRecordSettings) -> Self {
        Self {
            id: "native.long_record".to_owned(),
            version: "0.1.0".to_owned(),
            manifest_digest: None,
            settings,
        }
    }

    pub fn from_settings(value: &serde_json::Value) -> Self {
        Self::new(LongRecordSettings::from_value(value))
    }

    /// Bind manifest identity (id/version/digest) around manifest settings,
    /// for the `builtin:long_record` install path.
    pub fn for_manifest(manifest: &AdvisorManifest, manifest_digest: &str) -> Self {
        let settings = manifest
            .settings
            .as_ref()
            .map(LongRecordSettings::from_value)
            .unwrap_or_default();
        Self {
            id: manifest.id.clone(),
            version: manifest.version.clone(),
            manifest_digest: Some(manifest_digest.to_owned()),
            settings,
        }
    }
}

impl Advisor for LongRecordAdvisor {
    fn id(&self) -> &str {
        &self.id
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn watches(&self, tool: &str, record_type: &str, record_kind: &str) -> bool {
        tool == "update_record"
            && ((record_type == "WorkItem" && record_kind == "task")
                || (record_type == "Document" && record_kind == "note"))
    }

    fn needs_body_change(&self) -> bool {
        // A body-untouched write leaves before_chars == after_chars, which
        // can never enter a new milestone band.
        true
    }

    fn advise<'a>(&'a self, ctx: &'a AdviceContext) -> BoxFuture<'a, Result<Vec<Advisory>>> {
        Box::pin(async move {
            let mut advisories = Vec::new();
            // Length nudge: task and note bodies crossing a milestone band.
            if let (Some(before), Some(after), Some(revisions)) = (
                ctx.body_chars_before,
                ctx.body_chars_after,
                ctx.recent_body_revisions,
            ) {
                // The source counted revisions up to 5 while the hook context
                // caps the count at 10 (`ADVISOR_BODY_REVISIONS_CAP`); the
                // `revisions >= min_revisions` comparison works either way.
                // The source ran the band gate before the revision query; here
                // the context already carries both, so order is irrelevant.
                if before >= 0 && after >= 0 && revisions >= 0 {
                    let kind = if ctx.record_kind.is_empty() {
                        None
                    } else {
                        Some(ctx.record_kind.as_str())
                    };
                    if let Some(decision) = decide(
                        &ctx.record_type,
                        kind,
                        before as usize,
                        after as usize,
                        revisions as usize,
                        &self.settings,
                    ) {
                        advisories.push(Advisory {
                            advisor_id: self.id.clone(),
                            version: self.version.clone(),
                            manifest_digest: self.manifest_digest.clone(),
                            code: decision.code,
                            record_id: ctx.record_id.clone(),
                            message: decision.message,
                            level: AdvisoryLevel::Advise,
                            details: Some(serde_json::json!({
                                "milestone_chars": decision.milestone_chars,
                                "body_chars": decision.body_chars,
                                "body_bearing_revisions_at_least": decision.revisions,
                            })),
                        });
                    }
                }
            }
            // Repeated same-run append nudge: independent of body length. The
            // detail counts append transitions (pairs), not rows.
            if let Some(streak) = ctx.recent_same_run_append_streak {
                if streak >= REPEATED_APPEND_MIN {
                    advisories.push(Advisory {
                        advisor_id: self.id.clone(),
                        version: self.version.clone(),
                        manifest_digest: self.manifest_digest.clone(),
                        code: REPEATED_APPEND_CODE.to_owned(),
                        record_id: ctx.record_id.clone(),
                        message: REPEATED_APPEND_MESSAGE.to_owned(),
                        level: AdvisoryLevel::Advise,
                        details: Some(serde_json::json!({ "same_run_append_transitions": streak })),
                    });
                }
            }
            Ok(advisories)
        })
    }
}

/// Registry constructor for S4's builtin registry (`builtin:long_record`).
pub fn long_record_builtin(settings: &serde_json::Value) -> Arc<dyn Advisor> {
    Arc::new(LongRecordAdvisor::from_settings(settings))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn defaults() -> LongRecordSettings {
        LongRecordSettings::default()
    }

    fn demo() -> LongRecordSettings {
        LongRecordSettings::from_value(&json!({"milestones": [15000, 30000], "min_revisions": 3}))
    }

    #[test]
    fn decision_fires_only_for_task_band_crossing_with_enough_revisions() {
        let s = defaults();
        let hit = decide("WorkItem", Some("task"), 10, 40_000, 5, &s).unwrap();
        assert_eq!(hit.code, LONG_RECORD_CODE);
        assert!(hit.message.contains("40000"));
        assert_eq!(hit.milestone_chars, 40_000);
        assert_eq!(hit.body_chars, 40_000);
        assert_eq!(hit.revisions, 5);
        assert!(decide("WorkItem", Some("task"), 40_000, 50_000, 9, &s).is_none());
        assert!(decide("WorkItem", Some("task"), 50_000, 10, 9, &s).is_none());
        assert!(decide("WorkItem", Some("task"), 50_000, 0, 9, &s).is_none());
        assert!(decide("WorkItem", Some("task"), 10, 40_000, 4, &s).is_none());
        let note = decide("Document", Some("note"), 10, 40_000, 9, &s).unwrap();
        assert_eq!(note.code, NOTE_LONG_RECORD_CODE);
        assert!(note
            .message
            .starts_with("Note body crossed 40000 characters"));
        assert!(note.message.contains("one coherent document"));
        // Note wording must not leak the task noun.
        assert!(!note.message.contains("one coherent artifact"));
        assert!(decide("Document", Some("artifact"), 10, 40_000, 9, &s).is_none());
        assert!(decide("Document", None, 10, 40_000, 9, &s).is_none());
        assert!(decide("WorkItem", Some("epic"), 10, 40_000, 9, &s).is_none());
        assert!(decide("WorkItem", None, 10, 40_000, 9, &s).is_none());
        let second = decide("WorkItem", Some("task"), 41_000, 81_000, 9, &s).unwrap();
        assert!(second.message.contains("80000"));
        assert_eq!(second.milestone_chars, 80_000);
        let jump = decide("WorkItem", Some("task"), 10, 200_000, 9, &s).unwrap();
        assert!(jump.message.contains("160000"));
        assert_eq!(jump.milestone_chars, 160_000);
    }

    #[test]
    fn message_text_matches_source_verbatim() {
        let s = defaults();
        let decision = decide("WorkItem", Some("task"), 10, 40_000, 5, &s).unwrap();
        let message = decision.message;
        assert_eq!(
            message,
            "Task body crossed 40000 characters (40000 chars after at least 5 body-bearing revisions). Advisory only: if a section has its own subject or deliverable, consider moving it to a titled linked record and leaving a concise synthesis here. If linked records already carry those subjects, or this is one coherent artifact, keep it as is. There is no hard cap and nothing is auto-split."
        );
    }

    #[test]
    fn note_message_text_is_note_specific_verbatim() {
        let s = defaults();
        let decision = decide("Document", Some("note"), 10, 40_000, 5, &s).unwrap();
        assert_eq!(
            decision.message,
            "Note body crossed 40000 characters (40000 chars after at least 5 body-bearing revisions). Advisory only: if a section has its own subject or deliverable, consider moving it to a titled linked record and leaving a concise synthesis here. If linked records already carry those subjects, or this is one coherent document, keep it as is. There is no hard cap and nothing is auto-split."
        );
    }

    #[test]
    fn demo_settings_crossing_fires_on_third_revision() {
        let s = demo();
        assert_eq!(s.min_revisions, 3);
        let hit = decide("WorkItem", Some("task"), 10, 15_000, 3, &s).unwrap();
        assert!(hit.message.contains("15000"));
        assert!(decide("WorkItem", Some("task"), 10, 15_000, 2, &s).is_none());
        assert!(decide("WorkItem", Some("task"), 15_000, 20_000, 9, &s).is_none());
        let regrow = decide("WorkItem", Some("task"), 10, 16_000, 9, &s).unwrap();
        assert!(regrow.message.contains("15000"));
    }

    #[test]
    fn settings_parsing_missing_or_invalid_yields_defaults() {
        assert_eq!(LongRecordSettings::from_value(&json!(null)), defaults());
        assert_eq!(LongRecordSettings::from_value(&json!({})), defaults());
        assert_eq!(
            LongRecordSettings::from_value(&json!({"milestones": "x"})),
            defaults()
        );
        assert_eq!(
            LongRecordSettings::from_value(&json!({"milestones": [1], "min_revisions": "x"})),
            defaults()
        );
        let sorted = LongRecordSettings::from_value(
            &json!({"milestones": [30000, 15000, 15000], "min_revisions": 3}),
        );
        assert_eq!(sorted.milestones, vec![15000, 30000]);
        assert_eq!(sorted.min_revisions, 3);
    }

    #[test]
    fn min_revisions_above_context_cap_clamps() {
        let clamped = LongRecordSettings::from_value(&json!({"min_revisions": 11}));
        assert_eq!(clamped.min_revisions, 10);
        assert_eq!(clamped.milestones, defaults().milestones);
        // At the cap it can still fire; above it never could.
        let s = LongRecordSettings::from_value(&json!({"min_revisions": 10}));
        assert_eq!(s.min_revisions, 10);
        assert!(decide("WorkItem", Some("task"), 10, 40_000, 10, &s).is_some());
    }

    fn advisories_of(receipt: &serde_json::Value) -> Vec<&serde_json::Value> {
        receipt
            .get("advisories")
            .and_then(serde_json::Value::as_array)
            .map(|items| items.iter().collect())
            .unwrap_or_default()
    }

    fn advisory(result: &serde_json::Value) -> Option<&serde_json::Value> {
        advisory_code(result, LONG_RECORD_CODE)
    }

    fn advisory_code<'a>(
        result: &'a serde_json::Value,
        code: &str,
    ) -> Option<&'a serde_json::Value> {
        advisories_of(result)
            .into_iter()
            .find(|item| item.get("code").and_then(serde_json::Value::as_str) == Some(code))
    }

    fn run_caller(run: &str) -> crate::mcp::Caller {
        crate::mcp::Caller::local().with_run_context(Some(run.to_owned()), None)
    }

    /// Two shape-valid run keys (handle-disambiguator-run_id); any legal key is
    /// accepted, so the advisor path sees exactly the run we name.
    const RUN_A: &str = "scout-chair-a748b2";
    const RUN_B: &str = "scout-chair-b748b2";

    async fn append(
        registry: &crate::mcp::ToolRegistry,
        db: &crate::Db,
        caller: crate::mcp::Caller,
        run: &str,
        id: &str,
        text: &str,
    ) -> serde_json::Value {
        registry
            .call(
                db.clone(),
                caller,
                "update_record",
                json!({ "id": id, "body_append": text, "run_key": run, "reason": "advisory fixture" }),
            )
            .await
            .unwrap()
    }

    fn big(chars: usize) -> String {
        "x".repeat(chars)
    }

    async fn setup() -> (crate::Db, crate::mcp::ToolRegistry) {
        let db = crate::create_database(":memory:").await.unwrap();
        // Presence assertions, not budget assertions: run generous so a
        // loaded runner cannot flip them into silence. Budget behaviour
        // stays pinned by the slow-advisor tests, which never opt in.
        db.advisors()
            .set_test_timeout_ms(super::super::TEST_ADVISOR_BUDGET_MS);
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    /// No manual registration: every Db carries the default long-record
    /// install, so these prove the default path end to end.
    async fn create_fixture(
        registry: &crate::mcp::ToolRegistry,
        db: &crate::Db,
        record_type: &str,
        kind: &str,
        body: &str,
    ) -> String {
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": record_type,
                    "kind": kind,
                    "name": "advisory probe",
                    "body": body,
                    "reason": "advisory fixture",
                }),
            )
            .await
            .unwrap();
        assert!(
            advisory(&created).is_none(),
            "create never advises: {created}"
        );
        created["id"].as_str().unwrap().to_string()
    }

    async fn set_body(
        registry: &crate::mcp::ToolRegistry,
        db: &crate::Db,
        id: &str,
        body: &str,
    ) -> serde_json::Value {
        // Whole-body writes on a non-empty body require the current digest.
        let digest = current_digest(db, id).await;
        registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "body_set": body, "if_body_digest": digest, "reason": "advisory fixture" }),
            )
            .await
            .unwrap()
    }

    async fn current_digest(db: &crate::Db, id: &str) -> String {
        let current: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        crate::mcp::tools::lifecycle::body_digest(current.as_deref())
    }

    async fn set_body_as(
        registry: &crate::mcp::ToolRegistry,
        db: &crate::Db,
        run: &str,
        id: &str,
        body: Option<&str>,
    ) -> serde_json::Value {
        let digest = current_digest(db, id).await;
        registry
            .call(
                db.clone(),
                run_caller(run),
                "update_record",
                json!({ "id": id, "body_set": body, "if_body_digest": digest, "run_key": run, "reason": "advisory fixture" }),
            )
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn update_crossing_demo_milestone_advises_exactly_once() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        db.advisors().register(long_record_builtin(
            &json!({"milestones": [15000, 30000], "min_revisions": 3}),
        ));
        let created = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "create_record",
                json!({
                    "type": "WorkItem", "kind": "task",
                    "name": "long probe", "body": "seed",
                    "reason": "long-record e2e",
                }),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        let first = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({"id": id, "body_append": " more", "reason": "long-record e2e"}),
            )
            .await
            .unwrap();
        assert!(advisories_of(&first).is_empty());
        let big = "x".repeat(15_005);
        let crossed = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({"id": id, "body_append": big, "reason": "long-record e2e"}),
            )
            .await
            .unwrap();
        let found = advisories_of(&crossed);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0]["code"], json!("task_body_length_advisory"));
        assert_eq!(found[0]["advisor_id"], json!("native.long_record"));
        db.close().await;
    }

    #[tokio::test]
    async fn crossing_first_milestone_advises_on_fifth_body_revision() {
        let (db, registry) = setup().await;
        let id = create_fixture(&registry, &db, "WorkItem", "task", "seed").await;
        for n in 0..3 {
            let updated = set_body(&registry, &db, &id, &format!("seed {n}")).await;
            assert!(advisory(&updated).is_none(), "gate needs five revisions");
        }
        let crossed = set_body(&registry, &db, &id, &big(41_000)).await;
        let found = advisory(&crossed).expect("fifth body revision crosses 40k");
        assert!(found["message"].as_str().unwrap().contains("40000"));
        assert_eq!(found["advisor_id"], json!("native.long_record"));
        assert_eq!(found["details"]["milestone_chars"], json!(40_000));
        assert_eq!(found["details"]["body_chars"], json!(41_000));
        db.close().await;
    }

    #[tokio::test]
    async fn below_revision_gate_stays_silent() {
        let (db, registry) = setup().await;
        let id = create_fixture(&registry, &db, "WorkItem", "task", "seed").await;
        set_body(&registry, &db, &id, "seed 1").await;
        let crossed = set_body(&registry, &db, &id, &big(41_000)).await;
        assert!(advisory(&crossed).is_none(), "only three body revisions");
        db.close().await;
    }

    #[tokio::test]
    async fn field_only_update_stays_silent_and_notes_are_nudged() {
        let (db, registry) = setup().await;
        let id = create_fixture(&registry, &db, "WorkItem", "task", "seed").await;
        for n in 0..4 {
            set_body(&registry, &db, &id, &format!("seed {n}")).await;
        }
        let touched = registry
            .call(
                db.clone(),
                crate::mcp::Caller::local(),
                "update_record",
                json!({ "id": id, "summary": "still small", "reason": "advisory fixture" }),
            )
            .await
            .unwrap();
        assert!(
            advisory(&touched).is_none(),
            "field-only update never advises"
        );
        // A Document/note now receives the same length nudge as a task, with
        // note-appropriate wording and its own code.
        let note = create_fixture(&registry, &db, "Document", "note", "seed").await;
        for n in 0..4 {
            set_body(&registry, &db, &note, &format!("seed {n}")).await;
        }
        let crossed = set_body(&registry, &db, &note, &big(41_000)).await;
        let found =
            advisory_code(&crossed, NOTE_LONG_RECORD_CODE).expect("note crosses the 40k milestone");
        assert!(found["message"].as_str().unwrap().contains("Note body"));
        assert!(
            advisory(&crossed).is_none(),
            "note never uses the task code"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn same_run_rapid_appends_advise() {
        let (db, registry) = setup().await;
        let caller = run_caller(RUN_A);
        let created = registry
            .call(
                db.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note",
                    "name": "append probe", "body": "a",
                    "run_key": RUN_A,
                    "reason": "advisory fixture",
                }),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        // Three same-run appends are below the four-append trigger.
        for piece in ["b", "c", "d"] {
            let out = append(&registry, &db, caller.clone(), RUN_A, &id, piece).await;
            assert!(
                advisory_code(&out, REPEATED_APPEND_CODE).is_none(),
                "streak below four stays silent: {out}"
            );
        }
        let out = append(&registry, &db, caller.clone(), RUN_A, &id, "e").await;
        let found = advisory_code(&out, REPEATED_APPEND_CODE).expect("fourth append advises");
        assert_eq!(found["advisor_id"], json!("native.long_record"));
        assert!(found["message"]
            .as_str()
            .unwrap()
            .contains("re-sent in growing pieces"));
        assert_eq!(found["details"]["same_run_append_transitions"], json!(4));
        db.close().await;
    }

    #[tokio::test]
    async fn a_different_run_does_not_inherit_the_append_streak() {
        let (db, registry) = setup().await;
        let caller = run_caller(RUN_A);
        let created = registry
            .call(
                db.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note",
                    "name": "append probe", "body": "a",
                    "run_key": RUN_A,
                    "reason": "advisory fixture",
                }),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        for piece in ["b", "c", "d"] {
            let out = append(&registry, &db, caller.clone(), RUN_A, &id, piece).await;
            assert!(advisory_code(&out, REPEATED_APPEND_CODE).is_none());
        }
        // A new run has a one-revision same-run history, so no trigger.
        let out = append(&registry, &db, caller, RUN_B, &id, "e").await;
        assert!(
            advisory_code(&out, REPEATED_APPEND_CODE).is_none(),
            "a different run does not inherit another run's appends: {out}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn non_append_edits_do_not_trigger_the_append_advisory() {
        let (db, registry) = setup().await;
        let caller = run_caller(RUN_A);
        let created = registry
            .call(
                db.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note",
                    "name": "append probe", "body": "a",
                    "run_key": RUN_A,
                    "reason": "advisory fixture",
                }),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        // Same run, many revisions, but each body_set replaces rather than
        // extends the previous body: the streak never accumulates.
        for n in 0..6 {
            let out = registry
                .call(
                    db.clone(),
                    caller.clone(),
                    "update_record",
                    json!({ "id": id, "body_set": format!("replacement {n}"), "if_body_digest": current_digest(&db, &id).await, "run_key": RUN_A, "reason": "advisory fixture" }),
                )
                .await
                .unwrap();
            assert!(
                advisory_code(&out, REPEATED_APPEND_CODE).is_none(),
                "non-append edit must not trigger: {out}"
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn a_body_clear_breaks_the_append_streak() {
        let (db, registry) = setup().await;
        let caller = run_caller(RUN_A);
        let created = registry
            .call(
                db.clone(),
                caller.clone(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note",
                    "name": "clear probe", "body": "abc",
                    "run_key": RUN_A,
                    "reason": "advisory fixture",
                }),
            )
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap().to_owned();
        // Clear the body, then grow a new body that begins with the old one.
        // Without clear handling the chain would bridge the clear and reach
        // four transitions; with it, only the three appends after the clear.
        set_body_as(&registry, &db, RUN_A, &id, None).await;
        set_body_as(&registry, &db, RUN_A, &id, Some("abcd")).await;
        for piece in ["e", "f", "g"] {
            let out = append(&registry, &db, caller.clone(), RUN_A, &id, piece).await;
            assert!(
                advisory_code(&out, REPEATED_APPEND_CODE).is_none(),
                "a body clear must break the streak: {out}"
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn within_band_silent_but_recross_and_next_milestone_advise() {
        let (db, registry) = setup().await;
        let id = create_fixture(&registry, &db, "WorkItem", "task", "seed").await;
        for n in 0..3 {
            set_body(&registry, &db, &id, &format!("seed {n}")).await;
        }
        set_body(&registry, &db, &id, &big(41_000)).await;
        let grown = set_body(&registry, &db, &id, &big(50_000)).await;
        assert!(
            advisory(&grown).is_none(),
            "growth within one band stays silent"
        );
        let shrunk = set_body(&registry, &db, &id, "small").await;
        assert!(advisory(&shrunk).is_none(), "shrink stays silent");
        let recrossed = set_body(&registry, &db, &id, &big(42_000)).await;
        assert!(
            advisory(&recrossed).is_some(),
            "shrink-then-regrow advises again"
        );
        let next = set_body(&registry, &db, &id, &big(81_000)).await;
        let found = advisory(&next).expect("80k band crossing advises");
        assert!(found["message"].as_str().unwrap().contains("80000"));
        db.close().await;
    }

    #[tokio::test]
    async fn advisor_lookup_failure_cannot_fail_the_write() {
        let (db, _registry) = setup().await;
        // A closed pool makes the optional post-commit context read fail.
        // The hook swallows it and yields no advisories, never an error.
        db.close().await;
        let out = super::super::advisories_for_write(
            &db,
            "update_record",
            "missing",
            "WorkItem",
            "task",
            true,
            None,
            Some(0),
            None,
            true,
        )
        .await;
        assert!(out.is_none(), "failed lookup cannot add advice");
        db.close().await;
    }

    async fn setup_on_disk(
        dir: &tempfile::TempDir,
        file: &str,
    ) -> (crate::Db, crate::mcp::ToolRegistry) {
        let path = dir.path().join(file);
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        db.advisors()
            .set_test_timeout_ms(super::super::TEST_ADVISOR_BUDGET_MS);
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        (db, registry)
    }

    #[tokio::test]
    async fn on_disk_database_advises_without_registration() {
        let directory = tempfile::tempdir().unwrap();
        let (db, registry) = setup_on_disk(&directory, "long-record.db").await;
        // No manual registration: the on-disk constructor installs defaults.
        let id = create_fixture(&registry, &db, "WorkItem", "task", "seed").await;
        for n in 0..3 {
            set_body(&registry, &db, &id, &format!("seed {n}")).await;
        }
        let crossed = set_body(&registry, &db, &id, &big(41_000)).await;
        let found = advisory(&crossed).expect("on-disk fifth revision crosses 40k");
        assert_eq!(found["advisor_id"], json!("native.long_record"));
        assert_eq!(found["details"]["milestone_chars"], json!(40_000));
        db.close().await;
    }

    #[tokio::test]
    async fn reopened_database_keeps_default_and_advises_at_80k() {
        let directory = tempfile::tempdir().unwrap();
        let (db, registry) = setup_on_disk(&directory, "long-record-reopen.db").await;
        let id = create_fixture(&registry, &db, "WorkItem", "task", "seed").await;
        for n in 0..3 {
            set_body(&registry, &db, &id, &format!("seed {n}")).await;
        }
        set_body(&registry, &db, &id, &big(41_000)).await;
        db.close().await;
        let path = directory.path().join("long-record-reopen.db");
        let reopened = crate::db::open_existing_database_at(&path).await.unwrap();
        assert!(
            reopened
                .advisors()
                .watches("update_record", "WorkItem", "task"),
            "reopened database must carry native.long_record"
        );
        let next = set_body(&registry, &reopened, &id, &big(81_000)).await;
        let found = advisory(&next).expect("reopened database crosses 80k");
        assert_eq!(found["details"]["milestone_chars"], json!(80_000));
        reopened.close().await;
    }
}
