//! Shared keyed-replay seam for engine writes (task 8bef361, design 515067b
//! §4, slice A0).
//!
//! The store already exists: every governed commit attests its outputs with
//! the dispatch's `sha256(idempotency_key)`, and the UNIQUE
//! `(principal, operation, key digest)` authority index refuses a second keyed
//! commit. This module is the part each write shares on top of that store:
//! accepting the key, finding the original command, and handing the tool's
//! replay renderer what it needs to rebuild the original receipt.
//!
//! # Contract for a wired write
//!
//! 1. **Accept the key.** Parse an optional `idempotency_key`, check it with
//!    [`idempotency_key`], and advertise [`idempotency_key_schema`]. List the
//!    tool (and action) in [`KEYED_REPLAY_WRITES`] so non-SQLite engines
//!    refuse it plainly instead of failing on an unknown field.
//! 2. **Look up inside the handler's transaction.** Open the write
//!    transaction (`BEGIN IMMEDIATE`), finish the handler's own authorization,
//!    then call [`keyed_replay_in`] with the exact handler arguments. This is
//!    the `create_record` ordering: the lookup cannot become a
//!    command-existence oracle, and a concurrent duplicate serializes on
//!    `BEGIN` and replays rather than racing. Call it **before** any state
//!    precondition (CAS guards, "already removed", ownership-of-current-state
//!    checks): those describe the world the first call changed, and a retry
//!    must not be judged against them.
//! 3. **Render a hit from the attestation, then return without writing.**
//!    The replay renderer builds the tool's normal receipt from
//!    [`KeyedReplay`] — the command's own outputs, act and pinned
//!    `previous_seq` — not from the request's view of live state. It
//!    re-checks access to anything it discloses, then calls
//!    [`KeyedReplay::settle`]. A key reused with different normalized
//!    arguments or under a different resolved intent never reaches the
//!    renderer: the lookup refuses it as `idempotency_conflict`.
//! 4. **On a miss, run unchanged and commit once.** Call [`anchor_noop_in`]
//!    in the write transaction immediately before commit, so a keyed write
//!    that changed nothing still leaves the row a retry finds and replays as
//!    the same no-op. A handler that commits more than once per call cannot
//!    be keyed: its second keyed commit would hit the authority index.
//! 5. **Register through [`with_race_replay`],** which turns the authority
//!    index's unique violation into one replay attempt. Under SQLite's single
//!    writer step 2 makes that race unreachable; this is the backstop.
//! 6. **Keyed receipts carry no live advisory fields** (advisories, the
//!    undeclared-basis pointer, `similar_existing`), on the first call or a
//!    replay, so the two match.
//! 7. **A replay never holds the writer for more than a lookup, and never
//!    outlives one host attempt.** A receipt that must fold history is folded
//!    after the write transaction rolls back, on a read transaction, under
//!    `KEYED_REPLAY_DEADLINE` (5 s, chosen to finish well inside appHost's
//!    10 s per-attempt timeout; the summary fallback after a refused rebuild
//!    has 2 s more). A fold that outruns it fails the call with
//!    [`Error::ReplayBounded`]: HTTP 503, `Retry-After: 1`, `error_code:
//!    REPLAY_BOUND_EXCEEDED`, `retryable: true`, never a 4xx. The write
//!    committed, so the caller retries with the same key. `applied` says how
//!    much is confirmed: `true` for a single write; for `create_many`, which
//!    makes several, `"partial"` with `completed_items` and `total_items`,
//!    because the items after the one that hit the bound were never reached.
//!    `"partial"` is retried with the same key and arguments to resume: the
//!    retry replays what committed and creates each remaining item exactly
//!    once. `true` is not retried by a host that distinguishes the two: its
//!    write is complete, so it is answered as applied without a retry.
//! 8. **Load and state checks follow the replay lookup** — a compile slot, an
//!    artifact being live, a target's kind — like the CAS guards in step 2: a
//!    retry of a committed write must not be refused for a world that moved
//!    on, or a compiler that is busy, after the first call.
//!
//! What a replay pins is the command's own facts: ids, event ids, `act`,
//! `previous_seq`, body/source identity and the operation receipts. Each
//! renderer documents anything it serves from current state instead.

use futures::future::BoxFuture;
use serde_json::{json, Value};
use sqlx::{Row, Sqlite, Transaction};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::registry::Caller;

/// Upper bound on a key, shared with every provenance-keyed tool.
pub(crate) const MAX_IDEMPOTENCY_KEY_CHARS: usize = 200;

/// Why `resolve_external` takes no key: find-or-create by binding already
/// makes a retry resolve the same record without writing again.
pub(crate) const RESOLVE_EXTERNAL_IS_IDEMPOTENT: &str =
    "repeating the same claims resolves the same record without writing again, and reports created:false";

/// Tool actions wired to this seam. `None` means every action of the tool.
pub(crate) const KEYED_REPLAY_WRITES: &[(&str, Option<&[&str]>)] = &[
    ("update_record", None),
    ("manage_links", Some(&["add", "remove"])),
    ("manage_facet_observations", Some(&["set", "unset"])),
    ("archive_record", None),
    ("claim_unowned_record", None),
    ("manage_citations", Some(&["reanchor"])),
    ("manage_attributions", Some(&["retract", "add_evidence"])),
    // Accept is not keyed: see `resolve_suggestions`.
    ("resolve_suggestions", Some(&["reject"])),
    (
        "manage_participants",
        Some(&["register_persona", "retire_persona"]),
    ),
    // `share_history` is not keyed: see `messaging::refuse_share_history_key`.
    (
        "manage_messages",
        Some(&[
            "classify",
            "unclassify",
            "move",
            "mark_no_longer_relevant",
            "unmark_no_longer_relevant",
        ]),
    ),
    ("manage_renderer_binding", Some(&["bind", "unbind"])),
    (
        "manage_artifact_inputs",
        Some(&["bind", "bind_many", "unbind"]),
    ),
    (
        "manage_mdx_modules",
        Some(&["publish", "deprecate", "withdraw"]),
    ),
    ("manage_surface_bindings", Some(&["set", "reset"])),
    // `advance_artifact_port_pin` is not keyed: see its handler.
    ("create_many", None),
    ("instantiate_artifact", None),
    ("attach_from_url", None),
];

/// The one schema fragment every wired write advertises.
pub(crate) fn idempotency_key_schema() -> Value {
    json!({ "type": "string", "minLength": 1, "maxLength": MAX_IDEMPOTENCY_KEY_CHARS })
}

/// Whether `name` with these arguments is a write wired to this seam.
pub(crate) fn is_keyed_replay_write(name: &str, arguments: &Value) -> bool {
    KEYED_REPLAY_WRITES.iter().any(|(tool, actions)| {
        *tool == name
            && actions.is_none_or(|actions| {
                arguments
                    .get("action")
                    .and_then(Value::as_str)
                    .is_some_and(|action| actions.contains(&action))
            })
    })
}

/// Keyed writes are SQLite-only, like `batch_write`: the Postgres adapter has
/// no provenance tables and the Turso-local handlers have no replay path.
/// Refuse a real key by name before the engine's handler sees it. A null or
/// blank key means no key, as on SQLite, so it is dropped here: those
/// handlers do not know the field.
pub(crate) fn refuse_on_engine(name: &str, arguments: &mut Value, engine: &str) -> Result<()> {
    if !is_keyed_replay_write(name, arguments) {
        return Ok(());
    }
    let Some(key) = arguments.get("idempotency_key") else {
        return Ok(());
    };
    let blank = match key {
        Value::Null => true,
        Value::String(key) => key.trim().is_empty(),
        _ => false,
    };
    if !blank {
        return Err(Error::engine(format!(
            "{name}: idempotency_key is supported on the SQLite engine only, not {engine}; retry without it"
        )));
    }
    if let Some(arguments) = arguments.as_object_mut() {
        arguments.remove("idempotency_key");
    }
    Ok(())
}

/// For a write that is idempotent by construction and so takes no key: drop
/// a null or blank key, as everywhere else, and refuse a real one by name
/// rather than with the generic unknown-field error.
pub(crate) fn refuse_key_on_naturally_idempotent_write(
    tool: &str,
    why: &str,
    arguments: &mut Value,
) -> Result<()> {
    let Some(object) = arguments.as_object_mut() else {
        return Ok(());
    };
    match object.get("idempotency_key") {
        None => Ok(()),
        Some(key) if key.is_null() || key.as_str().is_some_and(|key| key.trim().is_empty()) => {
            object.remove("idempotency_key");
            Ok(())
        }
        Some(_) => Err(Error::engine(format!(
            "{tool} does not accept idempotency_key: {why}; retry without a key"
        ))),
    }
}

/// Validate a parsed key. Blank means no key, matching the provenance digest.
pub(crate) fn idempotency_key(tool: &str, key: Option<&str>) -> Result<Option<String>> {
    let Some(key) = key.map(str::trim).filter(|key| !key.is_empty()) else {
        return Ok(None);
    };
    if key.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS {
        return Err(Error::engine(format!(
            "{tool}: idempotency_key must be at most {MAX_IDEMPOTENCY_KEY_CHARS} characters"
        )));
    }
    Ok(Some(key.to_string()))
}

/// One content event the original command appended, in attested order.
#[derive(Clone, Debug)]
pub(crate) struct ContentOutput {
    pub(crate) event_id: String,
    pub(crate) seq: i64,
    pub(crate) record_id: String,
    pub(crate) event_type: String,
    pub(crate) payload: Value,
    pub(crate) created_at: String,
}

/// One relationship event the original command appended, in attested order.
#[derive(Clone, Debug)]
pub(crate) struct RelationshipOutput {
    pub(crate) event_id: String,
    pub(crate) seq: i64,
    pub(crate) stream_kind: String,
    pub(crate) stream_id: String,
    pub(crate) relationship_origin_db_id: String,
    pub(crate) relationship_id: String,
    pub(crate) issuer_origin_db_id: String,
}

/// What a replay renderer receives: the original command's attestation and
/// everything it appended. An anchor (a keyed no-op) has no outputs and no
/// act.
#[derive(Debug)]
pub(crate) struct KeyedReplay {
    attestation_id: String,
    act: Option<i64>,
    content: Vec<ContentOutput>,
    relationship: Vec<RelationshipOutput>,
}

impl KeyedReplay {
    /// The original command changed nothing; it left only an anchor.
    pub(crate) fn is_noop(&self) -> bool {
        self.content.is_empty() && self.relationship.is_empty()
    }

    pub(crate) fn attestation_id(&self) -> &str {
        &self.attestation_id
    }

    /// The act the original command allocated; `None` only for a no-op.
    pub(crate) fn act(&self) -> Option<i64> {
        self.act
    }

    pub(crate) fn content(&self) -> &[ContentOutput] {
        &self.content
    }

    pub(crate) fn relationship(&self) -> &[RelationshipOutput] {
        &self.relationship
    }

    pub(crate) fn content_for<'a>(
        &'a self,
        record_id: &'a str,
    ) -> impl Iterator<Item = &'a ContentOutput> + 'a {
        self.content
            .iter()
            .filter(move |output| output.record_id == record_id)
    }

    /// Highest content seq the command appended anywhere: the prefix a
    /// historical rebuild replays.
    pub(crate) fn content_horizon(&self) -> Option<i64> {
        self.content.iter().map(|output| output.seq).max()
    }

    pub(crate) fn relationship_horizon(&self) -> Option<i64> {
        self.relationship.iter().map(|output| output.seq).max()
    }

    /// Highest content seq the command appended on `record_id`.
    pub(crate) fn content_horizon_for(&self, record_id: &str) -> Option<i64> {
        self.content_for(record_id).map(|output| output.seq).max()
    }

    /// `record_id`'s content position just before the original command, the
    /// value its `previous_seq` echoed. Acts are gapless and allocated under
    /// the writer lock, so every content event committed earlier carries a
    /// smaller act. An act-less event counts as earlier only below the first
    /// content event carrying the command's act or a later one, so a
    /// pre-act event imported after the command cannot inflate the value.
    /// This works whichever log the command wrote to. A no-op has no act; its receipt echoed the
    /// position at the time, which is the current one unless the record has
    /// been written since.
    pub(crate) async fn previous_seq_in(
        &self,
        tx: &mut Transaction<'static, Sqlite>,
        record_id: &str,
    ) -> Result<Option<i64>> {
        match self.act {
            Some(act) => Ok(sqlx::query_scalar(
                "SELECT MAX(seq) FROM content_events
                  WHERE record_id = ?1
                    AND (act < ?2
                         OR (act IS NULL
                             AND seq < COALESCE(
                                 (SELECT seq FROM content_events WHERE act >= ?2
                                   ORDER BY act, seq LIMIT 1),
                                 9223372036854775807)))",
            )
            .bind(record_id)
            .bind(act)
            .fetch_one(&mut **tx)
            .await?),
            None => super::previous_record_seq_in(tx, record_id).await,
        }
    }

    /// Attach the original attestation to this response's receipt ids. Call
    /// once the renderer has succeeded.
    pub(crate) fn settle(&self) {
        crate::provenance::note_replayed_action_attestation(self.attestation_id.clone());
    }
}

/// Find the caller's original command for this key inside the handler's
/// write transaction (contract step 2). `arguments` must be exactly the
/// arguments the handler was dispatched with: the lookup recomputes their
/// action digest and refuses a mismatch as `idempotency_conflict`.
///
/// Boxed, so a handler's own future holds only a pointer: these lookups sit
/// inside long handler frames that already run close to the stack budget.
pub(crate) fn keyed_replay_in<'a>(
    tx: &'a mut Transaction<'static, Sqlite>,
    caller: &'a Caller,
    operation: &'a str,
    arguments: &'a Value,
) -> BoxFuture<'a, Result<Option<KeyedReplay>>> {
    Box::pin(lookup_and_load_in(tx, caller, operation, arguments))
}

async fn lookup_and_load_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    operation: &str,
    arguments: &Value,
) -> Result<Option<KeyedReplay>> {
    let Some(attestation_id) = crate::provenance::lookup_authorized_command_attestation_in(
        tx,
        caller.credential(),
        operation,
        arguments,
        caller.intent(),
    )
    .await?
    else {
        return Ok(None);
    };
    let content = sqlx::query(
        "SELECT e.id, e.seq, e.record_id, e.type, e.payload, e.created_at
           FROM provenance_action_outputs o
           JOIN content_events e ON e.id = o.output_event_id
          WHERE o.action_attestation_id = ? AND o.output_domain = 'content'
          ORDER BY o.ordinal",
    )
    .bind(&attestation_id)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|row| {
        Ok(ContentOutput {
            event_id: row.try_get("id")?,
            seq: row.try_get("seq")?,
            record_id: row.try_get("record_id")?,
            event_type: row.try_get("type")?,
            payload: serde_json::from_str(&row.try_get::<String, _>("payload")?)?,
            created_at: row.try_get("created_at")?,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    // Qualified by the attestation's issuer origin, as every relationship
    // event lookup must be: the table is UNIQUE only per issuer.
    let relationship = sqlx::query(
        "SELECT e.id, e.seq, e.stream_kind, e.stream_id, e.relationship_origin_db_id,
                e.relationship_id, e.issuer_origin_db_id
           FROM provenance_action_outputs o
           JOIN relationship_events e ON e.id = o.output_event_id
          WHERE o.action_attestation_id = ? AND o.output_domain = 'relationship'
            AND e.issuer_origin_db_id = (
                SELECT issuer_origin_database_id FROM provenance_action_attestations
                 WHERE id = ?)
          ORDER BY o.ordinal",
    )
    .bind(&attestation_id)
    .bind(&attestation_id)
    .fetch_all(&mut **tx)
    .await?
    .into_iter()
    .map(|row| {
        Ok(RelationshipOutput {
            event_id: row.try_get("id")?,
            seq: row.try_get("seq")?,
            stream_kind: row.try_get("stream_kind")?,
            stream_id: row.try_get("stream_id")?,
            relationship_origin_db_id: row.try_get("relationship_origin_db_id")?,
            relationship_id: row.try_get("relationship_id")?,
            issuer_origin_db_id: row.try_get("issuer_origin_db_id")?,
        })
    })
    .collect::<Result<Vec<_>>>()?;
    let act = super::attested_act_in(tx, &attestation_id).await?;
    Ok(Some(KeyedReplay {
        attestation_id,
        act,
        content,
        relationship,
    }))
}

/// Fast path for a handler that must do work *before* its write transaction
/// (a live-session flush) which a replay would not need: whether this key
/// already names a command of the caller's with the same arguments. Read-only
/// and unauthorized, so the answer is only ever used to skip that work, never
/// to decide or disclose anything. `true` is a claim the handler must check:
/// the in-transaction [`keyed_replay_in`] stays the authority (and where a
/// concurrent duplicate resolves), and a handler that skipped its gate on
/// `true` must not write if that lookup then misses. No command, or a key
/// reused with different arguments or intent (the in-transaction lookup
/// reports that conflict after authorization, or the gate refuses the call
/// first), is `false`. A read error is an `Err`, not a guess either way: the
/// handler must fail the call before entering any gate, because the gate
/// flushes and the lookup might have found a replay.
pub(crate) async fn replay_may_exist(
    db: &Db,
    caller: &Caller,
    operation: &str,
    arguments: &Value,
) -> Result<bool> {
    #[cfg(test)]
    if let Some(forced) = forced_answer(arguments) {
        return match forced {
            ForcedAnswer::Replay => Ok(true),
            ForcedAnswer::ReadError => Err(Error::engine("keyed lookup read failed (forced)")),
        };
    }
    let mut read = db.pool().begin().await?;
    let found = crate::provenance::lookup_authorized_command_attestation_in(
        &mut read,
        caller.credential(),
        operation,
        arguments,
        caller.intent(),
    )
    .await;
    read.rollback().await?;
    match found {
        Ok(found) => Ok(found.is_some()),
        Err(conflict) if conflict.is_idempotency_conflict() => Ok(false),
        Err(error) => Err(error),
    }
}

/// Test hook: what [`replay_may_exist`] answers for a key, whether or not a
/// replay exists, to drive a handler's backstop and error paths.
#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum ForcedAnswer {
    Replay,
    ReadError,
}

#[cfg(test)]
static FORCED_ANSWERS: std::sync::Mutex<Vec<(String, ForcedAnswer)>> =
    std::sync::Mutex::new(Vec::new());

/// Forces `answer` for `key` until dropped.
#[cfg(test)]
pub(crate) struct ForcedAnswerGuard(String);

#[cfg(test)]
pub(crate) fn force_answer(key: &str, answer: ForcedAnswer) -> ForcedAnswerGuard {
    FORCED_ANSWERS.lock().unwrap().push((key.into(), answer));
    ForcedAnswerGuard(key.into())
}

#[cfg(test)]
impl Drop for ForcedAnswerGuard {
    fn drop(&mut self) {
        FORCED_ANSWERS
            .lock()
            .unwrap()
            .retain(|(key, _)| *key != self.0);
    }
}

#[cfg(test)]
fn forced_answer(arguments: &Value) -> Option<ForcedAnswer> {
    let key = arguments.get("idempotency_key")?.as_str()?;
    FORCED_ANSWERS
        .lock()
        .unwrap()
        .iter()
        .find(|(forced, _)| forced == key)
        .map(|(_, answer)| *answer)
}

/// Contract step 4: anchor a keyed write that is about to commit nothing.
/// Boxed for the same reason as [`keyed_replay_in`].
pub(crate) fn anchor_noop_in<'a>(
    tx: &'a mut Transaction<'static, Sqlite>,
) -> BoxFuture<'a, Result<()>> {
    Box::pin(async move {
        crate::provenance::issue_keyed_noop_anchor_in(tx).await?;
        Ok(())
    })
}

/// Contract step 5: run `attempt`, and once more if it lost the authority
/// index race to a concurrent call with the same key. The second attempt
/// finds that call's attestation and replays it.
pub(crate) async fn with_race_replay<F, Fut, T>(mut attempt: F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    match attempt().await {
        Err(error) if crate::provenance::is_command_identity_race(&error) => attempt().await,
        outcome => outcome,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wired_writes_are_matched_by_tool_and_action() {
        assert!(is_keyed_replay_write("update_record", &json!({"id": "x"})));
        assert!(is_keyed_replay_write(
            "manage_links",
            &json!({"action": "add"})
        ));
        assert!(is_keyed_replay_write(
            "manage_links",
            &json!({"action": "remove"})
        ));
        assert!(!is_keyed_replay_write(
            "manage_links",
            &json!({"action": "list"})
        ));
        assert!(!is_keyed_replay_write("create_record", &json!({})));
    }

    #[test]
    fn naturally_idempotent_writes_refuse_a_real_key_by_name() {
        let mut blank = json!({"bindings": [], "idempotency_key": "  "});
        refuse_key_on_naturally_idempotent_write("t", "why", &mut blank).unwrap();
        assert!(blank.get("idempotency_key").is_none());
        let mut null = json!({"idempotency_key": null});
        refuse_key_on_naturally_idempotent_write("t", "why", &mut null).unwrap();
        assert!(null.get("idempotency_key").is_none());
        let refused = refuse_key_on_naturally_idempotent_write(
            "t",
            "why",
            &mut json!({"idempotency_key": "k"}),
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            refused,
            "t does not accept idempotency_key: why; retry without a key"
        );
    }

    /// appHost's body-save fallback (`KEY_UNSUPPORTED`, task 8bef361 Phase 2)
    /// reads this refusal off the plain HTTP tool route, which sends an
    /// `Error::Engine` as 400 `{"error": <message>}`: pin the variant and the
    /// exact text, whose tail is `; retry without it`.
    #[test]
    fn a_non_sqlite_engine_refuses_a_real_key_as_an_engine_error_with_the_wire_tail() {
        for engine in ["postgres", "turso-local"] {
            let mut args =
                json!({"id": "r", "body_append": "x", "reason": "r", "idempotency_key": "k"});
            let error = refuse_on_engine("update_record", &mut args, engine).unwrap_err();
            assert!(matches!(error, Error::Engine(_)), "{error:?}");
            assert_eq!(
                error.to_string(),
                format!("update_record: idempotency_key is supported on the SQLite engine only, not {engine}; retry without it")
            );
        }
    }

    #[test]
    fn keys_trim_blank_to_absent_and_bound_length() {
        assert_eq!(idempotency_key("t", None).unwrap(), None);
        assert_eq!(idempotency_key("t", Some("  ")).unwrap(), None);
        assert_eq!(idempotency_key("t", Some(" k ")).unwrap(), Some("k".into()));
        // The whitespace set is Unicode White_Space (Rust's `trim()`):
        // U+0085 is blank, so no key; U+FEFF is not, so it is a real key.
        // appHost's `BLANK_KEY` refuses exactly the keys this treats as none.
        assert_eq!(idempotency_key("t", Some("\u{85}")).unwrap(), None);
        assert_eq!(
            idempotency_key("t", Some(" \u{85}\u{3000} ")).unwrap(),
            None
        );
        assert_eq!(
            idempotency_key("t", Some("\u{feff}")).unwrap(),
            Some("\u{feff}".into())
        );
        let long = "k".repeat(MAX_IDEMPOTENCY_KEY_CHARS + 1);
        assert!(idempotency_key("t", Some(&long))
            .unwrap_err()
            .to_string()
            .contains("at most 200 characters"));
    }

    #[test]
    fn other_engines_refuse_a_key_by_name_and_drop_a_blank_one() {
        let refused = refuse_on_engine(
            "update_record",
            &mut json!({"id": "x", "idempotency_key": "k"}),
            "postgres",
        )
        .unwrap_err()
        .to_string();
        assert!(refused.contains("SQLite engine only"), "{refused}");
        refuse_on_engine("update_record", &mut json!({"id": "x"}), "postgres").unwrap();
        refuse_on_engine(
            "manage_links",
            &mut json!({"action": "list", "idempotency_key": "k"}),
            "postgres",
        )
        .unwrap();
        // Null and blank are no key: dropped, so the engine's own handler,
        // which does not know the field, sees an ordinary unkeyed call.
        for blank in [json!(null), json!(""), json!("  ")] {
            let mut arguments = json!({"id": "x", "idempotency_key": blank});
            refuse_on_engine("update_record", &mut arguments, "turso").unwrap();
            assert_eq!(arguments, json!({"id": "x"}));
        }
        let mut number = json!({"id": "x", "idempotency_key": 7});
        assert!(refuse_on_engine("update_record", &mut number, "turso").is_err());
    }

    /// The unique-violation backstop, made deterministic: SQLite's single
    /// writer means two in-process keyed calls never race to the authority
    /// index, so the genuine violation is produced directly on the real
    /// schema and then fed to `with_race_replay`.
    #[tokio::test]
    async fn the_authority_index_race_is_recognised_and_replayed_exactly_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let db = crate::create_database(":memory:").await.unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        sqlx::query("PRAGMA defer_foreign_keys = ON")
            .execute(&mut *tx)
            .await
            .unwrap();
        let insert = |attestation: &'static str| {
            sqlx::query(
                "INSERT INTO provenance_local_attestation_authority
                    (attestation_id, issuer_origin_database_id, principal, operation,
                     command_identity_digest, anchored_at)
                 VALUES (?, 'origin', 'acct:alice', 'update_record', 'digest', 'now')",
            )
            .bind(attestation)
        };
        insert("first").execute(&mut *tx).await.unwrap();
        let race: Error = insert("second").execute(&mut *tx).await.unwrap_err().into();
        tx.rollback().await.unwrap();
        assert!(crate::provenance::is_command_identity_race(&race), "{race}");
        // The commit path can surface the same violation as an engine string.
        let message = race.to_string();
        assert!(crate::provenance::is_command_identity_race(&Error::engine(
            message.clone()
        )));

        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        let replayed = with_race_replay(move || {
            let attempt = counted.fetch_add(1, Ordering::SeqCst);
            let message = message.clone();
            async move {
                if attempt == 0 {
                    Err(Error::engine(message))
                } else {
                    Ok("replayed")
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(replayed, "replayed");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);

        // Any other failure is returned as is, without a second attempt.
        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        let refused = with_race_replay(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            async { Err::<(), _>(Error::engine("ordinary refusal")) }
        })
        .await
        .unwrap_err();
        assert_eq!(refused.to_string(), "ordinary refusal");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!crate::provenance::is_command_identity_race(&refused));
        db.close().await;
    }

    #[test]
    fn conflict_refusals_carry_the_machine_code() {
        assert!(
            Error::engine(crate::provenance::IDEMPOTENCY_CONFLICTING_INPUT)
                .is_idempotency_conflict()
        );
        assert!(Error::engine(format!(
            "update_record: {}",
            crate::provenance::IDEMPOTENCY_DIFFERENT_INTENT
        ))
        .is_idempotency_conflict());
        assert!(
            !Error::conflict(crate::provenance::IDEMPOTENCY_CONFLICTING_INPUT)
                .is_idempotency_conflict()
        );
        assert!(!Error::engine("something else").is_idempotency_conflict());
    }
}
