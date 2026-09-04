//! Governed vocabularies — the system/meta-tier write API for `vocabularies` /
//! `vocabulary_values`, EVENT-PROJECTED off the `meta_events` log since decision
//! ba9f97e. Every verb below is append-then-fold: it appends its event via
//! `crate::meta::log` and the meta projector is what actually touches the two
//! tables. No verb here writes them directly.
//!
//! This module carries the contract guards `manage_vocabularies` promises
//! (docs/tool-surface.md, tool 20; Native task e035091 guard 1):
//!
//!   - The lifecycle is **propose / promote / deprecate / alias**, not CRUD.
//!     Values transition `status` ('proposed' -> 'active' -> 'deprecated');
//!     renames/merges go through `alias_of`, never through delete-and-recreate.
//!   - **No hard delete of seeded or referenced values/vocabularies.**
//!     `facet_values.vocab_ref` has no FK in the frozen DDL (it is plain TEXT),
//!     while `vocabulary_values` cascade-delete off their parent vocabulary — so
//!     an unguarded delete would strand facet assignments. This module IS the
//!     app-layer closure of that structural hole (the DDL-FK alternative goes
//!     through the conformance re-freeze path and was deliberately not taken at
//!     v1).
//!
//! Deleting a value/vocabulary that is neither seeded nor referenced (e.g. a
//! just-proposed typo) is permitted — the guard protects integrity, it is not a
//! blanket immutability rule.
//!
//! Guards run as read-check + write pairs inside a single write transaction:
//! this is a single-PRINCIPAL engine, not single-agent — and the pool uses more
//! than one connection — so as separate autocommit statements a concurrent
//! writer could interleave between check and mutation. The transaction
//! serializes against every other write transaction, closing the window.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, SqliteConnection};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::meta::kind::{
    core_kind_manifest, kind_vocabulary_id, kind_vocabulary_name, KindMetadataV1,
};
use crate::meta::log::{append_meta_in, MetaAppendSpec};
use crate::schema::SPINE_TYPES;

pub type VocabularyValueStatus = String;

/// What reaching a value means for the record using it. This is intentionally
/// separate from value lifecycle status: a deprecated label may have any of
/// these meanings, and an active terminal value remains active vocabulary.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VocabularyValueTerminality {
    #[default]
    Open,
    TerminalPositive,
    TerminalNegative,
}

impl VocabularyValueTerminality {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::TerminalPositive => "terminal_positive",
            Self::TerminalNegative => "terminal_negative",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct VocabularyRow {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct VocabularyValueRow {
    pub id: String,
    pub vocabulary_id: String,
    pub value: String,
    pub gloss: Option<String>,
    pub status: VocabularyValueStatus,
    pub ordinal: f64,
    pub terminality: String,
    pub metadata: serde_json::Value,
    pub alias_of: Option<String>,
}

/// The `facet_values.vocab_ref` format is `rec:<vocabulary_id>` when
/// vocab-governed (DDL spec 9561d43); a bare id is accepted when resolving.
pub fn vocab_ref(vocabulary_id: &str) -> String {
    format!("rec:{vocabulary_id}")
}

/// Strip the optional `rec:` prefix off a vocab_ref to get the vocabulary id.
pub fn resolve_vocab_ref(vocab_ref: &str) -> &str {
    vocab_ref.strip_prefix("rec:").unwrap_or(vocab_ref)
}

/// The pack-seeded vocabularies — the values the recommended-defaults pack
/// ships (DDL spec 9561d43: `maturity` spine vocab, `confidence` anti-preamble
/// pack facet). Seeded values are part of the shipped contract: they can be
/// deprecated (the sanctioned lifecycle) but never hard-deleted.
pub const TASK_LIFECYCLE_VOCABULARY: &str = "lifecycle";
pub const TASK_LIFECYCLE_VOCABULARY_ID: &str = "voc:lifecycle";
pub const TASK_LIFECYCLE_VALUES: [(&str, f64, VocabularyValueTerminality); 5] = [
    ("open", 100.0, VocabularyValueTerminality::Open),
    ("in_progress", 200.0, VocabularyValueTerminality::Open),
    ("blocked", 300.0, VocabularyValueTerminality::Open),
    (
        "completed",
        400.0,
        VocabularyValueTerminality::TerminalPositive,
    ),
    (
        "closed",
        500.0,
        VocabularyValueTerminality::TerminalNegative,
    ),
];

pub const SUGGESTION_LIFECYCLE_VOCABULARY: &str = "suggestion-lifecycle";
pub const SUGGESTION_LIFECYCLE_VOCABULARY_ID: &str = "voc:suggestion-lifecycle";
pub const SUGGESTION_LIFECYCLE_VALUES: [(&str, f64, VocabularyValueTerminality); 4] = [
    ("open", 100.0, VocabularyValueTerminality::Open),
    (
        "accepted",
        200.0,
        VocabularyValueTerminality::TerminalPositive,
    ),
    (
        "rejected",
        300.0,
        VocabularyValueTerminality::TerminalNegative,
    ),
    ("stale", 400.0, VocabularyValueTerminality::TerminalNegative),
];

pub fn is_task_lifecycle_value(value: &str) -> bool {
    TASK_LIFECYCLE_VALUES
        .iter()
        .any(|(token, _, _)| *token == value)
}

/// Comment thread state. Governed separately from the task `lifecycle`
/// vocabulary because a comment root's states are not a work progression:
/// `informational` is an FYI that is deliberately never resolvable and never
/// counted as an open thread, and it is the NAME of what legacy rows store as
/// a null lifecycle. Roots created without a lifecycle are born
/// `informational`; two pre-naming rows still carry null and stay readable.
pub const COMMENT_LIFECYCLE_VOCABULARY: &str = "comment-lifecycle";
pub const COMMENT_LIFECYCLE_VALUES: [(&str, f64, VocabularyValueTerminality); 3] = [
    ("informational", 100.0, VocabularyValueTerminality::Open),
    ("open", 200.0, VocabularyValueTerminality::Open),
    (
        "resolved",
        300.0,
        VocabularyValueTerminality::TerminalPositive,
    ),
];

/// Canonical prose definitions shipped for the built-in lifecycle answers.
///
/// These are separate from ordinal/terminality so the existing progression
/// tables stay the single source for ordering while this table makes the
/// agent-readable contract equally explicit. Seeding backfills only a missing
/// or blank gloss; a nonblank amendment remains the installation's wording.
pub const BUILT_IN_LIFECYCLE_GLOSSES: [(&str, &str, &str); 12] = [
    (
        TASK_LIFECYCLE_VOCABULARY,
        "open",
        "Work is available but has not started.",
    ),
    (
        TASK_LIFECYCLE_VOCABULARY,
        "in_progress",
        "Work is actively underway.",
    ),
    (
        TASK_LIFECYCLE_VOCABULARY,
        "blocked",
        "Work cannot currently proceed because of an impediment.",
    ),
    (
        TASK_LIFECYCLE_VOCABULARY,
        "completed",
        "Work finished successfully and achieved its intended outcome.",
    ),
    (
        TASK_LIFECYCLE_VOCABULARY,
        "closed",
        "Work ended without completion or is no longer being pursued.",
    ),
    (
        COMMENT_LIFECYCLE_VOCABULARY,
        "informational",
        "An informational thread that requires no resolution.",
    ),
    (
        COMMENT_LIFECYCLE_VOCABULARY,
        "open",
        "A thread that remains active and may require a response or resolution.",
    ),
    (
        COMMENT_LIFECYCLE_VOCABULARY,
        "resolved",
        "A thread whose question or concern has been addressed.",
    ),
    (
        SUGGESTION_LIFECYCLE_VOCABULARY,
        "open",
        "A proposed change awaiting disposition.",
    ),
    (
        SUGGESTION_LIFECYCLE_VOCABULARY,
        "accepted",
        "A proposed change that was applied to its target.",
    ),
    (
        SUGGESTION_LIFECYCLE_VOCABULARY,
        "rejected",
        "A proposed change declined on its merits and not applied.",
    ),
    (
        SUGGESTION_LIFECYCLE_VOCABULARY,
        "stale",
        "A proposed change ended without application because its precondition no longer held.",
    ),
];

fn built_in_lifecycle_gloss(vocabulary: &str, value: &str) -> Option<&'static str> {
    BUILT_IN_LIFECYCLE_GLOSSES
        .iter()
        .find(|(candidate_vocabulary, candidate_value, _)| {
            *candidate_vocabulary == vocabulary && *candidate_value == value
        })
        .map(|(_, _, gloss)| *gloss)
}

/// How a seeded vocabulary's values are shaped. Every seeded vocabulary picks
/// one arm, so "this vocabulary has no progression" is a statement the table
/// makes rather than a lookup that silently misses.
///
/// The lifecycle vocabularies used to declare their values here and their
/// ordinals/terminality in a separate `match`, joined by name with a `_ => &[]`
/// wildcard. Deleting an arm of that join was a clean merge and a clean
/// compile, and it degraded silently: the vocabulary seeded flat and open, so
/// `accepted` / `rejected` / `stale` / `resolved` were all reported
/// non-terminal. That happened (merging branch `6a1d721`). With one arm per
/// vocabulary there is no join to lose.
#[derive(Debug, Clone, Copy)]
pub enum SeededValues {
    /// Flat on purpose: an unordered label set with no progression and no
    /// terminal states, so every value is born ordinal `0.0` and `open`.
    Flat(&'static [&'static str]),
    /// A progression: each value declares its own ordinal and terminality
    /// right where it is declared.
    Progression(&'static [(&'static str, f64, VocabularyValueTerminality)]),
}

impl SeededValues {
    /// Every seeded value paired with the ordinal and terminality it is born
    /// with. This is the only way seeding learns a value's progression, so a
    /// vocabulary cannot be seeded without having answered the question.
    pub fn seeded(self) -> impl Iterator<Item = (&'static str, f64, VocabularyValueTerminality)> {
        let (flat, progression): (
            &'static [&'static str],
            &'static [(&'static str, f64, VocabularyValueTerminality)],
        ) = match self {
            Self::Flat(values) => (values, &[]),
            Self::Progression(values) => (&[], values),
        };
        flat.iter()
            .map(|value| (*value, 0.0, VocabularyValueTerminality::Open))
            .chain(progression.iter().copied())
    }

    /// The seeded value tokens, in seeding order.
    pub fn values(self) -> impl Iterator<Item = &'static str> {
        self.seeded().map(|(value, _, _)| value)
    }

    pub fn contains(self, value: &str) -> bool {
        self.values().any(|token| token == value)
    }

    pub fn is_progression(self) -> bool {
        matches!(self, Self::Progression(_))
    }
}

pub const SEED_VOCABULARIES: [(&str, SeededValues); 10] = [
    (
        "maturity",
        SeededValues::Flat(&[
            "exploratory",
            "candidate",
            "proposed",
            "decided",
            "superseded",
        ]),
    ),
    (
        "confidence",
        SeededValues::Flat(&["speculative", "tentative", "likely", "confident"]),
    ),
    // Team language starts empty and grows through propose/promote. The stable
    // id is part of the definition-document join contract; example terms such
    // as `artifact` are deliberately not shipped as data.
    ("glossary", SeededValues::Flat(&[])),
    // Opaque, versioned adapter identifiers. The vocabulary is open-additive:
    // later runtimes are proposed/promoted through the ordinary governed path.
    (
        "artifact-runtime",
        SeededValues::Flat(&[
            "native.board.v1",
            "native.html.v1",
            "native.mdx.v1",
            "native.mdx.v2",
        ]),
    ),
    // Recipe interpreters are governed independently from presentation/module
    // runtimes. The carrier migration prepares this one exact v1 identity;
    // recipe execution remains outside this change.
    ("recipe-runtime", SeededValues::Flat(&["native.recipe.v1"])),
    // Sender-authored Message response demand. Absence is deliberately not a
    // vocabulary value: historical Messages without the facet derive
    // `unknown`, while `none` is an affirmative declaration. Flat because the
    // five demands do not rank against each other.
    (
        "message-expectation",
        SeededValues::Flat(&["none", "ack", "reply", "action", "decision"]),
    ),
    (
        TASK_LIFECYCLE_VOCABULARY,
        SeededValues::Progression(&TASK_LIFECYCLE_VALUES),
    ),
    // Comment thread state, governed apart from the task progression above.
    // `informational` names the FYI root that was previously expressed only by
    // omitting the field.
    (
        COMMENT_LIFECYCLE_VOCABULARY,
        SeededValues::Progression(&COMMENT_LIFECYCLE_VALUES),
    ),
    // Suggestion state. Terminal in three distinct ways: `accepted` became the
    // target's body, `rejected` was declined on its merits, and `stale` ended
    // without being achieved because its precondition no longer held.
    (
        SUGGESTION_LIFECYCLE_VOCABULARY,
        SeededValues::Progression(&SUGGESTION_LIFECYCLE_VALUES),
    ),
    // What role a `Collection kind:selection` plays. A selection collection is
    // generic, so kind plus membership alone cannot distinguish a deliberate
    // exploration from an ordinary curated list; this supplies the dispatch
    // semantics without hiding the collection itself.
    (
        crate::contribution::SELECTION_ROLE_VOCABULARY,
        SeededValues::Flat(&[crate::contribution::ALTERNATIVE_SET_ROLE]),
    ),
];

pub fn is_seeded_vocabulary(name: &str) -> bool {
    SEED_VOCABULARIES.iter().any(|(n, _)| *n == name)
        || SPINE_TYPES
            .iter()
            .any(|record_type| name == kind_vocabulary_name(record_type))
}

pub fn is_seeded_value(vocabulary_name: &str, value: &str) -> bool {
    SEED_VOCABULARIES
        .iter()
        .find(|(n, _)| *n == vocabulary_name)
        .is_some_and(|(_, values)| values.contains(value))
        || core_kind_manifest().is_ok_and(|manifest| {
            manifest.kinds.iter().any(|kind| {
                kind_vocabulary_name(&kind.record_type) == vocabulary_name && kind.token == value
            })
        })
}

/// Deterministic ids so seeding is idempotent and refs are stable.
pub(crate) fn vocabulary_id(name: &str) -> String {
    format!("voc:{name}")
}
pub(crate) fn value_id(vocabulary_id: &str, value: &str) -> String {
    format!("vv:{vocabulary_id}:{value}")
}

/// Seed the pack vocabularies into a database. Idempotent — safe to run on every
/// open.
///
/// Idempotence is now the caller's guarantee AND the log's: seeding appends an
/// event only for a row that does not already exist, so a re-seed appends
/// nothing. Getting this wrong would be quietly corrosive — this function is
/// designed to run on every open, so an unconditional append would grow the log
/// by 12 no-op events per open forever while rebuild-and-diff kept passing,
/// which is exactly the silent drift an authoritative log exists to prevent.
///
/// The existence check and the append share one write transaction, so two
/// concurrent seeds cannot both observe "absent" and both append.
pub async fn seed_vocabularies(db: &Db) -> Result<()> {
    for (name, values) in SEED_VOCABULARIES {
        let vid = vocabulary_id(name);
        let mut tx = crate::db::begin_write(db.write_pool()).await?;
        let exists = sqlx::query("SELECT 1 FROM vocabularies WHERE id = ?")
            .bind(&vid)
            .fetch_optional(&mut *tx)
            .await?;
        if exists.is_none() {
            append_meta_in(
                &mut tx,
                MetaAppendSpec::with_payload(&vid, "vocabulary.created", json!({ "name": name })),
            )
            .await?;
        }
        for (value, ordinal, terminality) in values.seeded() {
            let value_id = value_id(&vid, value);
            let existing_gloss = sqlx::query_scalar::<_, Option<String>>(
                "SELECT gloss FROM vocabulary_values WHERE id = ?",
            )
            .bind(&value_id)
            .fetch_optional(&mut *tx)
            .await?;
            let seeded_gloss = built_in_lifecycle_gloss(name, value);
            if let Some(existing_gloss) = existing_gloss {
                if let Some(gloss) = seeded_gloss.filter(|_| {
                    existing_gloss
                        .as_deref()
                        .is_none_or(|existing| existing.trim().is_empty())
                }) {
                    set_gloss_in(&mut tx, &value_id, Some(gloss), Some("engine:seed")).await?;
                }
                continue;
            }
            // Seeded values are born 'active': the pack ships them as contract,
            // so they legitimately skip the proposal step. The payload records
            // that rather than letting the fold assume a status.
            let mut payload = json!({
                "vocabulary_id": &vid,
                "value": value,
                "status": "active",
                "ordinal": ordinal,
                "terminality": terminality.as_str(),
                "metadata": {},
            });
            if let Some(gloss) = seeded_gloss {
                payload["gloss"] = json!(gloss);
            }
            append_meta_in(
                &mut tx,
                MetaAppendSpec::with_payload(&value_id, "vocab_value.proposed", payload),
            )
            .await?;
        }
        tx.commit().await?;
    }
    // Core kind identities are one manifest installation, so preflight all
    // ten vocabularies and every shipped value before appending any of them.
    // The single transaction also makes a late uniqueness conflict roll the
    // whole installation back.
    let manifest = core_kind_manifest()?;
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut reconcile_proposed = HashSet::new();
    for record_type in SPINE_TYPES {
        let name = kind_vocabulary_name(record_type);
        let vid = kind_vocabulary_id(record_type);
        let existing = get_vocabulary_on(&mut tx, &vid).await?;
        if let Some(existing) = existing {
            if existing.id != vid || existing.name != name {
                return Err(Error::engine(format!(
                    "core kind vocabulary identity conflict: expected '{vid}' / '{name}', found '{}' / '{}'",
                    existing.id, existing.name
                )));
            }
        } else {
            let name_owner = get_vocabulary_on(&mut tx, &name).await?;
            if let Some(owner) = name_owner {
                return Err(Error::engine(format!(
                    "core kind vocabulary identity conflict: name '{name}' uses id '{}' instead of '{vid}'",
                    owner.id
                )));
            }
        }
        for kind in manifest
            .kinds
            .iter()
            .filter(|kind| kind.record_type == record_type)
        {
            let existing = sqlx::query(
                "SELECT id, vocabulary_id, value, status, alias_of, metadata
                   FROM vocabulary_values
                  WHERE id = ? OR (vocabulary_id = ? AND value = ?)",
            )
            .bind(&kind.value_id)
            .bind(&vid)
            .bind(&kind.token)
            .fetch_all(&mut *tx)
            .await?;
            let mut saw_reconcile_candidate = false;
            for existing in existing {
                let id: String = existing.try_get("id")?;
                let vocabulary_id: String = existing.try_get("vocabulary_id")?;
                let token: String = existing.try_get("value")?;
                let status: String = existing.try_get("status")?;
                let alias_of: Option<String> = existing.try_get("alias_of")?;
                let metadata: String = existing.try_get("metadata")?;
                let exact_identity =
                    id == kind.value_id && vocabulary_id == vid && token == kind.token;
                if !exact_identity {
                    return Err(Error::engine(format!(
                        "core kind identity/payload conflict for {record_type}:{}; seed made no core-kind writes",
                        kind.token
                    )));
                }
                if status == "proposed" && alias_of.is_none() {
                    if saw_reconcile_candidate {
                        return Err(Error::engine(format!(
                            "core kind identity/payload conflict for {record_type}:{}; seed made no core-kind writes",
                            kind.token
                        )));
                    }
                    saw_reconcile_candidate = true;
                    reconcile_proposed.insert(kind.value_id.clone());
                    continue;
                }
                if !matches!(status.as_str(), "active" | "deprecated")
                    || alias_of.is_some()
                    || serde_json::from_str::<serde_json::Value>(&metadata)?
                        != serde_json::to_value(&kind.metadata)?
                {
                    return Err(Error::engine(format!(
                        "core kind identity/payload conflict for {record_type}:{}; seed made no core-kind writes",
                        kind.token
                    )));
                }
            }
        }
    }
    for record_type in SPINE_TYPES {
        let name = kind_vocabulary_name(record_type);
        let vid = kind_vocabulary_id(record_type);
        if get_vocabulary_on(&mut tx, &vid).await?.is_none() {
            append_meta_in(
                &mut tx,
                MetaAppendSpec::with_payload(&vid, "vocabulary.created", json!({ "name": name })),
            )
            .await?;
        }
        for kind in manifest
            .kinds
            .iter()
            .filter(|kind| kind.record_type == record_type)
        {
            if reconcile_proposed.contains(&kind.value_id) {
                set_value_metadata_in(
                    &mut tx,
                    &kind.value_id,
                    kind.metadata.clone(),
                    Some("engine:seed"),
                )
                .await?;
                set_gloss_in(
                    &mut tx,
                    &kind.value_id,
                    kind.gloss.as_deref(),
                    Some("engine:seed"),
                )
                .await?;
                promote_value_in(&mut tx, &kind.value_id, Some("engine:seed")).await?;
                continue;
            }
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM vocabulary_values WHERE id = ?)")
                    .bind(&kind.value_id)
                    .fetch_one(&mut *tx)
                    .await?;
            if !exists {
                let mut payload = json!({
                    "vocabulary_id": &vid,
                    "value": &kind.token,
                    "status": "active",
                    "metadata": &kind.metadata,
                });
                if let Some(gloss) = &kind.gloss {
                    payload["gloss"] = json!(gloss);
                }
                append_meta_in(
                    &mut tx,
                    MetaAppendSpec::with_payload(&kind.value_id, "vocab_value.proposed", payload),
                )
                .await?;
            }
        }
    }
    tx.commit().await?;
    Ok(())
}

// ---- Lookups --------------------------------------------------------------

pub(crate) async fn get_vocabulary_on(
    conn: &mut SqliteConnection,
    id_or_name: &str,
) -> Result<Option<VocabularyRow>> {
    let row = sqlx::query("SELECT id, name FROM vocabularies WHERE id = ? OR name = ?")
        .bind(id_or_name)
        .bind(id_or_name)
        .fetch_optional(conn)
        .await?;
    Ok(row.map(|r| VocabularyRow {
        id: r.get("id"),
        name: r.get("name"),
    }))
}

pub async fn get_vocabulary(db: &Db, id_or_name: &str) -> Result<Option<VocabularyRow>> {
    let mut conn = db.write_pool().acquire().await?;
    get_vocabulary_on(&mut conn, id_or_name).await
}

pub(crate) async fn get_value_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<VocabularyValueRow> {
    find_value_on(conn, id)
        .await?
        .ok_or_else(|| Error::engine(format!("vocabulary value {id} does not exist")))
}

pub(crate) async fn find_value_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Option<VocabularyValueRow>> {
    let row = sqlx::query(
        "SELECT id, vocabulary_id, value, gloss, status, ordinal, terminality, metadata, alias_of
          FROM vocabulary_values WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(conn)
    .await?;
    row.map(|row| {
        Ok(VocabularyValueRow {
            id: row.get("id"),
            vocabulary_id: row.get("vocabulary_id"),
            value: row.get("value"),
            gloss: row.get("gloss"),
            status: row.get("status"),
            ordinal: row.get("ordinal"),
            terminality: row.get("terminality"),
            metadata: serde_json::from_str(&row.get::<String, _>("metadata"))?,
            alias_of: row.get("alias_of"),
        })
    })
    .transpose()
}

/// Options for [`list_values`].
#[derive(Debug, Clone, Default)]
pub struct ListValuesOptions {
    /// Only values with this `status` ('proposed' | 'active' | 'deprecated').
    /// `None` lists all.
    pub status: Option<String>,
    /// Resolve `alias_of` on each returned value into its canonical value
    /// (always one hop — `alias_value` forbids chains).
    pub resolve_aliases: bool,
}

/// The canonical value an alias redirects to.
#[derive(Debug, Clone, Serialize)]
pub struct CanonicalValue {
    pub id: String,
    pub value: String,
}

/// One entry of a value listing: the row, plus its resolved canonical when
/// asked for and applicable.
#[derive(Debug, Clone, Serialize)]
pub struct VocabularyValueListing {
    #[serde(flatten)]
    pub row: VocabularyValueRow,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canonical: Option<CanonicalValue>,
}

/// List a vocabulary's values, status-filtered and alias-resolved — the read
/// tools 15 (`suggest_facet_values`) and 20 (`manage_vocabularies`) share
/// (tool-surface finding 6: nothing could enumerate values before this).
/// The vocabulary is addressed by id or name; a missing vocabulary errors
/// (same contract as the lifecycle verbs).
pub async fn list_values(
    db: &Db,
    vocabulary: &str,
    opts: ListValuesOptions,
) -> Result<Vec<VocabularyValueListing>> {
    let Some(vocab) = get_vocabulary(db, vocabulary).await? else {
        return Err(Error::engine(format!(
            "vocabulary {vocabulary} does not exist"
        )));
    };
    let base = "SELECT v.id, v.vocabulary_id, v.value, v.gloss, v.status,
                 v.ordinal, v.terminality, v.metadata, v.alias_of,
                 c.id AS canonical_id, c.value AS canonical_value
          FROM vocabulary_values v
          LEFT JOIN vocabulary_values c ON c.id = v.alias_of
          WHERE v.vocabulary_id = ?";
    let order = "ORDER BY v.ordinal, v.value, v.id";
    let rows = match &opts.status {
        Some(status) => {
            sqlx::query(&format!("{base} AND v.status = ? {order}"))
                .bind(&vocab.id)
                .bind(status)
                .fetch_all(db.write_pool())
                .await?
        }
        None => {
            sqlx::query(&format!("{base} {order}"))
                .bind(&vocab.id)
                .fetch_all(db.write_pool())
                .await?
        }
    };
    rows.iter()
        .map(|row| {
            let alias_of: Option<String> = row.try_get("alias_of")?;
            let canonical = if opts.resolve_aliases && alias_of.is_some() {
                let id: Option<String> = row.try_get("canonical_id")?;
                let value: Option<String> = row.try_get("canonical_value")?;
                id.zip(value)
                    .map(|(id, value)| CanonicalValue { id, value })
            } else {
                None
            };
            Ok(VocabularyValueListing {
                row: VocabularyValueRow {
                    id: row.try_get("id")?,
                    vocabulary_id: row.try_get("vocabulary_id")?,
                    value: row.try_get("value")?,
                    gloss: row.try_get("gloss")?,
                    status: row.try_get("status")?,
                    ordinal: row.try_get("ordinal")?,
                    terminality: row.try_get("terminality")?,
                    metadata: serde_json::from_str(&row.try_get::<String, _>("metadata")?)?,
                    alias_of,
                },
                canonical,
            })
        })
        .collect()
}

// ---- Lifecycle (the sanctioned verbs) -------------------------------------

/// Create a governed vocabulary (e.g. 'lifecycle', 'kind:Document').
pub async fn create_vocabulary(db: &Db, name: &str, id: Option<&str>) -> Result<String> {
    create_vocabulary_as(db, name, id, None).await
}

pub async fn create_vocabulary_as(
    db: &Db,
    name: &str,
    id: Option<&str>,
    actor: Option<&str>,
) -> Result<String> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let vid = create_vocabulary_in(&mut tx, name, id, actor).await?;
    tx.commit().await?;
    Ok(vid)
}

pub(crate) async fn create_vocabulary_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    name: &str,
    id: Option<&str>,
    actor: Option<&str>,
) -> Result<String> {
    let vid = id.map(String::from).unwrap_or_else(|| vocabulary_id(name));
    if let Some(existing) = get_vocabulary_on(tx, &vid).await? {
        if existing.name == name {
            return Ok(vid);
        }
        return Err(Error::engine(format!(
            "vocabulary identity conflict: id '{vid}' is already named '{}'",
            existing.name
        )));
    }
    if let Some(existing) = get_vocabulary_on(tx, name).await? {
        return Err(Error::engine(format!(
            "vocabulary identity conflict: name '{name}' already uses id '{}'",
            existing.id
        )));
    }
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(&vid, "vocabulary.created", json!({ "name": name }))
            .with_actor(actor),
    )
    .await?;
    Ok(vid)
}

/// Propose a new value into a vocabulary. It starts at status 'proposed'.
pub async fn propose_value(
    db: &Db,
    vocabulary: &str,
    value: &str,
    gloss: Option<&str>,
) -> Result<String> {
    propose_value_as(db, vocabulary, value, gloss, None).await
}

pub async fn propose_value_as(
    db: &Db,
    vocabulary: &str,
    value: &str,
    gloss: Option<&str>,
    actor: Option<&str>,
) -> Result<String> {
    propose_value_with_metadata_as(
        db,
        vocabulary,
        value,
        gloss,
        0.0,
        VocabularyValueTerminality::Open,
        actor,
    )
    .await
}

/// Propose a value with its per-vocabulary presentation/progression metadata.
/// The original proposal API remains as the safe `0/open` convenience path.
pub async fn propose_value_with_metadata_as(
    db: &Db,
    vocabulary: &str,
    value: &str,
    gloss: Option<&str>,
    ordinal: f64,
    terminality: VocabularyValueTerminality,
    actor: Option<&str>,
) -> Result<String> {
    propose_value_with_kind_metadata_as(
        db,
        vocabulary,
        value,
        gloss,
        ordinal,
        terminality,
        None,
        actor,
    )
    .await
}

/// Propose a value, requiring valid `KindMetadataV1` for `kind:<Type>`
/// vocabularies. Replaying the same deterministic identity and payload is a
/// no-op; disagreement is a conflict before any event is appended.
#[allow(clippy::too_many_arguments)]
pub async fn propose_value_with_kind_metadata_as(
    db: &Db,
    vocabulary: &str,
    value: &str,
    gloss: Option<&str>,
    ordinal: f64,
    terminality: VocabularyValueTerminality,
    kind_metadata: Option<KindMetadataV1>,
    actor: Option<&str>,
) -> Result<String> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let id = propose_value_with_kind_metadata_in(
        &mut tx,
        vocabulary,
        value,
        gloss,
        ordinal,
        terminality,
        kind_metadata,
        actor,
    )
    .await?;
    tx.commit().await?;
    Ok(id)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn propose_value_with_kind_metadata_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    vocabulary: &str,
    value: &str,
    gloss: Option<&str>,
    ordinal: f64,
    terminality: VocabularyValueTerminality,
    kind_metadata: Option<KindMetadataV1>,
    actor: Option<&str>,
) -> Result<String> {
    if !ordinal.is_finite() {
        return Err(Error::engine("vocabulary value ordinal must be finite"));
    }
    let Some(vocab) = get_vocabulary_on(tx, vocabulary).await? else {
        return Err(Error::engine(format!(
            "vocabulary {vocabulary} does not exist"
        )));
    };
    let is_kind = vocab.name.starts_with("kind:");
    if is_kind {
        let record_type = vocab.name.trim_start_matches("kind:");
        if !SPINE_TYPES.contains(&record_type) {
            return Err(Error::engine(format!(
                "kind vocabulary '{}' does not name a closed spine type",
                vocab.name
            )));
        }
        let Some(metadata) = kind_metadata.as_ref() else {
            return Err(Error::engine(format!(
                "proposing '{value}' in '{}' requires complete KindMetadataV1",
                vocab.name
            )));
        };
        metadata.validate()?;
    } else if kind_metadata.is_some() {
        return Err(Error::engine(
            "kind metadata is only valid on kind:<Type> vocabularies",
        ));
    }
    let id = value_id(&vocab.id, value);
    let metadata = kind_metadata
        .as_ref()
        .map(serde_json::to_value)
        .transpose()?
        .unwrap_or_else(|| json!({}));
    if let Some(existing) = sqlx::query(
        "SELECT id, gloss, status, ordinal, terminality, metadata
           FROM vocabulary_values WHERE vocabulary_id = ? AND value = ?",
    )
    .bind(&vocab.id)
    .bind(value)
    .fetch_optional(&mut **tx)
    .await?
    {
        let status = existing.try_get::<String, _>("status")?;
        let same = existing.try_get::<String, _>("id")? == id
            && existing.try_get::<Option<String>, _>("gloss")? == gloss.map(String::from)
            && matches!(status.as_str(), "proposed" | "active")
            && existing.try_get::<f64, _>("ordinal")? == ordinal
            && existing.try_get::<String, _>("terminality")? == terminality.as_str()
            && serde_json::from_str::<serde_json::Value>(
                &existing.try_get::<String, _>("metadata")?,
            )? == metadata;
        if same {
            return Ok(id);
        }
        return Err(Error::engine(format!(
            "vocabulary value identity/payload conflict for '{}':'{value}'",
            vocab.name
        )));
    }
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            &id,
            "vocab_value.proposed",
            json!({
                "vocabulary_id": &vocab.id,
                "value": value,
                "gloss": gloss,
                "status": "proposed",
                "ordinal": ordinal,
                "terminality": terminality.as_str(),
                "metadata": metadata,
            }),
        )
        .with_actor(actor),
    )
    .await?;
    Ok(id)
}

pub async fn set_value_metadata_as(
    db: &Db,
    id: &str,
    metadata: KindMetadataV1,
    actor: Option<&str>,
) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    set_value_metadata_in(&mut tx, id, metadata, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn set_value_metadata_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    metadata: KindMetadataV1,
    actor: Option<&str>,
) -> Result<()> {
    metadata.validate()?;
    let value = get_value_on(tx, id).await?;
    let vocab = get_vocabulary_on(tx, &value.vocabulary_id)
        .await?
        .ok_or_else(|| Error::engine("vocabulary value has no vocabulary"))?;
    if !vocab.name.starts_with("kind:") {
        return Err(Error::engine(
            "KindMetadataV1 may only be set on kind:<Type> values",
        ));
    }
    if value.metadata == serde_json::to_value(&metadata)? {
        return Ok(());
    }
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            id,
            "vocab_value.metadata_set",
            json!({ "metadata": metadata }),
        )
        .with_actor(actor),
    )
    .await?;
    Ok(())
}

/// Move a value within its vocabulary without changing lifecycle status or
/// identity. Fractional ordinals let callers insert between existing values by
/// updating only the moved row.
pub async fn reorder_value(db: &Db, id: &str, ordinal: f64) -> Result<()> {
    reorder_value_as(db, id, ordinal, None).await
}

pub async fn reorder_value_as(db: &Db, id: &str, ordinal: f64, actor: Option<&str>) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    reorder_value_in(&mut tx, id, ordinal, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn reorder_value_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    ordinal: f64,
    actor: Option<&str>,
) -> Result<()> {
    if !ordinal.is_finite() {
        return Err(Error::engine("vocabulary value ordinal must be finite"));
    }
    get_value_on(tx, id).await?;
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(id, "vocab_value.reordered", json!({ "ordinal": ordinal }))
            .with_actor(actor),
    )
    .await?;
    Ok(())
}

/// Amend a value's gloss — the short prose definition callers read through
/// `suggest_facet_values` — without changing lifecycle status or identity.
///
/// `propose_value` is the only other writer of `gloss`, and it is closed to a
/// value that already exists, so without this verb every already-active value
/// (including every engine-seeded one) is permanently unglossed.
///
/// Deliberately imposes no status condition, exactly as `reorder_value` does
/// not: a proposed value's gloss should be correctable before promotion, and a
/// deprecated or aliased value's historical meaning is precisely what a later
/// reader of an old assignment needs. The event log preserves the before-state
/// either way.
pub async fn set_gloss(db: &Db, id: &str, gloss: Option<&str>) -> Result<()> {
    set_gloss_as(db, id, gloss, None).await
}

pub async fn set_gloss_as(
    db: &Db,
    id: &str,
    gloss: Option<&str>,
    actor: Option<&str>,
) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    set_gloss_in(&mut tx, id, gloss, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn set_gloss_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    gloss: Option<&str>,
    actor: Option<&str>,
) -> Result<()> {
    get_value_on(tx, id).await?;
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(id, "vocab_value.gloss_set", json!({ "gloss": gloss }))
            .with_actor(actor),
    )
    .await?;
    Ok(())
}

/// Promote a value to 'active'. Also the re-activation path for a deprecated
/// value — promotion clears any alias (an active value is canonical, not an
/// alias of something else).
pub async fn promote_value(db: &Db, id: &str) -> Result<()> {
    promote_value_as(db, id, None).await
}

pub async fn promote_value_as(db: &Db, id: &str, actor: Option<&str>) -> Result<()> {
    // The existence check moved inside the append transaction: as separate
    // autocommit statements a concurrent delete could land between check and
    // append, committing an authoritative event against a value that is gone.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    promote_value_in(&mut tx, id, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn promote_value_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    actor: Option<&str>,
) -> Result<()> {
    let value = get_value_on(tx, id).await?; // errors if missing
    let vocab = get_vocabulary_on(tx, &value.vocabulary_id).await?;
    if vocab
        .as_ref()
        .is_some_and(|vocab| vocab.name.starts_with("kind:"))
    {
        let metadata: KindMetadataV1 = serde_json::from_value(value.metadata).map_err(|err| {
            Error::engine(format!(
                "cannot promote kind value {id}: invalid or incomplete KindMetadataV1: {err}"
            ))
        })?;
        metadata.validate()?;
    }
    if value.status == "active" && value.alias_of.is_none() {
        return Ok(());
    }
    append_meta_in(
        tx,
        MetaAppendSpec::bare(id, "vocab_value.promoted").with_actor(actor),
    )
    .await?;
    Ok(())
}

/// Deprecate a value. This — not deletion — is how a value leaves service:
/// existing `facet_values` assignments keep resolving, tools stop suggesting it.
pub async fn deprecate_value(db: &Db, id: &str) -> Result<()> {
    deprecate_value_as(db, id, None).await
}

pub async fn deprecate_value_as(db: &Db, id: &str, actor: Option<&str>) -> Result<()> {
    deprecate_value_with_quarantine_count_as(db, id, actor)
        .await
        .map(|_| ())
}

/// Deprecate a value and report the live records newly quarantined by that
/// transition. The count and authoritative event share the same write
/// transaction, so another writer cannot change the population between them.
pub async fn deprecate_value_with_quarantine_count_as(
    db: &Db,
    id: &str,
    actor: Option<&str>,
) -> Result<i64> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let records_quarantined = deprecate_value_with_quarantine_count_in(&mut tx, id, actor).await?;
    tx.commit().await?;
    Ok(records_quarantined)
}

pub(crate) async fn deprecate_value_with_quarantine_count_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    actor: Option<&str>,
) -> Result<i64> {
    let value = get_value_on(tx, id).await?;
    if value.status == "deprecated" {
        return Ok(0);
    }
    let vocabulary = get_vocabulary_on(tx, &value.vocabulary_id).await?;
    let records_quarantined = if value.status == "active"
        && value.alias_of.is_none()
        && vocabulary
            .as_ref()
            .is_some_and(|vocabulary| vocabulary.name.starts_with("kind:"))
    {
        let record_type = vocabulary
            .as_ref()
            .and_then(|vocabulary| vocabulary.name.strip_prefix("kind:"))
            .expect("kind vocabulary prefix checked above");
        sqlx::query_scalar(
            "SELECT COUNT(*)
               FROM records r
              WHERE r.type = ? AND r.deleted_at IS NULL
                AND r.kind IN (
                    SELECT candidate.value
                      FROM vocabulary_values candidate
                     WHERE candidate.id = ? OR candidate.alias_of = ?
                )",
        )
        .bind(record_type)
        .bind(id)
        .bind(id)
        .fetch_one(&mut **tx)
        .await?
    } else {
        0
    };
    append_meta_in(
        tx,
        MetaAppendSpec::bare(id, "vocab_value.deprecated").with_actor(actor),
    )
    .await?;
    Ok(records_quarantined)
}

/// Alias a value to a canonical value in the same vocabulary (rename/merge).
/// The aliased value is deprecated in the same step — an alias is a redirect,
/// not a live value. Chains are rejected (the canonical must not itself be an
/// alias) so resolution is always one hop.
pub async fn alias_value(db: &Db, id: &str, canonical_id: &str) -> Result<()> {
    alias_value_as(db, id, canonical_id, None).await
}

pub async fn alias_value_as(
    db: &Db,
    id: &str,
    canonical_id: &str,
    actor: Option<&str>,
) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    alias_value_in(&mut tx, id, canonical_id, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn alias_value_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    canonical_id: &str,
    actor: Option<&str>,
) -> Result<()> {
    if id == canonical_id {
        return Err(Error::engine(format!(
            "cannot alias vocabulary value {id} to itself"
        )));
    }
    // Atomic with the checks: a concurrent alias of the canonical between the
    // chain check and this write would form the two-hop chain the check forbids.
    let value = get_value_on(tx, id).await?;
    let canonical = get_value_on(tx, canonical_id).await?;
    if value.vocabulary_id != canonical.vocabulary_id {
        return Err(Error::engine(format!(
            "cannot alias across vocabularies: {id} ({}) -> {canonical_id} ({})",
            value.vocabulary_id, canonical.vocabulary_id
        )));
    }
    if let Some(alias_of) = canonical.alias_of.as_ref() {
        return Err(Error::engine(format!(
            "cannot alias to {canonical_id}: it is itself an alias of {alias_of} — alias to the canonical value"
        )));
    }
    let vocabulary = get_vocabulary_on(tx, &value.vocabulary_id)
        .await?
        .ok_or_else(|| Error::engine("vocabulary value has no vocabulary"))?;
    if vocabulary.name.starts_with("kind:") && canonical.status != "active" {
        return Err(Error::engine(format!(
            "cannot alias kind value {id} to inactive canonical {canonical_id}; promote the canonical value first"
        )));
    }
    if value.vocabulary_id == "voc:glossary" {
        assert_glossary_alias_preserves_definitions(tx, &value, &canonical).await?;
    }
    append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            id,
            "vocab_value.aliased",
            json!({ "alias_of": canonical_id }),
        )
        .with_actor(actor),
    )
    .await?;
    Ok(())
}

/// Guard the content-side identity criterion while changing glossary identity.
///
/// Meta and content events remain separate authoritative logs, so this is a
/// live write guard rather than a projector rule. The check shares the meta
/// write transaction: SQLite's `BEGIN IMMEDIATE` serializes it with content
/// writes and closes the check/alias race without coupling either replay fold
/// to the other tier.
async fn assert_glossary_alias_preserves_definitions(
    conn: &mut SqliteConnection,
    value: &VocabularyValueRow,
    canonical: &VocabularyValueRow,
) -> Result<()> {
    let definition = crate::generated::kinds::CoreKind::DocumentDefinition.sql_matches("r");
    let source_definition_sql = format!(
        "SELECT r.id
           FROM records r
           JOIN facet_values f ON f.record_id = r.id
          WHERE {definition}
            AND r.maturity = 'decided'
            AND r.deleted_at IS NULL
            AND f.key = 'term'
            AND f.value = ?
            AND f.vocab_ref IN ('voc:glossary', 'rec:voc:glossary')
            AND NOT EXISTS (
                SELECT 1 FROM facet_values a
                 WHERE a.record_id = r.id AND a.key = 'archived'
            )
          ORDER BY r.id
          LIMIT 1"
    );
    let source_definition: Option<String> = sqlx::query_scalar(&source_definition_sql)
        .bind(&value.value)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(record_id) = source_definition {
        return Err(Error::engine(format!(
            "cannot alias glossary term '{}' while current agreed definition {} uses it — retarget or supersede that definition first",
            value.value, record_id
        )));
    }

    // Include definitions attached to pre-existing aliases of the source. Such
    // data can exist in an imported/legacy file even though supported writes
    // accept active values only. Moving the source must not collapse that
    // canonical identity onto another definition silently.
    let collision_sql = format!(
        "WITH current_definitions AS (
             SELECT r.id AS record_id,
                    CASE
                      WHEN term.id = ? THEN ?
                      WHEN term.alias_of = ? THEN ?
                      ELSE COALESCE(term.alias_of, term.id)
                    END AS resulting_canonical_id
               FROM records r
               JOIN facet_values f ON f.record_id = r.id
               JOIN vocabulary_values term
                 ON term.vocabulary_id = 'voc:glossary' AND term.value = f.value
              WHERE {definition}
                AND r.maturity = 'decided'
                AND r.deleted_at IS NULL
                AND f.key = 'term'
                AND f.vocab_ref IN ('voc:glossary', 'rec:voc:glossary')
                AND NOT EXISTS (
                    SELECT 1 FROM facet_values a
                     WHERE a.record_id = r.id AND a.key = 'archived'
                )
         )
         SELECT resulting_canonical_id, GROUP_CONCAT(record_id) AS record_ids
           FROM current_definitions
          WHERE resulting_canonical_id = ?
          GROUP BY resulting_canonical_id
         HAVING COUNT(*) > 1
          ORDER BY resulting_canonical_id
          LIMIT 1"
    );
    let collision = sqlx::query(&collision_sql)
        .bind(&value.id)
        .bind(&canonical.id)
        .bind(&value.id)
        .bind(&canonical.id)
        .bind(&canonical.id)
        .fetch_optional(&mut *conn)
        .await?;
    if let Some(row) = collision {
        let record_ids: String = row.try_get("record_ids")?;
        return Err(Error::engine(format!(
            "cannot alias glossary term '{}' to '{}': the resulting canonical term would have multiple current agreed definitions ({record_ids})",
            value.value, canonical.value
        )));
    }
    Ok(())
}

// ---- Hard delete — guarded (contract guard 1, task e035091) ---------------

/// Both forms a facet assignment may carry for a given vocabulary.
fn ref_forms(vocabulary_id: &str) -> (String, String) {
    (vocabulary_id.to_string(), vocab_ref(vocabulary_id))
}

/// Delete a vocabulary VALUE. Rejected when the value is:
///   - seeded (part of the shipped pack contract),
///   - referenced by a facet assignment (a `facet_values` row carries this
///     vocabulary's ref and this value), or
///   - the alias target of another value (deleting it would dangle `alias_of`).
///
/// Use `deprecate_value` / `alias_value` instead — that is the contract lifecycle.
pub async fn delete_value(db: &Db, id: &str) -> Result<()> {
    delete_value_as(db, id, None).await
}

pub async fn delete_value_as(db: &Db, id: &str, actor: Option<&str>) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    delete_value_in(&mut tx, id, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn delete_value_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id: &str,
    actor: Option<&str>,
) -> Result<()> {
    let value = get_value_on(tx, id).await?;
    let vocab = get_vocabulary_on(tx, &value.vocabulary_id).await?;
    if let Some(vocab) = &vocab {
        if is_seeded_value(&vocab.name, &value.value) {
            return Err(Error::engine(format!(
                "cannot delete seeded vocabulary value '{}' of '{}': seeded values are contract; deprecate instead",
                value.value, vocab.name
            )));
        }
        if let Some(record_type) = vocab.name.strip_prefix("kind:") {
            let referenced_by_records: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE type = ? AND kind = ?")
                    .bind(record_type)
                    .bind(&value.value)
                    .fetch_one(&mut **tx)
                    .await?;
            if referenced_by_records > 0 {
                return Err(Error::engine(format!(
                    "cannot delete kind value '{}' ({id}): {referenced_by_records} record(s) of type '{record_type}' store that token, including tombstones — deprecate or alias instead",
                    value.value
                )));
            }
        }
    }
    let (bare, prefixed) = ref_forms(&value.vocabulary_id);
    let referenced: i64 = sqlx::query(
        "SELECT COUNT(*) AS n FROM facet_values
            WHERE (vocab_ref = ? OR vocab_ref = ?) AND value = ?",
    )
    .bind(&bare)
    .bind(&prefixed)
    .bind(&value.value)
    .fetch_one(&mut **tx)
    .await?
    .get("n");
    if referenced > 0 {
        return Err(Error::engine(format!(
            "cannot delete vocabulary value '{}' ({id}): {referenced} facet assignment(s) reference it — deprecate or alias instead",
            value.value
        )));
    }
    let aliased: i64 =
        sqlx::query("SELECT COUNT(*) AS n FROM vocabulary_values WHERE alias_of = ?")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?
            .get("n");
    if aliased > 0 {
        return Err(Error::engine(format!(
            "cannot delete vocabulary value '{}' ({id}): {aliased} value(s) alias to it",
            value.value
        )));
    }
    append_meta_in(
        tx,
        MetaAppendSpec::bare(id, "vocab_value.deleted").with_actor(actor),
    )
    .await?;
    Ok(())
}

/// Delete a VOCABULARY. Rejected when it is seeded, when ANY facet assignment
/// references it, or when ANY `schema_config` row names it as a facet's
/// governing vocabulary — `vocabulary_values` cascade-delete off their parent,
/// and neither `facet_values.vocab_ref` nor a schema shape has an FK, so an
/// unguarded delete would strand what points at it.
///
/// The `schema_config` half is not a nicety. The four SPINE facets project to
/// COLUMNS on `records` and never produce a `facet_values` row, so the
/// assignment count below is structurally incapable of protecting a vocabulary
/// that governs one — however many records carry it. Without this second
/// count, a spine facet's interop floor (3057bba §4, enforced at
/// `mcp::tools::meta`) can be left naming a vocabulary that no longer exists.
pub async fn delete_vocabulary(db: &Db, id_or_name: &str) -> Result<()> {
    delete_vocabulary_as(db, id_or_name, None).await
}

pub async fn delete_vocabulary_as(db: &Db, id_or_name: &str, actor: Option<&str>) -> Result<()> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    delete_vocabulary_in(&mut tx, id_or_name, actor).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn delete_vocabulary_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    id_or_name: &str,
    actor: Option<&str>,
) -> Result<()> {
    let Some(vocab) = get_vocabulary_on(tx, id_or_name).await? else {
        return Err(Error::engine(format!(
            "vocabulary {id_or_name} does not exist"
        )));
    };
    if is_seeded_vocabulary(&vocab.name) {
        return Err(Error::engine(format!(
            "cannot delete seeded vocabulary '{}': seeded vocabularies are contract; deprecate values instead",
            vocab.name
        )));
    }
    let (bare, prefixed) = ref_forms(&vocab.id);
    let referenced: i64 =
        sqlx::query("SELECT COUNT(*) AS n FROM facet_values WHERE vocab_ref = ? OR vocab_ref = ?")
            .bind(&bare)
            .bind(&prefixed)
            .fetch_one(&mut **tx)
            .await?
            .get("n");
    if referenced > 0 {
        return Err(Error::engine(format!(
            "cannot delete vocabulary '{}' ({}): {referenced} facet assignment(s) reference it — deleting would cascade its values and strand them",
            vocab.name, vocab.id
        )));
    }
    // Any depth, any shape, both key spellings, and every designator form a
    // stored config may legally carry: `rec:<id>`, bare `<id>`, and the NAME —
    // `get_vocabulary` matches id OR name, and pack rows are seeded as written
    // rather than canonicalised.
    let configured: Vec<String> = sqlx::query(
        "SELECT DISTINCT layer FROM schema_config, json_tree(schema_config.data)
          WHERE json_tree.key IN ('vocab', 'vocab_ref')
            AND json_tree.value IN (?, ?, ?)
          ORDER BY layer",
    )
    .bind(&bare)
    .bind(&prefixed)
    .bind(&vocab.name)
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|row| row.get::<String, _>("layer"))
    .collect();
    if !configured.is_empty() {
        return Err(Error::engine(format!(
            "cannot delete vocabulary '{}' ({}): the {} schema_config layer(s) govern a facet with it — deleting would leave the shape naming a vocabulary that does not exist. Re-point the shape first (a pack layer is seed-only, so a pack reference cannot be edited away)",
            vocab.name,
            vocab.id,
            configured.join(" and ")
        )));
    }
    append_meta_in(
        tx,
        MetaAppendSpec::bare(&vocab.id, "vocabulary.deleted").with_actor(actor),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One seeded value as it is born: token, ordinal, terminality.
    type PinnedValue = (&'static str, f64, VocabularyValueTerminality);
    /// A seeded vocabulary name with the values it ships.
    type PinnedVocabulary = (&'static str, &'static [PinnedValue]);

    /// Every seeded vocabulary, every value, and the ordinal and terminality
    /// that value is born with — written out rather than derived, so a change
    /// to the seeding tables has to be made twice and meant once.
    ///
    /// This is the shipped contract: these rows are what `seed_vocabularies`
    /// projects into `vocabulary_values`, what the Postgres and Turso-local
    /// genesis projections write, and what rebuild-and-diff conformance
    /// compares against. Values here are never re-seeded once a database
    /// exists, so an edit is a migration question, not an edit.
    const PINNED_SEEDING: &[PinnedVocabulary] = &[
        (
            "maturity",
            &[
                ("exploratory", 0.0, VocabularyValueTerminality::Open),
                ("candidate", 0.0, VocabularyValueTerminality::Open),
                ("proposed", 0.0, VocabularyValueTerminality::Open),
                ("decided", 0.0, VocabularyValueTerminality::Open),
                ("superseded", 0.0, VocabularyValueTerminality::Open),
            ],
        ),
        (
            "confidence",
            &[
                ("speculative", 0.0, VocabularyValueTerminality::Open),
                ("tentative", 0.0, VocabularyValueTerminality::Open),
                ("likely", 0.0, VocabularyValueTerminality::Open),
                ("confident", 0.0, VocabularyValueTerminality::Open),
            ],
        ),
        ("glossary", &[]),
        (
            "artifact-runtime",
            &[
                ("native.board.v1", 0.0, VocabularyValueTerminality::Open),
                ("native.html.v1", 0.0, VocabularyValueTerminality::Open),
                ("native.mdx.v1", 0.0, VocabularyValueTerminality::Open),
                ("native.mdx.v2", 0.0, VocabularyValueTerminality::Open),
            ],
        ),
        (
            "recipe-runtime",
            &[("native.recipe.v1", 0.0, VocabularyValueTerminality::Open)],
        ),
        (
            "message-expectation",
            &[
                ("none", 0.0, VocabularyValueTerminality::Open),
                ("ack", 0.0, VocabularyValueTerminality::Open),
                ("reply", 0.0, VocabularyValueTerminality::Open),
                ("action", 0.0, VocabularyValueTerminality::Open),
                ("decision", 0.0, VocabularyValueTerminality::Open),
            ],
        ),
        (
            "lifecycle",
            &[
                ("open", 100.0, VocabularyValueTerminality::Open),
                ("in_progress", 200.0, VocabularyValueTerminality::Open),
                ("blocked", 300.0, VocabularyValueTerminality::Open),
                (
                    "completed",
                    400.0,
                    VocabularyValueTerminality::TerminalPositive,
                ),
                (
                    "closed",
                    500.0,
                    VocabularyValueTerminality::TerminalNegative,
                ),
            ],
        ),
        (
            "comment-lifecycle",
            &[
                ("informational", 100.0, VocabularyValueTerminality::Open),
                ("open", 200.0, VocabularyValueTerminality::Open),
                (
                    "resolved",
                    300.0,
                    VocabularyValueTerminality::TerminalPositive,
                ),
            ],
        ),
        (
            "suggestion-lifecycle",
            &[
                ("open", 100.0, VocabularyValueTerminality::Open),
                (
                    "accepted",
                    200.0,
                    VocabularyValueTerminality::TerminalPositive,
                ),
                (
                    "rejected",
                    300.0,
                    VocabularyValueTerminality::TerminalNegative,
                ),
                ("stale", 400.0, VocabularyValueTerminality::TerminalNegative),
            ],
        ),
        (
            "selection-role",
            &[("alternative_set", 0.0, VocabularyValueTerminality::Open)],
        ),
    ];

    const PINNED_LIFECYCLE_GLOSSES: &[(&str, &str, &str)] = &[
        (
            "lifecycle",
            "open",
            "Work is available but has not started.",
        ),
        ("lifecycle", "in_progress", "Work is actively underway."),
        (
            "lifecycle",
            "blocked",
            "Work cannot currently proceed because of an impediment.",
        ),
        (
            "lifecycle",
            "completed",
            "Work finished successfully and achieved its intended outcome.",
        ),
        (
            "lifecycle",
            "closed",
            "Work ended without completion or is no longer being pursued.",
        ),
        (
            "comment-lifecycle",
            "informational",
            "An informational thread that requires no resolution.",
        ),
        (
            "comment-lifecycle",
            "open",
            "A thread that remains active and may require a response or resolution.",
        ),
        (
            "comment-lifecycle",
            "resolved",
            "A thread whose question or concern has been addressed.",
        ),
        (
            "suggestion-lifecycle",
            "open",
            "A proposed change awaiting disposition.",
        ),
        (
            "suggestion-lifecycle",
            "accepted",
            "A proposed change that was applied to its target.",
        ),
        (
            "suggestion-lifecycle",
            "rejected",
            "A proposed change declined on its merits and not applied.",
        ),
        (
            "suggestion-lifecycle",
            "stale",
            "A proposed change ended without application because its precondition no longer held.",
        ),
    ];

    #[test]
    fn seeded_vocabularies_match_their_pinned_values_ordinals_and_terminality() {
        let actual: Vec<(&str, Vec<PinnedValue>)> = SEED_VOCABULARIES
            .iter()
            .map(|(name, values)| (*name, values.seeded().collect()))
            .collect();
        let pinned: Vec<(&str, Vec<PinnedValue>)> = PINNED_SEEDING
            .iter()
            .map(|(name, values)| (*name, values.to_vec()))
            .collect();
        assert_eq!(actual, pinned);
    }

    #[test]
    fn built_in_lifecycle_glosses_match_their_pinned_nonblank_contract() {
        assert_eq!(
            BUILT_IN_LIFECYCLE_GLOSSES.as_slice(),
            PINNED_LIFECYCLE_GLOSSES
        );
        assert_eq!(BUILT_IN_LIFECYCLE_GLOSSES.len(), 12);
        for (vocabulary, value, gloss) in BUILT_IN_LIFECYCLE_GLOSSES {
            assert!(
                !gloss.trim().is_empty(),
                "`{vocabulary}` value `{value}` has a blank built-in gloss"
            );
            let seeded = SEED_VOCABULARIES
                .iter()
                .find(|(name, _)| *name == vocabulary)
                .is_some_and(|(_, values)| values.contains(value));
            assert!(
                seeded,
                "`{vocabulary}` gloss names unseeded value `{value}`"
            );
        }
        for (vocabulary, values) in SEED_VOCABULARIES {
            if vocabulary == "lifecycle" || vocabulary.ends_with("-lifecycle") {
                for value in values.values() {
                    assert!(
                        built_in_lifecycle_gloss(vocabulary, value).is_some(),
                        "`{vocabulary}` value `{value}` has no built-in gloss"
                    );
                }
            }
        }
    }

    /// The failure this exists for: a lifecycle vocabulary seeded flat and
    /// open, so its terminal values are reported non-terminal to every
    /// downstream reader. That used to be reachable by deleting one arm of a
    /// name-keyed `match` whose wildcard returned an empty table — a clean
    /// merge, a clean compile, and a silent degradation, which is how the
    /// `suggestion-lifecycle` arm was lost once already.
    ///
    /// `SeededValues` now makes flat-versus-progression a choice each entry
    /// states, so the arm cannot go missing. This asserts the choice was made
    /// the right way for anything shaped like a lifecycle, including
    /// vocabularies nobody has written yet.
    #[test]
    fn every_lifecycle_vocabulary_declares_a_progression() {
        for (name, values) in SEED_VOCABULARIES {
            if name == "lifecycle" || name.ends_with("-lifecycle") {
                assert!(
                    values.is_progression(),
                    "lifecycle vocabulary `{name}` is seeded flat and open: its terminal \
                     values would be reported non-terminal. Declare it as \
                     SeededValues::Progression with an ordinal and terminality per value."
                );
            }
        }
    }

    /// A progression that is declared but half-written is the other way to get
    /// meaningless ordinals. Duplicate or unordered ordinals make "later in the
    /// progression" undecidable, and a duplicate token makes seeding
    /// non-idempotent against its own value ids.
    #[test]
    fn declared_progressions_are_strictly_ordered_and_unique() {
        for (name, values) in SEED_VOCABULARIES {
            let SeededValues::Progression(progression) = values else {
                continue;
            };
            let mut previous: Option<(&str, f64)> = None;
            for (token, ordinal, _) in progression {
                assert!(
                    *ordinal > 0.0,
                    "`{name}` value `{token}` has ordinal {ordinal}: a progression value \
                     needs a real position, and 0.0 is what flat-and-open means"
                );
                if let Some((previous_token, previous_ordinal)) = previous {
                    assert!(
                        *ordinal > previous_ordinal,
                        "`{name}` value `{token}` (ordinal {ordinal}) does not come after \
                         `{previous_token}` (ordinal {previous_ordinal})"
                    );
                }
                previous = Some((token, *ordinal));
            }
            let mut tokens: Vec<&str> = progression.iter().map(|(token, _, _)| *token).collect();
            tokens.sort_unstable();
            let unique = tokens.len();
            tokens.dedup();
            assert_eq!(tokens.len(), unique, "`{name}` declares a value twice");
        }
    }

    /// Seeding reads its ordinals and terminality straight off the entry, so a
    /// vocabulary that is flat is flat because it says so, not because a
    /// lookup missed.
    #[test]
    fn flat_vocabularies_seed_every_value_open_at_the_same_ordinal() {
        for (name, values) in SEED_VOCABULARIES {
            let SeededValues::Flat(_) = values else {
                continue;
            };
            for (token, ordinal, terminality) in values.seeded() {
                assert_eq!(
                    ordinal, 0.0,
                    "flat `{name}` value `{token}` carries an ordinal"
                );
                assert_eq!(
                    terminality,
                    VocabularyValueTerminality::Open,
                    "flat `{name}` value `{token}` claims terminality"
                );
            }
        }
    }
}
