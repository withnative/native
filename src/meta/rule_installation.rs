//! Gated v2 rule-installation snapshot registry (task 81c1d95, S1).
//!
//! One row per `(scope_home, namespace, name)`: the full installation
//! snapshot carried by `rule_installation.set.v1`. Storage only — no
//! admission, call, or authority API here (S2). The fold verifies immutable
//! bytes/digests/receipt bindings only: never SQL preparation, catalog,
//! adoption, authority, or scope-existence checks (meta replays before
//! content roots/principals exist, so no FK to scope/principal).

use sqlx::{Sqlite, SqliteConnection, Transaction};

use crate::error::{Error, Result};
use crate::meta::events::RuleInstallationSetV1Payload;
use crate::meta::log::{append_meta_in, MetaAppendSpec};

/// Installation projection DDL, owned by the v2 kernel (never frozen v1
/// DDL, no migration). No FK to scope/principal: the meta fold runs before
/// content roots exist. Gated setup code executes these explicitly.
pub const RULE_INSTALLATION_DDL: [&str; 2] = [
    r#"CREATE TABLE rule_installations (
     scope_home       TEXT NOT NULL CHECK (length(scope_home) > 0),
     namespace        TEXT NOT NULL,
     name             TEXT NOT NULL,
     revision_json    TEXT NOT NULL CHECK (length(revision_json) > 0),
     revision_digest  TEXT NOT NULL CHECK (length(revision_digest) = 64),
     settings_json    TEXT NOT NULL,
     settings_digest  TEXT NOT NULL CHECK (length(settings_digest) = 64),
     catalog_revision INTEGER NOT NULL CHECK (catalog_revision >= 0),
     profile_id       TEXT NOT NULL CHECK (length(profile_id) > 0),
     profile_revision INTEGER NOT NULL CHECK (profile_revision >= 0),
     readsets_json    TEXT NOT NULL,
     readset_digest   TEXT NOT NULL CHECK (length(readset_digest) = 64),
     receipt_json     TEXT NOT NULL CHECK (length(receipt_json) > 0),
     language         TEXT NOT NULL CHECK (length(language) > 0),
     active           INTEGER NOT NULL CHECK (active IN (0, 1)),
     event_seq        INTEGER NOT NULL CHECK (event_seq >= 1),
     actor            TEXT NOT NULL CHECK (length(actor) > 0),
     created_at       TEXT NOT NULL,
     PRIMARY KEY (scope_home, namespace, name)
    )"#,
    r#"CREATE INDEX idx_rule_installations_scope
        ON rule_installations(scope_home)"#,
];

pub(crate) async fn ensure_rule_installation_tables(db: &crate::db::Db) -> Result<()> {
    for statement in RULE_INSTALLATION_DDL {
        sqlx::query(statement).execute(db.write_pool()).await?;
    }
    Ok(())
}

/// Consumer kind for rule-derived definition requirements in the single K6a
/// collector. Never a generic-registry kind: `CONSUMER_KINDS` stays closed,
/// so no generic register/retire API can forge or clear these rows.
pub const RULE_CONSUMER_KIND: &str = "rule";

/// Hex of the UTF-8 scope bytes: kernel root IDs are arbitrary nonempty text
/// and may contain `:`, so the raw scope can never be a subject component.
/// Namespace/name tokens (`[A-Za-z0-9._-]`) never contain `:` or `/`.
fn scope_hex(scope_home: &str) -> String {
    hex::encode(scope_home.as_bytes())
}

fn decode_scope_hex(hex_part: &str) -> Result<String> {
    let bytes = hex::decode(hex_part)
        .map_err(|_| Error::engine("rule installation subject has a corrupt scope"))?;
    String::from_utf8(bytes)
        .map_err(|_| Error::engine("rule installation subject has a corrupt scope"))
}

/// Deterministic meta-event subject for one installation key.
pub fn installation_subject(scope_home: &str, namespace: &str, name: &str) -> String {
    format!(
        "rule-installation:{}:{namespace}:{name}",
        scope_hex(scope_home)
    )
}

/// Literal subject prefix for one scope (indexed range census). Compared
/// with substr equality, never LIKE.
pub fn installation_scope_prefix(scope_home: &str) -> String {
    format!("rule-installation:{}:", scope_hex(scope_home))
}

/// Parse `rule-installation:{hex}:{namespace}:{name}` back into parts.
fn parse_installation_subject(subject: &str) -> Result<(String, String, String)> {
    let rest = subject
        .strip_prefix("rule-installation:")
        .ok_or_else(|| Error::engine("rule installation subject has a corrupt prefix"))?;
    let mut parts = rest.splitn(3, ':');
    let (Some(hex_part), Some(namespace), Some(name)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::engine(
            "rule installation subject has a corrupt shape",
        ));
    };
    if namespace.is_empty() || name.is_empty() {
        return Err(Error::engine("rule installation subject has a corrupt key"));
    }
    Ok((
        decode_scope_hex(hex_part)?,
        namespace.to_owned(),
        name.to_owned(),
    ))
}

/// Structural payload verification: recomputed digests, receipt bindings,
/// language, input/slot correspondence, population encoding, and retained
/// artifact pins. No SQL preparation, no catalog, no adoption, no authority,
/// no scope-existence checks — safe for historical fold before content roots
/// exist. Authoring defects (bad revision/settings) need a corrected revision
/// or settings, never a retry of the same bytes.
pub fn verify_installation_payload(
    subject_id: &str,
    payload: &RuleInstallationSetV1Payload,
) -> Result<()> {
    use crate::query::rule_install as ri;
    let revision = &payload.revision;
    if subject_id != installation_subject(&payload.scope_home, &revision.namespace, &revision.name)
    {
        return Err(Error::engine(
            "rule installation subject does not match revision identity",
        ));
    }
    // Replay-shaped prefix: shape plus recomputed revision/settings digests
    // through the shared helper (S1 tamper coverage pins the refusals).
    ri::verify_replay_revision(
        revision,
        &payload.revision_digest,
        &payload.settings,
        &payload.settings_digest,
    )?;
    // Exact input-name correspondence between declaration and host read-sets.
    let declared: std::collections::BTreeSet<&str> =
        revision.inputs.iter().map(|i| i.name.as_str()).collect();
    let derived: std::collections::BTreeSet<&str> =
        payload.readsets.keys().map(String::as_str).collect();
    if declared != derived {
        return Err(Error::engine(
            "rule installation read-sets do not exactly cover the declared inputs",
        ));
    }
    for input in &revision.inputs {
        let readset = payload.readsets.get(&input.name).ok_or_else(|| {
            Error::engine("rule installation read-set is missing a declared input")
        })?;
        let mut declared_slots: Vec<usize> = input.parameters.iter().map(|p| p.slot).collect();
        declared_slots.sort_unstable();
        let mut derived_slots = readset.parameter_slots.clone();
        derived_slots.sort_unstable();
        if declared_slots != derived_slots {
            return Err(Error::engine(
                "rule installation slots do not match the derived read-set",
            ));
        }
        for pinned in &readset.relations {
            if pinned.population_only != pinned.columns.is_empty() {
                return Err(Error::engine(
                    "rule installation population flag must match empty columns",
                ));
            }
        }
    }
    let pairs: Vec<(
        &str,
        &native_query_contract::rule_contract::RuleInputReadset,
    )> = payload
        .readsets
        .iter()
        .map(|(k, v)| (k.as_str(), v))
        .collect();
    let recomputed = ri::readset_digest(
        payload.catalog_revision,
        &payload.profile_id,
        payload.profile_revision,
        &pairs,
    );
    if recomputed != payload.readset_digest {
        return Err(Error::engine(
            "rule installation read-set digest does not match canonical evidence",
        ));
    }
    if payload.profile_id.is_empty() {
        return Err(Error::engine("rule installation profile must not be empty"));
    }
    let receipt = &payload.receipt;
    if receipt.revision_digest != payload.revision_digest
        || receipt.settings_digest != payload.settings_digest
        || receipt.readset_digest != payload.readset_digest
        || receipt.language_identity != revision.language
    {
        return Err(Error::engine(
            "rule installation receipt does not bind the snapshot digests",
        ));
    }
    ri::verify_receipt_usable(receipt)?;
    Ok(())
}

/// One stored installation as read back, with the authorizing event seq.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredInstallation {
    pub scope_home: String,
    pub namespace: String,
    pub name: String,
    pub revision: crate::query::rule_install::RuleRevision,
    pub revision_digest: String,
    pub settings: serde_json::Value,
    pub settings_digest: String,
    pub catalog_revision: u32,
    pub profile_id: String,
    pub profile_revision: u32,
    pub readsets:
        std::collections::BTreeMap<String, native_query_contract::rule_contract::RuleInputReadset>,
    pub readset_digest: String,
    pub receipt: crate::query::rule_install::RuleAdmissionReceipt,
    pub active: bool,
    pub event_seq: i64,
    pub actor: String,
}

/// Fold one `rule_installation.set.v1` event. Verifies the structural payload,
/// the nonempty actor, retained artifact pins by key lookup of installed
/// bytes only, and the previous-seq precondition against the live row — then
/// upserts the snapshot. Replacement and disable are atomic snapshot swaps:
/// the old live requirements vanish by derivation, never by partial edits.
pub(crate) async fn fold_installation_set_v1(
    conn: &mut SqliteConnection,
    event: &crate::meta::events::MetaEventRow,
) -> Result<()> {
    let payload_str = event
        .payload
        .as_deref()
        .ok_or_else(|| Error::engine("rule installation event has no payload"))?;
    let p: RuleInstallationSetV1Payload = serde_json::from_str(payload_str)?;
    verify_installation_payload(&event.subject_id, &p)?;
    if event.seq < 1 {
        return Err(Error::engine(
            "rule installation event has invalid sequence",
        ));
    }
    let actor = event.actor.clone().unwrap_or_default();
    if actor.is_empty() {
        return Err(Error::engine("rule installation event has no actor"));
    }
    for pin in &p.revision.definition_pins {
        let installed = crate::definition_registry::read_definition_artifact_on(
            &mut *conn,
            &pin.family,
            pin.version,
            &pin.digest,
        )
        .await?;
        if installed.is_none() {
            return Err(Error::engine(
                "rule installation selects a definition revision that is not installed",
            ));
        }
    }
    let current: Option<(i64,)> = sqlx::query_as(
        "SELECT event_seq FROM rule_installations
          WHERE scope_home = ? AND namespace = ? AND name = ?",
    )
    .bind(&p.scope_home)
    .bind(&p.revision.namespace)
    .bind(&p.revision.name)
    .fetch_optional(&mut *conn)
    .await?;
    // The pointer must advance: a previous seq is positive and strictly
    // below this event's seq — never self-referential or non-advancing.
    if let Some(previous) = p.previous_seq {
        if previous < 1 || previous >= event.seq {
            return Err(Error::engine(
                "rule installation previous seq must advance the log",
            ));
        }
    }
    match (current, p.previous_seq) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(Error::engine(
                "stale rule installation: create-only snapshot names a prior seq",
            ));
        }
        (Some(_), None) => {
            return Err(Error::engine(
                "stale rule installation: updates must name the current event seq",
            ));
        }
        (Some((seq,)), Some(previous)) if previous == seq => {}
        (Some(_), Some(_)) => {
            return Err(Error::engine(
                "stale rule installation: the snapshot moved under this writer",
            ));
        }
    }
    sqlx::query(
        "INSERT INTO rule_installations
            (scope_home, namespace, name, revision_json, revision_digest,
             settings_json, settings_digest, catalog_revision, profile_id,
             profile_revision, readsets_json, readset_digest, receipt_json,
             language, active, event_seq, actor, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(scope_home, namespace, name)
           DO UPDATE SET revision_json=excluded.revision_json,
             revision_digest=excluded.revision_digest,
             settings_json=excluded.settings_json,
             settings_digest=excluded.settings_digest,
             catalog_revision=excluded.catalog_revision,
             profile_id=excluded.profile_id,
             profile_revision=excluded.profile_revision,
             readsets_json=excluded.readsets_json,
             readset_digest=excluded.readset_digest,
             receipt_json=excluded.receipt_json, language=excluded.language,
             active=excluded.active, event_seq=excluded.event_seq,
             actor=excluded.actor, created_at=excluded.created_at",
    )
    .bind(&p.scope_home)
    .bind(&p.revision.namespace)
    .bind(&p.revision.name)
    .bind(serde_json::to_string(&p.revision)?)
    .bind(&p.revision_digest)
    .bind(serde_json::to_string(&p.settings)?)
    .bind(&p.settings_digest)
    .bind(p.catalog_revision as i64)
    .bind(&p.profile_id)
    .bind(p.profile_revision as i64)
    .bind(serde_json::to_string(&p.readsets)?)
    .bind(&p.readset_digest)
    .bind(serde_json::to_string(&p.receipt)?)
    .bind(&p.revision.language)
    .bind(if p.active { 1 } else { 0 })
    .bind(event.seq)
    .bind(&actor)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Projection row in SELECT field order: revision/settings/read-set JSON plus
/// digests, catalog/profile pins, language, status, seq, and actor.
type InstallationProjectionRow = (
    String,
    String,
    String,
    String,
    i64,
    String,
    i64,
    String,
    String,
    String,
    String,
    i64,
    i64,
    String,
);

/// Verified keyed read: projection row + latest authorizing event must agree
/// on bytes, seq, actor, and every hash (fixture guard included). Missing on
/// both sides is `Ok(None)`; log-only, projection-only, or any disagreement
/// is corruption, never a fallback.
pub(crate) async fn read_installation_in(
    conn: &mut SqliteConnection,
    scope_home: &str,
    namespace: &str,
    name: &str,
) -> Result<Option<StoredInstallation>> {
    let row: Option<InstallationProjectionRow> = sqlx::query_as(
        "SELECT revision_json, revision_digest, settings_json, settings_digest,
                catalog_revision, profile_id, profile_revision, readsets_json,
                readset_digest, receipt_json, language, active, event_seq, actor
           FROM rule_installations
          WHERE scope_home = ? AND namespace = ? AND name = ?",
    )
    .bind(scope_home)
    .bind(namespace)
    .bind(name)
    .fetch_optional(&mut *conn)
    .await?;
    let subject = installation_subject(scope_home, namespace, name);
    let event: Option<(String, String, i64, Option<String>)> = sqlx::query_as(
        "SELECT type, payload, seq, actor FROM meta_events
          WHERE subject_id = ? AND type = 'rule_installation.set.v1'
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(&subject)
    .fetch_optional(&mut *conn)
    .await?;
    match (row, event) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(Error::engine(
            "rule installation projection/log disagreement: events but no row",
        )),
        (Some(_), None) => Err(Error::engine(
            "rule installation projection/log disagreement: row but no event",
        )),
        (
            Some((
                revision_json,
                revision_digest,
                settings_json,
                settings_digest,
                catalog_revision,
                profile_id,
                profile_revision,
                readsets_json,
                readset_digest,
                receipt_json,
                language,
                active,
                event_seq,
                actor,
            )),
            Some((etype, payload, seq, eactor)),
        ) => {
            if etype != "rule_installation.set.v1" || seq != event_seq {
                return Err(Error::engine(
                    "rule installation projection disagrees with its log event",
                ));
            }
            if eactor.as_deref().unwrap_or("") != actor {
                return Err(Error::engine(
                    "rule installation actor disagrees with its log event",
                ));
            }
            let p: RuleInstallationSetV1Payload = serde_json::from_str(&payload)?;
            verify_installation_payload(&subject, &p)?;
            if p.scope_home != scope_home
                || p.revision.namespace != namespace
                || p.revision.name != name
            {
                return Err(Error::engine(
                    "rule installation event names a different key",
                ));
            }
            let revision: crate::query::rule_install::RuleRevision =
                serde_json::from_str(&revision_json)?;
            let settings: serde_json::Value = serde_json::from_str(&settings_json)?;
            let readsets: std::collections::BTreeMap<
                String,
                native_query_contract::rule_contract::RuleInputReadset,
            > = serde_json::from_str(&readsets_json)?;
            let receipt: crate::query::rule_install::RuleAdmissionReceipt =
                serde_json::from_str(&receipt_json)?;
            if revision != p.revision
                || settings != p.settings
                || readsets != p.readsets
                || receipt != p.receipt
                || revision_digest != p.revision_digest
                || settings_digest != p.settings_digest
                || readset_digest != p.readset_digest
                || language != p.revision.language
                || active != if p.active { 1 } else { 0 }
                || catalog_revision != p.catalog_revision as i64
                || profile_id != p.profile_id
                || profile_revision != p.profile_revision as i64
            {
                return Err(Error::engine(
                    "rule installation projection disagrees with its log event",
                ));
            }
            // Re-verify from the projected row itself (single verification
            // policy): a tampered projection that changes global/profile pins
            // while keeping a matching old read-set digest must still fail,
            // because the digest is recomputed from the row's own pins.
            let row_payload = RuleInstallationSetV1Payload {
                scope_home: scope_home.to_owned(),
                revision: revision.clone(),
                revision_digest: revision_digest.clone(),
                settings: settings.clone(),
                settings_digest: settings_digest.clone(),
                catalog_revision: u32::try_from(catalog_revision)
                    .map_err(|_| Error::engine("rule installation catalog revision is corrupt"))?,
                profile_id: profile_id.clone(),
                profile_revision: u32::try_from(profile_revision)
                    .map_err(|_| Error::engine("rule installation profile revision is corrupt"))?,
                readsets: readsets.clone(),
                readset_digest: readset_digest.clone(),
                receipt: receipt.clone(),
                active: active == 1,
                previous_seq: p.previous_seq,
            };
            verify_installation_payload(&subject, &row_payload)?;
            Ok(Some(StoredInstallation {
                scope_home: scope_home.to_owned(),
                namespace: namespace.to_owned(),
                name: name.to_owned(),
                revision,
                revision_digest,
                settings,
                settings_digest,
                catalog_revision: u32::try_from(catalog_revision)
                    .map_err(|_| Error::engine("rule installation catalog revision is corrupt"))?,
                profile_id,
                profile_revision: u32::try_from(profile_revision)
                    .map_err(|_| Error::engine("rule installation profile revision is corrupt"))?,
                readsets,
                readset_digest,
                receipt,
                active: active == 1,
                event_seq,
                actor,
            }))
        }
    }
}

/// Scoped census over the existing `idx_meta_events_subject`: a scope-prefix
/// range (never a global DISTINCT + Rust filter), unioned with the
/// scope-keyed projection. Log-only or projection-only keys fail the whole
/// list closed; every returned row is verified.
pub(crate) async fn list_installations_in_scope(
    conn: &mut SqliteConnection,
    scope_home: &str,
) -> Result<Vec<StoredInstallation>> {
    let prefix = installation_scope_prefix(scope_home);
    let end = format!("{prefix}\u{10FFFF}");
    let subjects: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT subject_id FROM meta_events
          WHERE subject_id >= ? AND subject_id < ?
            AND type = 'rule_installation.set.v1'",
    )
    .bind(&prefix)
    .bind(&end)
    .fetch_all(&mut *conn)
    .await?;
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT namespace, name FROM rule_installations WHERE scope_home = ?")
            .bind(scope_home)
            .fetch_all(&mut *conn)
            .await?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (namespace, name) in &rows {
        seen.insert(installation_subject(scope_home, namespace, name));
        let stored = read_installation_in(conn, scope_home, namespace, name)
            .await?
            .ok_or_else(|| Error::engine("rule installation vanished mid-list"))?;
        out.push(stored);
    }
    for (subject,) in subjects {
        let (scope, namespace, name) = parse_installation_subject(&subject)?;
        if scope != scope_home {
            return Err(Error::engine(
                "rule installation census crossed scopes: delimiter failure",
            ));
        }
        if !seen.contains(&subject) {
            return Err(Error::engine(
                "rule installation projection/log disagreement: events but no row",
            ));
        }
        let _ = (namespace, name);
    }
    out.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
    Ok(out)
}

/// Internal sealed host snapshot seam (S1): the host passes fully derived
/// objects — revision, settings, read-sets, receipt — and this seam computes
/// every digest, verifies the snapshot, enforces the previous-seq precondition
/// inside the caller's transaction, appends, and reads back. No caller proof
/// or receipt is accepted over any public API (none exists in S1); authoring
/// defects need a corrected revision or settings, never a retry. Exact retry
/// (same bytes, same actor) appends nothing and returns the stored row.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn set_installation_in(
    tx: &mut Transaction<'static, Sqlite>,
    scope_home: &str,
    revision: &crate::query::rule_install::RuleRevision,
    settings: &serde_json::Value,
    catalog_revision: u32,
    profile_id: &str,
    profile_revision: u32,
    readsets: &std::collections::BTreeMap<
        String,
        native_query_contract::rule_contract::RuleInputReadset,
    >,
    receipt: &crate::query::rule_install::RuleAdmissionReceipt,
    active: bool,
    previous_seq: Option<i64>,
    actor: Option<&str>,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<(StoredInstallation, bool)> {
    use crate::query::rule_install as ri;
    if scope_home.is_empty() {
        return Err(Error::engine("rule installation scope must not be empty"));
    }
    let actor_name = actor.unwrap_or("");
    if actor_name.is_empty() {
        return Err(Error::engine("rule installation actor must not be empty"));
    }
    let revision_digest = ri::revision_digest(revision)?;
    let settings_digest = ri::settings_digest(settings)?;
    let pairs: Vec<(
        &str,
        &native_query_contract::rule_contract::RuleInputReadset,
    )> = readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let readset_digest = ri::readset_digest(catalog_revision, profile_id, profile_revision, &pairs);
    let subject = installation_subject(scope_home, &revision.namespace, &revision.name);
    let payload = RuleInstallationSetV1Payload {
        scope_home: scope_home.to_owned(),
        revision: revision.clone(),
        revision_digest,
        settings: settings.clone(),
        settings_digest,
        catalog_revision,
        profile_id: profile_id.to_owned(),
        profile_revision,
        readsets: readsets.clone(),
        readset_digest,
        receipt: receipt.clone(),
        active,
        previous_seq,
    };
    // Shape/receipt proof first: no no-op return may bypass verification,
    // and no current-catalog check lives here (S2 admission owns that).
    verify_installation_payload(&subject, &payload)?;
    // Strict ExpectedSeq before any no-op: existing rows demand
    // Some(current seq), absent keys demand None. Writer precondition
    // mismatches are Conflict; fold/log inconsistency stays Engine.
    let current =
        read_installation_in(&mut *tx, scope_home, &revision.namespace, &revision.name).await?;
    match (&current, previous_seq) {
        (None, None) => {}
        (None, Some(_)) => {
            return Err(Error::conflict(
                "stale rule installation: create-only snapshot names a prior seq",
            ));
        }
        (Some(_), None) => {
            return Err(Error::conflict(
                "stale rule installation: updates must name the current event seq",
            ));
        }
        (Some(stored), Some(expected)) if expected != stored.event_seq => {
            return Err(Error::conflict(
                "stale rule installation: the snapshot moved under this writer",
            ));
        }
        (Some(_), Some(_)) => {}
    }
    if let Some(stored) = current {
        // Digest-grained no-op: canonical-equivalent permutations (e.g. input
        // declaration reorder, same digest) mint no new event. Scope/keys are
        // already current-read verified above.
        let same = stored.revision_digest == payload.revision_digest
            && stored.settings_digest == payload.settings_digest
            && stored.catalog_revision == catalog_revision
            && stored.profile_id == profile_id
            && stored.profile_revision == profile_revision
            && stored.readset_digest == payload.readset_digest
            && stored.receipt == *receipt
            && stored.active == active
            && actor_name == stored.actor;
        if same {
            return Ok((stored, false));
        }
    }
    let event = append_meta_in(
        tx,
        MetaAppendSpec::with_payload(
            &subject,
            "rule_installation.set.v1",
            serde_json::to_value(&payload)?,
        )
        .with_actor(actor),
        act_alloc,
    )
    .await?;
    let stored = read_installation_in(&mut *tx, scope_home, &revision.namespace, &revision.name)
        .await?
        .ok_or_else(|| Error::engine("rule installation missing after append"))?;
    debug_assert_eq!(stored.event_seq, event.seq);
    Ok((stored, true))
}
