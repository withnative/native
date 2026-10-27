//! Retained named-view interpreters. Available even when v2 serving is disabled.
//! No operation can emit these events until the admission surface is enabled.
use crate::{events::EventRow, Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

pub(crate) mod closure;
pub(crate) mod contract;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod details;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod gate;
#[cfg(feature = "v2-kernel-probe")]
mod source_proof;
pub(crate) mod storage;
mod v2;
pub(crate) use storage::load_prefix;
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) use storage::INDEX_DDL;

pub(crate) const LEGACY: &str = "kernel.named_view_admitted.v1";
pub(crate) const REVISION: &str = "kernel.named_view_revision_recorded.v1";
pub(crate) const TRANSITION: &str = "kernel.named_view_binding_changed.v1";
pub(crate) const MAX_CARRIER_BYTES: usize = 256 * 1024;
pub(crate) const MAX_REVISIONS: usize = 256;
pub(crate) const MAX_TRANSITIONS: usize = 512;
pub(crate) const MAX_ACTIVE: usize = 8;

pub(crate) fn is_new_event(kind: &str) -> bool {
    matches!(kind, REVISION | TRANSITION)
}

/// Retained replay never consults the producer gate.
pub(crate) fn admit(kind: &str) -> Result<()> {
    if is_new_event(kind) {
        #[cfg(feature = "v2-kernel-probe")]
        return gate::require();
        #[cfg(not(feature = "v2-kernel-probe"))]
        return Err(Error::engine("named view admission is disabled"));
    }
    if kind == LEGACY && !cfg!(test) {
        return Err(Error::engine("legacy named-view admission is unsupported"));
    }
    Ok(())
}

pub(crate) const MISSING: &str = "view_missing: required view or definition unavailable";

fn invalid(message: &str) -> Error {
    if message == "view_missing" {
        return Error::engine(MISSING);
    }
    Error::engine(format!("named view: {message}"))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub(crate) struct Pin {
    pub view_id: String,
    pub revision_id: String,
    pub definition_sha256: String,
    pub schema_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revision {
    pub v: u32,
    pub view_id: String,
    pub definition_sha256: String,
    pub definition: serde_json::Value,
}

impl Revision {
    fn generated_name(&self) -> Option<String> {
        if self.v != 2 {
            return None;
        }
        Some(contract::generated_name(
            self.definition
                .pointer("/generated/workspace_id")?
                .as_str()?,
            self.definition.pointer("/origin/generator")?.as_str()?,
            self.definition
                .pointer("/origin/source_identity")?
                .as_str()?,
            self.definition.pointer("/origin/selector")?.as_str()?,
        ))
    }
    pub(crate) fn digest(&self) -> String {
        let value = serde_json::json!([
            "native.named-view-revision.v1",
            self.v,
            self.view_id,
            self.definition
        ]);
        format!(
            "{:x}",
            Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
                &value
            ))
        )
    }

    #[cfg(any(test, feature = "v2-kernel-probe"))]
    fn validate(&self, event: &EventRow) -> Result<contract::Definition> {
        if self.v != 1 {
            return Err(invalid("view_revision_unavailable"));
        }
        self.validate_retained(event)
    }

    fn validate_retained(&self, event: &EventRow) -> Result<contract::Definition> {
        if !matches!(self.v, 1 | 2)
            || self.view_id != format!("native.named-view:{}", event.record_id)
            || self.definition_sha256 != self.digest()
            || uuid::Uuid::parse_str(&event.id).is_err()
        {
            return Err(invalid("revision identity/version/digest mismatch"));
        }
        if self.v == 2 {
            let definition: v2::Definition = serde_json::from_value(self.definition.clone())?;
            if serde_json::to_value(&definition)? != self.definition {
                return Err(invalid("non-canonical revision definition"));
            }
            definition.validate()?;
            return Ok(definition.common());
        }
        let definition: contract::Definition = serde_json::from_value(self.definition.clone())?;
        if serde_json::to_value(&definition)? != self.definition {
            return Err(invalid("non-canonical revision definition"));
        }
        definition.validate_retained()?;
        Ok(definition)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(try_from = "TransitionWire")]
pub(crate) struct Transition {
    pub v: u32,
    pub view_id: String,
    pub expected: Option<String>,
    #[serde(flatten)]
    pub action: Action,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransitionWire {
    v: u32,
    view_id: String,
    expected: Option<String>,
    action: String,
    name: Option<String>,
    pin: Option<Pin>,
}
impl TryFrom<TransitionWire> for Transition {
    type Error = String;
    fn try_from(w: TransitionWire) -> std::result::Result<Self, String> {
        let action = match (w.action.as_str(), w.name, w.pin) {
            ("activate", Some(name), Some(pin)) => Action::Activate { name, pin },
            ("unpublish", None, None) => Action::Unpublish,
            _ => return Err("invalid binding action fields".into()),
        };
        Ok(Self {
            v: w.v,
            view_id: w.view_id,
            expected: w.expected,
            action,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Action {
    Activate { name: String, pin: Pin },
    Unpublish,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RevisionHeader {
    pub record_id: String,
    pub seq: i64,
    pub digest: String,
    pub schema_digest: String,
    pub generated: bool,
    pub generated_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub event_id: String,
    pub active: Option<(String, Pin)>,
}

#[derive(Default, Clone, Debug)]
pub(crate) struct ReplayChecker {
    pub revisions: BTreeMap<String, RevisionHeader>,
    pub bindings: BTreeMap<String, Binding>,
    pub transitions: usize,
    pub legacy: bool,
    last_seq: i64,
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
    if !(6..=128).contains(&name.len())
        || !name.starts_with("view_")
        || crate::query::sql_contract::is_logical_relation(name)
        || !name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    {
        return Err(invalid("invalid view_ relation name"));
    }
    Ok(())
}

fn decode<T: serde::de::DeserializeOwned>(event: &EventRow, cap: usize) -> Result<T> {
    let raw = event
        .payload
        .as_deref()
        .ok_or_else(|| invalid("missing payload"))?;
    if raw.len() > cap {
        return Err(invalid("payload exceeds bound"));
    }
    Ok(serde_json::from_str(raw)?)
}

impl ReplayChecker {
    /// Validate before changing the checker; callers discard it on any error.
    pub(crate) fn apply(&mut self, event: &EventRow) -> Result<()> {
        self.apply_with_headers(event, true)
    }

    // Only the separately typed live reducer may trust canonical historical pins.
    fn apply_with_headers(&mut self, event: &EventRow, certified: bool) -> Result<()> {
        if !is_new_event(&event.event_type) && event.event_type != LEGACY {
            return Ok(());
        }
        if event.local_seq <= self.last_seq {
            return Err(invalid("event prefix order mismatch"));
        }
        if event.event_type == LEGACY {
            self.legacy = true;
        } else if event.event_type == REVISION {
            let revision: Revision = decode(event, MAX_CARRIER_BYTES)?;
            let definition = revision.validate_retained(event)?;
            for dep in definition.query.relations.values() {
                if let contract::Dependency::View(pin) = dep {
                    let header = self
                        .revisions
                        .get(&pin.revision_id)
                        .ok_or_else(|| invalid("revision dependency unavailable"))?;
                    if header.seq >= event.local_seq
                        || format!("native.named-view:{}", header.record_id) != pin.view_id
                        || header.digest != pin.definition_sha256
                        || header.schema_digest != pin.schema_sha256
                    {
                        return Err(invalid("retained revision dependency pin mismatch"));
                    }
                }
            }
            if self.revisions.len() >= MAX_REVISIONS
                || self.revisions.contains_key(&event.id)
                || self
                    .revisions
                    .values()
                    .filter(|r| r.record_id == event.record_id)
                    .count()
                    >= 128
            {
                return Err(invalid("revision history limit or duplicate revision"));
            }
            let schema = revision
                .definition
                .pointer("/query/output/schema_sha256")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| invalid("missing schema digest"))?;
            self.revisions.insert(
                event.id.clone(),
                RevisionHeader {
                    record_id: event.record_id.clone(),
                    seq: event.local_seq,
                    generated_name: revision.generated_name(),
                    digest: revision.definition_sha256,
                    schema_digest: schema.to_owned(),
                    generated: revision
                        .definition
                        .pointer("/origin/kind")
                        .and_then(serde_json::Value::as_str)
                        == Some("generated"),
                },
            );
        } else {
            let transition: Transition = decode(event, 2048)?;
            if transition.v != 1
                || transition.view_id != format!("native.named-view:{}", event.record_id)
                || self.bindings.get(&transition.view_id).map(|b| &b.event_id)
                    != transition.expected.as_ref()
            {
                return Err(invalid("binding identity/version/predecessor mismatch"));
            }
            if self.transitions >= MAX_TRANSITIONS {
                return Err(invalid("transition history limit"));
            }
            let active = match transition.action {
                Action::Activate { name, pin } => {
                    validate_name(&name)?;
                    contract::validate_pin(&pin)?;
                    if self.transitions >= MAX_TRANSITIONS - MAX_ACTIVE {
                        return Err(invalid("transition unpublish reserve"));
                    }
                    let header = self
                        .revisions
                        .get(&pin.revision_id)
                        .ok_or_else(|| invalid("revision unavailable"))?;
                    if certified
                        && header
                            .generated_name
                            .as_ref()
                            .is_some_and(|expected| expected != &name)
                    {
                        return Err(invalid("generated revision name mismatch"));
                    }
                    if certified && header.generated && !name.starts_with("view_gen_") {
                        return Err(invalid("generated revision requires view_gen_ name"));
                    }
                    if certified && !header.generated {
                        contract::authored_name(&name)?;
                    }
                    if pin.view_id != transition.view_id
                        || header.record_id != event.record_id
                        || header.seq >= event.local_seq
                        || (certified
                            && (header.digest != pin.definition_sha256
                                || header.schema_digest != pin.schema_sha256))
                    {
                        return Err(invalid("revision pin mismatch"));
                    }
                    if self.bindings.iter().any(|(id, b)| {
                        id != &transition.view_id
                            && b.active
                                .as_ref()
                                .is_some_and(|(n, _)| n.eq_ignore_ascii_case(&name))
                    }) {
                        return Err(invalid("name unavailable"));
                    }
                    let replacing = self
                        .bindings
                        .get(&transition.view_id)
                        .is_some_and(|b| b.active.is_some());
                    if !replacing
                        && self
                            .bindings
                            .values()
                            .filter(|b| b.active.is_some())
                            .count()
                            >= MAX_ACTIVE
                    {
                        return Err(invalid("active binding limit"));
                    }
                    Some((name, pin))
                }
                Action::Unpublish => {
                    if !self
                        .bindings
                        .get(&transition.view_id)
                        .is_some_and(|b| b.active.is_some())
                    {
                        return Err(invalid("unpublish requires active binding"));
                    }
                    None
                }
            };
            self.bindings.insert(
                transition.view_id,
                Binding {
                    event_id: event.id.clone(),
                    active,
                },
            );
            self.transitions += 1;
        }
        self.last_seq = event.local_seq;
        Ok(())
    }
}

type StoredEvent = (
    i64,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    String,
);

#[cfg(test)]
tokio::task_local! { static REVISION_READS: std::cell::Cell<usize>;
static REVISION_READ_IDS: std::cell::RefCell<BTreeMap<String, usize>>; }
#[cfg(test)]
async fn measured_revision_reads<T>(work: impl std::future::Future<Output = T>) -> (T, usize) {
    REVISION_READS
        .scope(std::cell::Cell::new(0), async {
            let result = work.await;
            (result, REVISION_READS.with(std::cell::Cell::get))
        })
        .await
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
async fn measured_revision_ids<T>(
    work: impl std::future::Future<Output = T>,
) -> (T, BTreeMap<String, usize>) {
    REVISION_READ_IDS
        .scope(std::cell::RefCell::new(BTreeMap::new()), async {
            let result = work.await;
            (result, REVISION_READ_IDS.with(|ids| ids.borrow().clone()))
        })
        .await
}

#[cfg(test)]
fn record_revision_access(id: &str) {
    let _ = REVISION_READS.try_with(|n| n.set(n.get() + 1));
    let _ =
        REVISION_READ_IDS.try_with(|ids| *ids.borrow_mut().entry(id.to_owned()).or_default() += 1);
}

pub(crate) async fn read_event(
    conn: &mut SqliteConnection,
    id: &str,
    head: i64,
) -> Result<EventRow> {
    let row: Option<StoredEvent> = sqlx::query_as(
        "SELECT seq,id,record_id,type,payload,actor,created_at FROM content_events WHERE id=? AND seq<=?")
        .bind(id).bind(head).fetch_optional(conn).await?;
    let (local_seq, id, record_id, event_type, payload, actor, created_at) =
        row.ok_or_else(|| invalid("view_revision_unavailable"))?;
    #[cfg(test)]
    if event_type == REVISION {
        record_revision_access(&id);
    }
    Ok(EventRow {
        local_seq,
        id,
        record_id,
        event_type,
        payload,
        actor,
        created_at,
        run_key: None,
        parent_key: None,
        intent: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    })
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.event_type == LEGACY {
        #[derive(Deserialize, Serialize)]
        #[serde(deny_unknown_fields)]
        struct Legacy {
            v: u32,
            name: String,
            definition_sha256: String,
            origin: String,
        }
        let binding: Legacy = decode(event, MAX_CARRIER_BYTES)?;
        validate_name(&binding.name)?;
        if binding.v != 1 || binding.origin != "authored" {
            return Err(invalid("legacy format mismatch"));
        }
        sqlx::query("INSERT INTO kernel_facets(record_id,key,value,as_of,event_seq) VALUES(?,'named_view',?,?,?)")
            .bind(&event.record_id).bind(serde_json::to_string(&binding)?).bind(&event.created_at).bind(event.local_seq)
            .execute(conn).await?;
        return Ok(());
    }
    // Replay uses deterministic work caps; only live requests have deadlines.
    let mut checker = load_prefix(conn, event.local_seq - 1, None).await?;
    checker.apply(event)?;
    verify_retained_sources_on(conn, event).await?;
    touch_metadata(conn, event).await
}

pub(crate) async fn touch_metadata(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    sqlx::query(
        "UPDATE kernel_record_metadata SET last_activity_at=?,event_seq=? WHERE record_id=?",
    )
    .bind(&event.created_at)
    .bind(event.local_seq)
    .bind(&event.record_id)
    .execute(conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests;

pub(crate) async fn verify_retained_sources_on(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    if event.event_type != REVISION {
        return Ok(());
    }
    let revision: Revision = decode(event, MAX_CARRIER_BYTES)?;
    // The checker already validates v2's closed manifest and empty strict pins.
    // Live generated-source requirements belong to the later serving adapter.
    if revision.v == 2 {
        return Ok(());
    }
    let definition: contract::Definition = serde_json::from_value(revision.definition)?;
    for pin in &definition.source_pins {
        let source = read_event(conn, &pin.revision_id, event.local_seq - 1).await?;
        if source.record_id != pin.record_id || closure::source_digest(&source)? != pin.sha256 {
            return Err(invalid("retained source pin mismatch"));
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) fn testing_definition() -> serde_json::Value {
    tests::definition_fixture()
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn inject_v2_reader_fixture(db: &crate::Db, bearer: &str) -> Pin {
    tests::v2_tests::inject_v2_reader_fixture(db, bearer).await
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) fn testing_v2_definition() -> serde_json::Value {
    let event = tests::v2_tests::v2_revision_for("fixture", 1);
    decode::<Revision>(&event, MAX_CARRIER_BYTES)
        .unwrap()
        .definition
}
