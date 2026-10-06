//! Internal hosted producer. No normal tool/HTTP dispatch invokes this module.
//! Safe parsing proves syntax only; readiness requires the privileged request
//! bridge and original clock, then consuming transactional current checks.
use super::adoption_intent::{Consent, Intent as AdoptIntent, Outcome};
use super::*;
use serde::de::{MapAccess, SeqAccess, Visitor};
use std::fmt;
use std::time::{Duration, Instant};

pub const INPUT_BYTES: usize = 32 * 1024 * 1024;
pub(super) const SOURCE_BYTES: i64 = 16 * 1024 * 1024;

fn refused() -> Error {
    Error::engine("internal body producer refused")
}
fn conflict() -> Error {
    Error::engine("internal body install intent conflict")
}

// Recursively reject escaped-equivalent duplicate map keys BEFORE Value. This
// applies only to this new private raw lane, not arbitrary legacy JSON.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("duplicate-free JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(v)) = a.next_element()? {
                    out.push(v);
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(serde::de::Error::custom("duplicate JSON field"));
                    }
                    let Unique(v) = a.next_value()?;
                    out.insert(k, v);
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    action: String,
    package: String,
    version: String,
    digest: String,
    artifact_id: String,
    source_revision: String,
    declaration: Value,
    reason: String,
    #[serde(default)]
    request: Option<String>,
    #[serde(default)]
    expected_install_event_id: Option<String>,
    #[serde(default)]
    idempotency_key: Option<String>,
    #[serde(default)]
    receipt_id: Option<String>,
    #[serde(default)]
    preview_session: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}
impl Request {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() > INPUT_BYTES {
            return Err(refused());
        }
        let Unique(v) = serde_json::from_slice(raw).map_err(|_| refused())?;
        let r: Self = serde_json::from_value(v).map_err(|_| refused())?;
        if !matches!(r.action.as_str(), "install" | "preview" | "adopt") {
            return Err(refused());
        }
        if r.action != "install" && r.request.is_some() {
            return Err(refused());
        }
        if r.action != "adopt"
            && (r.receipt_id.is_some() || r.preview_session.is_some() || r.nonce.is_some())
        {
            return Err(refused());
        }
        // No current/frozen grammar check here: historical original lookup
        // must also retain unknown declaration material and ordered arrays.
        Ok(r)
    }
    pub fn action(&self) -> &str {
        &self.action
    }
    pub fn adopt_intent(&self) -> Result<AdoptIntent> {
        if self.action != "adopt" {
            return Err(refused());
        }
        Ok(AdoptIntent {
            package: self.package.clone(),
            version: self.version.clone(),
            digest: self.digest.clone(),
            artifact_id: self.artifact_id.clone(),
            source_revision: self.source_revision.clone(),
            declaration: self.declaration.clone(),
            reason: self.reason.clone(),
            expected_install_event_id: self
                .expected_install_event_id
                .clone()
                .ok_or_else(refused)?,
            idempotency_key: self.idempotency_key.clone(),
            consent: Consent::Receipt {
                receipt_id: self.receipt_id.clone().ok_or_else(refused)?,
                preview_session: self.preview_session.clone().ok_or_else(refused)?,
            },
        })
    }
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }
}

/// Borrowed nonserialized request, never a cloneable Caller marker.
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum PreviewFault {
    BeforeSample,
    AfterSample,
    BeforeReceipt,
    AfterReceipt,
}
#[cfg(test)]
type PreviewCapture = std::sync::Arc<std::sync::Mutex<Option<(String, Option<String>)>>>;
pub struct Ingress<'a> {
    db: &'a Db,
    caller: &'a Caller,
    request: &'a Request,
    handle: Uuid,
    deadline: Instant,
    #[cfg(test)]
    preview_fault: Option<PreviewFault>,
    #[cfg(test)]
    preview_capture: Option<PreviewCapture>,
}
impl<'a> Ingress<'a> {
    /// # Safety
    /// Host has verified actual configured-Origin cookie/CSRF, selected current
    /// membership/raw account/Db/handle and exact install or preview action.
    /// Retain deployment mutation admission through publication. started comes
    /// from private middleware BEFORE bounded Bytes extraction. No header,
    /// serialized flag, history, bearer/MCP/frame or legacy marker can supply it.
    pub unsafe fn from_verified_host(
        db: &'a Db,
        caller: &'a Caller,
        request: &'a Request,
        started: Instant,
    ) -> Result<Self> {
        if !matches!(request.action.as_str(), "install" | "preview") {
            return Err(refused());
        }
        for (s, cap) in [
            (caller.credential(), 256),
            (request.package.as_str(), 128),
            (request.version.as_str(), 256),
            (request.digest.as_str(), 256),
            (request.artifact_id.as_str(), 256),
            (request.source_revision.as_str(), 256),
            (request.reason.as_str(), 4096),
        ] {
            if s.trim().is_empty() || s.len() > cap {
                return Err(refused());
            }
        }
        if request
            .expected_install_event_id
            .as_ref()
            .is_some_and(|s| s.trim().is_empty() || s.len() > 256)
            || request
                .idempotency_key
                .as_ref()
                .is_some_and(|s| s.trim().is_empty() || s.len() > 1024)
            || request
                .request
                .as_ref()
                .is_some_and(|s| s.len() > INPUT_BYTES)
        {
            return Err(refused());
        }
        let g = Self {
            #[cfg(test)]
            preview_fault: None,
            #[cfg(test)]
            preview_capture: None,
            db,
            caller,
            request,
            handle: db.handle_id(),
            deadline: started
                .checked_add(Duration::from_secs(5))
                .ok_or_else(refused)?,
        };
        g.check()?;
        Ok(g)
    }
    fn check(&self) -> Result<()> {
        if self.db.handle_id() != self.handle || Instant::now() >= self.deadline {
            Err(refused())
        } else {
            Ok(())
        }
    }
    fn key(&self) -> String {
        let r = self.request;
        r.idempotency_key.clone().unwrap_or_else(|| {
            format!(
                "alpha-tab-install:{}:{}:{}:{}:{}",
                self.caller.credential(),
                r.package,
                r.version,
                r.digest,
                r.expected_install_event_id.as_deref().unwrap_or("genesis")
            )
        })
    }
}
fn checked_declaration(g: &Ingress<'_>) -> Result<(String, Vec<String>, Vec<String>)> {
    g.check()?;
    let r = g.request;
    require_package(&r.package)?;
    require_version(&r.version)?;
    require_digest(&r.digest)?;
    require_reason(TOOL, &r.reason)?;
    let dd = crate::alpha_tab_body_admission_v1::declaration_digest(&r.declaration)?;
    if !crate::alpha_tab_body_admission_v1::has_body_descriptor(&r.declaration)? {
        return Err(refused());
    }
    g.check()?;
    let parsed = require_declaration_for_adoption(&r.declaration, true)?;
    let mut needs = parsed.needs;
    let mut effects = parsed.effects;
    needs.sort();
    effects.sort();
    g.check()?;
    Ok((dd, needs, effects))
}

// Pure intrinsic installed grammar normalization, not current declaration
// admission: absent/null/blank request was stored as None by original install.
fn original_request(r: &Request) -> Option<&str> {
    r.request.as_deref().filter(|s| !s.trim().is_empty())
}
/// Original audit plus whether this invocation appended; neither is a current launch.
pub struct InstallOutcome {
    pub original: Outcome,
    pub changed: bool,
}
pub async fn install(g: &Ingress<'_>) -> Result<InstallOutcome> {
    if g.request.action != "install" {
        return Err(refused());
    }
    g.check()?;
    let r = g.request;
    let mut tx = crate::db::begin_write(g.db.write_pool()).await?;
    g.check()?;
    let key = g.key();
    let size: Option<i64> = sqlx::query_scalar(
        "SELECT octet_length(payload) FROM control_events WHERE idempotency_key=?",
    )
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;
    g.check()?;
    if let Some(size) = size {
        if !(0..=INPUT_BYTES as i64).contains(&size) {
            return Err(conflict());
        }
        let row=sqlx::query("SELECT id,type,schema_version,aggregate_kind,aggregate_id,actor,reason,payload,run_key,act FROM control_events WHERE idempotency_key=? AND octet_length(id)+octet_length(type)+octet_length(aggregate_kind)+octet_length(aggregate_id)+octet_length(actor)+octet_length(reason)+COALESCE(octet_length(run_key),0)<=8192")
            .bind(&key).fetch_optional(&mut *tx).await?.ok_or_else(conflict)?;
        g.check()?;
        if row.try_get::<String, _>("type")? != "alpha_tab.installed"
            || row.try_get::<i64, _>("schema_version")? != 1
            || row.try_get::<String, _>("aggregate_kind")? != "alpha_tab"
            || row.try_get::<String, _>("aggregate_id")?
                != alpha_tab_aggregate_id(g.caller.credential(), &r.package)
            || row.try_get::<String, _>("actor")? != g.caller.actor()
            || row.try_get::<String, _>("reason")? != r.reason
        {
            return Err(conflict());
        }
        let p: AlphaTabStatePayload =
            serde_json::from_str(&row.try_get::<String, _>("payload")?).map_err(|_| conflict())?;
        if p.account_id != g.caller.credential()
            || p.package != r.package
            || p.version != r.version
            || p.digest != r.digest
            || p.artifact_id != r.artifact_id
            || p.consented_source_revision != r.source_revision
            || p.consented_declaration != r.declaration
            || p.previous_event_id != r.expected_install_event_id
            || p.request.as_deref() != original_request(r)
            || p.adoption != crate::control::ALPHA_TAB_ADOPTION_CALLER_ASSERTED
        {
            return Err(conflict());
        }
        let out = Outcome {
            event_id: row.try_get("id")?,
            event_type: "alpha_tab.installed".into(),
            original_run_key: row.try_get("run_key")?,
            original_act: row.try_get("act")?,
            original_request: p.request,
        };
        tx.rollback().await?;
        g.check()?;
        return Ok(InstallOutcome {
            original: out,
            changed: false,
        });
    }
    let (dd, _, _) = checked_declaration(g)?;
    let request = require_request(r.request.clone())?;
    let _ = checked_source(
        &mut tx,
        g.caller,
        &r.artifact_id,
        &r.source_revision,
        &r.digest,
        &dd,
        || g.check(),
    )
    .await?;
    let size:Option<i64>=sqlx::query_scalar("SELECT octet_length(status)+octet_length(event_id) FROM alpha_tab_installs WHERE account_id=? AND package=?")
        .bind(g.caller.credential()).bind(&r.package).fetch_optional(&mut *tx).await?;
    g.check()?;
    if size.is_some_and(|n| !(0..=8192).contains(&n)) {
        return Err(refused());
    }
    let current: Option<(String, String)> = sqlx::query_as(
        "SELECT status,event_id FROM alpha_tab_installs WHERE account_id=? AND package=?",
    )
    .bind(g.caller.credential())
    .bind(&r.package)
    .fetch_optional(&mut *tx)
    .await?;
    g.check()?;
    match current {
        None if r.expected_install_event_id.is_none() => {}
        Some((status, event))
            if status == "removed" && Some(&event) == r.expected_install_event_id.as_ref() => {}
        _ => return Err(refused()),
    }
    let payload = install_payload(
        g.caller.credential(),
        &r.package,
        &r.version,
        &r.digest,
        &r.artifact_id,
        &r.source_revision,
        &dd,
        &r.declaration,
        request,
        r.expected_install_event_id.clone(),
    );
    let mut act = ActAllocation::new();
    g.check()?;
    let event = append_control_event_in(
        &mut tx,
        NewControlEvent::authored(
            key,
            alpha_tab_aggregate_id(g.caller.credential(), &r.package),
            g.caller.actor(),
            g.caller.run_key().map(str::to_owned),
            &r.reason,
            ControlEventPayload::AlphaTabInstalled(payload.clone()),
        )?,
        &mut act,
    )
    .await?;
    g.check()?;
    tx.commit().await?;
    g.check()?;
    Ok(InstallOutcome {
        changed: true,
        original: Outcome {
            event_id: event.id,
            event_type: event.event_type,
            original_run_key: event.run_key,
            original_act: event.act,
            original_request: payload.request,
        },
    })
}

/// Owned pending publication removes only its newly issued unexposed receipt.
/// No Clone/Serde/public fields; exposing consumes the ownership guard.
const PREVIEW_OUTPUT_BYTES: usize = 16384;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreviewPublicationFailure {
    Busy,
    Closed,
    Serialization,
    OutputLimit,
    ResponseConstruction,
    Deadline,
    Cancelled,
    Ownership,
}
impl From<PreviewPublicationFailure> for Error {
    fn from(_: PreviewPublicationFailure) -> Self {
        refused()
    }
}
fn publication_sample_error(e: crate::artifact_html::SampleFailure) -> PreviewPublicationFailure {
    use crate::artifact_html::SampleFailure;
    match e {
        SampleFailure::Busy => PreviewPublicationFailure::Busy,
        SampleFailure::Closed => PreviewPublicationFailure::Closed,
        SampleFailure::Expired => PreviewPublicationFailure::Deadline,
        SampleFailure::Invalid => PreviewPublicationFailure::Ownership,
    }
}
pub struct PreviewBytes(Vec<u8>);
impl PreviewBytes {
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}
struct CappedWriter {
    bytes: Vec<u8>,
    overflow: bool,
}
impl std::io::Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > PREVIEW_OUTPUT_BYTES - self.bytes.len() {
            self.overflow = true;
            return Err(std::io::Error::from(std::io::ErrorKind::FileTooLarge));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn capped_preview(value: &Value) -> std::result::Result<PreviewBytes, PreviewPublicationFailure> {
    let mut w = CappedWriter {
        bytes: Vec::with_capacity(PREVIEW_OUTPUT_BYTES),
        overflow: false,
    };
    if serde_json::to_writer(&mut w, value).is_err() {
        return Err(if w.overflow {
            PreviewPublicationFailure::OutputLimit
        } else {
            PreviewPublicationFailure::Serialization
        });
    }
    Ok(PreviewBytes(w.bytes))
}
struct PreviewReceiptGuard {
    receipt: AlphaTabPreviewReceipt,
    publication: crate::artifact_html::SamplePublicationMarker,
}
impl PreviewReceiptGuard {
    fn owns(&self, entry: &StoredPreviewReceipt) -> bool {
        !entry.1
            && entry.0.nonce == self.receipt.nonce
            && entry.0.preview_session == self.receipt.preview_session
            && entry
                .2
                .as_ref()
                .is_some_and(|b| b.publication.same_owner(&self.publication))
    }
}
impl Drop for PreviewReceiptGuard {
    fn drop(&mut self) {
        self.publication.invalidate_unpublished();
        if !self.publication.is_invalid() {
            return;
        }
        if let Ok(mut store) = preview_receipt_store().try_lock() {
            if store
                .get(&self.receipt.receipt_id)
                .is_some_and(|e| self.owns(e))
            {
                store.remove(&self.receipt.receipt_id);
            }
        }
    }
}
pub struct Preview<'a> {
    ingress: &'a Ingress<'a>,
    sample: crate::artifact_html::SampleTicketReservation,
    receipt: PreviewReceiptGuard,
    output: Value,
}
impl Preview<'_> {
    fn check_publication(&self) -> std::result::Result<(), PreviewPublicationFailure> {
        self.ingress
            .check()
            .map_err(|_| PreviewPublicationFailure::Deadline)
    }
    fn commit_publication(&self) -> std::result::Result<(), PreviewPublicationFailure> {
        let lease = self
            .sample
            .try_lock_for_publication(self.ingress.deadline)
            .map_err(publication_sample_error)?;
        let store = preview_receipt_store().try_lock().map_err(|e| match e {
            std::sync::TryLockError::WouldBlock => PreviewPublicationFailure::Busy,
            std::sync::TryLockError::Poisoned(_) => PreviewPublicationFailure::Closed,
        })?;
        self.check_publication()?;
        if !store
            .get(&self.receipt.receipt.receipt_id)
            .is_some_and(|e| self.receipt.owns(e))
        {
            return Err(PreviewPublicationFailure::Ownership);
        }
        lease
            .commit(self.ingress.deadline)
            .map_err(publication_sample_error)?;
        // Shared Published cell disarms BOTH guards. No awaited work after commit.
        drop(store);
        Ok(())
    }
    pub fn expose(self) -> std::result::Result<Vec<u8>, PreviewPublicationFailure> {
        self.check_publication()?;
        let bytes = capped_preview(&self.output)?.into_bytes();
        self.check_publication()?;
        self.commit_publication()?;
        Ok(bytes)
    }
    pub fn publish_http(
        self,
        build: impl FnOnce(
            PreviewBytes,
        )
            -> std::result::Result<axum::response::Response, PreviewPublicationFailure>,
    ) -> std::result::Result<axum::response::Response, PreviewPublicationFailure> {
        self.check_publication()?;
        let bytes = capped_preview(&self.output)?;
        self.check_publication()?;
        let response = build(bytes)?;
        self.check_publication()?;
        self.commit_publication()?;
        Ok(response)
    }
}
#[cfg(test)]
fn preview_fault(
    g: &Ingress<'_>,
    point: PreviewFault,
    sample: Option<&crate::artifact_html::SampleTicketReservation>,
    receipt: Option<&AlphaTabPreviewReceipt>,
) -> Result<()> {
    if g.preview_fault == Some(point) {
        if let Some(c) = &g.preview_capture {
            *c.lock().unwrap() = Some((
                sample
                    .map(|s| s.descriptor().url.clone())
                    .unwrap_or_default(),
                receipt.map(|r| r.receipt_id.clone()),
            ));
        }
        return Err(refused());
    }
    Ok(())
}
pub async fn preview<'a>(
    g: &'a Ingress<'a>,
    delivery: &crate::artifact_html::LaunchDelivery,
) -> Result<Preview<'a>> {
    if g.request.action != "preview" {
        return Err(refused());
    }
    let r = g.request;
    let (dd, needs, effects) = checked_declaration(g)?;
    let generation = r.expected_install_event_id.as_deref().ok_or_else(refused)?;
    if Uuid::parse_str(generation)
        .ok()
        .is_none_or(|u| u.to_string() != generation)
    {
        return Err(refused());
    }
    let mut tx = crate::db::begin_write(g.db.write_pool()).await?;
    g.check()?;
    let size:Option<i64>=sqlx::query_scalar("SELECT octet_length(consented_declaration)+octet_length(package)+octet_length(version)+octet_length(digest)+octet_length(artifact_id)+octet_length(consented_source_revision)+octet_length(declaration_digest)+octet_length(adoption)+octet_length(status)+octet_length(event_id)+COALESCE(octet_length(request),0) FROM alpha_tab_installs WHERE account_id=? AND package=?")
        .bind(g.caller.credential()).bind(&r.package).fetch_optional(&mut *tx).await?;
    g.check()?;
    if !size.is_some_and(|n| (0..=INPUT_BYTES as i64).contains(&n)) {
        return Err(refused());
    }
    let row = install_row_in(&mut tx, g.caller.credential(), &r.package)
        .await?
        .ok_or_else(refused)?;
    g.check()?;
    if row.status != "installed"
        || row.event_id != generation
        || row.version != r.version
        || row.digest != r.digest
        || row.artifact_id != r.artifact_id
        || row.consented_source_revision != r.source_revision
        || row.declaration_digest != dd
        || row.consented_declaration != r.declaration
    {
        return Err(refused());
    }
    let (body, bundle) = checked_source(
        &mut tx,
        g.caller,
        &r.artifact_id,
        &r.source_revision,
        &r.digest,
        &dd,
        || g.check(),
    )
    .await?;
    let manifest = crate::artifact_html::validate_cached(&body).map_err(|_| refused())?;
    g.check()?;
    let last_update_event_id =
        last_alpha_update_in(&mut tx, g.caller.credential(), &r.package).await?;
    g.check()?;
    tx.rollback().await?;
    g.check()?;
    #[cfg(test)]
    preview_fault(g, PreviewFault::BeforeSample, None, None)?;
    let launch = delivery
        .reserve_sample_launch(
            &body,
            &manifest,
            g.caller
                .hosting_principal()
                .unwrap_or(g.caller.credential()),
            g.caller.hosting_database(),
            &r.artifact_id,
        )
        .map_err(|_| refused())?;
    g.check()?;
    #[cfg(test)]
    preview_fault(g, PreviewFault::AfterSample, Some(&launch), None)?;
    let now = chrono::Utc::now().timestamp();
    let receipt = AlphaTabPreviewReceipt {
        receipt_id: format!("preview_{}", &random_hex_32()[..16]),
        nonce: random_hex_32(),
        account_id: g.caller.credential().into(),
        package: r.package.clone(),
        version: r.version.clone(),
        digest: r.digest.clone(),
        artifact_id: r.artifact_id.clone(),
        source_revision: r.source_revision.clone(),
        declaration_digest: dd.clone(),
        needs,
        effects,
        preview_session: format!("sess_{}", &random_hex_32()[..16]),
        last_update_event_id,
        issued_at_secs: now,
        expires_at_secs: now + ALPHA_TAB_PREVIEW_RECEIPT_TTL_SECS,
    };
    // Binding accompanies this NEW receipt atomically. Generic issue remains None.
    #[cfg(test)]
    preview_fault(
        g,
        PreviewFault::BeforeReceipt,
        Some(&launch),
        Some(&receipt),
    )?;
    let receipt_guard;
    {
        let mut store = preview_receipt_store().try_lock().map_err(|_| refused())?;
        g.check()?;
        store.retain(|_, (r, _, b)| {
            r.expires_at_secs > now && !b.as_ref().is_some_and(|b| b.publication.is_invalid())
        });
        if store.len() >= ALPHA_TAB_PREVIEW_RECEIPT_MAX_COUNT
            || store
                .values()
                .filter(|(r, _, _)| r.account_id == receipt.account_id)
                .count()
                >= ALPHA_TAB_PREVIEW_RECEIPTS_PER_ACCOUNT
        {
            return Err(refused());
        }
        if store.contains_key(&receipt.receipt_id) {
            return Err(refused());
        }
        receipt_guard = PreviewReceiptGuard {
            receipt: receipt.clone(),
            publication: launch.publication_marker(),
        };
        store.insert(
            receipt.receipt_id.clone(),
            (
                receipt.clone(),
                false,
                Some(BodyPreviewBinding {
                    install_event_id: generation.into(),
                    scope: BODY_READ_SCOPE.into(),
                    publication: launch.publication_marker(),
                }),
            ),
        );
    }
    #[cfg(test)]
    preview_fault(g, PreviewFault::AfterReceipt, Some(&launch), Some(&receipt))?;
    let sample = alpha_tab_sample_input();
    let output = json!({"package":r.package,"install_event_id":generation,
        "scope":BODY_READ_SCOPE,"preview":{"sample_only":true,"live_reads":false,"effects_wired":false,
            "artifact_id":r.artifact_id,"source_revision":r.source_revision,"digest":r.digest,
            "declaration_digest":dd,"body_digest":manifest.body_digest,"runtime":"native.html.v1","bundle_sha256":bundle,
            "sample_input":sample,"sample_input_digest":alpha_tab_sample_input_digest(&sample),
            "launch":{"url":launch.descriptor().url,"expires_in_ms":launch.descriptor().expires_in_ms,"bridge_version":crate::artifact_html::BRIDGE_VERSION}},
        "receipt":{"receipt_id":receipt.receipt_id,"nonce":receipt.nonce,
            "preview_session":receipt.preview_session,"expires_at_secs":receipt.expires_at_secs}});
    let pending = Preview {
        ingress: g,
        sample: launch,
        receipt: receipt_guard,
        output,
    };
    g.check()?;
    Ok(pending)
}

// Shared ONLY with private A; legacy source resolution remains unchanged.
pub(super) async fn checked_source(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_revision: &str,
    digest: &str,
    declaration_digest: &str,
    check: impl Fn() -> Result<()>,
) -> Result<(String, String)> {
    let target = target_state_in(tx, artifact_id).await?;
    check()?;
    if target != TargetState::Resolvable {
        return Err(refused());
    }
    super::super::require_record_in(&mut *tx, caller, TOOL, artifact_id, Capability::View).await?;
    check()?;
    // CASE is deliberately nested: do not evaluate JSON on BLOB, oversized,
    // or malformed storage, or hydrate extraction-rendered objects/arrays.
    // The exact historical event is read inside this same write transaction.
    let body: Option<String> = sqlx::query_scalar(
        "SELECT CASE WHEN typeof(payload)='text' THEN
                CASE WHEN octet_length(payload)<=? THEN
                    CASE WHEN json_valid(payload) THEN
                        CASE WHEN json_type(payload)='object' THEN
                            CASE WHEN json_type(payload,'$.body')='text'
                                THEN json_extract(payload,'$.body') END
                        END
                    END
                END
             END FROM content_events WHERE record_id=? AND id=?
                AND type IN ('record.created','record.updated','receipt.committed.v1')",
    )
    .bind(SOURCE_BYTES)
    .bind(artifact_id)
    .bind(source_revision)
    .fetch_optional(&mut **tx)
    .await?
    .flatten();
    check()?;
    let body = body.ok_or_else(refused)?;
    let runtime:Option<String>=sqlx::query_scalar("SELECT CASE WHEN octet_length(value)<=256 THEN value END FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(artifact_id).fetch_optional(&mut **tx).await?.flatten();
    check()?;
    if runtime.as_deref() != Some("native.html.v1") {
        return Err(refused());
    }
    let bundle_sha256 = alpha_tab_bundle_digest(&body);
    if crate::alpha_tab_body_admission_v1::install_digest(
        &bundle_sha256,
        declaration_digest,
        "native.html.v1",
    ) != digest
    {
        return Err(refused());
    }

    check()?;
    Ok((body, bundle_sha256))
}

#[cfg(test)]
mod tests;
