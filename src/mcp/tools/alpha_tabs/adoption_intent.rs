//! Private Unit A. No tool/HTTP action dispatches this service.
//! The unsafe bridge is an explicit privileged hosted-embedding boundary;
//! authoritative history/legacy pin markers cannot construct request readiness.
use super::*;
use crate::control::{AlphaTabAdoptV2Payload, AlphaTabBodyReadAdmission};
use std::time::{Duration, Instant};

const PROOF_BYTES: i64 = 32 * 1024 * 1024;

/// Original client fields only. Derived declaration/runtime/bundle/request
/// proof is selected from the original outcome, never reconstructed for retry.
pub struct Intent {
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub source_revision: String,
    pub declaration: Value,
    pub expected_install_event_id: String,
    pub reason: String,
    pub idempotency_key: Option<String>,
    pub consent: Consent,
}
pub enum Consent {
    Receipt {
        receipt_id: String,
        preview_session: String,
    },
    Authored {
        launch_id: Option<String>,
        authored_run_key: Option<String>,
    },
}

/// Nonserialized, non-Clone and borrowed from ONE authenticated request.
/// The original pin/action cannot be replaced after minting.
pub struct Ingress<'request> {
    db: &'request Db,
    caller: &'request Caller,
    intent: &'request Intent,
    handle: Uuid,
    deadline: Instant,
}
impl<'request> Ingress<'request> {
    /// # Safety
    /// The trusted hosted dispatcher must have authenticated an actual cookie
    /// (not bearer+cookie), matched a configured public Origin and its CSRF
    /// rules, verified selected database membership/account/action and retained
    /// the deployment mutation lease for this request. `started` is RAW ingress,
    /// not checkout time. Original JSON must have been byte-bounded before parse.
    /// Do not call from MCP/frame/agent dispatch, legacy pin markers, receipt or
    /// control history. Privileged unsafe embeddings remain trusted, as with
    /// Caller::with_verified_hosted_activity. No production route calls this yet.
    pub unsafe fn from_verified_host(
        db: &'request Db,
        caller: &'request Caller,
        intent: &'request Intent,
        started: Instant,
    ) -> Result<Self> {
        bounded(caller.credential(), 256)?;
        bounded(&intent.package, 128)?;
        bounded(&intent.version, 256)?;
        bounded(&intent.digest, 256)?;
        for value in [
            &intent.artifact_id,
            &intent.source_revision,
            &intent.expected_install_event_id,
        ] {
            bounded(value, 256)?;
        }
        bounded(&intent.reason, 4096)?;
        if let Some(key) = &intent.idempotency_key {
            bounded(key, 1024)?;
        }
        match &intent.consent {
            Consent::Receipt {
                receipt_id,
                preview_session,
            } => {
                bounded(receipt_id, 256)?;
                bounded(preview_session, 256)?;
            }
            Consent::Authored {
                launch_id,
                authored_run_key,
            } => {
                for field in [launch_id, authored_run_key].into_iter().flatten() {
                    bounded(field, 1024)?;
                }
            }
        }
        let ingress = Self {
            db,
            caller,
            intent,
            handle: db.handle_id(),
            deadline: started
                .checked_add(Duration::from_secs(5))
                .ok_or_else(refused)?,
        };
        ingress.check()?;
        Ok(ingress)
    }
    fn check(&self) -> Result<()> {
        if self.db.handle_id() != self.handle || Instant::now() >= self.deadline {
            return Err(refused());
        }
        bounded(self.caller.credential(), 256)
    }
    fn key(&self) -> String {
        self.intent.idempotency_key.clone().unwrap_or_else(|| {
            let prefix = match &self.intent.consent {
                Consent::Receipt { .. } => "alpha-tab-adopted",
                Consent::Authored { .. } => "alpha-tab-adopt-authored",
            };
            format!(
                "{prefix}:{}:{}:{}",
                self.caller.credential(),
                self.intent.package,
                self.intent.expected_install_event_id
            )
        })
    }
}
fn refused() -> Error {
    Error::engine("private body adoption refused")
}
fn conflict() -> Error {
    Error::engine("private body adoption idempotency intent conflict")
}
fn bounded(value: &str, cap: usize) -> Result<()> {
    if value.trim().is_empty() || value.len() > cap {
        Err(refused())
    } else {
        Ok(())
    }
}

/// An inert original audit outcome, NOT a current launch/admission response.
pub struct Outcome {
    pub event_id: String,
    pub event_type: String,
    pub original_run_key: Option<String>,
    pub original_act: Option<i64>,
    pub original_request: Option<String>,
}
pub enum Decision<'request> {
    Recovered(Outcome),
    Fresh(Fresh<'request>),
}
/// Current validation is reachable only after the same write transaction has
/// found no outcome. This is deliberately not a marker stored on Caller.
pub struct Fresh<'request> {
    ingress: &'request Ingress<'request>,
    tx: sqlx::Transaction<'static, sqlx::Sqlite>,
}

/// BEGIN IMMEDIATE and bounded raw envelope lookup precede ALL current
/// declaration, install, source, pin preparation and receipt work.
pub async fn begin<'request>(ingress: &'request Ingress<'request>) -> Result<Decision<'request>> {
    ingress.check()?;
    let mut tx = crate::db::begin_write(ingress.db.write_pool()).await?;
    ingress.check()?;
    let key = ingress.key();
    let size: Option<i64> = sqlx::query_scalar(
        "SELECT octet_length(payload) FROM control_events WHERE idempotency_key=?",
    )
    .bind(&key)
    .fetch_optional(&mut *tx)
    .await?;
    ingress.check()?;
    if let Some(size) = size {
        if !(0..=PROOF_BYTES).contains(&size) {
            return Err(conflict());
        }
        // Type/schema are selected before decode. Small envelope columns are
        // preflighted as well, so corrupt audit text cannot bypass the bound.
        let row=sqlx::query("SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,reason,payload,run_key,act,created_at,
            octet_length(id)+octet_length(type)+octet_length(aggregate_kind)+octet_length(aggregate_id)+octet_length(actor)+octet_length(reason)+COALESCE(octet_length(run_key),0)+octet_length(created_at)+octet_length(idempotency_key) AS envelope_bytes
            FROM control_events WHERE idempotency_key=? AND
            octet_length(id)+octet_length(type)+octet_length(aggregate_kind)+octet_length(aggregate_id)+octet_length(actor)+octet_length(reason)+COALESCE(octet_length(run_key),0)+octet_length(created_at)+octet_length(idempotency_key)<=8192")
            .bind(&key).fetch_optional(&mut *tx).await?.ok_or_else(conflict)?;
        ingress.check()?;
        let kind: String = row.try_get("type")?;
        if row.try_get::<i64, _>("schema_version")? != 1
            || row.try_get::<String, _>("aggregate_kind")? != "alpha_tab"
            || row.try_get::<String, _>("aggregate_id")?
                != alpha_tab_aggregate_id(ingress.caller.credential(), &ingress.intent.package)
            || row.try_get::<String, _>("actor")? != ingress.caller.actor()
            || row.try_get::<String, _>("reason")? != ingress.intent.reason
        {
            return Err(conflict());
        }
        let raw: String = row.try_get("payload")?;
        let request = match kind.as_str() {
            "alpha_tab.adopted" => {
                let old: AlphaTabAdoptPayload =
                    serde_json::from_str(&raw).map_err(|_| conflict())?;
                compare(ingress, &old)?;
                old.request
            }
            "alpha_tab.adopted.v2" => {
                let old: AlphaTabAdoptV2Payload =
                    serde_json::from_str(&raw).map_err(|_| conflict())?;
                // Intrinsic frozen validator, including closed payload, audit
                // shape and commitment linkage; no current SQL/catalog calls.
                let event = crate::control::ControlEventRow {
                    seq: row.try_get("seq")?,
                    id: row.try_get("id")?,
                    idempotency_key: row.try_get("idempotency_key")?,
                    event_type: kind.clone(),
                    schema_version: row.try_get("schema_version")?,
                    aggregate_kind: row.try_get("aggregate_kind")?,
                    aggregate_id: row.try_get("aggregate_id")?,
                    actor: row.try_get("actor")?,
                    run_key: row.try_get("run_key")?,
                    reason: row.try_get("reason")?,
                    payload: raw.clone(),
                    created_at: row.try_get("created_at")?,
                    act: row.try_get("act")?,
                };
                crate::control::validate_alpha_tab_adopt_v2(&event, &old)
                    .map_err(|_| conflict())?;
                let common = AlphaTabAdoptPayload {
                    account_id: old.account_id,
                    package: old.package,
                    version: old.version,
                    digest: old.digest,
                    artifact_id: old.artifact_id,
                    consented_source_revision: old.consented_source_revision,
                    declaration_digest: old.declaration_digest,
                    consented_declaration: old.consented_declaration,
                    adoption: old.adoption,
                    previous_event_id: old.previous_event_id,
                    receipt_id: old.receipt_id,
                    preview_session: old.preview_session,
                    launch_id: old.launch_id,
                    authored_run_key: old.authored_run_key,
                    request: old.request,
                };
                compare(ingress, &common)?;
                common.request
            }
            _ => return Err(conflict()),
        };
        ingress.check()?;
        let outcome = Outcome {
            event_id: row.try_get("id")?,
            event_type: kind,
            original_run_key: row.try_get("run_key")?,
            original_act: row.try_get("act")?,
            original_request: request,
        };
        tx.rollback().await?;
        ingress.check()?;
        return Ok(Decision::Recovered(outcome));
    }
    ingress.check()?;
    Ok(Decision::Fresh(Fresh { ingress, tx }))
}
fn compare(ingress: &Ingress<'_>, p: &AlphaTabAdoptPayload) -> Result<()> {
    let i = ingress.intent;
    if p.account_id != ingress.caller.credential()
        || p.package != i.package
        || p.version != i.version
        || p.digest != i.digest
        || p.artifact_id != i.artifact_id
        || p.consented_source_revision != i.source_revision
        || p.consented_declaration != i.declaration
        || p.previous_event_id != i.expected_install_event_id
    {
        return Err(conflict());
    }
    let same = match &i.consent {
        Consent::Receipt {
            receipt_id,
            preview_session,
        } => {
            p.adoption == ALPHA_TAB_ADOPTION_VERIFIED
                && p.receipt_id.as_ref() == Some(receipt_id)
                && p.preview_session.as_ref() == Some(preview_session)
                && p.launch_id.is_none()
                && p.authored_run_key.is_none()
                && p.request.is_none()
        }
        Consent::Authored {
            launch_id,
            authored_run_key,
        } => {
            p.adoption == ALPHA_TAB_ADOPTION_SHELL_AUTO
                && p.launch_id == *launch_id
                && p.authored_run_key == *authored_run_key
                && p.receipt_id.is_none()
                && p.preview_session.is_none()
        }
    };
    if same {
        Ok(())
    } else {
        Err(conflict())
    }
}
fn descriptor() -> AlphaTabBodyReadAdmission {
    AlphaTabBodyReadAdmission {
        need: BODY_READ_NEED.into(),
        scope: "viewer-visible-current-bodies".into(),
    }
}

/// Fresh proof borrows the one request and owns its current write transaction.
/// It cannot be serialized, cloned, minted from history or reused after commit.
pub struct Ready<'request> {
    fresh: Fresh<'request>,
    payload: AlphaTabAdoptV2Payload,
    needs: Vec<String>,
    effects: Vec<String>,
}
impl<'request> Fresh<'request> {
    /// Prepare only the original immutable declaration after outcome absence.
    /// This is not current install/source readiness and accepts no reusable pin.
    pub fn prepare_current_pin(self) -> Result<Prepared<'request>> {
        let g = self.ingress;
        let i = g.intent;
        g.check()?;
        require_package(&i.package)?;
        require_version(&i.version)?;
        require_digest(&i.digest)?;
        require_reason(TOOL, &i.reason)?;
        let declaration_digest =
            crate::alpha_tab_body_admission_v1::declaration_digest(&i.declaration)?;
        if !crate::alpha_tab_body_admission_v1::has_body_descriptor(&i.declaration)? {
            return Err(refused());
        }
        g.check()?;
        let parsed = require_declaration_for_adoption(&i.declaration, true)?;
        let mut needs = parsed.needs;
        let mut effects = parsed.effects;
        needs.sort();
        effects.sort();
        // Frozen/current parsing is synchronous: an elapsed parse must refuse
        // before it can produce a completion stage, not receive a reset clock.
        g.check()?;
        Ok(Prepared {
            fresh: self,
            declaration_digest,
            needs,
            effects,
        })
    }
}

/// Checked request declaration, not a transferable credential. Owns the same
/// Fresh transaction and borrows the same request; no Clone/Serde/constructor.
pub struct Prepared<'request> {
    fresh: Fresh<'request>,
    declaration_digest: String,
    needs: Vec<String>,
    effects: Vec<String>,
}
impl<'request> Prepared<'request> {
    pub async fn qualify(self) -> Result<Ready<'request>> {
        let Self {
            mut fresh,
            declaration_digest,
            needs,
            effects,
        } = self;
        let g = fresh.ingress;
        let i = g.intent;
        g.check()?;
        let size:Option<i64>=sqlx::query_scalar("SELECT octet_length(consented_declaration)+COALESCE(octet_length(request),0)+octet_length(package)+octet_length(version)+octet_length(digest)+octet_length(artifact_id)+octet_length(consented_source_revision)+octet_length(declaration_digest)+octet_length(adoption)+octet_length(status)+octet_length(event_id) FROM alpha_tab_installs WHERE account_id=? AND package=?")
            .bind(g.caller.credential()).bind(&i.package).fetch_optional(&mut *fresh.tx).await?;
        g.check()?;
        if !size.is_some_and(|s| (0..=PROOF_BYTES).contains(&s)) {
            return Err(refused());
        }
        let row = install_row_in(&mut fresh.tx, g.caller.credential(), &i.package)
            .await?
            .ok_or_else(refused)?;
        g.check()?;
        if row.status != "installed"
            || row.event_id != i.expected_install_event_id
            || row.version != i.version
            || row.digest != i.digest
            || row.artifact_id != i.artifact_id
            || row.consented_source_revision != i.source_revision
            || row.declaration_digest != declaration_digest
            || row.consented_declaration != i.declaration
        {
            return Err(refused());
        }
        let (_, bundle_sha256) = super::hosted_producer::checked_source(
            &mut fresh.tx,
            g.caller,
            &i.artifact_id,
            &i.source_revision,
            &i.digest,
            &declaration_digest,
            || g.check(),
        )
        .await?;
        let (adoption, receipt_id, preview_session, launch_id, authored_run_key, request) =
            match &i.consent {
                Consent::Receipt {
                    receipt_id,
                    preview_session,
                } => (
                    ALPHA_TAB_ADOPTION_VERIFIED,
                    Some(receipt_id.clone()),
                    Some(preview_session.clone()),
                    None,
                    None,
                    None,
                ),
                Consent::Authored {
                    launch_id,
                    authored_run_key,
                } => (
                    ALPHA_TAB_ADOPTION_SHELL_AUTO,
                    None,
                    None,
                    require_authored_field("launch_id", launch_id.clone())?,
                    require_authored_field("authored_run_key", authored_run_key.clone())?,
                    row.request,
                ),
            };
        g.check()?;
        let payload = AlphaTabAdoptV2Payload {
            account_id: g.caller.credential().into(),
            package: i.package.clone(),
            version: i.version.clone(),
            digest: i.digest.clone(),
            artifact_id: i.artifact_id.clone(),
            consented_source_revision: i.source_revision.clone(),
            declaration_digest,
            consented_declaration: i.declaration.clone(),
            adoption: adoption.into(),
            previous_event_id: i.expected_install_event_id.clone(),
            receipt_id,
            preview_session,
            launch_id,
            authored_run_key,
            request,
            runtime: "native.html.v1".into(),
            bundle_sha256,
            body_read_admission: descriptor(),
        };
        Ok(Ready {
            fresh,
            payload,
            needs,
            effects,
        })
    }
}
impl Ready<'_> {
    /// Fresh nonce is never stored in intent/payload. None for authored consent.
    pub async fn commit(mut self, nonce: Option<&str>) -> Result<Outcome> {
        let g = self.fresh.ingress;
        let i = g.intent;
        g.check()?;
        if let Consent::Receipt {
            receipt_id,
            preview_session,
        } = &i.consent
        {
            let nonce = nonce.ok_or_else(refused)?;
            bounded(nonce, 256)?;
            let mut store = preview_receipt_store().lock().map_err(|_| refused())?;
            g.check()?;
            let owned = store.get(receipt_id).cloned();
            if !owned
                .as_ref()
                .and_then(|(_, _, binding)| binding.as_ref())
                .is_some_and(|b| {
                    b.publication.is_published()
                        && b.install_event_id == i.expected_install_event_id
                        && b.install_event_id == self.payload.previous_event_id
                        && b.scope == self.payload.body_read_admission.scope
                        && b.scope == BODY_READ_SCOPE
                })
            {
                return Err(refused());
            }
            let confirm = AlphaTabAdoptConfirm {
                receipt_id: receipt_id.clone(),
                nonce: nonce.into(),
                account_id: g.caller.credential().into(),
                package: i.package.clone(),
                version: i.version.clone(),
                digest: i.digest.clone(),
                artifact_id: i.artifact_id.clone(),
                source_revision: i.source_revision.clone(),
                declaration_digest: self.payload.declaration_digest.clone(),
                needs: self.needs.clone(),
                effects: self.effects.clone(),
                preview_session: preview_session.clone(),
                reason: i.reason.clone(),
                expected_install_event_id: i.expected_install_event_id.clone(),
                current_event_id: i.expected_install_event_id.clone(),
            };
            verify_alpha_tab_adopt_confirm(
                owned.as_ref().map(|(r, _, _)| r),
                &confirm,
                chrono::Utc::now().timestamp(),
                owned.as_ref().is_some_and(|(_, c, _)| *c),
                false,
                true,
            )
            .map_err(|_| refused())?;
            g.check()?;
            store.get_mut(receipt_id).ok_or_else(refused)?.1 = true;
        } else if nonce.is_some() {
            return Err(refused());
        }
        g.check()?;
        let mut act = ActAllocation::new();
        let event = append_control_event_in(
            &mut self.fresh.tx,
            NewControlEvent::authored(
                g.key(),
                alpha_tab_aggregate_id(g.caller.credential(), &i.package),
                g.caller.actor(),
                g.caller.run_key().map(str::to_owned),
                &i.reason,
                ControlEventPayload::AlphaTabAdoptedV2(self.payload.clone()),
            )?,
            &mut act,
        )
        .await?;
        g.check()?;
        self.fresh.tx.commit().await?;
        g.check()?;
        Ok(Outcome {
            event_id: event.id,
            event_type: event.event_type,
            original_run_key: event.run_key,
            original_act: event.act,
            original_request: self.payload.request,
        })
    }
}

#[cfg(test)]
mod tests;
