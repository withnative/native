//! Durable consent continuity. A carry certifies a declaration, never a new preview.
use super::*;
use serde_json::json;

const CANONICALIZATION_VERSION: &str = "alpha-tab-declaration.v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabAdoptionProvenance {
    pub carried_from_event_id: Option<String>,
    pub original_adoption_event_id: String,
    pub original_adoption_method: String,
    pub adopted_declaration_digest: String,
    pub canonicalization_version: String,
    pub original_source_revision: String,
    pub original_bundle_digest: String,
    pub reviewed_source_revision: Option<String>,
    pub reviewed_bundle_digest: Option<String>,
    pub launch_id: Option<String>,
    pub authored_run_key: Option<String>,
}

/// Complete new pin plus explicit predecessor and deterministic consent outcome.
/// `previous_pin_digest` hashes the
/// canonical pin object returned by `alpha_tab_pin_digest` (not the bundle hash).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTabUpdatePayload {
    pub account_id: String,
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub consented_source_revision: String,
    pub declaration_digest: String,
    pub consented_declaration: Value,
    pub previous_event_id: String,
    pub previous_pin_digest: String,
    pub status: String,
    pub request: Option<String>,
    pub command_digest: String,
    pub adoption: String,
    pub adoption_basis: String,
    pub adoption_provenance: Option<AlphaTabAdoptionProvenance>,
}

impl AlphaTabUpdatePayload {
    fn state(&self) -> AlphaTabStatePayload {
        AlphaTabStatePayload {
            account_id: self.account_id.clone(),
            package: self.package.clone(),
            version: self.version.clone(),
            digest: self.digest.clone(),
            artifact_id: self.artifact_id.clone(),
            consented_source_revision: self.consented_source_revision.clone(),
            declaration_digest: self.declaration_digest.clone(),
            consented_declaration: self.consented_declaration.clone(),
            adoption: self.adoption.clone(),
            request: self.request.clone(),
            previous_event_id: Some(self.previous_event_id.clone()),
        }
    }
}

fn canonical_digest(declaration: &Value) -> Result<String> {
    crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(declaration)
}

pub fn alpha_tab_pin_digest(pin: &AlphaTabStatePayload) -> Result<String> {
    Ok(crate::canonical_json::digest_json(&json!({
        "account_id": pin.account_id, "package": pin.package,
        "version": pin.version, "digest": pin.digest, "artifact_id": pin.artifact_id,
        "consented_source_revision": pin.consented_source_revision,
        "declaration_digest": pin.declaration_digest,
        "consented_declaration": crate::mcp::tools::alpha_tabs::alpha_tab_canonical_declaration(&pin.consented_declaration)?,
    })))
}

// V2 stored evidence compares a versioned structural pin. Ordinary v1 pin
// commitments and fresh update validation continue using the public helper.
fn frozen_v2_pin_digest(pin: &AlphaTabStatePayload) -> Result<String> {
    Ok(crate::canonical_json::digest_json(&json!({
        "account_id":pin.account_id,"package":pin.package,"version":pin.version,
        "digest":pin.digest,"artifact_id":pin.artifact_id,
        "consented_source_revision":pin.consented_source_revision,
        "declaration_digest":pin.declaration_digest,
        "consented_declaration":crate::alpha_tab_body_admission_v1::canonical_declaration(&pin.consented_declaration)?,
    })))
}

fn adopt_state(value: &AlphaTabAdoptPayload) -> AlphaTabStatePayload {
    AlphaTabStatePayload {
        account_id: value.account_id.clone(),
        package: value.package.clone(),
        version: value.version.clone(),
        digest: value.digest.clone(),
        artifact_id: value.artifact_id.clone(),
        consented_source_revision: value.consented_source_revision.clone(),
        declaration_digest: value.declaration_digest.clone(),
        consented_declaration: value.consented_declaration.clone(),
        adoption: value.adoption.clone(),
        request: value.request.clone(),
        previous_event_id: Some(value.previous_event_id.clone()),
    }
}

// Typed v2 bridge preserves its original intent and frozen commitments.
fn v2_adopt(value: &AlphaTabAdoptV2Payload) -> AlphaTabAdoptPayload {
    AlphaTabAdoptPayload {
        account_id: value.account_id.clone(),
        package: value.package.clone(),
        version: value.version.clone(),
        digest: value.digest.clone(),
        artifact_id: value.artifact_id.clone(),
        consented_source_revision: value.consented_source_revision.clone(),
        declaration_digest: value.declaration_digest.clone(),
        consented_declaration: value.consented_declaration.clone(),
        adoption: value.adoption.clone(),
        previous_event_id: value.previous_event_id.clone(),
        receipt_id: value.receipt_id.clone(),
        preview_session: value.preview_session.clone(),
        launch_id: value.launch_id.clone(),
        authored_run_key: value.authored_run_key.clone(),
        request: value.request.clone(),
    }
}
fn v2_direct_provenance(
    event: &ControlEventRow,
    value: &AlphaTabAdoptV2Payload,
) -> Result<AlphaTabAdoptionProvenance> {
    validate_alpha_tab_adopt_v2(event, value)?;
    let reviewed = value.adoption == ALPHA_TAB_ADOPTION_VERIFIED;
    Ok(AlphaTabAdoptionProvenance {
        carried_from_event_id: None,
        original_adoption_event_id: event.id.clone(),
        original_adoption_method: value.adoption.clone(),
        adopted_declaration_digest: value.declaration_digest.clone(),
        canonicalization_version: CANONICALIZATION_VERSION.into(),
        original_source_revision: value.consented_source_revision.clone(),
        original_bundle_digest: value.digest.clone(),
        reviewed_source_revision: reviewed.then(|| value.consented_source_revision.clone()),
        reviewed_bundle_digest: reviewed.then(|| value.digest.clone()),
        launch_id: value.launch_id.clone(),
        authored_run_key: value.authored_run_key.clone(),
    })
}
pub(super) async fn direct_v2_provenance_json(
    conn: &mut SqliteConnection,
    event: &ControlEventRow,
    value: &AlphaTabAdoptV2Payload,
) -> Result<String> {
    let root = provenance_at(conn, &event.id, &adopt_state(&v2_adopt(value)))
        .await?
        .ok_or_else(|| Error::engine("v2 adoption has no coherent direct provenance"))?;
    Ok(serde_json::to_string(&root)?)
}

fn direct_provenance(
    event: &ControlEventRow,
    value: &AlphaTabAdoptPayload,
) -> Result<AlphaTabAdoptionProvenance> {
    let reviewed = value.adoption == ALPHA_TAB_ADOPTION_VERIFIED;
    Ok(AlphaTabAdoptionProvenance {
        carried_from_event_id: None,
        original_adoption_event_id: event.id.clone(),
        original_adoption_method: value.adoption.clone(),
        adopted_declaration_digest: canonical_digest(&value.consented_declaration)?,
        canonicalization_version: CANONICALIZATION_VERSION.into(),
        original_source_revision: value.consented_source_revision.clone(),
        original_bundle_digest: value.digest.clone(),
        reviewed_source_revision: reviewed.then(|| value.consented_source_revision.clone()),
        reviewed_bundle_digest: reviewed.then(|| value.digest.clone()),
        launch_id: value.launch_id.clone(),
        authored_run_key: value.authored_run_key.clone(),
    })
}

pub(super) async fn direct_provenance_json(
    conn: &mut SqliteConnection,
    event: &ControlEventRow,
    value: &AlphaTabAdoptPayload,
) -> Result<Option<String>> {
    // Derive from the same immutable history used by migration and carry checks.
    // Historical eligibility survives absent/inconsistent evidence, but no direct
    // preview provenance is invented for a declaration the predecessor did not pin.
    provenance_at(conn, &event.id, &adopt_state(value))
        .await?
        .map(|p| serde_json::to_string(&p).map_err(Error::from))
        .transpose()
}

pub(super) fn validate_update(
    event: &ControlEventRow,
    value: &AlphaTabUpdatePayload,
) -> Result<()> {
    let mut state = value.state();
    // Shape validation for state payloads predates shell_auto; do not change
    // historical decoding or validation as part of the update foundation.
    state.adoption = ALPHA_TAB_ADOPTION_CALLER_ASSERTED.into();
    validate_alpha_tab(event, &state)?;
    if canonical_digest(&value.consented_declaration)? != value.declaration_digest {
        return Err(Error::engine(
            "alpha tab update declaration digest mismatch",
        ));
    }
    nonblank("alpha tab update predecessor", &value.previous_event_id)?;
    valid_sha256_hex("alpha tab previous pin digest", &value.previous_pin_digest)?;
    valid_sha256_hex("alpha tab command digest", &value.command_digest)?;
    if !matches!(value.status.as_str(), "installed" | "disabled")
        || !matches!(
            value.adoption_basis.as_str(),
            "carried" | "requires_adoption"
        )
    {
        return Err(Error::engine(
            "alpha tab update status or adoption basis invalid",
        ));
    }
    Ok(())
}

/// Shared history lookup keeps SQLite and Turso legacy backfills on one walker.
pub(crate) trait AdoptionHistory: Send {
    fn event_by_id<'a>(
        &'a mut self,
        id: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Option<ControlEventRow>>>;
    fn nearest_before<'a>(
        &'a mut self,
        aggregate: &'a str,
        seq: i64,
    ) -> futures::future::BoxFuture<'a, Result<Option<String>>>;
}

impl AdoptionHistory for SqliteConnection {
    fn nearest_before<'a>(
        &'a mut self,
        aggregate: &'a str,
        seq: i64,
    ) -> futures::future::BoxFuture<'a, Result<Option<String>>> {
        Box::pin(async move {
            Ok(sqlx::query_scalar("SELECT id FROM control_events WHERE aggregate_kind='alpha_tab' AND aggregate_id=? AND seq<? ORDER BY seq DESC LIMIT 1")
                .bind(aggregate).bind(seq).fetch_optional(self).await?)
        })
    }
    fn event_by_id<'a>(
        &'a mut self,
        id: &'a str,
    ) -> futures::future::BoxFuture<'a, Result<Option<ControlEventRow>>> {
        Box::pin(async move {
            sqlx::query("SELECT seq,id,idempotency_key,type,schema_version,aggregate_kind,aggregate_id,actor,run_key,reason,payload,created_at,act FROM control_events WHERE id=?")
                .bind(id).fetch_optional(self).await?.map(row_from_sql).transpose()
        })
    }
}

fn event_pin(event: &ControlEventRow) -> Result<AlphaTabStatePayload> {
    match event.event_type.as_str() {
        "alpha_tab.adopted" => Ok(adopt_state(&decode(event)?)),
        "alpha_tab.adopted.v2" => Ok(adopt_state(&v2_adopt(&decode(event)?))),
        "alpha_tab.updated" => Ok(decode::<AlphaTabUpdatePayload>(event)?.state()),
        "alpha_tab.import_reset" => Ok(decode::<super::AlphaTabImportResetPayload>(event)?.pin),
        "alpha_tab.installed"
        | "alpha_tab.disabled"
        | "alpha_tab.restored"
        | "alpha_tab.removed" => decode(event),
        _ => Err(Error::engine(
            "alpha tab predecessor is not an install transition",
        )),
    }
}

/// Follow only the current chain, never search for an older matching adoption.
/// Monotonically decreasing sequence numbers also rule out cycles. Missing legacy
/// history gives no provenance; inconsistent carry assertions fail closed.
async fn provenance_at<H: AdoptionHistory + ?Sized>(
    conn: &mut H,
    token: &str,
    pin: &AlphaTabStatePayload,
) -> Result<Option<AlphaTabAdoptionProvenance>> {
    let mut token = token.to_owned();
    let mut expected = pin.clone();
    let mut before = None;
    let mut carries: Vec<AlphaTabUpdatePayload> = Vec::new();
    let mut next_pin_digest: Option<String> = None;
    loop {
        let Some(event) = conn.event_by_id(&token).await? else {
            return Ok(None);
        };
        if before.is_some_and(|seq| event.seq >= seq)
            || event.aggregate_id != alpha_tab_aggregate_id(&pin.account_id, &pin.package)
        {
            return Err(Error::engine(
                "alpha tab adoption history predecessor inconsistent",
            ));
        }
        before = Some(event.seq);
        // Disable is status-only. Its historical payload is caller_asserted,
        // even when the projection remains adopted, and is not adoption evidence.
        if event.event_type == "alpha_tab.disabled" {
            let state: AlphaTabStatePayload = decode(&event)?;
            let Some(previous) = state.previous_event_id else {
                return Ok(None);
            };
            token = previous;
            continue;
        }
        // Restore is a pending generation, never a route to an older root.
        if matches!(
            event.event_type.as_str(),
            "alpha_tab.restored" | "alpha_tab.import_reset"
        ) {
            return Ok(None);
        }
        let current = event_pin(&event)?;
        let is_v2 = event.event_type == "alpha_tab.adopted.v2";
        let pin_digest: fn(&AlphaTabStatePayload) -> Result<String> = if is_v2 {
            frozen_v2_pin_digest
        } else {
            alpha_tab_pin_digest
        };
        let Ok(current_digest) = pin_digest(&current) else {
            return Ok(None);
        };
        if let Some(digest) = next_pin_digest.take() {
            if current_digest != digest {
                return Err(Error::engine("alpha tab history previous pin mismatch"));
            }
        } else if current_digest != pin_digest(&expected)? {
            return Ok(None);
        }
        if current.adoption != expected.adoption {
            return Err(Error::engine("alpha tab history adoption method mismatch"));
        }
        match event.event_type.as_str() {
            "alpha_tab.adopted" | "alpha_tab.adopted.v2" => {
                let is_v2 = event.event_type == "alpha_tab.adopted.v2";
                let (value, v2_root) = if is_v2 {
                    let v: AlphaTabAdoptV2Payload = decode(&event)?;
                    validate_alpha_tab_adopt_v2(&event, &v)?;
                    if event.aggregate_kind != "alpha_tab"
                        || conn
                            .nearest_before(&event.aggregate_id, event.seq)
                            .await?
                            .as_deref()
                            != Some(&v.previous_event_id)
                    {
                        return Err(Error::engine("v2 adoption nearest predecessor mismatch"));
                    }
                    (v2_adopt(&v), Some(v2_direct_provenance(&event, &v)?))
                } else {
                    let v: AlphaTabAdoptPayload = decode(&event)?;
                    validate_alpha_tab_adopt(&event, &v)?;
                    (v, None)
                };
                let Some(predecessor) = conn.event_by_id(&value.previous_event_id).await? else {
                    return Ok(None);
                };
                if predecessor.seq >= event.seq
                    || predecessor.aggregate_id != event.aggregate_id
                    || !matches!(
                        predecessor.event_type.as_str(),
                        "alpha_tab.installed"
                            | "alpha_tab.updated"
                            | "alpha_tab.adopted"
                            | "alpha_tab.adopted.v2"
                            | "alpha_tab.restored"
                            | "alpha_tab.import_reset"
                    )
                    || pin_digest(&event_pin(&predecessor)?).ok().as_ref() != Some(&current_digest)
                {
                    return Ok(None);
                }
                if is_v2
                    && event_pin(&predecessor)?.consented_declaration
                        != current.consented_declaration
                {
                    return Err(Error::engine(
                        "v2 adoption raw declaration predecessor mismatch",
                    ));
                }
                let mut root = match v2_root {
                    Some(root) => root,
                    None => {
                        let Ok(root) = direct_provenance(&event, &value) else {
                            return Ok(None);
                        };
                        root
                    }
                };
                if !carries.is_empty()
                    && root.adopted_declaration_digest != value.declaration_digest
                {
                    return Err(Error::engine(
                        "alpha tab root stored declaration digest mismatch",
                    ));
                }
                for carry in carries.iter().rev() {
                    if root.adopted_declaration_digest != carry.declaration_digest
                        || root.original_adoption_method != carry.adoption
                    {
                        return Err(Error::engine(
                            "alpha tab carry root declaration or method mismatch",
                        ));
                    }
                    root.carried_from_event_id = Some(carry.previous_event_id.clone());
                    if carry.adoption_provenance.as_ref() != Some(&root) {
                        return Err(Error::engine("alpha tab forged carry provenance"));
                    }
                }
                return Ok(Some(root));
            }
            "alpha_tab.updated" => {
                let value: AlphaTabUpdatePayload = decode(&event)?;
                validate_update(&event, &value)?;
                if value.adoption_basis != "carried" {
                    return Ok(None);
                }
                next_pin_digest = Some(value.previous_pin_digest.clone());
                token = value.previous_event_id.clone();
                carries.push(value);
            }
            _ => return Ok(None),
        }
        expected = current;
    }
}

/// One authoritative consent calculation, shared by producer and fold.
async fn update_adoption(
    conn: &mut SqliteConnection,
    row: &sqlx::sqlite::SqliteRow,
    pin: &AlphaTabStatePayload,
    token: &str,
    declaration_digest: &str,
) -> Result<(String, String, Option<AlphaTabAdoptionProvenance>)> {
    let same = pin.declaration_digest == declaration_digest;
    let adopted = matches!(
        pin.adoption.as_str(),
        ALPHA_TAB_ADOPTION_VERIFIED | ALPHA_TAB_ADOPTION_SHELL_AUTO
    );
    let outcome = if adopted {
        let history = provenance_at(conn, token, pin).await?;
        let stored: Option<AlphaTabAdoptionProvenance> = row
            .try_get::<Option<String>, _>("adoption_provenance")?
            .map(|text| serde_json::from_str(&text))
            .transpose()?;
        if stored != history
            || history
                .as_ref()
                .is_some_and(|p| p.adopted_declaration_digest != pin.declaration_digest)
        {
            return Err(Error::engine(
                "alpha tab adopted predecessor provenance mismatch",
            ));
        }
        if let Some(mut carried) = history.filter(|_| same) {
            carried.carried_from_event_id = Some(token.to_owned());
            (pin.adoption.as_str(), "carried", Some(carried))
        } else {
            (
                ALPHA_TAB_ADOPTION_CALLER_ASSERTED,
                "requires_adoption",
                None,
            )
        }
    } else {
        (
            ALPHA_TAB_ADOPTION_CALLER_ASSERTED,
            "requires_adoption",
            None,
        )
    };
    Ok((outcome.0.to_owned(), outcome.1.to_owned(), outcome.2))
}

/// Fill server-derived predecessor and consent fields while holding the same
/// write transaction that appends the event. Fold independently repeats this
/// calculation and checks the entire supplied outcome.
pub(crate) async fn complete_update_in(
    conn: &mut SqliteConnection,
    value: &mut AlphaTabUpdatePayload,
) -> Result<()> {
    let row = sqlx::query("SELECT * FROM alpha_tab_installs WHERE account_id=? AND package=?")
        .bind(&value.account_id)
        .bind(&value.package)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("alpha tab update requires a predecessor"))?;
    let pin = projection_pin(&row)?;
    let token: String = row.try_get("event_id")?;
    let status: String = row.try_get("status")?;
    if token != value.previous_event_id
        || !matches!(status.as_str(), "installed" | "disabled")
        || pin.request != value.request
        || canonical_digest(&pin.consented_declaration)? != pin.declaration_digest
    {
        return Err(Error::engine(
            "alpha tab update predecessor pin/status/request mismatch",
        ));
    }
    let (adoption, basis, provenance) =
        update_adoption(conn, &row, &pin, &token, &value.declaration_digest).await?;
    value.previous_pin_digest = alpha_tab_pin_digest(&pin)?;
    value.status = status;
    value.adoption = adoption;
    value.adoption_basis = basis;
    value.adoption_provenance = provenance;
    Ok(())
}

pub(super) async fn fold_update(
    conn: &mut SqliteConnection,
    event: &ControlEventRow,
) -> Result<()> {
    let value: AlphaTabUpdatePayload = decode(event)?;
    validate_update(event, &value)?;
    let row = sqlx::query("SELECT * FROM alpha_tab_installs WHERE account_id=? AND package=?")
        .bind(&value.account_id)
        .bind(&value.package)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("alpha tab update requires a predecessor"))?;
    let pin = projection_pin(&row)?;
    let status: String = row.try_get("status")?;
    let token: String = row.try_get("event_id")?;
    if token != value.previous_event_id
        || status != value.status
        || status == "removed"
        || event.seq <= row.try_get::<i64, _>("event_seq")?
        || pin.request != value.request
        || alpha_tab_pin_digest(&pin)? != value.previous_pin_digest
        || canonical_digest(&pin.consented_declaration)? != pin.declaration_digest
    {
        return Err(Error::engine(
            "alpha tab update predecessor pin/status/request mismatch",
        ));
    }
    let (adoption, basis, provenance) =
        update_adoption(conn, &row, &pin, &token, &value.declaration_digest).await?;
    if value.adoption != adoption
        || value.adoption_basis != basis
        || value.adoption_provenance != provenance
    {
        return Err(Error::engine(
            "alpha tab update forged adoption carry or provenance",
        ));
    }
    let result = sqlx::query("UPDATE alpha_tab_installs SET version=?,digest=?,artifact_id=?,consented_source_revision=?,declaration_digest=?,consented_declaration=?,adoption=?,adoption_provenance=?,body_read_admission_event_id=NULL,event_id=?,event_seq=?,updated_at=? WHERE account_id=? AND package=? AND event_id=? AND status=?")
        .bind(&value.version).bind(&value.digest).bind(&value.artifact_id).bind(&value.consented_source_revision)
        .bind(&value.declaration_digest).bind(serde_json::to_string(&value.consented_declaration)?)
        .bind(&adoption).bind(provenance.map(|p| serde_json::to_string(&p)).transpose()?)
        .bind(&event.id).bind(event.seq).bind(&event.created_at).bind(&value.account_id).bind(&value.package)
        .bind(&token).bind(&status).execute(conn).await?;
    require_one(result, event).await
}

pub(super) fn projection_pin(row: &sqlx::sqlite::SqliteRow) -> Result<AlphaTabStatePayload> {
    Ok(AlphaTabStatePayload {
        account_id: row.try_get("account_id")?,
        package: row.try_get("package")?,
        version: row.try_get("version")?,
        digest: row.try_get("digest")?,
        artifact_id: row.try_get("artifact_id")?,
        consented_source_revision: row.try_get("consented_source_revision")?,
        declaration_digest: row.try_get("declaration_digest")?,
        consented_declaration: serde_json::from_str(
            &row.try_get::<String, _>("consented_declaration")?,
        )?,
        adoption: row.try_get("adoption")?,
        request: row.try_get("request")?,
        previous_event_id: None,
    })
}

/// Missing or corrupt legacy evidence cannot block an additive migration and
/// cannot be promoted to reviewed consent. Log each refused chain for repair.
pub(crate) async fn backfill_provenance<H: AdoptionHistory + ?Sized>(
    history: &mut H,
    token: &str,
    pin: &AlphaTabStatePayload,
    status: &str,
) -> Option<AlphaTabAdoptionProvenance> {
    if status == "removed" || pin.adoption == ALPHA_TAB_ADOPTION_CALLER_ASSERTED {
        return None;
    }
    match provenance_at(history, token, pin).await {
        Ok(provenance) => provenance,
        Err(error) => {
            tracing::warn!(account_id=%pin.account_id, package=%pin.package, event_id=token, %error,
                "alpha-tab backfill refused inconsistent evidence; provenance remains NULL");
            None
        }
    }
}

pub(crate) async fn backfill(conn: &mut SqliteConnection) -> Result<()> {
    // One install's history at a time, with an index-friendly primary-key scan.
    let mut after: Option<(String, String)> = None;
    loop {
        let row = if let Some((account, package)) = &after {
            sqlx::query("SELECT * FROM alpha_tab_installs WHERE (account_id,package)>(?,?) ORDER BY account_id,package LIMIT 1")
                .bind(account).bind(package).fetch_optional(&mut *conn).await?
        } else {
            sqlx::query("SELECT * FROM alpha_tab_installs ORDER BY account_id,package LIMIT 1")
                .fetch_optional(&mut *conn)
                .await?
        };
        let Some(row) = row else {
            break;
        };
        let pin = projection_pin(&row)?;
        let provenance = backfill_provenance(
            conn,
            &row.try_get::<String, _>("event_id")?,
            &pin,
            &row.try_get::<String, _>("status")?,
        )
        .await;
        sqlx::query(
            "UPDATE alpha_tab_installs SET adoption_provenance=? WHERE account_id=? AND package=?",
        )
        .bind(provenance.map(|p| serde_json::to_string(&p)).transpose()?)
        .bind(&pin.account_id)
        .bind(&pin.package)
        .execute(&mut *conn)
        .await?;
        after = Some((pin.account_id, pin.package));
    }
    Ok(())
}

/// Import resets are status-preserving CAS transitions, never adoption roots.
pub(super) async fn fold_import_reset(
    conn: &mut SqliteConnection,
    event: &ControlEventRow,
) -> Result<()> {
    let value: super::AlphaTabImportResetPayload = decode(event)?;
    let row = sqlx::query("SELECT * FROM alpha_tab_installs WHERE account_id=? AND package=?")
        .bind(&value.pin.account_id)
        .bind(&value.pin.package)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| Error::engine("alpha tab import reset requires predecessor"))?;
    let pin = projection_pin(&row)?;
    if value.pin.previous_event_id.as_deref()
        != Some(row.try_get::<String, _>("event_id")?.as_str())
        || value.status != row.try_get::<String, _>("status")?
        || event.seq <= row.try_get::<i64, _>("event_seq")?
        || pin.request != value.pin.request
        || alpha_tab_pin_digest(&pin)? != alpha_tab_pin_digest(&value.pin)?
    {
        return Err(Error::engine(
            "alpha tab import reset predecessor pin/status/request mismatch",
        ));
    }
    sqlx::query("UPDATE alpha_tab_installs SET adoption='caller_asserted',adoption_provenance=NULL,body_read_admission_event_id=NULL,event_id=?,event_seq=?,updated_at=? WHERE account_id=? AND package=?")
        .bind(&event.id).bind(event.seq).bind(&event.created_at)
        .bind(&pin.account_id).bind(&pin.package).execute(&mut *conn).await?;
    Ok(())
}
