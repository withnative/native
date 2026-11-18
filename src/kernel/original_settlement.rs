//! Internal mutating accept-or-fence producer. No public MCP operation.
//! Frozen contract: docs/original-settlement-design.md (revision 3).
use super::mcp_write_receipts::{
    self as receipts,
    fences::{self, FenceFact, Terminal},
};
use super::*;
use crate::error::NativeFenceReference;
use serde_json::{json, Value};

#[cfg(feature = "v2-kernel-probe")]
pub mod installed;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub action: String,
    pub purpose: String,
    pub abandon_if_unapplied: bool,
    pub original: Original,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Original {
    pub account_id: String,
    pub principal_id: String,
    pub database_id: String,
    pub origin_database_id: String,
    pub operation: String,
    pub operation_key: String,
    pub journal_variant: u32,
    pub retained_contract_digest: String,
    pub catalog_executor: String,
    pub catalog_operation: String,
    pub retained_provider_fingerprint: String,
    pub arguments: Value,
    pub assertion: String,
    pub app: Option<Value>,
    pub mint_context: Option<String>,
    pub delegation_ref: Option<String>,
    pub asserting_client_id: Option<String>,
    pub asserting_device_id: Option<String>,
    pub expected_binding_sha256: String,
}
/// Constructed by the bearer-only internal route after actual resource admission.
/// None of these coordinates may be selected from the submitted original.
pub trait RouteGuard: Send + Sync {
    fn recheck(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>>;
}
pub struct AuthenticatedRoute<'a> {
    pub guard: std::sync::Arc<dyn RouteGuard>,
    pub account: &'a str,
    pub principal: &'a str,
    pub database: &'a str,
    pub origin: &'a str,
    pub node_client: &'a str,
}
pub(crate) enum KeyedOutcome {
    Absent,
    Accepted {
        request: String,
        receipt: String,
        native: NativeFenceReference,
    },
    Terminal {
        fact: Box<FenceFact>,
        native: NativeFenceReference,
    },
}
fn invalid() -> Error {
    Error::engine("original settlement evidence unavailable")
}
fn sha(domain: &str, value: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(serde_jcs::to_vec(value).expect("JSON value"));
    hex::encode(h.finalize())
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn binding(o: &Original, fp: &str) -> Value {
    json!({"schema":"native.original-binding.v1","account_id":o.account_id,"principal_id":o.principal_id,"database_id":o.database_id,"origin_database_id":o.origin_database_id,"operation":o.operation,"operation_key":o.operation_key.trim(),"journal_variant":o.journal_variant,"retained_contract_digest":o.retained_contract_digest,"catalog_executor":o.catalog_executor,"catalog_operation":o.catalog_operation,"fingerprint_utf8":fp,"mint_context":o.mint_context,"delegation_ref":o.delegation_ref,"assertion":o.assertion,"app":o.app,"asserting_client_id":o.asserting_client_id,"asserting_device_id":o.asserting_device_id})
}
fn namespace(o: &Original) -> String {
    sha(
        "native.original-key.v1\0",
        &json!({"account_id":o.account_id,"principal_id":o.principal_id,"database_id":o.database_id,"origin_database_id":o.origin_database_id,"operation":o.operation,"operation_key":o.operation_key.trim()}),
    )
}
/// Uses retained variant/identity, never current flags or a fabricated historical label.
pub fn recompute_binding(o: &Original) -> Result<(String, String)> {
    if !digest(&o.retained_contract_digest)
        || o.assertion != "first_party"
        || o.app.is_some()
        || o.delegation_ref.is_some()
        || o.asserting_client_id.is_some()
        || o.asserting_device_id.is_some()
    {
        return Err(invalid());
    }
    let create = match (o.journal_variant, o.operation.as_str()) {
        (7, "update_record") => false,
        (8, "create_record") => true,
        (9, "create_record") => true,
        (9, "update_record" | "archive_record" | "manage_links") => false,
        _ => return Err(invalid()),
    };
    if o.operation == "manage_links"
        && !matches!(o.arguments["action"].as_str(), Some("add" | "remove"))
    {
        return Err(invalid());
    }
    let key = o.operation_key.trim();
    if key.is_empty()
        || key.chars().count() > 200
        || o.arguments["idempotency_key"].as_str().map(str::trim) != Some(key)
    {
        return Err(invalid());
    }
    let identity = if create {
        if o.mint_context.as_deref() != Some("first-party") {
            return Err(invalid());
        }
        let id = o.arguments["id"].as_str().ok_or_else(invalid)?;
        let nonce = o.arguments["id_nonce"].as_str().ok_or_else(invalid)?;
        if !crate::record_id::verify(
            &crate::record_id::qualified_principal(&o.principal_id),
            "first-party",
            id,
            nonce,
        ) {
            return Err(invalid());
        }
        json!({"app":null,"mint_context":"first-party"})
    } else {
        if o.mint_context.is_some() {
            return Err(invalid());
        }
        Value::Null
    };
    let fp = receipts::intent_fingerprint(&o.operation, o.arguments.clone(), identity)?;
    if fp.as_bytes() != o.retained_provider_fingerprint.as_bytes() {
        return Err(invalid());
    }
    Ok((sha("native.original-binding.v1\0", &binding(o, &fp)), fp))
}
pub fn status_required(reason: &str) -> Value {
    json!({"schema":"native.original-settlement.answer.v1","verdict":"status_required","binding_verified":false,"original_binding_sha256":null,"namespace_sha256":null,"reason":reason,"terminal":false})
}
pub(crate) fn validate_fact(f: &FenceFact, actor: &str) -> Result<()> {
    let t = &f.terminal;
    if f.format != 1
        || t.schema != "native.original-fence.v1"
        || t.reason != "owner_abandoned_unapplied"
        || t.scope != "entire_idempotency_namespace"
        || t.principal_id != actor
        || t.settled_by_client_id.is_empty()
        || Uuid::parse_str(&t.fence_id).is_err()
    {
        return Err(invalid());
    }
    let intent: Value = serde_json::from_str(&f.request_json)?;
    let mut args = intent["arguments"].clone();
    args.as_object_mut()
        .ok_or_else(invalid)?
        .insert("idempotency_key".into(), json!(f.operation_key));
    let o = Original {
        account_id: t.account_id.clone(),
        principal_id: t.principal_id.clone(),
        database_id: t.database_id.clone(),
        origin_database_id: t.origin_database_id.clone(),
        operation: f.operation.clone(),
        operation_key: f.operation_key.clone(),
        journal_variant: t.journal_variant,
        retained_contract_digest: t.retained_contract_digest.clone(),
        catalog_executor: t.catalog_executor.clone(),
        catalog_operation: t.catalog_operation.clone(),
        retained_provider_fingerprint: f.request_json.clone(),
        arguments: args,
        assertion: t.assertion.clone(),
        app: t.app.clone(),
        mint_context: t.mint_context.clone(),
        delegation_ref: t.delegation_ref.clone(),
        asserting_client_id: t.asserting_client_id.clone(),
        asserting_device_id: t.asserting_device_id.clone(),
        expected_binding_sha256: t.original_binding_sha256.clone(),
    };
    let (hash, _) = recompute_binding(&o)?;
    if hash != t.original_binding_sha256
        || namespace(&o) != t.namespace_sha256
        || t.retired_record_id.as_deref()
            != if f.operation == "create_record" {
                o.arguments["id"].as_str()
            } else {
                None
            }
    {
        return Err(invalid());
    }
    Ok(())
}
type StoredOutcomeRow = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
);

pub(crate) async fn lookup_outcome_on(
    conn: &mut SqliteConnection,
    principal: &str,
    operation: &str,
    key: &str,
) -> Result<KeyedOutcome> {
    if !fences::typed_on(conn).await? {
        return Err(invalid());
    }
    let accepted_query = receipts::indexed_sql_on(
        conn,
        receipts::ACCEPTED_LOOKUP_SQL,
        "main.content_events",
        receipts::INDEX,
    )
    .await?;
    let mut rows: Vec<(String, String, String)> = sqlx::query_as(&accepted_query)
        .bind(principal)
        .bind(operation)
        .bind(key)
        .fetch_all(&mut *conn)
        .await?;
    let fence_query = receipts::indexed_sql_on(
        conn,
        fences::LOOKUP_SQL,
        "main.content_events",
        "idx_kernel_mcp_write_fence_events",
    )
    .await?;
    rows.extend(
        sqlx::query_as::<_, (String, String, String)>(&fence_query)
            .bind(principal)
            .bind(operation)
            .bind(key)
            .fetch_all(&mut *conn)
            .await?,
    );
    let row: Option<StoredOutcomeRow> =sqlx::query_as("SELECT request_json,receipt_json,outcome_kind,terminal_json,retired_record_id FROM main.kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?").bind(principal).bind(operation).bind(key).fetch_optional(&mut *conn).await?;
    match (rows.as_slice(), row) {
        ([], None) => Ok(KeyedOutcome::Absent),
        ([(id, kind, raw)], Some((request, receipt, outcome, terminal, retired)))
            if kind == fences::EVENT && outcome == "unapplied_terminal" =>
        {
            let f: FenceFact = serde_json::from_str(raw)?;
            validate_fact(&f, principal)?;
            if request != f.request_json
                || receipt.is_some()
                || terminal.as_deref() != Some(serde_jcs::to_string(&f.terminal)?.as_str())
                || retired != f.terminal.retired_record_id
            {
                return Err(invalid());
            }
            Ok(KeyedOutcome::Terminal {
                fact: Box::new(f),
                native: fences::native_on(conn, id).await?,
            })
        }
        ([(id, kind, raw)], Some((request, Some(receipt), outcome, None, None)))
            if kind == receipts::EVENT && outcome == "accepted" =>
        {
            let f: receipts::Fact = serde_json::from_str(raw)?;
            if receipts::normalized_request(operation, &request)? != f.request_json
                || receipt != f.receipt_json
            {
                return Err(invalid());
            }
            Ok(KeyedOutcome::Accepted {
                request: f.request_json,
                receipt,
                native: fences::native_on(conn, id).await?,
            })
        }
        _ => Err(invalid()),
    }
}
fn terminal_answer(
    o: &Original,
    hash: &str,
    f: &FenceFact,
    native: &NativeFenceReference,
) -> Value {
    json!({"schema":"native.original-settlement.answer.v1","verdict":"unapplied_terminal","binding_verified":true,"original_binding_sha256":hash,"namespace_sha256":namespace(o),"fence":{"schema":"native.original-fence.v1","fence_id":f.terminal.fence_id,"reason":f.terminal.reason,"scope":f.terminal.scope,"fenced_original_binding_sha256":f.terminal.original_binding_sha256,"retired_record_id":f.terminal.retired_record_id,"native":native},"terminal":true})
}
/// Explicit operator maintenance, independently disabled by default at its
/// operator switch. Never invoke this on a node working copy or a serving read.
#[cfg(feature = "v2-kernel-probe")]
pub async fn prepare(db: &Db, enabled: bool) -> Result<()> {
    receipts::prepare_typed(db, enabled).await
}

/// Hosted must hold its authenticated route and deployment Write lease until this
/// canonical transaction has physically settled. This does not authorize an app.
#[cfg(feature = "v2-kernel-probe")]
struct SettlementOwner {
    body: crate::coedit::live::kernel_writes::KernelBodyWrite,
    guard: std::sync::Arc<dyn RouteGuard>,
}
#[cfg(feature = "v2-kernel-probe")]
enum SettlementMode {
    Pilot,
    Installed {
        install: String,
        action: installed::Action,
    },
}
#[cfg(feature = "v2-kernel-probe")]
impl SettlementOwner {
    fn quarantine(owner: &mut Self, operation: &str) {
        owner.body.quarantine(operation);
    }
}
/// Detached owned submission: a lost response cannot drop physical custody or
/// the deployment/authentication guards before writer settlement completes.
#[cfg(feature = "v2-kernel-probe")]
pub async fn settle(db: &Db, route: &AuthenticatedRoute<'_>, request: Request) -> Result<Value> {
    settle_owned(db, route, request, SettlementMode::Pilot).await
}

#[cfg(feature = "v2-kernel-probe")]
async fn settle_owned(
    db: &Db,
    route: &AuthenticatedRoute<'_>,
    request: Request,
    mode: SettlementMode,
) -> Result<Value> {
    let db = db.clone();
    let (account, principal, database, origin, node_client) = (
        route.account.to_owned(),
        route.principal.to_owned(),
        route.database.to_owned(),
        route.origin.to_owned(),
        route.node_client.to_owned(),
    );
    let guard = route.guard.clone();
    crate::coedit::live::kernel_writes::owned_result(db.clone(), async move {
        let route = AuthenticatedRoute {
            guard,
            account: &account,
            principal: &principal,
            database: &database,
            origin: &origin,
            node_client: &node_client,
        };
        settle_retained(&db, &route, request, mode).await
    })
    .await
}
#[cfg(feature = "v2-kernel-probe")]
async fn settle_retained(
    db: &Db,
    route: &AuthenticatedRoute<'_>,
    r: Request,
    mode: SettlementMode,
) -> Result<Value> {
    let o = &r.original;
    if r.schema != "native.original-settlement.request.v1"
        || r.action != "settle_original"
        || r.purpose != "held_refusal_resolution"
        || !r.abandon_if_unapplied
    {
        return Ok(status_required("original_evidence_incomplete"));
    }
    if (
        o.account_id.as_str(),
        o.principal_id.as_str(),
        o.database_id.as_str(),
        o.origin_database_id.as_str(),
    ) != (route.account, route.principal, route.database, route.origin)
    {
        return Ok(status_required("route_binding_unavailable"));
    }
    let (hash, fp) = match recompute_binding(o) {
        Ok(v) => v,
        Err(_) => return Ok(status_required("original_evidence_incomplete")),
    };
    if hash != o.expected_binding_sha256 {
        return Ok(status_required("original_binding_mismatch"));
    }
    #[cfg(feature = "mcp-executor-prototype")]
    if crate::mcp::executor_prototype::original_settlement_contract(
        o.journal_variant,
        &o.operation,
        o.arguments["action"].as_str(),
        &o.catalog_executor,
        &o.catalog_operation,
        Some(&o.retained_contract_digest),
    )?
    .as_deref()
        != Some(o.retained_contract_digest.as_str())
    {
        return Ok(status_required("profile_unsupported"));
    }
    #[cfg(not(feature = "mcp-executor-prototype"))]
    return Ok(status_required("profile_unsupported"));
    // This denies unprepared files; it is not a schema-capability attestation
    // for node replay. The serialized typed lookup still verifies coverage.
    let prepared = match db.pool().acquire().await {
        Ok(mut conn) => fences::typed_on(&mut conn).await,
        Err(_) => return Ok(status_required("settlement_qualification_unavailable")),
    };
    match prepared {
        Ok(true) => (),
        Ok(false) => return Ok(status_required("settlement_preparation_required")),
        Err(_) => return Ok(status_required("settlement_qualification_unavailable")),
    }
    if matches!(
        &mode,
        SettlementMode::Installed {
            action: installed::Action::Status,
            ..
        }
    ) {
        let mut tx = db.pool().begin().await?;
        route.guard.recheck().await?;
        return decide_on(db, &mut tx, route, o, hash, fp, mode).await;
    }
    // Acquire lifecycle/availability ownership BEFORE the SQLite writer;
    // metadata mode takes no record/session locks and never flushes a body.
    let caller = crate::mcp::registry::Caller::authenticated(route.account);
    let body = crate::coedit::live::kernel_writes::KernelBodyWrite::acquire(
        db,
        &caller,
        None,
        crate::coedit::live::kernel_writes::KernelWriteMode::Metadata,
    )
    .await;
    let body = match body {
        Ok(body) => body,
        Err(_) => return Ok(status_required("settlement_writer_unavailable")),
    };
    let owner = SettlementOwner {
        body,
        guard: route.guard.clone(),
    };
    let transaction = crate::coedit::live::kernel_writes::KernelTransaction::begin(
        db,
        owner,
        SettlementOwner::quarantine,
    )
    .await;
    let mut transaction = match transaction {
        Ok(tx) => tx,
        Err(_) => return Ok(status_required("settlement_writer_unavailable")),
    };
    let work = async {
        let (conn, owner) = transaction.parts();
        owner.guard.recheck().await?;
        let answer = decide_on(db, conn, route, o, hash, fp, mode).await?;
        owner.body.validate_in(conn).await?;
        Ok::<_, Error>(answer)
    }
    .await;
    match work {
        Ok(answer) => {
            transaction.commit().await?;
            Ok(answer)
        }
        Err(error) => Err(transaction.rollback(error).await),
    }
}
#[cfg(feature = "v2-kernel-probe")]
#[allow(clippy::too_many_arguments)]
async fn decide_on(
    db: &Db,
    tx: &mut SqliteConnection,
    route: &AuthenticatedRoute<'_>,
    o: &Original,
    hash: String,
    fp: String,
    mode: SettlementMode,
) -> Result<Value> {
    if fences::origin_on(&mut *tx).await? != route.origin {
        return Ok(status_required("route_binding_unavailable"));
    }
    // Resolve the actual principal on this writer, never from submitted JSON.
    let actual: Option<(String, String, String)> = sqlx::query_as(
        "SELECT principal_id,kind,display_label FROM main.kernel_principals WHERE auth_binding=?",
    )
    .bind(route.account)
    .fetch_optional(&mut *tx)
    .await?;
    if actual.as_ref().map(|p| p.0.as_str()) != Some(route.principal) {
        return Ok(status_required("route_binding_unavailable"));
    }
    let outcome = match lookup_outcome_on(
        &mut *tx,
        route.principal,
        &o.operation,
        o.operation_key.trim(),
    )
    .await
    {
        Ok(v) => v,
        Err(_) => return Ok(status_required("receipt_coverage_unverified")),
    };
    if let SettlementMode::Installed { install, action } = mode {
        return installed::decide_on(db, tx, route, &install, action, o, &hash, outcome).await;
    }
    match outcome {
        KeyedOutcome::Accepted {
            request,
            receipt,
            native,
        } => Ok(accepted_answer(
            route, o, &hash, &fp, request, receipt, native,
        )),
        KeyedOutcome::Terminal { fact, native } => Ok(terminal_answer(o, &hash, &fact, &native)),
        KeyedOutcome::Absent => {
            let retired = if o.operation == "create_record" {
                Some(o.arguments["id"].as_str().ok_or_else(invalid)?.to_owned())
            } else {
                None
            };
            if let Some(id) = &retired {
                let occupied: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=?)",
                )
                .bind(id)
                .fetch_one(&mut *tx)
                .await?;
                if occupied || fences::refuse_retired_on(&mut *tx, id, None).await.is_err() {
                    return Ok(status_required("receipt_coverage_unverified"));
                }
            }
            let f = FenceFact {
                format: 1,
                operation: o.operation.clone(),
                operation_key: o.operation_key.trim().into(),
                request_json: fp,
                terminal: Terminal {
                    schema: "native.original-fence.v1".into(),
                    fence_id: Uuid::new_v4().to_string(),
                    reason: "owner_abandoned_unapplied".into(),
                    scope: "entire_idempotency_namespace".into(),
                    retired_record_id: retired,
                    namespace_sha256: namespace(o),
                    original_binding_sha256: hash.clone(),
                    account_id: o.account_id.clone(),
                    principal_id: o.principal_id.clone(),
                    database_id: o.database_id.clone(),
                    origin_database_id: o.origin_database_id.clone(),
                    journal_variant: o.journal_variant,
                    retained_contract_digest: o.retained_contract_digest.clone(),
                    catalog_executor: o.catalog_executor.clone(),
                    catalog_operation: o.catalog_operation.clone(),
                    mint_context: o.mint_context.clone(),
                    delegation_ref: None,
                    assertion: "first_party".into(),
                    app: None,
                    asserting_client_id: None,
                    asserting_device_id: None,
                    settled_by_client_id: route.node_client.into(),
                },
            };
            validate_fact(&f, route.principal)?;
            let event = crate::store::append_kernel_mcp_receipt_on(
                db,
                &mut *tx,
                crate::store::AppendSpec {
                    record_id: receipts::STREAM.into(),
                    event_type: fences::EVENT.into(),
                    payload: serde_json::to_value(&f)?,
                    actor: Some(route.principal.into()),
                },
                &mut crate::act::ActAllocation::new(),
            )
            .await?;
            let native = fences::native_on(&mut *tx, &event.id).await?;
            let answer = terminal_answer(o, &hash, &f, &native);
            Ok(answer)
        }
    }
}

#[cfg(feature = "v2-kernel-probe")]
fn accepted_answer(
    route: &AuthenticatedRoute<'_>,
    o: &Original,
    hash: &str,
    fp: &str,
    request: String,
    receipt: String,
    native: NativeFenceReference,
) -> Value {
    if request != fp {
        return json!({"schema":"native.original-settlement.answer.v1","verdict":"mismatch","binding_verified":true,"original_binding_sha256":hash,"namespace_sha256":namespace(o),"reason":"occupied_by_other_accepted_original","terminal":false});
    }
    use sha2::{Digest, Sha256};
    json!({"schema":"native.original-settlement.answer.v1","verdict":"accepted","binding_verified":true,"original_binding_sha256":hash,"namespace_sha256":namespace(o),"receipt":{"identity":{"principal_id":route.principal,"operation":o.operation,"operation_key":o.operation_key.trim(),"canonical_event_id":native.canonical_event_id,"receipt_sha256":hex::encode(Sha256::digest(receipt.as_bytes()))},"native":native}})
}

/// Read only, canonical native/imported origin for trusted route binding.
pub async fn origin(db: &Db) -> Result<String> {
    let mut conn = db.pool().acquire().await?;
    fences::origin_on(&mut conn).await
}

#[cfg(all(test, feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))]
#[path = "original_settlement_tests.rs"]
pub(crate) mod tests;

#[cfg(not(feature = "v2-kernel-probe"))]
pub async fn settle(_db: &Db, _route: &AuthenticatedRoute<'_>, _request: Request) -> Result<Value> {
    Ok(status_required("operation_unsupported"))
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) mod outcome_profile;
