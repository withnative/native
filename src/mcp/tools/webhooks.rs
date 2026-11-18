//! V1 structured intake. Configuration and receipts live in the canonical log,
//! so ordinary act deltas and restore carry them with the application and blob.
//! The September webhook tables remain unused: they lack act-based carriage.
use super::require_record_in;
use crate::{
    act::ActAllocation, authorization::Capability, db::begin_write, mcp::Caller, store::AppendSpec,
    webhook_contract::*, Db, Error, Result,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Sqlite, SqliteConnection, Transaction};

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
async fn append(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut ActAllocation,
    actor: &str,
    id: &str,
    kind: &str,
    payload: Value,
) -> Result<()> {
    let subject = if kind == ACCEPTED {
        format!(
            "native:webhook:{id}:{}",
            payload["submission_key"].as_str().unwrap_or("")
        )
    } else if kind == REVOKED {
        format!("native:webhook:{id}:revoked")
    } else if kind == DIAGNOSTIC {
        format!("native:webhook:{id}:diagnostic")
    } else {
        format!("native:webhook:{id}")
    };
    crate::store::append_webhook_in(
        db,
        tx,
        &Seal(()),
        AppendSpec {
            record_id: subject,
            event_type: kind.into(),
            payload,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}
async fn managed(
    conn: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    id: &str,
) -> Result<(String, Endpoint)> {
    let actor = caller.credential().to_string();
    let e = endpoint_on(conn, id)
        .await?
        .ok_or_else(|| Error::auth("endpoint_not_found"))?;
    if e.issuer_principal != actor || caller.hosting_principal() != Some(e.issuer_user_id.as_str())
    {
        return Err(Error::auth("endpoint_not_found"));
    }
    require_record_in(
        conn,
        caller,
        "webhook",
        &e.config.home_id,
        Capability::Manage,
    )
    .await
    .map_err(|_| Error::auth("issuer_not_authorized"))?;
    Ok((actor, e))
}
/// Hosting must supply a hash of a cryptographically random bearer; plaintext is
/// returned once by the HTTP handler and is never persisted here.
async fn configure_inner(db: &Db, caller: &Caller, mut endpoint: Endpoint) -> Result<Value> {
    endpoint.config.validate()?;
    let mut tx = begin_write(db.write_pool()).await?;
    let actor = caller.credential().to_string();
    if caller.hosting_principal() != Some(endpoint.issuer_user_id.as_str()) {
        return Err(Error::auth("issuer_not_authorized"));
    }
    endpoint.issuer_principal = actor.clone();
    require_record_in(
        &mut tx,
        caller,
        "webhook",
        &endpoint.config.home_id,
        Capability::Manage,
    )
    .await
    .map_err(|_| Error::auth("issuer_not_authorized"))?;
    let mut acts = ActAllocation::new();
    append(
        db,
        &mut tx,
        &mut acts,
        &actor,
        &endpoint.endpoint_id,
        CONFIGURED,
        serde_json::to_value(&endpoint)?,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(public_endpoint(&endpoint, false))
}
fn public_endpoint(e: &Endpoint, revoked: bool) -> Value {
    json!({"endpoint_id":e.endpoint_id,"config":e.config,"revoked":revoked,"owner":"issuing_member","profile":e.config.profile})
}
/// Management never returns credential hashes, raw submitted fields, or submission IDs.
async fn manage_inner(db: &Db, caller: &Caller, args: Value) -> Result<Value> {
    let action = args["action"].as_str().unwrap_or("");
    if action == "list" {
        let mut tx = db.pool().begin().await?;
        let actor = caller.credential().to_string();
        let ids:Vec<String>=sqlx::query_scalar("SELECT record_id FROM main.content_events WHERE type='webhook.configured.v1' AND actor=? AND record_id>? ORDER BY record_id LIMIT 101")
            .bind(&actor).bind(args["after_id"].as_str().map(subject).unwrap_or_default()).fetch_all(&mut *tx).await?;
        let more = ids.len() > 100;
        let mut values = Vec::new();
        for subject in ids.iter().take(100) {
            let id = subject
                .strip_prefix("native:webhook:")
                .ok_or_else(|| Error::engine("invalid_configuration"))?;
            if let Ok((_, e)) = managed(&mut tx, caller, id).await {
                values.push(public_endpoint(&e, revoked_on(&mut tx, id).await?));
            }
        }
        return Ok(
            json!({"endpoints":values,"next_after_id":if more {ids.get(99).and_then(|s|s.strip_prefix("native:webhook:"))}else{None}}),
        );
    }
    let id = args["endpoint_id"]
        .as_str()
        .ok_or_else(|| Error::engine("endpoint_id required"))?;
    let mut tx = begin_write(db.write_pool()).await?;
    let (actor, e) = managed(&mut tx, caller, id).await?;
    let revoked = revoked_on(&mut tx, id).await?;
    match action {
        "inspect" => {
            let accepted:i64=sqlx::query_scalar("SELECT count(*) FROM main.content_events WHERE record_id>=? AND record_id<? AND type='webhook.accepted.v1'").bind(subject(id)).bind(format!("{}~", subject(id))).fetch_one(&mut *tx).await?;
            let last:Option<String>=sqlx::query_scalar("SELECT max(created_at) FROM main.content_events WHERE record_id>=? AND record_id<? AND type='webhook.accepted.v1'").bind(subject(id)).bind(format!("{}~", subject(id))).fetch_one(&mut *tx).await?;
            let mut value = public_endpoint(&e, revoked);
            value["accepted_count"] = accepted.into();
            value["last_accepted_at"] = json!(last);
            Ok(value)
        }
        "revoke" => {
            if !revoked {
                append(
                    db,
                    &mut tx,
                    &mut ActAllocation::new(),
                    &actor,
                    id,
                    REVOKED,
                    json!({"revoked":true}),
                )
                .await?;
            }
            db.commit_content(tx).await?;
            Ok(json!({"endpoint_id":id,"revoked":true}))
        }
        "deliveries" => {
            let after = args["before_seq"].as_i64().unwrap_or(i64::MAX);
            let rows:Vec<(i64,String,String,String)>=sqlx::query_as("SELECT seq,type,payload,created_at FROM main.content_events WHERE record_id>=? AND record_id<? AND type IN ('webhook.accepted.v1','webhook.diagnostic.v1') AND seq<? ORDER BY seq DESC LIMIT 100").bind(subject(id)).bind(format!("{}~", subject(id))).bind(after).fetch_all(&mut *tx).await?;
            let values:Vec<Value>=rows.into_iter().map(|(seq,kind,raw,time)| {
                let p:Value=serde_json::from_str(&raw).unwrap_or(Value::Null);
                if kind==ACCEPTED {json!({"seq":seq,"outcome":"accepted","delivery_id":p["delivery_id"],"record_id":p["record_id"],"created_at":time})}
                else {json!({"seq":seq,"outcome":"rejected_or_ignored","code":p["code"],"created_at":time})}
            }).collect();
            Ok(
                json!({"deliveries":values,"next_before_seq":values.last().map(|v|v["seq"].clone())}),
            )
        }
        _ => Err(Error::engine("invalid management action")),
    }
}

/// The caller must have hosting's verified delegated-service evidence. A normal
/// user transport cannot invoke this seam as if it were a webhook.
async fn ingest_inner(db: &Db, caller: &Caller, endpoint_id: &str, raw: &[u8]) -> Result<Value> {
    let evidence = caller
        .verified_delegated_service()
        .ok_or_else(|| Error::auth("invalid_credential"))?;
    let mut tx = begin_write(db.write_pool()).await?;
    let actor = caller.credential().to_string();
    let e = endpoint_on(&mut tx, endpoint_id)
        .await?
        .ok_or_else(|| Error::auth("invalid_credential"))?;
    if e.issuer_principal != actor
        || caller.hosting_principal() != Some(e.issuer_user_id.as_str())
        || revoked_on(&mut tx, endpoint_id).await?
        || evidence.endpoint_id != endpoint_id
        || evidence.credential_id != e.credential_id
    {
        return Err(Error::auth("invalid_credential"));
    }
    require_record_in(
        &mut tx,
        caller,
        "webhook",
        &e.config.home_id,
        Capability::Edit,
    )
    .await
    .map_err(|_| Error::auth("issuer_not_authorized"))?;
    let mut acts = ActAllocation::new();
    let submitted = serde_json::from_slice::<Submission>(raw);
    let submitted = match submitted {
        Ok(s)
            if s.profile == e.config.profile
                && !s.submission_id.is_empty()
                && s.submission_id.len() <= 200
                && !s.submission_id.chars().any(char::is_control) =>
        {
            s
        }
        _ => {
            append(
                db,
                &mut tx,
                &mut acts,
                &actor,
                endpoint_id,
                DIAGNOSTIC,
                json!({"code":"invalid_submission"}),
            )
            .await?;
            db.commit_content(tx).await?;
            return Ok(json!({"outcome":"rejected","code":"invalid_submission","applied":false}));
        }
    };
    let key = digest(submitted.submission_id.as_bytes());
    let canonical = json!({"profile":submitted.profile,"submission_id":submitted.submission_id,"fields":submitted.fields});
    let fingerprint = digest(&serde_json::to_vec(&canonical)?);
    if let Some(old) = accepted_on(&mut tx, endpoint_id, &key).await? {
        let mismatch = old.payload_digest != fingerprint;
        if mismatch {
            append(
                db,
                &mut tx,
                &mut acts,
                &actor,
                endpoint_id,
                DIAGNOSTIC,
                json!({"code":"duplicate_mismatch"}),
            )
            .await?;
        }
        db.commit_content(tx).await?;
        return Ok(
            json!({"outcome":if mismatch{"duplicate_mismatch"}else{"duplicate"},"code":if mismatch{Some("duplicate_mismatch")}else{None},"delivery_id":old.delivery_id,"record_id":old.record_id}),
        );
    }
    let args = match e.config.map(&submitted.fields) {
        Ok(a) => a,
        Err(_) => {
            append(
                db,
                &mut tx,
                &mut acts,
                &actor,
                endpoint_id,
                DIAGNOSTIC,
                json!({"code":"invalid_submission"}),
            )
            .await?;
            db.commit_content(tx).await?;
            return Ok(json!({"outcome":"rejected","code":"invalid_submission","applied":false}));
        }
    };
    let delivery = uuid::Uuid::new_v4().to_string();
    let origin = json!({"kind":"webhook","profile":e.config.profile,"endpoint_id":endpoint_id,"credential_id":e.credential_id,"delivery_id":delivery,"submission_key":key,"payload_digest":fingerprint,"executor_kind":"delegated_service","channel":"webhook","delegation_principal":actor});
    let schema = crate::query::cascade::schema_config_rows_in(&mut tx).await?;
    let owner = super::mint::caller_owner_in(&mut tx, caller, "webhook").await?;
    let draft = crate::provenance::reserve_action_attestation()?;
    let record_id = Box::pin(super::mint::mint_record_in(
        db,
        &mut tx,
        caller,
        &schema,
        owner.as_deref(),
        "Accepted structured form submission",
        &super::mint::MintRequest {
            record_type: &e.config.record_type,
            kind: &e.config.record_kind,
            name: args["name"].as_str(),
            body: args["body"].as_str(),
            summary: args["summary"].as_str(),
            home_id: Some(&e.config.home_id),
            lifecycle: args["lifecycle"].as_str(),
            persistence: args["persistence"].as_str(),
            maturity: args["maturity"].as_str(),
            facets: args["facets"].as_object(),
            links: &[],
            origin: Some(&origin),
        },
        &super::mint::MintPolicy {
            tool: "webhook",
            refuse_message: true,
            refuse_supplied_member_of: true,
            workitem_lifecycle_default: true,
        },
        &draft,
        &mut acts,
    ))
    .await?;
    let after = super::lifecycle::required_violations_in(&mut tx, &schema, &[&record_id]).await?;
    super::lifecycle::assert_required_not_worsened("webhook", &Default::default(), &after)?;
    let attachment = Box::pin(crate::domain_transaction::create_attachment(
        &mut super::attachments::SqliteAttachmentTransaction {
            db,
            tx: &mut tx,
            act_alloc: &mut acts,
        },
        crate::domain_transaction::AttachmentCreate {
            tool: "webhook",
            bearer_id: &record_id,
            bytes: raw,
            mime: Some("application/json"),
            filename: Some("submission.json"),
            name: "submission.json",
            lifecycle: None,
            owner_id: owner.as_deref(),
            persistence: None,
            maturity: None,
            extra_facets: vec![],
            actor: caller.actor(),
            credential: caller.credential(),
            principal: super::principal(caller),
            attachment_id: None,
            image_insert: None,
        },
    ))
    .await?;
    let receipt = Acceptance {
        submission_key: key,
        payload_digest: fingerprint,
        delivery_id: delivery.clone(),
        record_id: record_id.clone(),
        attachment_id: attachment["attachment_id"].as_str().unwrap().into(),
    };
    append(
        db,
        &mut tx,
        &mut acts,
        &actor,
        endpoint_id,
        ACCEPTED,
        serde_json::to_value(receipt)?,
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(json!({"outcome":"accepted","delivery_id":delivery,"record_id":record_id}))
}

/// Check destination authority before the hosting-only delegated caller seam.
pub async fn authorize_delivery(db: &Db, caller: &Caller, id: &str) -> Result<()> {
    let mut tx = db.pool().begin().await?;
    let actor = caller.credential().to_string();
    let e = endpoint_on(&mut tx, id)
        .await?
        .ok_or_else(|| Error::auth("invalid_credential"))?;
    if e.issuer_principal != actor
        || caller.hosting_principal() != Some(e.issuer_user_id.as_str())
        || revoked_on(&mut tx, id).await?
    {
        return Err(Error::auth("invalid_credential"));
    }
    require_record_in(
        &mut tx,
        caller,
        "webhook",
        &e.config.home_id,
        Capability::Edit,
    )
    .await
    .map_err(|_| Error::auth("issuer_not_authorized"))
}

pub const CONFIGURED: &str = "webhook.configured.v1";
pub const REVOKED: &str = "webhook.revoked.v1";
pub const ACCEPTED: &str = "webhook.accepted.v1";
pub const DIAGNOSTIC: &str = "webhook.diagnostic.v1";
pub(crate) fn is_event(kind: &str) -> bool {
    matches!(kind, CONFIGURED | REVOKED | ACCEPTED | DIAGNOSTIC)
}
fn subject(id: &str) -> String {
    format!("native:webhook:{id}")
}

pub async fn endpoint_on(conn: &mut SqliteConnection, id: &str) -> Result<Option<Endpoint>> {
    let raw: Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='webhook.configured.v1' ORDER BY seq LIMIT 1")
        .bind(subject(id)).fetch_optional(conn).await?;
    raw.map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}
async fn revoked_on(conn: &mut SqliteConnection, id: &str) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='webhook.revoked.v1')").bind(format!("{}:revoked", subject(id))).fetch_one(conn).await?)
}
async fn accepted_on(
    conn: &mut SqliteConnection,
    id: &str,
    key: &str,
) -> Result<Option<Acceptance>> {
    let raw: Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='webhook.accepted.v1' ORDER BY seq LIMIT 1")
        .bind(format!("{}:{key}", subject(id))).fetch_optional(conn).await?;
    raw.map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}

pub fn configure<'a>(
    db: &'a Db,
    caller: &'a Caller,
    endpoint: Endpoint,
) -> futures::future::BoxFuture<'a, Result<Value>> {
    Box::pin(async move {
        let args = serde_json::to_value(&endpoint)?;
        crate::provenance::ProvenanceDispatch::from_caller(caller, "webhook.configure", &args, None)
            .scope(Box::pin(configure_inner(db, caller, endpoint)))
            .await
    })
}
pub fn manage<'a>(
    db: &'a Db,
    caller: &'a Caller,
    args: Value,
) -> futures::future::BoxFuture<'a, Result<Value>> {
    Box::pin(async move {
        crate::provenance::ProvenanceDispatch::from_caller(caller, "webhook.manage", &args, None)
            .scope(Box::pin(manage_inner(db, caller, args.clone())))
            .await
    })
}
pub fn ingest<'a>(
    db: &'a Db,
    caller: &'a Caller,
    id: &'a str,
    raw: &'a [u8],
) -> futures::future::BoxFuture<'a, Result<Value>> {
    Box::pin(async move {
        let args = json!({"endpoint_id":id,"payload_digest":digest(raw)});
        crate::provenance::ProvenanceDispatch::from_caller(caller, "webhook.ingest", &args, None)
            .scope(Box::pin(ingest_inner(db, caller, id, raw)))
            .await
    })
}

/// Historical validation only. Current authority is checked by ingress, never
/// by replay. Reserved subjects cannot become records or leak through record reads.
pub(crate) async fn validate_recorded(
    conn: &mut SqliteConnection,
    event: &crate::events::EventRow,
) -> Result<()> {
    let invalid = || Error::engine("invalid recorded webhook event");
    let raw = event.payload.as_deref().ok_or_else(invalid)?;
    let rest = event
        .record_id
        .strip_prefix("native:webhook:")
        .ok_or_else(invalid)?;
    let id = rest.split(':').next().ok_or_else(invalid)?;
    if uuid::Uuid::parse_str(id).is_err() || event.act.is_none() {
        return Err(invalid());
    }
    if event.event_type == CONFIGURED {
        let e: Endpoint = serde_json::from_str(raw)?;
        e.config.validate()?;
        if event.record_id != subject(&e.endpoint_id)
            || event.actor.as_deref() != Some(&e.issuer_principal)
            || e.issuer_principal.is_empty()
            || e.issuer_user_id.is_empty()
            || uuid::Uuid::parse_str(&e.credential_id).is_err()
            || e.credential_hash.len() != 64
            || !e.credential_hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(invalid());
        }
        let previous: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='webhook.configured.v1' AND seq<?)")
            .bind(&event.record_id).bind(event.local_seq).fetch_one(&mut *conn).await?;
        if previous {
            return Err(invalid());
        }
        return Ok(());
    }
    let e = endpoint_on(conn, id).await?.ok_or_else(invalid)?;
    let config_before: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='webhook.configured.v1' AND seq<?)")
        .bind(subject(id)).bind(event.local_seq).fetch_one(&mut *conn).await?;
    if !config_before || event.actor.as_deref() != Some(&e.issuer_principal) {
        return Err(invalid());
    }
    match event.event_type.as_str() {
        REVOKED => {
            if event.record_id != format!("{}:revoked", subject(id))
                || serde_json::from_str::<Value>(raw)? != json!({"revoked":true})
            {
                return Err(invalid());
            }
        }
        DIAGNOSTIC => {
            let v: Value = serde_json::from_str(raw)?;
            if event.record_id != format!("{}:diagnostic", subject(id))
                || v.as_object().is_none_or(|o| o.len() != 1)
                || !matches!(
                    v["code"].as_str(),
                    Some("invalid_submission" | "duplicate_mismatch")
                )
            {
                return Err(invalid());
            }
        }
        ACCEPTED => {
            let p: Acceptance = serde_json::from_str(raw)?;
            if [&p.submission_key, &p.payload_digest]
                .iter()
                .any(|v| v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()))
                || [&p.record_id, &p.attachment_id, &p.delivery_id]
                    .iter()
                    .any(|v| uuid::Uuid::parse_str(v).is_err())
                || event.record_id != format!("{}:{}", subject(id), p.submission_key)
            {
                return Err(invalid());
            }
            let previous: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='webhook.accepted.v1' AND seq<?)")
                .bind(&event.record_id).bind(event.local_seq).fetch_one(&mut *conn).await?;
            let revoked: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='webhook.revoked.v1' AND seq<?)")
                .bind(format!("{}:revoked", subject(id))).bind(event.local_seq).fetch_one(&mut *conn).await?;
            let lineage: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events e WHERE e.record_id=?1 AND e.type='record.created' AND e.act=?2 AND e.actor IS ?3 AND e.seq<?4 AND json_extract(e.payload,'$.intake_origin.endpoint_id')=?5 AND json_extract(e.payload,'$.intake_origin.delivery_id')=?6 AND json_extract(e.payload,'$.intake_origin.submission_key')=?7 AND json_extract(e.payload,'$.intake_origin.payload_digest')=?8 AND json_extract(e.payload,'$.intake_origin.credential_id')=?9 AND EXISTS(SELECT 1 FROM content_events a WHERE a.record_id=?10 AND a.type='record.created' AND a.act=e.act AND a.actor=e.actor AND a.seq<?4 AND json_extract(a.payload,'$.type')='Document' AND json_extract(a.payload,'$.kind')='attachment') AND EXISTS(SELECT 1 FROM content_events l WHERE l.record_id=?10 AND l.type='link.added' AND l.act=e.act AND l.actor=e.actor AND l.seq<?4 AND json_extract(l.payload,'$.target_id')=e.record_id AND json_extract(l.payload,'$.relationship')='part_of'))")
                .bind(&p.record_id).bind(event.act).bind(&event.actor).bind(event.local_seq).bind(id).bind(&p.delivery_id).bind(&p.submission_key).bind(&p.payload_digest).bind(&e.credential_id).bind(&p.attachment_id).fetch_one(&mut *conn).await?;
            if previous || revoked || !lineage {
                return Err(invalid());
            }
        }
        _ => return Err(invalid()),
    }
    Ok(())
}

/// Only this host adapter can construct canonical intake events.
pub(crate) struct Seal(());

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub(crate) async fn fixture() -> (Db, Caller) {
        let db = crate::create_database(":memory:").await.unwrap();
        let account = crate::identity::hosted::resolve_account_identity(
            &db,
            "owner@example.test",
            "catalog-owner",
        )
        .await
        .unwrap();
        crate::authorization::add_account_grant(
            &db,
            "fixture",
            "native:unfiled",
            &account,
            Capability::Manage,
        )
        .await
        .unwrap();
        let caller = Caller::authenticated(account)
            .with_hosting_context("catalog-owner", "database")
            .with_hosting_owner(true)
            .with_hosting_member(true)
            .with_channel(crate::provenance::Channel::Webhook);
        (db, caller)
    }
    pub(crate) fn config() -> FormConfig {
        serde_json::from_value(json!({"profile":"structured_form.v1","home_id":"native:unfiled","record_type":"WorkItem","record_kind":"task",
            "fields":{"name":{"required":true,"max_length":100},"email":{"required":true,"max_length":320},"website":{"max_length":1000},"cv_url":{"max_length":1000},"answers":{"max_length":16000},"details":{"max_length":1000},"video_url":{"max_length":1000}},
            "mappings":{"name":"name","email":"facet:candidate_email","website":"facet:candidate_website","cv_url":"facet:cv_url","answers":"facet:candidate_answers","details":"facet:candidate_details","video_url":"facet:video_url"},"constants":{"body":"","lifecycle":"open","facets":{"stage":"applied","role":"intern"}}})).unwrap()
    }
    pub(crate) async fn endpoint(db: &Db, caller: &Caller) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        configure(
            db,
            caller,
            Endpoint {
                endpoint_id: id.clone(),
                issuer_user_id: "catalog-owner".into(),
                issuer_principal: String::new(),
                credential_id: uuid::Uuid::new_v4().to_string(),
                credential_hash: digest(b"test secret"),
                config: config(),
            },
        )
        .await
        .unwrap();
        id
    }
    pub(crate) async fn delegated(db: &Db, caller: &Caller, id: &str) -> Caller {
        let e = endpoint_on(&mut db.pool().acquire().await.unwrap(), id)
            .await
            .unwrap()
            .unwrap();
        // SAFETY: this isolated fixture owns the synthetic credential verifier.
        unsafe {
            caller
                .clone()
                .with_verified_delegated_service(id, e.credential_id)
        }
        .unwrap()
    }
    pub(crate) fn payload(id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"profile":"structured_form.v1","submission_id":id,"fields":{"name":"Applicant","email":"candidate@example.test","website":"https://example.test/project","cv_url":"https://example.test/private-cv","answers":"1. Building\nhttps://example.test/video","details":"Available now","video_url":"https://example.test/video"}})).unwrap()
    }
    async fn count(db: &Db, query: &str) -> i64 {
        sqlx::query_scalar(query)
            .fetch_one(db.pool())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn v1_atomic_concurrent_retries_mismatch_fields_provenance_and_revoke() {
        let (db, caller) = fixture().await;
        let id = endpoint(&db, &caller).await;
        let source = delegated(&db, &caller, &id).await;
        let raw = payload("application-1");
        let (a, b) = tokio::join!(
            ingest(&db, &source, &id, &raw),
            ingest(&db, &source, &id, &raw)
        );
        let a = a.unwrap();
        let b = b.unwrap();
        assert_eq!(a["record_id"], b["record_id"]);
        assert_eq!(a["delivery_id"], b["delivery_id"]);
        assert_ne!(a["outcome"], b["outcome"]);
        let before = count(&db, "SELECT next_act FROM act_state").await;
        let retry = ingest(&db, &source, &id, &raw).await.unwrap();
        assert_eq!(retry["delivery_id"], a["delivery_id"]);
        assert_eq!(before, count(&db, "SELECT next_act FROM act_state").await);
        let mut changed: Value = serde_json::from_slice(&raw).unwrap();
        changed["fields"]["email"] = "changed@example.test".into();
        let mismatch = ingest(&db, &source, &id, &serde_json::to_vec(&changed).unwrap())
            .await
            .unwrap();
        assert_eq!(mismatch["outcome"], "duplicate_mismatch");
        assert_eq!(mismatch["record_id"], a["record_id"]);
        let record: (String, String, String, String) =
            sqlx::query_as("SELECT type,kind,body,owner_id FROM records WHERE id=?")
                .bind(a["record_id"].as_str().unwrap())
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(
            (&*record.0, &*record.1, &*record.2),
            ("WorkItem", "task", "")
        );
        let fields: Vec<(String, String)> =
            sqlx::query_as("SELECT key,value FROM facet_values WHERE record_id=? ORDER BY key")
                .bind(a["record_id"].as_str().unwrap())
                .fetch_all(db.pool())
                .await
                .unwrap();
        for (key, value) in [
            ("candidate_email", "candidate@example.test"),
            ("candidate_website", "https://example.test/project"),
            ("cv_url", "https://example.test/private-cv"),
            (
                "candidate_answers",
                "1. Building\nhttps://example.test/video",
            ),
            ("candidate_details", "Available now"),
            ("video_url", "https://example.test/video"),
            ("stage", "applied"),
            ("role", "intern"),
        ] {
            assert!(
                fields.iter().any(|(k, v)| k == key && v == value),
                "missing {key}: {fields:?}"
            );
        }
        let bytes: Vec<u8> =
            sqlx::query_scalar("SELECT bytes FROM blobs WHERE mime='application/json'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(bytes, raw);
        let provenance: (String,String) = sqlx::query_as("SELECT a.executor_kind,a.channel FROM provenance_action_attestations a JOIN provenance_action_outputs o ON o.action_attestation_id=a.id JOIN content_events e ON e.id=o.output_event_id WHERE e.record_id=? AND e.type='record.created'")
            .bind(a["record_id"].as_str().unwrap()).fetch_one(db.pool()).await.unwrap();
        assert_eq!(provenance, ("delegated_service".into(), "webhook".into()));
        assert_eq!(
            count(&db, "SELECT count(*) FROM webhook_endpoints").await,
            0
        );
        assert_eq!(
            count(&db, "SELECT count(*) FROM webhook_credentials").await,
            0
        );
        assert_eq!(
            count(&db, "SELECT count(*) FROM webhook_deliveries").await,
            0
        );
        let diff = crate::conformance::rebuild_and_diff(&db).await.unwrap();
        assert!(diff.equal, "{diff:?}");
        manage(&db, &caller, json!({"action":"revoke","endpoint_id":id}))
            .await
            .unwrap();
        assert!(ingest(&db, &source, &id, &raw).await.is_err());
        assert!(ingest(&db, &source, &id, &payload("new")).await.is_err());
        db.close().await;
    }

    #[tokio::test]
    async fn v1_current_destination_authority_and_private_event_subjects() {
        let (db, caller) = fixture().await;
        let id = endpoint(&db, &caller).await;
        let source = delegated(&db, &caller, &id).await;
        let raw = payload("authority");
        ingest(&db, &source, &id, &raw).await.unwrap();
        let mut registry = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        let event: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? AND type='webhook.configured.v1'",
        )
        .bind(subject(&id))
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(registry
            .call(
                db.clone(),
                caller.clone(),
                "get_history",
                json!({"record_id":subject(&id)})
            )
            .await
            .is_err());
        let sql = registry.call(db.clone(),caller.clone(),"query_sql",json!({"sql":"SELECT id FROM content_events WHERE type='webhook.configured.v1' ORDER BY id"})).await;
        let sql = sql.unwrap();
        assert_eq!(sql["rows"].as_array().unwrap().len(), 0, "{sql}");
        let events = registry
            .call(
                db.clone(),
                caller.clone(),
                "get_event_context",
                json!({"event_id":event}),
            )
            .await;
        assert!(events.is_err());
        crate::authorization::replace_explicit_policy(
            &db,
            "fixture",
            "native:unfiled",
            vec![crate::authorization::AllowEntry::account(
                caller.credential(),
                Capability::Edit,
            )],
        )
        .await
        .unwrap();
        assert_eq!(
            ingest(&db, &source, &id, &raw).await.unwrap()["outcome"],
            "duplicate"
        );
        assert_eq!(
            ingest(&db, &source, &id, &payload("edit-only"))
                .await
                .unwrap()["outcome"],
            "accepted"
        );
        assert!(
            manage(&db, &caller, json!({"action":"inspect","endpoint_id":id}))
                .await
                .is_err()
        );
        assert!(
            manage(&db, &caller, json!({"action":"revoke","endpoint_id":id}))
                .await
                .is_err()
        );
        crate::authorization::replace_explicit_policy(
            &db,
            "fixture",
            "native:unfiled",
            vec![crate::authorization::AllowEntry {
                subject: crate::authorization::PolicySubject::Account(caller.credential().into()),
                capability: Capability::View,
            }],
        )
        .await
        .unwrap();
        assert!(ingest(&db, &source, &id, &raw).await.is_err());
        assert!(ingest(&db, &source, &id, &payload("new-denied"))
            .await
            .is_err());
        assert!(
            manage(&db, &caller, json!({"action":"inspect","endpoint_id":id}))
                .await
                .is_err()
        );
        assert!(
            manage(&db, &caller, json!({"action":"revoke","endpoint_id":id}))
                .await
                .is_err()
        );
        db.close().await;
    }

    #[tokio::test]
    async fn v1_rollback_after_attachment_leaves_no_partial_application_blob_or_receipt() {
        let (db, caller) = fixture().await;
        let id = endpoint(&db, &caller).await;
        let source = delegated(&db, &caller, &id).await;
        let before = count(&db, "SELECT count(*) FROM content_events").await;
        sqlx::query("CREATE TRIGGER injected_intake_failure BEFORE INSERT ON content_events WHEN NEW.type='webhook.accepted.v1' BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END").execute(db.write_pool()).await.unwrap();
        assert!(ingest(&db, &source, &id, &payload("rollback"))
            .await
            .is_err());
        assert_eq!(
            before,
            count(&db, "SELECT count(*) FROM content_events").await
        );
        assert_eq!(count(&db, "SELECT count(*) FROM blobs").await, 0);
        sqlx::query("DROP TRIGGER injected_intake_failure")
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            ingest(&db, &source, &id, &payload("rollback"))
                .await
                .unwrap()["outcome"],
            "accepted"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn v1_invalid_authority_and_sealed_events_cannot_create_applications() {
        let (db, caller) = fixture().await;
        let id = endpoint(&db, &caller).await;
        let source = delegated(&db, &caller, &id).await;
        assert!(ingest(&db, &caller, &id, &payload("unverified"))
            .await
            .is_err());
        let mut invalid: Value = serde_json::from_slice(&payload("invalid")).unwrap();
        invalid["fields"]["stage"] = "hired".into();
        assert_eq!(
            ingest(&db, &source, &id, &serde_json::to_vec(&invalid).unwrap())
                .await
                .unwrap()["outcome"],
            "rejected"
        );
        let other =
            Caller::authenticated("another-account").with_hosting_context("other-user", "database");
        assert!(
            manage(&db, &other, json!({"action":"inspect","endpoint_id":id}))
                .await
                .is_err()
        );
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let generic = crate::store::append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: subject(&id),
                event_type: REVOKED.into(),
                payload: json!({"revoked":true}),
                actor: Some(caller.actor().into()),
            },
            &mut ActAllocation::new(),
        )
        .await;
        assert!(generic.is_err());
        tx.rollback().await.unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM records WHERE type='WorkItem' AND name='Applicant'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(count, 0);
        db.close().await;
    }
}
