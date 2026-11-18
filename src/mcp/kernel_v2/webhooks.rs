//! Sealed hosting adapter: authorized create, retained JSON attachment and the
//! accepted key share one BEGIN IMMEDIATE and one kernel commit.
use super::{principal_on, writes};
use crate::{
    act::ActAllocation,
    authorization::Capability,
    db::begin_write,
    kernel::{self, webhooks::*},
    mcp::Caller,
    store::AppendSpec,
    Db, Error, Result,
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
    crate::store::append_in(
        db,
        tx,
        AppendSpec {
            record_id: id.into(),
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
    conn: &mut SqliteConnection,
    caller: &Caller,
    id: &str,
) -> Result<(String, Endpoint)> {
    let actor = principal_on(conn, caller).await?;
    let e = endpoint_on(conn, id)
        .await?
        .ok_or_else(|| Error::auth("endpoint_not_found"))?;
    if e.issuer_principal != actor || caller.hosting_principal() != Some(e.issuer_user_id.as_str())
    {
        return Err(Error::auth("endpoint_not_found"));
    }
    kernel::kernel_require(conn, &actor, &e.config.home_id, Capability::Manage)
        .await
        .map_err(|_| Error::auth("issuer_not_authorized"))?;
    Ok((actor, e))
}
/// Hosting must supply a hash of a cryptographically random bearer; plaintext is
/// returned once by the HTTP handler and is never persisted here.
pub async fn configure(db: &Db, caller: &Caller, mut endpoint: Endpoint) -> Result<Value> {
    endpoint.config.validate()?;
    let mut tx = begin_write(db.write_pool()).await?;
    let actor = principal_on(&mut tx, caller).await?;
    if caller.hosting_principal() != Some(endpoint.issuer_user_id.as_str()) {
        return Err(Error::auth("issuer_not_authorized"));
    }
    endpoint.issuer_principal = actor.clone();
    kernel::kernel_require(
        &mut tx,
        &actor,
        &endpoint.config.home_id,
        Capability::Manage,
    )
    .await?;
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
    db.commit_kernel_content(tx).await?;
    Ok(public_endpoint(&endpoint, false))
}
fn public_endpoint(e: &Endpoint, revoked: bool) -> Value {
    json!({"endpoint_id":e.endpoint_id,"config":e.config,"revoked":revoked,"owner":"issuing_member","profile":e.config.profile})
}
/// Management never returns credential hashes, raw submitted fields, or raw IDs.
pub async fn manage(db: &Db, caller: &Caller, args: Value) -> Result<Value> {
    let action = args["action"].as_str().unwrap_or("");
    if action == "list" {
        let mut tx = db.pool().begin().await?;
        let actor = principal_on(&mut tx, caller).await?;
        let ids:Vec<String>=sqlx::query_scalar("SELECT record_id FROM main.content_events WHERE type='kernel.webhook_configured.v1' AND actor=? AND record_id>? ORDER BY record_id LIMIT 101")
            .bind(&actor).bind(args["after_id"].as_str().unwrap_or("")).fetch_all(&mut *tx).await?;
        let more = ids.len() > 100;
        let mut values = Vec::new();
        for id in ids.iter().take(100) {
            if let Ok((_, e)) = managed(&mut tx, caller, id).await {
                values.push(public_endpoint(
                    &e,
                    kernel::webhooks::revoked_on(&mut tx, id).await?,
                ));
            }
        }
        return Ok(json!({"endpoints":values,"next_after_id":if more {ids.get(99)}else{None}}));
    }
    let id = args["endpoint_id"]
        .as_str()
        .ok_or_else(|| Error::engine("endpoint_id required"))?;
    let mut tx = begin_write(db.write_pool()).await?;
    let (actor, e) = managed(&mut tx, caller, id).await?;
    let revoked = kernel::webhooks::revoked_on(&mut tx, id).await?;
    match action {
        "inspect" => {
            let accepted:i64=sqlx::query_scalar("SELECT count(*) FROM main.content_events WHERE record_id=? AND type='kernel.webhook_accepted.v1'").bind(id).fetch_one(&mut *tx).await?;
            let last:Option<String>=sqlx::query_scalar("SELECT max(created_at) FROM main.content_events WHERE record_id=? AND type='kernel.webhook_accepted.v1'").bind(id).fetch_one(&mut *tx).await?;
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
            db.commit_kernel_content(tx).await?;
            Ok(json!({"endpoint_id":id,"revoked":true}))
        }
        "deliveries" => {
            let after = args["before_seq"].as_i64().unwrap_or(i64::MAX);
            let rows:Vec<(i64,String,String,String)>=sqlx::query_as("SELECT seq,type,payload,created_at FROM main.content_events WHERE record_id=? AND type IN ('kernel.webhook_accepted.v1','kernel.webhook_diagnostic.v1') AND seq<? ORDER BY seq DESC LIMIT 100").bind(id).bind(after).fetch_all(&mut *tx).await?;
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
pub async fn ingest(db: &Db, caller: &Caller, endpoint_id: &str, raw: &[u8]) -> Result<Value> {
    let evidence = caller
        .verified_delegated_service()
        .ok_or_else(|| Error::auth("invalid_credential"))?;
    let mut tx = begin_write(db.write_pool()).await?;
    let actor = principal_on(&mut tx, caller).await?;
    let e = endpoint_on(&mut tx, endpoint_id)
        .await?
        .ok_or_else(|| Error::auth("invalid_credential"))?;
    if e.issuer_principal != actor
        || caller.hosting_principal() != Some(e.issuer_user_id.as_str())
        || kernel::webhooks::revoked_on(&mut tx, endpoint_id).await?
        || evidence.endpoint_id != endpoint_id
        || evidence.credential_id != e.credential_id
    {
        return Err(Error::auth("invalid_credential"));
    }
    kernel::kernel_require(&mut tx, &actor, &e.config.home_id, Capability::Edit)
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
            db.commit_kernel_content(tx).await?;
            return Ok(json!({"outcome":"rejected","code":"invalid_submission","applied":false}));
        }
    };
    let key = digest(submitted.submission_id.as_bytes());
    let canonical = json!({"profile":submitted.profile,"submission_id":submitted.submission_id,"fields":submitted.fields});
    let fingerprint = digest(&serde_json::to_vec(&canonical)?);
    if let Some(old) = kernel::webhooks::accepted_on(&mut tx, endpoint_id, &key).await? {
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
        db.commit_kernel_content(tx).await?;
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
            db.commit_kernel_content(tx).await?;
            return Ok(json!({"outcome":"rejected","code":"invalid_submission","applied":false}));
        }
    };
    let delivery = uuid::Uuid::new_v4().to_string();
    let origin = json!({"kind":"webhook","profile":e.config.profile,"endpoint_id":endpoint_id,"credential_id":e.credential_id,"delivery_id":delivery,"submission_key":key,"payload_digest":fingerprint,"executor_kind":"delegated_service","channel":"webhook","delegation_principal":actor});
    let record = writes::create_with_origin(db, &mut tx, &mut acts, &actor, &args, origin)
        .await
        .map_err(|e| match e {
            Error::Engine(_) => Error::engine("invalid_configuration"),
            e => e,
        })?;
    let record_id = record["id"]
        .as_str()
        .ok_or_else(|| Error::engine("missing created record"))?
        .to_owned();
    let attachment=writes::attach_text(db,&mut tx,&mut acts,&actor,&json!({"record_id":record_id,"text":std::str::from_utf8(raw).map_err(|_|Error::engine("invalid_submission"))?,"mime":"application/json","filename":"submission.json"})).await?;
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
    db.commit_kernel_content(tx).await?;
    Ok(json!({"outcome":"accepted","delivery_id":delivery,"record_id":record_id}))
}

/// Check destination authority before the hosting-only delegated caller seam.
pub async fn authorize_delivery(db: &Db, caller: &Caller, id: &str) -> Result<()> {
    let mut tx = db.pool().begin().await?;
    let actor = principal_on(&mut tx, caller).await?;
    let e = endpoint_on(&mut tx, id)
        .await?
        .ok_or_else(|| Error::auth("invalid_credential"))?;
    if e.issuer_principal != actor
        || caller.hosting_principal() != Some(e.issuer_user_id.as_str())
        || kernel::webhooks::revoked_on(&mut tx, id).await?
    {
        return Err(Error::auth("invalid_credential"));
    }
    kernel::kernel_require(&mut tx, &actor, &e.config.home_id, Capability::Edit)
        .await
        .map_err(|_| Error::auth("issuer_not_authorized"))
}

/// Called only after the ordinary record/history visibility gate. No principal
/// binding or credential hash is disclosed as a source author.
pub(super) async fn recorded_source_on(
    conn: &mut SqliteConnection,
    id: &str,
    through: i64,
) -> Result<Option<(Value, i64, String)>> {
    let row:Option<(String,i64,String)>=sqlx::query_as("SELECT json_extract(payload,'$.origin'),act,id FROM main.content_events WHERE record_id=? AND seq<=? AND type IN ('kernel.record_created.v1','kernel.record_created.v2') AND json_extract(payload,'$.origin.kind')='webhook' ORDER BY seq LIMIT 1")
        .bind(id).bind(through).fetch_optional(conn).await?;
    row.map(|(raw, act, id)| {
        let mut source: Value = serde_json::from_str(&raw)?;
        source
            .as_object_mut()
            .ok_or_else(|| Error::engine("invalid webhook source"))?
            .remove("delegation_principal");
        Ok((source, act, id))
    })
    .transpose()
}
pub(super) fn contribution(source: &Value, created: &str, event: &str, kind: &str) -> Value {
    json!({"executor":{"kind":"delegated_service","ref":source["credential_id"],"assurance":"server_observed"},"channel":{"kind":"webhook","assurance":"server_observed","display_inference":"automated"},"revision":{"event_id":event,"event_type":kind,"produced_current_body":true},"created_by":{"event_id":created,"same_run":null},"context":{},"source":source,"interpretation_limits":["delegation_is_not_source_authorship_or_endorsement","recorded_host_ingress_is_not_a_v1_action_attestation"]})
}
