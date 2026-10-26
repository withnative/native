//! Local, sealed human-resolution evidence for kernel HCP suggestions.
//!
//! Ingress verifies the signed short-lived interaction and exact accepted
//! action. Replay validates the recorded receipt, action and exact output set;
//! it never asks today's issuer, clock or membership roster to re-admit it.
use super::{
    client::ClientIdentity,
    kernel_view,
    store::{payload_of, record_id_of, sha256_hex, Store, WriteTx},
};
use crate::{
    control::{ControlEventRow, HcpEntryConfirmedPayload, HcpEntrySuggestionPayload},
    db::Db,
    events::EventRow,
    mcp::registry::Caller,
    Error, Result,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Row, SqliteConnection};

pub(crate) const EVENT: &str = "kernel.hcp_human_resolution.v1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    id: String,
    principal: String,
    nonce: String,
    verifier: String,
    verified_at: String,
    scope_digest: String,
    evidence_digest: String,
    action_digest: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resolution {
    principal_id: String,
    credential: String,
    action: Value,
    receipt: Receipt,
    entry_id: String,
    version: u64,
    suggestion_id: String,
    created_event_id: String,
    body_digest: String,
    resolution_event_id: String,
    disposition: String,
    after_seq: i64,
    through_seq: i64,
    output_ids: Vec<String>,
    resolved_at: String,
}
fn invalid() -> Error {
    Error::engine("invalid kernel HCP human resolution evidence")
}
fn admit(caller: &Caller, args: &Value) -> Result<Option<Receipt>> {
    let Some(proof) = caller.verified_provenance_interaction() else {
        return Ok(None);
    };
    let digest = crate::provenance::action_digest("resolve_suggestions", args);
    if caller.host_asserted_app().is_some()
        || proof.principal != caller.credential()
        || proof.accepted_action_digest.as_deref() != Some(&digest)
    {
        return Err(invalid());
    }
    Ok(Some(Receipt {
        id: proof.receipt_id.clone(),
        principal: proof.principal.clone(),
        nonce: proof.nonce.clone(),
        verifier: proof.verifier.clone(),
        verified_at: proof.verified_at.clone(),
        scope_digest: proof.scope_digest.clone(),
        evidence_digest: proof.evidence_digest.clone(),
        action_digest: digest,
    }))
}

/// `None` delegates an entirely ordinary batch to the existing resolver. Any
/// batch containing an HCP suggestion is handled here, or refused before effects.
pub(crate) async fn resolve(
    db: &Db,
    caller: &Caller,
    actor: &str,
    args: &Value,
) -> Result<Option<Value>> {
    let ids: Vec<&str> = args["suggestion_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut hcp = Vec::new();
    for id in &ids {
        let mapped:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_hcp_audit WHERE principal_id=? AND event_type='hcp.entry.suggestion.v1' AND json_extract(payload,'$.suggestion_id')=?)").bind(actor).bind(id).fetch_one(&mut *tx).await?;
        // A custom HCP view without a sealed mapping still cannot fall back to
        // a weaker ordinary resolver, nor can a foreign HCP suggestion.
        let custom: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=? AND pin_family=?)",
        )
        .bind(id)
        .bind(super::setup::KERNEL_SUGGESTION_FAMILY)
        .fetch_one(&mut *tx)
        .await?;
        if custom && !mapped {
            return Err(Error::engine(
                "resolve_suggestions: suggestion does not exist",
            ));
        }
        if mapped {
            hcp.push(*id);
        }
    }
    if hcp.is_empty() {
        tx.rollback().await?;
        return Ok(None);
    }
    let own:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_principals WHERE principal_id=? AND auth_binding=? AND kind='account')").bind(actor).bind(caller.credential()).fetch_one(&mut *tx).await?;
    if !own || !crate::kernel::hosted_identity::admitted(&mut tx, actor).await? {
        return Err(invalid());
    }
    crate::kernel::app_installs::admit_dispatched_on(&mut tx, actor).await?;
    if args["suggestion_ids"]
        .as_array()
        .is_none_or(|raw| raw.len() != ids.len())
    {
        return Err(invalid());
    }
    if ids.len() != 1 || hcp.len() != 1 {
        return Err(Error::engine(
            "HCP suggestion resolution requires exactly one suggestion; mixed batches are refused",
        ));
    }
    // Check the original arguments, before dropping envelope fields or parsing.
    let evidence = admit(caller, args)?;
    for key in args.as_object().ok_or_else(invalid)?.keys() {
        if ![
            "action",
            "suggestion_ids",
            "reason",
            "dry_run",
            "idempotency_key",
        ]
        .contains(&key.as_str())
        {
            return Err(invalid());
        }
    }
    let action = args["action"].as_str().ok_or_else(invalid)?;
    if !matches!(action, "accept" | "reject") || !args["suggestion_ids"].is_array() {
        return Err(invalid());
    }
    crate::mcp::tools::require_nonblank_reason(
        "resolve_suggestions",
        args["reason"].as_str().ok_or_else(invalid)?,
    )?;
    if args.get("idempotency_key").is_some_and(|v| !v.is_null()) {
        return Err(Error::engine(
            "HCP resolutions retry by their sealed human receipt; idempotency_key is not supported",
        ));
    }
    let dry = match args.get("dry_run") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(v)) => *v,
        _ => return Err(invalid()),
    };
    if dry && action != "accept" {
        return Err(invalid());
    }
    let store = Store::management_kernel(db, caller, actor.into());
    let fold = store.fold_all_in(&mut tx).await?;
    let mapping = fold.suggestions.get(ids[0]).ok_or_else(invalid)?;
    if let Some(resolved) = fold.resolutions.get(ids[0]) {
        let held: Option<String> = sqlx::query_scalar(
            "SELECT payload FROM kernel_hcp_resolutions WHERE principal_id=? AND suggestion_id=?",
        )
        .bind(actor)
        .bind(ids[0])
        .fetch_optional(&mut *tx)
        .await?;
        let old: Resolution = serde_json::from_str(held.as_deref().ok_or_else(invalid)?)?;
        let Some(proof) = evidence else {
            return Err(invalid());
        };
        if old.receipt.id != proof.id
            || old.receipt.nonce != proof.nonce
            || old.receipt.action_digest != proof.action_digest
        {
            return Err(invalid());
        }
        tx.rollback().await?;
        return Ok(Some(
            json!({"status":if resolved.disposition=="confirmed"{"accepted"}else{"rejected"},"target_id":record_id_of(&mapping.entry_id),"suggestion_ids":ids}),
        ));
    }
    let current = fold
        .entries
        .get(&mapping.entry_id)
        .ok_or_else(invalid)?
        .current();
    if current.version() != mapping.version || current.status() != "conflicted" {
        return Err(invalid());
    }
    let start: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events")
        .fetch_one(&mut *tx)
        .await?;
    let suggestion_revision = structural(&mut tx, actor, mapping, start, "open").await?;
    let target = record_id_of(&mapping.entry_id).unwrap();
    if dry {
        tx.rollback().await?;
        return Ok(Some(
            json!({"status":"would_accept","target_id":target,"suggestion_ids":ids,"prospective_body":current.view_body()}),
        ));
    }
    let mut acts = crate::act::ActAllocation::new();
    // The immutable suggestion body is the exact target body at this version;
    // accepting it requires no body write, only the ordinary lifecycle output.
    let life = if action == "accept" {
        "accepted"
    } else {
        "rejected"
    };
    let raw = json!({"lifecycle":life}).to_string();
    crate::kernel::revise_input_in(
        db,
        &mut tx,
        &mut acts,
        actor,
        ids[0],
        crate::kernel::FieldInput::Raw(&raw),
        Some(suggestion_revision),
    )
    .await?;
    let (output,through,at):(String,i64,String)=sqlx::query_as("SELECT id,seq,created_at FROM content_events WHERE record_id=? AND seq>? ORDER BY seq DESC LIMIT 1").bind(ids[0]).bind(start).fetch_one(&mut *tx).await?;
    let output_ids: Vec<String> =
        sqlx::query_scalar("SELECT id FROM content_events WHERE seq>? AND seq<=? ORDER BY seq")
            .bind(start)
            .bind(through)
            .fetch_all(&mut *tx)
            .await?;
    if let Some(receipt) = evidence {
        let resolution = Resolution {
            principal_id: actor.into(),
            credential: caller.credential().into(),
            action: args.clone(),
            receipt,
            entry_id: mapping.entry_id.clone(),
            version: mapping.version,
            suggestion_id: mapping.suggestion_id.clone(),
            created_event_id: mapping.created_event_id.clone(),
            body_digest: mapping.body_digest.clone(),
            resolution_event_id: output,
            disposition: if action == "accept" {
                "confirmed"
            } else {
                "rejected"
            }
            .into(),
            after_seq: start,
            through_seq: through,
            output_ids,
            resolved_at: at,
        };
        crate::store::append_kernel_hcp_in(
            db,
            &mut tx,
            &super::HcpWriteSeal::mint(),
            crate::store::AppendSpec {
                record_id: actor.into(),
                event_type: EVENT.into(),
                actor: Some(actor.into()),
                payload: serde_json::to_value(resolution)?,
            },
            &mut acts,
        )
        .await?;
        // Confirmation, counterpart consequences and management output share
        // one transaction and act. A later edit cannot race past resolution.
        store
            .consume_resolutions_in(&mut tx, &mut acts, &mapping.entry_id)
            .await?;
    }
    store.commit(tx).await?;
    store.sync_version_views(&mapping.entry_id).await;
    Ok(Some(
        json!({"status":life,"target_id":target,"suggestion_ids":ids}),
    ))
}

/// Evaluate the private suggestion's immutable local lineage at event time.
async fn structural(
    tx: &mut SqliteConnection,
    principal: &str,
    mapping: &HcpEntrySuggestionPayload,
    before: i64,
    lifecycle: &str,
) -> Result<i64> {
    let target = record_id_of(&mapping.entry_id).ok_or_else(invalid)?;
    if kernel_view::private_revision_on(tx, principal, &target, true)
        .await?
        .is_none()
        || kernel_view::private_revision_on(tx, principal, &mapping.suggestion_id, false)
            .await?
            .is_none()
    {
        return Err(invalid());
    }
    let suggestion = crate::kernel::read_record_on(tx, principal, &mapping.suggestion_id)
        .await?
        .ok_or_else(invalid)?;
    let entry = crate::kernel::read_record_on(tx, principal, &target)
        .await?
        .ok_or_else(invalid)?;
    let targets:Vec<String>=sqlx::query_scalar("SELECT target_id FROM kernel_generic_links WHERE source_id=? AND relationship='part_of' AND active=1 ORDER BY target_id").bind(&mapping.suggestion_id).fetch_all(&mut *tx).await?;
    if targets != [target]
        || suggestion
            .body
            .as_deref()
            .is_none_or(|b| sha256_hex(b) != mapping.body_digest)
        || entry
            .body
            .as_deref()
            .is_none_or(|b| sha256_hex(b) != mapping.body_digest)
    {
        return Err(invalid());
    }
    if suggestion.fields["lifecycle"] != lifecycle {
        return Err(invalid());
    }
    let created:Option<(i64,Option<i64>)>=sqlx::query_as("SELECT seq,act FROM content_events WHERE id=? AND record_id=? AND actor=? AND type='kernel.record_created.v1'").bind(&mapping.created_event_id).bind(&mapping.suggestion_id).bind(principal).fetch_optional(&mut *tx).await?;
    let (seq, act) = created.ok_or_else(invalid)?;
    let changed:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND seq>? AND seq<=? AND act IS NOT ?)").bind(&mapping.suggestion_id).bind(seq).bind(before).bind(act).fetch_one(&mut *tx).await?;
    if changed {
        return Err(invalid());
    }
    // This is the kernel's record revision token, captured with the exact
    // private body, lifecycle and lineage that were admitted above. /5 field
    // revisions require it and record it as their replay-checked base_revision.
    Ok(suggestion.revision)
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Resolution = serde_json::from_str(event.payload.as_deref().unwrap_or("null"))?;
    if event.record_id != p.principal_id
        || event.actor.as_deref() != Some(&p.principal_id)
        || p.credential != p.receipt.principal
        || p.credential.trim().is_empty()
        || p.receipt.verifier.trim().is_empty()
        || p.receipt.nonce.trim().is_empty()
        || p.receipt.action_digest
            != crate::provenance::action_digest("resolve_suggestions", &p.action)
        || p.action["suggestion_ids"] != json!([p.suggestion_id])
        || p.action["dry_run"] == true
        || !matches!(
            (p.action["action"].as_str(), p.disposition.as_str()),
            (Some("accept"), "confirmed") | (Some("reject"), "rejected")
        )
        || p.through_seq <= p.after_seq
        || p.through_seq >= event.local_seq
    {
        return Err(invalid());
    }
    for id in [
        &p.receipt.id,
        &p.receipt.nonce,
        &p.resolution_event_id,
        &p.suggestion_id,
    ] {
        uuid::Uuid::parse_str(id).map_err(|_| invalid())?;
    }
    for digest in [
        &p.receipt.action_digest,
        &p.receipt.evidence_digest,
        &p.receipt.scope_digest,
        &p.body_digest,
    ] {
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(invalid());
        }
    }
    chrono::DateTime::parse_from_rfc3339(&p.receipt.verified_at).map_err(|_| invalid())?;
    chrono::DateTime::parse_from_rfc3339(&p.resolved_at).map_err(|_| invalid())?;
    if p.receipt.scope_digest
        != crate::provenance::digest_json(&crate::provenance::verified_action_scope(
            "resolve_suggestions",
            &p.action,
        ))
    {
        return Err(invalid());
    }
    let history = super::kernel::events(conn, &p.principal_id, None).await?;
    let fold = super::fold::fold(
        &p.principal_id,
        &super::store::stored_subject_id_of(&p.principal_id),
        &history,
    );
    let mapping = fold.suggestions.get(&p.suggestion_id).ok_or_else(invalid)?;
    let current = fold.entries.get(&p.entry_id).ok_or_else(invalid)?.current();
    if mapping.entry_id != p.entry_id
        || mapping.version != p.version
        || mapping.body_digest != p.body_digest
        || mapping.created_event_id != p.created_event_id
        || current.version() != p.version
        || current.status() != "conflicted"
        || fold.resolutions.contains_key(&p.suggestion_id)
    {
        return Err(invalid());
    }
    let life = if p.disposition == "confirmed" {
        "accepted"
    } else {
        "rejected"
    };
    structural(conn, &p.principal_id, mapping, p.after_seq, life).await?;
    // The sole output is the exact local lifecycle revision. No imported or
    // unrelated outputs can be smuggled into a receipt, even in the same act.
    let outputs=sqlx::query("SELECT id,record_id,type,payload,actor,act,created_at FROM content_events WHERE seq>? AND seq<=? ORDER BY seq")
        .bind(p.after_seq).bind(p.through_seq).fetch_all(&mut *conn).await?;
    let ids: Vec<String> = outputs.iter().map(|r| r.get("id")).collect();
    if ids != p.output_ids || outputs.len() != 1 {
        return Err(invalid());
    }
    let output = &outputs[0];
    let data: Value = serde_json::from_str(&output.get::<String, _>("payload"))?;
    if output.get::<String, _>("id") != p.resolution_event_id
        || output.get::<String, _>("record_id") != p.suggestion_id
        || output.get::<Option<String>, _>("actor").as_deref() != Some(&p.principal_id)
        || output.get::<Option<i64>, _>("act") != event.act
        || event.act.is_none()
        || output.get::<String, _>("created_at") != p.resolved_at
        || !matches!(
            output.get::<String, _>("type").as_str(),
            "kernel.record_revised.v1" | "kernel.record_revised.v2"
        )
        || data["fields"]["lifecycle"] != life
    {
        return Err(invalid());
    }
    sqlx::query("INSERT INTO kernel_hcp_resolutions VALUES(?,?,?,?,?,?,?)")
        .bind(&p.principal_id)
        .bind(&p.suggestion_id)
        .bind(&p.receipt.id)
        .bind(&p.receipt.nonce)
        .bind(&event.id)
        .bind(serde_json::to_string(&p)?)
        .bind(event.local_seq)
        .execute(conn)
        .await?;
    Ok(())
}
fn confirmation(p: &Resolution, id: &str) -> HcpEntryConfirmedPayload {
    HcpEntryConfirmedPayload {
        account_id: p.principal_id.clone(),
        entry_id: p.entry_id.clone(),
        version: p.version,
        client: payload_of(&ClientIdentity::native()),
        disposition: p.disposition.clone(),
        suggestion_id: p.suggestion_id.clone(),
        resolution_event_id: p.resolution_event_id.clone(),
        attestation_id: id.into(),
        interaction_receipt_id: p.receipt.id.clone(),
        confirmed_at: p.resolved_at.clone(),
    }
}
pub(super) async fn verified_resolution(
    tx: &mut WriteTx,
    principal: &str,
    mapping: &HcpEntrySuggestionPayload,
) -> Result<Option<(i64, HcpEntryConfirmedPayload)>> {
    let held:Option<(String,String,i64)>=sqlx::query_as("SELECT event_id,payload,event_seq FROM kernel_hcp_resolutions WHERE principal_id=? AND suggestion_id=?").bind(principal).bind(&mapping.suggestion_id).fetch_optional(&mut **tx).await?;
    held.map(|(id, p, seq)| {
        let p: Resolution = serde_json::from_str(&p)?;
        Ok((seq, confirmation(&p, &id)))
    })
    .transpose()
}
pub(super) async fn validate_confirmation(
    conn: &mut SqliteConnection,
    row: &ControlEventRow,
) -> Result<()> {
    let confirmed: HcpEntryConfirmedPayload = serde_json::from_str(&row.payload)?;
    let held:Option<(String,String)>=sqlx::query_as("SELECT event_id,payload FROM kernel_hcp_resolutions WHERE principal_id=? AND suggestion_id=?").bind(&row.actor).bind(&confirmed.suggestion_id).fetch_optional(conn).await?;
    let (id, p) = held.ok_or_else(invalid)?;
    let p: Resolution = serde_json::from_str(&p)?;
    if confirmed != confirmation(&p, &id) {
        return Err(invalid());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{ops, setup, PseudonymKey};
    use super::*;
    use crate::{
        kernel,
        provenance::{verified_action_scope, ProvenanceInteractionTokenIssuer},
    };
    struct World {
        _dir: tempfile::TempDir,
        db: Db,
        actor: String,
        caller: Caller,
        key: PseudonymKey,
    }
    impl World {
        async fn fresh() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let url = format!("sqlite://{}", dir.path().join("human.db").display());
            let (db, actor) = kernel::create_v2_database(&url, "account", "Richard", "test:human")
                .await
                .unwrap();
            for (family, bytes) in [
                (setup::KERNEL_ENTRY_FAMILY, setup::KERNEL_ENTRY_DEFINITION),
                (
                    setup::KERNEL_SUGGESTION_FAMILY,
                    setup::KERNEL_SUGGESTION_DEFINITION,
                ),
            ] {
                let pin = kernel::install_definition_as(&db, &actor, family, 1, bytes.as_bytes())
                    .await
                    .unwrap();
                kernel::adopt_definition_as(&db, &actor, family, Some(&pin))
                    .await
                    .unwrap();
            }
            Self {
                _dir: dir,
                db,
                actor,
                caller: Caller::authenticated("test:human")
                    .with_oauth_client_id(Some("fixture-client".into())),
                key: PseudonymKey::from_secret(&[42; 32]).unwrap(),
            }
        }
        async fn store(&self) -> Store<'_> {
            Store::new_kernel(
                &self.db,
                &self.caller,
                ClientIdentity::of(&self.caller).unwrap(),
                self.key.clone(),
            )
            .await
            .unwrap()
        }
        async fn conflict(&self) -> (String, String, String) {
            let store = self.store().await;
            let declared=ops::add(&store,&json!({"category":"general_preferences","dimension":"verbosity","preference":"Be detailed","sourceContext":"fixture","declarationType":"user-declared"})).await.unwrap_or_else(|_|panic!("declared add failed"));
            let inferred=ops::add(&store,&json!({"category":"general_preferences","dimension":"verbosity","preference":"Be concise","sourceContext":"fixture","declarationType":"model-inferred","confidence":"high","assertedBy":"fixture model"})).await.unwrap_or_else(|_|panic!("inferred add failed"));
            let fold = store.fold_all().await.unwrap();
            let mapping = fold
                .suggestions
                .values()
                .find(|m| m.entry_id == inferred["id"])
                .expect("private version-bound suggestion");
            (
                declared["id"].as_str().unwrap().into(),
                inferred["id"].as_str().unwrap().into(),
                mapping.suggestion_id.clone(),
            )
        }
        fn human(&self, args: &Value) -> Caller {
            let issuer = ProvenanceInteractionTokenIssuer::random("kernel HCP test ingress");
            let scope = verified_action_scope("resolve_suggestions", args);
            let token = issuer.issue(self.caller.credential(), &scope, 60).unwrap();
            self.caller
                .clone()
                .with_provenance_interaction_token(&issuer, &token, &scope)
                .unwrap()
        }
        async fn count(&self) -> i64 {
            sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(self.db.pool())
                .await
                .unwrap()
        }
    }
    fn accept(id: &str) -> Value {
        json!({"action":"accept","suggestion_ids":[id],"reason":"I confirm this exact inference"})
    }

    #[tokio::test]
    async fn kernel_hcp_human_confirmation_atomic_version_bound_retry_and_replay() {
        let w = World::fresh().await;
        let (declared, inferred, id) = w.conflict().await;
        let args = accept(&id);
        let human = w.human(&args);
        let result = resolve(&w.db, &human, &w.actor, &args)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["status"], "accepted");
        let store = w.store().await;
        let fold = store.fold_all().await.unwrap();
        assert_eq!(fold.resolutions.len(), 1);
        assert_eq!(fold.entries[&inferred].current().status(), "active");
        // Ordinary MCP declarations remain unverified. Confirmation only
        // deprecates authoritative counterparts under the retained HCP rule.
        assert_eq!(fold.entries[&declared].current().assurance(), "unverified");
        assert!(!super::super::conflicts::authoritative(
            fold.entries[&declared].current()
        ));
        assert_eq!(fold.entries[&declared].current().status(), "conflicted");
        let view = kernel::read_record_as(&w.db, &w.actor, &record_id_of(&inferred).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            view.body.as_deref(),
            Some(fold.entries[&inferred].current().view_body().as_str())
        );
        let count = w.count().await;
        resolve(&w.db, &human, &w.actor, &args).await.unwrap();
        assert_eq!(w.count().await, count);
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        kernel::replay_all_projections(&w.db).await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
        ops::update(&store,&json!({"entryId":inferred,"updatedPreference":"Be brief","reason":"new statement","declarationType":"user-declared"})).await.unwrap_or_else(|_|panic!("update failed"));
        let fold = store.fold_all().await.unwrap();
        assert_eq!(fold.entries[&inferred].current().version(), 2);
        let value = fold.entries[&inferred].current().0.to_string();
        assert!(!value.contains("confirmedAt"));
        let view = kernel::read_record_as(&w.db, &w.actor, &record_id_of(&inferred).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            view.body.as_deref(),
            Some(fold.entries[&inferred].current().view_body().as_str())
        );
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        kernel::replay_all_projections(&w.db).await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }

    #[tokio::test]
    async fn kernel_hcp_authoritative_counterpart_consequences_are_atomic_and_replayable() {
        let w = World::fresh().await;
        let store = w.store().await;
        let declared_id = super::super::store::entry_urn(&uuid::Uuid::new_v4().to_string());
        let subject = store.stored_subject_id();
        let native = ClientIdentity::native();
        let mut declared = super::super::model::new_entry(
            &declared_id,
            "general_preferences",
            Some("authority-tone"),
            &subject,
            &super::super::model::Assertion {
                preference: &json!("Authoritative management statement"),
                declaration_type: "user-declared",
                confidence: None,
                asserted_by: &subject,
                source: "test:management",
                client: &native,
                recorded_at: &super::super::model::timestamp(chrono::Utc::now()),
                asserted_at: None,
            },
        );
        // Match the existing v1 C3 authenticated-management fixture. Public MCP
        // declarations cannot acquire this assurance through their arguments.
        declared.0["record"]["provenance"]["assertedBy"]["assurance"] = json!("authenticated");
        let mut tx = store.begin().await.unwrap();
        store
            .append_add(&mut tx, &mut crate::act::ActAllocation::new(), &declared)
            .await
            .unwrap();
        store.commit(tx).await.unwrap();
        store.sync_version_views(&declared_id).await;
        let inferred=ops::add(&store,&json!({"category":"general_preferences","dimension":"authority-tone","preference":"Inferred alternative","sourceContext":"fixture","declarationType":"model-inferred","confidence":"high","assertedBy":"fixture model"})).await.unwrap_or_else(|_|panic!("inference add failed"));
        let inferred_id = inferred["id"].as_str().unwrap();
        let fold = store.fold_all().await.unwrap();
        assert!(super::super::conflicts::authoritative(
            fold.entries[&declared_id].current()
        ));
        assert_eq!(fold.entries[&declared_id].current().status(), "active");
        assert_eq!(fold.entries[inferred_id].current().status(), "conflicted");
        let id = fold
            .suggestions
            .values()
            .find(|m| m.entry_id == inferred_id)
            .unwrap()
            .suggestion_id
            .clone();
        let args = accept(&id);
        let human = w.human(&args);
        sqlx::query("CREATE TRIGGER fail_hcp_deprecation BEFORE INSERT ON content_events WHEN NEW.type='kernel.hcp_entry_status_set.v1' AND json_extract(NEW.payload,'$.payload.cause')='deprecated' BEGIN SELECT RAISE(ABORT,'counterpart failure'); END").execute(w.db.write_pool()).await.unwrap();
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        let count = w.count().await;
        assert!(resolve(&w.db, &human, &w.actor, &args).await.is_err());
        assert_eq!(w.count().await, count);
        assert_eq!(
            before,
            kernel::dump_all_kernel_tables(&w.db).await.unwrap(),
            "output, evidence, confirmation and consequences roll back together"
        );
        sqlx::query("DROP TRIGGER fail_hcp_deprecation")
            .execute(w.db.write_pool())
            .await
            .unwrap();
        resolve(&w.db, &human, &w.actor, &args).await.unwrap();
        let fold = store.fold_all().await.unwrap();
        assert_eq!(fold.resolutions.len(), 1);
        assert_eq!(fold.entries[&declared_id].current().status(), "deprecated");
        assert_eq!(fold.entries[inferred_id].current().status(), "active");
        let acts:Vec<Option<i64>>=sqlx::query_scalar("SELECT DISTINCT act FROM content_events WHERE type IN ('kernel.hcp_human_resolution.v1','kernel.hcp_entry_confirmed.v1') OR (type='kernel.hcp_entry_status_set.v1' AND json_extract(payload,'$.payload.cause') IN ('deprecated','confirmed')) OR id IN (SELECT json_extract(payload,'$.resolution_event_id') FROM kernel_hcp_resolutions)").fetch_all(w.db.pool()).await.unwrap();
        assert_eq!(acts.len(), 1);
        assert!(acts[0].is_some());
        let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
        kernel::replay_all_projections(&w.db).await.unwrap();
        assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    }

    #[tokio::test]
    async fn kernel_hcp_tampered_action_wrong_owner_and_mixed_batches_refuse_before_effects() {
        let w = World::fresh().await;
        let (_, _, id) = w.conflict().await;
        let args = accept(&id);
        let human = w.human(&args);
        let before = w.count().await;
        let mut tampered = args.clone();
        tampered["reason"] = json!("different reason");
        assert!(resolve(&w.db, &human, &w.actor, &tampered).await.is_err());
        let mut mixed = args.clone();
        mixed["suggestion_ids"] = json!([id, uuid::Uuid::new_v4().to_string()]);
        assert!(resolve(&w.db, &w.human(&mixed), &w.actor, &mixed)
            .await
            .is_err());
        let other = kernel::create_principal(&w.db, "account", "Other", "test:other", &w.actor)
            .await
            .unwrap();
        let other_caller = Caller::authenticated("test:other");
        let after_principal = w.count().await;
        assert!(resolve(&w.db, &other_caller, &other, &args).await.is_err());
        assert_eq!(w.count().await, after_principal);
        assert!(after_principal > before);
        assert_eq!(
            w.store().await.fold_all().await.unwrap().resolutions.len(),
            0
        );
    }

    #[tokio::test]
    async fn kernel_hcp_bearer_resolution_is_not_human_confirmation() {
        let w = World::fresh().await;
        let (_, inferred, id) = w.conflict().await;
        let args = accept(&id);
        let mut bearer = w.caller.clone();
        bearer = bearer.with_channel(crate::provenance::Channel::Web);
        resolve(&w.db, &bearer, &w.actor, &args).await.unwrap();
        let fold = w.store().await.fold_all().await.unwrap();
        assert!(fold.resolutions.is_empty());
        assert_eq!(fold.entries[&inferred].current().status(), "conflicted");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_hcp_resolutions")
                .fetch_one(w.db.pool())
                .await
                .unwrap(),
            0
        );
    }
}
