//! Direct same-bearer type correction: current facts are checked and committed
//! in one transaction. Specialized identities still require their own creation.
use super::*;
use crate::authorization::Capability;
use crate::query::cascade;
use sqlx::Row;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Args {
    record_id: String,
    target_type: String,
    target_kind: String,
    reason: String,
    if_content_seq: Option<i64>,
}

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    registry.set_kernel_v2_schema("correct_record_type",json!({
        "type":"object","properties":{
            "record_id":{"type":"string"},"target_type":{"type":"string","enum":crate::schema::SPINE_TYPES},
            "target_kind":{"type":"string","minLength":1},"reason":{"type":"string","minLength":1},
            "if_content_seq":{"type":"integer"}
        },"required":["record_id","target_type","target_kind","reason"],"additionalProperties":false
    }))?;
    registry.register_engine_handler(
        "correct_record_type",
        EngineKind::KernelV2,
        |engine, caller, args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            execute(&db, &caller, args).await
        },
    )
}

async fn execute(db: &Db, caller: &Caller, args: Value) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&args)?));
    let args: Args = parse("correct_record_type", args)?;
    if args.reason.trim().is_empty()
        || !crate::schema::SPINE_TYPES.contains(&args.target_type.as_str())
        || args.target_kind.trim().is_empty()
    {
        return Err(Error::engine(
            "correct_record_type: closed target type, nonempty kind and reason required",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let actor = principal_on(&mut tx, caller).await?;
    kernel::app_installs::admit_dispatched_on(&mut tx, &actor).await?;
    kernel::kernel_require(&mut tx, &actor, &args.record_id, Capability::Manage).await?;
    let before = kernel::read_record_on(&mut tx, &actor, &args.record_id)
        .await?
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    if args
        .if_content_seq
        .is_some_and(|expected| expected != before.revision)
    {
        return Err(Error::conflict(
            "correct_record_type: record revision conflict; reload and retry",
        ));
    }
    let physical: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(&args.record_id)
            .fetch_one(&mut *tx)
            .await?;
    let (current_type, current_kind) = v1_type_and_kind(
        before.family.as_deref(),
        before.pin.as_ref().map(|p| p.version),
        physical.as_deref(),
        before.kind.as_deref(),
        &before.fields,
    );
    let current_type = current_type.unwrap_or_default();
    let current_kind = current_kind.unwrap_or_default();
    if crate::schema::ENGINE_PROVISIONED_RECORD_IDS.contains(&args.record_id.as_str())
        || args.record_id == crate::events::KERNEL_ROOT_ID
        || kernel::messaging::persona_on(&mut tx, &args.record_id)
            .await?
            .is_some()
        || matches!(current_type, "Message" | "Unit" | "Annotation")
        || (current_type == "Document" && current_kind == "attachment")
        || matches!(args.target_type.as_str(), "Message" | "Unit" | "Annotation")
        || (args.target_type == "Document" && args.target_kind == "attachment")
    {
        return Err(Error::engine(
            "correct_record_type: specialized identity requires a new bearer",
        ));
    }
    kernel::type_correction::require_unregistered_on(&mut tx, &args.record_id).await?;
    let specialized:bool=sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_comment_anchors WHERE annotation_id=?) OR EXISTS(SELECT 1 FROM kernel_attachment_blobs WHERE record_id=?) OR EXISTS(SELECT 1 FROM kernel_publications WHERE record_id=?) OR EXISTS(SELECT 1 FROM kernel_canvas_activations WHERE canvas_id=?) OR EXISTS(SELECT 1 FROM kernel_link4_edges WHERE source_id=? OR target_id=?)"
    ).bind(&args.record_id).bind(&args.record_id).bind(&args.record_id).bind(&args.record_id)
        .bind(&args.record_id).bind(&args.record_id)
        .fetch_one(&mut *tx).await?;
    let capsule: Option<String> =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id=?")
            .bind(&args.record_id)
            .fetch_optional(&mut *tx)
            .await?;
    let frozen_specialized = if let Some(raw) = capsule {
        let state: kernel::app_state::RetainedAppState = serde_json::from_str(&raw)?;
        !state.artifact_source_attestations.is_empty()
            || !state.module_releases.is_empty()
            || !state.module_release_imports.is_empty()
            || !state.canvas_objects.is_empty()
    } else {
        false
    };
    if specialized
        || frozen_specialized
        || current_type == "Program"
        || (current_type == "Annotation" && current_kind == "attribution")
    {
        return Err(Error::engine("correct_record_type: specialized state fixes this bearer's identity; create a new bearer"));
    }
    let imported: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type='kernel.import_state.v1')")
        .bind(&args.record_id).fetch_one(&mut *tx).await?;
    if imported {
        let guard: Option<String> = sqlx::query_scalar("SELECT payload FROM kernel_v1_state WHERE section='record_deletion_guards' AND source_id=? AND record_id=?")
            .bind(&args.record_id).bind(&args.record_id).fetch_optional(&mut *tx).await?;
        let guard: Option<Value> = guard.map(|raw| serde_json::from_str(&raw)).transpose()?;
        if guard.as_ref().is_none_or(|g| {
            g["record_id"] != args.record_id || g["type_correction_specialized"] != false
        }) {
            return Err(Error::engine("correct_record_type: specialized source identity evidence is active or unavailable; refresh source evidence before cutover"));
        }
    }

    // Stage only the authoritative catalogue data for the existing shared
    // kind and absolute facet validators. No v1 record or ACL table is used.
    shape::stage_catalog_on(&mut tx, &actor).await?;
    let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut tx);
    let resolution =
        crate::meta::kind::resolve_with(&mut executor, &args.target_type, &args.target_kind)
            .await?;
    let target = resolution
        .canonical_kind_for_write()
        .ok_or_else(|| Error::engine("correct_record_type: target kind is not active"))?
        .to_owned();
    if args.target_type == "Document" && target == "attachment" {
        return Err(Error::engine(
            "correct_record_type: an attachment requires a new bearer",
        ));
    }
    let incompatible:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_identity_bindings WHERE record_id=? AND system='native-principal' AND (?<>'Entity' OR ?<>'person'))")
        .bind(&args.record_id).bind(&args.target_type).bind(&target).fetch_one(&mut *tx).await?;
    if incompatible {
        return Err(Error::engine(
            "correct_record_type: preserved identity binding is incompatible with target",
        ));
    }

    if current_type == args.target_type && current_kind == target {
        return Err(Error::engine(
            "correct_record_type: current and target identity are identical",
        ));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(&args.record_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    crate::mcp::tools::lifecycle::validate_prospective_program(
        "correct_record_type",
        &args.target_type,
        Some(&target),
        runtime.as_deref(),
    )?;
    let schema = kernel::v1_state::schema_rows_on(&mut tx, &actor).await?;
    let bearer =
        kernel::v1_state::lifecycle_bearer_on(&mut tx, &before.home_id, Some(&args.record_id))
            .await?;
    let resolved = cascade::facets_for_record_context(
        &schema,
        &args.target_type,
        Some(&target),
        Some(&bearer),
    );
    let rows=sqlx::query("SELECT key,value,value_num,vocab_ref FROM kernel_facets WHERE record_id=? AND value IS NOT NULL AND key<>'archived'")
        .bind(&args.record_id).fetch_all(&mut *tx).await?;
    let mut facets = Vec::new();
    for row in rows {
        let key: String = row.try_get("key")?;
        let value: String = row.try_get("value")?;
        let number: Option<f64> = row.try_get("value_num")?;
        let value = if let Some(n) = number {
            json!(n)
        } else if value.starts_with('{') {
            serde_json::from_str(&value).unwrap_or(Value::String(value))
        } else {
            Value::String(value)
        };
        facets.push(crate::domain_transaction::FacetWrite {
            key,
            value,
            vocab_ref: row.try_get("vocab_ref")?,
            time_type: None,
        });
    }
    for (key, rule) in resolved {
        if rule["required"] != true {
            continue;
        }
        let present = match key.as_str() {
            "lifecycle" => before.fields.get("lifecycle").is_some_and(|v| !v.is_null()),
            "owner" | "owner_id" => before.owner_id.is_some(),
            "persistence" => !before.metadata.persistence.is_empty(),
            "maturity" => before.metadata.maturity.is_some(),
            _ => facets.iter().any(|f| f.key == key),
        };
        if !present {
            return Err(Error::engine(format!(
                "correct_record_type: preserved state lacks required facet '{key}'"
            )));
        }
    }
    kernel::v1_state::interpreter_on(&mut tx, &actor)
        .await?
        .validate_imported_write(
            &args.target_type,
            &target,
            Some(&bearer),
            before.fields.get("lifecycle").and_then(Value::as_str),
        )?;
    let mut executor = crate::portable_sql::BorrowedSqliteStatementExecutor::new(&mut tx);
    crate::domain_transaction::govern_facet_writes(
        &mut executor,
        &schema,
        "correct_record_type",
        &args.target_type,
        Some(&target),
        &mut facets,
    )
    .await?;
    for table in ["schema_config", "vocabulary_values", "vocabularies"] {
        sqlx::query(&format!("DROP TABLE temp.{table}"))
            .execute(&mut *tx)
            .await?;
    }
    let mut acts = crate::act::ActAllocation::new();
    let pending = kernel::app_installs::start_app_action_in(
        db,
        &mut tx,
        &actor,
        "correct_record_type",
        digest,
        Some(args.reason.clone()),
        &mut acts,
    )
    .await?;
    let mut result = kernel::type_correction::correct_in(
        db,
        &mut tx,
        &mut acts,
        &actor,
        &args.record_id,
        &args.target_type,
        &target,
        &args.reason,
    )
    .await?;
    // Check all preserved open facets against the prospective identity while
    // still inside the same transaction; failure rolls back the correction.
    let observations: Vec<kernel::hq::FacetObservation> = sqlx::query_as("SELECT key,value,value_num,vocab_ref,as_of FROM kernel_facets WHERE record_id=? AND value IS NOT NULL AND key<>'archived'")
        .bind(&args.record_id).fetch_all(&mut *tx).await?;
    for observation in observations {
        kernel::schema_configuration::assert_native_facet_conformance_on(
            &mut tx,
            &args.record_id,
            &observation,
        )
        .await?;
    }
    if let Some(attribution) =
        kernel::app_installs::finish_app_action_in(db, &mut tx, &actor, pending, &mut acts).await?
    {
        result["app_attribution"] = attribution;
    }
    db.commit_kernel_content(tx).await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::kernel_v2::{policy_tests::fixture, tests::registry};

    #[tokio::test]
    async fn kernel_v2_direct_type_correction_preserves_content_authority_links_and_replays() {
        let f = fixture(false).await;
        let created: (i64, String) =
            sqlx::query_as("SELECT created_seq,created_at FROM kernel_records WHERE id=?")
                .bind(&f.private)
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        let before = kernel::read_record_as(&f.db, &f.owner_principal, &f.private)
            .await
            .unwrap()
            .unwrap();
        let links: Vec<(String,String,String)> = sqlx::query_as("SELECT source_id,target_id,relationship FROM kernel_generic_links WHERE source_id=? OR target_id=? ORDER BY source_id,target_id,relationship")
            .bind(&f.private).bind(&f.private).fetch_all(f.db.pool()).await.unwrap();
        assert!(!links.is_empty(), "fixture must include attached comment");
        let args = json!({"record_id":f.private,"target_type":"Document","target_kind":"handoff","reason":"Correct the mistaken kind","if_content_seq":before.revision});
        let state = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        assert!(registry()
            .call_engine(
                EngineHandle::KernelV2(f.db.clone()),
                Caller::authenticated(&f.member),
                "correct_record_type",
                args.clone()
            )
            .await
            .is_err());
        assert_eq!(state, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
        let mut stale = args.clone();
        stale["if_content_seq"] = json!(before.revision - 1);
        assert!(registry()
            .call_engine(
                EngineHandle::KernelV2(f.db.clone()),
                Caller::authenticated(&f.owner),
                "correct_record_type",
                stale
            )
            .await
            .is_err());
        assert_eq!(state, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
        let result = registry()
            .call_engine(
                EngineHandle::KernelV2(f.db.clone()),
                Caller::authenticated(&f.owner),
                "correct_record_type",
                args.clone(),
            )
            .await
            .unwrap();
        assert_eq!(result["to"]["kind"], "handoff");
        assert!(uuid::Uuid::parse_str(result["event_id"].as_str().unwrap()).is_ok());
        let after = kernel::read_record_as(&f.db, &f.owner_principal, &f.private)
            .await
            .unwrap()
            .unwrap();
        let corrected: (i64, String) =
            sqlx::query_as("SELECT created_seq,created_at FROM kernel_records WHERE id=?")
                .bind(&f.private)
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        assert!(
            corrected.0 > created.0,
            "definition binding revision must advance"
        );
        assert_eq!(
            created.1, corrected.1,
            "original creation timestamp must survive"
        );
        assert_eq!(before.body, after.body);
        assert_eq!(before.owner_id, after.owner_id);
        assert_eq!(before.home_id, after.home_id);
        assert_eq!(before.metadata.persistence, after.metadata.persistence);
        assert_eq!(before.fields["title"], after.fields["title"]);
        let retained: Vec<(String,String,String)> = sqlx::query_as("SELECT source_id,target_id,relationship FROM kernel_generic_links WHERE source_id=? OR target_id=? ORDER BY source_id,target_id,relationship")
            .bind(&f.private).bind(&f.private).fetch_all(f.db.pool()).await.unwrap();
        assert_eq!(links, retained);
        let state = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        assert!(registry()
            .call_engine(
                EngineHandle::KernelV2(f.db.clone()),
                Caller::authenticated(&f.owner),
                "correct_record_type",
                args
            )
            .await
            .is_err());
        assert_eq!(state, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
        kernel::replay_all_projections(&f.db).await.unwrap();
        assert_eq!(state, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
        registry().call(f.source.clone(), Caller::authenticated(&f.owner),"update_record",json!({"id":f.private,"name":"Stale source revision","reason":"resume guard fixture"})).await.unwrap();
        let resumed = crate::v1_import::run(crate::v1_import::Options {
            source: f.target.with_file_name("source.db"),
            target: f.target.clone(),
            seeds: vec![],
            all: true,
            history: true,
            resume: true,
            members_file: Some(f.target.with_file_name("members.txt")),
        })
        .await;
        assert!(
            resumed.as_ref().map_or(true, |r| !r.refusals.is_empty()),
            "native correction must fence stale source resume"
        );
        let retained = kernel::read_record_as(&f.db, &f.owner_principal, &f.private)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retained.fields["v1_kind"], "handoff");
    }

    #[tokio::test]
    async fn kernel_v2_direct_type_correction_refusals_are_atomic() {
        let f = fixture(false).await;
        let state = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        for (id, typ, kind, reason) in [
            (f.private.as_str(), "Document", "note", "identical"),
            (f.comment.as_str(), "Document", "handoff", "derived source"),
            (
                f.private.as_str(),
                "Document",
                "no-such-active-kind",
                "invalid target",
            ),
            (
                f.private.as_str(),
                "Annotation",
                "comment",
                "specialized target",
            ),
            (
                f.private.as_str(),
                "Document",
                "attachment",
                "specialized target",
            ),
            (f.private.as_str(), "Document", "handoff", " "),
        ] {
            let result = registry()
                .call_engine(
                    EngineHandle::KernelV2(f.db.clone()),
                    Caller::authenticated(&f.owner),
                    "correct_record_type",
                    json!({"record_id":id,"target_type":typ,"target_kind":kind,"reason":reason}),
                )
                .await;
            assert!(result.is_err(), "{result:?}");
            assert_eq!(state, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
        }
    }
    #[tokio::test]
    async fn kernel_v2_direct_type_correction_refuses_registered_account_config() {
        let f = fixture(false).await;
        let registered = registry();
        let call = |tool: &'static str, arguments| {
            registered.call_engine(
                EngineHandle::KernelV2(f.db.clone()),
                Caller::authenticated(&f.owner),
                tool,
                arguments,
            )
        };
        let proposed=call("manage_vocabularies",json!({"action":"propose_value","vocabulary":"kind:Configuration","value":"focus_preferences","metadata":{
            "schema_version":1,"provenance_ref":"rec:private-config-fixture","definition":"A private caller configuration.",
            "identity":{"criterion":"One canonical configuration per caller.","dedup":{"mode":"record_id","keys":[]}},"declared_capabilities":[]
        }})).await.unwrap();
        call(
            "manage_vocabularies",
            json!({"action":"promote_value","value_id":proposed["value_id"]}),
        )
        .await
        .unwrap();
        let shape: Value = serde_json::from_str(include_str!(
            "../tools/account_config/preferences-shape.json"
        ))
        .unwrap();
        call("manage_schema_config",json!({"action":"write","id":"private-config-fixture","data":{"shapes":{"Configuration:focus_preferences":{"facets":{"focus.preferences":shape}}}}})).await.unwrap();
        let config=registry().call_engine(EngineHandle::KernelV2(f.db.clone()),Caller::authenticated(&f.owner),"manage_account_config",json!({"action":"ensure","kind":"focus_preferences","reason":"private mapping fixture"})).await.unwrap();
        let id = config["record_id"]
            .as_str()
            .expect("configuration mapping should be provisioned");
        let state = kernel::dump_all_kernel_tables(&f.db).await.unwrap();
        let result=registry().call_engine(EngineHandle::KernelV2(f.db.clone()),Caller::authenticated(&f.owner),"correct_record_type",json!({"record_id":id,"target_type":"Document","target_kind":"handoff","reason":"registered identity must survive"})).await;
        let error = result.unwrap_err().to_string();
        assert!(error.contains("registered identity"), "{error}");
        assert_eq!(state, kernel::dump_all_kernel_tables(&f.db).await.unwrap());
    }
}
