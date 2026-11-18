//! Direct kernel vocabulary commands. The registry advertises each action we execute.
use super::*;
use crate::authorization::Capability;
use crate::kernel::schema_catalogue;

pub(super) fn register(registry: &mut ToolRegistry) -> Result<()> {
    let original = registry
        .get("manage_vocabularies")
        .ok_or_else(|| Error::engine("missing vocabulary tool descriptor"))?
        .input_schema
        .clone();
    registry.extend_kernel_v2_arguments("manage_vocabularies",json!({"if_schema_state_revision":{"type":"string","description":"Optional opaque schema revision returned by a previous vocabulary mutation; a mismatch appends nothing."}}))?;
    registry.isolate_kernel_v2_schema("manage_vocabularies", original)?;
    registry.register_engine_handler_for_selector_values(
        "manage_vocabularies",
        EngineKind::KernelV2,
        "action",
        &[
            "list_values",
            "create_vocabulary",
            "propose_value",
            "promote_value",
            "alias_value",
            "deprecate_value",
            "reorder_value",
            "set_gloss",
            "set_metadata",
            "delete_value",
            "delete_vocabulary",
        ],
        |engine, caller, mut args| async move {
            let EngineHandle::KernelV2(db) = engine else {
                unreachable!()
            };
            let actor = principal(&db, &caller).await?;
            if args["action"] == "list_values" {
                let value = metadata_reads::list_values(&db, &actor, args).await?;
                if let Some(app) = caller.host_asserted_app() {
                    kernel::app_installs::admit_account_app_as(&db, caller.credential(), app)
                        .await?;
                }
                return Ok(value);
            }
            let object = args
                .as_object_mut()
                .ok_or_else(|| Error::engine("manage_vocabularies arguments must be an object"))?;
            let expected = object
                .remove("if_schema_state_revision")
                .filter(|v| !v.is_null())
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| Error::engine("if_schema_state_revision must be a string"))
                })
                .transpose()?;
            let mutation: schema_catalogue::Mutation = parse("manage_vocabularies", args)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let actor = principal_on(&mut tx, &caller).await?;
            let owner = caller.counter_footing().is_owner()
                || (caller.hosting_database().is_none()
                    && !caller.is_member_copy()
                    && kernel::kernel_effective_capability_on(
                        &mut tx,
                        &actor,
                        crate::events::KERNEL_ROOT_ID,
                    )
                    .await?
                    .allows(Capability::Manage));
            if !owner {
                return Err(Error::auth(
                    "manage_vocabularies: database owner host role required",
                ));
            }
            let mut acts = crate::act::ActAllocation::new();
            let mut result = schema_catalogue::mutate_in(
                &db,
                &mut tx,
                &actor,
                mutation,
                expected.as_deref(),
                &mut acts,
            )
            .await?;
            result["schema_state_revision"] = json!(schema_catalogue::revision_on(&mut tx).await?);
            db.commit_kernel_content(tx).await?;
            Ok(result)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn call(db: &Db, credential: &str, args: Value) -> Result<Value> {
        super::super::tests::registry()
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                Caller::authenticated(credential),
                "manage_vocabularies",
                args,
            )
            .await
    }
    async fn setup() -> (tempfile::TempDir, Db, String) {
        let dir = tempfile::tempdir().unwrap();
        let (db, owner) = kernel::create_v2_database(
            dir.path().join("schema.db").to_str().unwrap(),
            "account",
            "Owner",
            "owner:vocab",
        )
        .await
        .unwrap();
        (dir, db, owner)
    }

    #[tokio::test]
    async fn vocabulary_lifecycle_is_direct_atomic_and_replayable() {
        let (_dir, db, _owner) = setup().await;
        // The v2 definition registry owns a baseline meta_events log. Native
        // vocabulary mutations must leave it byte-for-byte unchanged.
        let meta_before: Vec<String> = sqlx::query_scalar(
            "SELECT json_array(seq,id,subject_id,type,payload,actor,created_at,act) FROM meta_events ORDER BY seq",
        ).fetch_all(db.pool()).await.unwrap();
        let create = call(
            &db,
            "owner:vocab",
            json!({"action":"create_vocabulary","name":"local-status"}),
        )
        .await
        .unwrap();
        assert_eq!(create["vocabulary_id"], "voc:local-status");
        let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"create_vocabulary","name":"local-status"}),
        )
        .await
        .unwrap();
        let head_after: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(head, head_after, "identical retry appends nothing");
        let first = call(&db,"owner:vocab",json!({"action":"propose_value","vocabulary":"local-status","value":"queued","gloss":"Awaiting work"})).await.unwrap();
        let second = call(
            &db,
            "owner:vocab",
            json!({"action":"propose_value","vocabulary":"local-status","value":"ready"}),
        )
        .await
        .unwrap();
        let a = &first["value_id"];
        let b = &second["value_id"];
        call(
            &db,
            "owner:vocab",
            json!({"action":"promote_value","value_id":b}),
        )
        .await
        .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"reorder_value","value_id":a,"ordinal":2.5}),
        )
        .await
        .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"set_gloss","value_id":a,"gloss":null}),
        )
        .await
        .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"alias_value","value_id":a,"canonical_id":b}),
        )
        .await
        .unwrap();
        assert!(call(
            &db,
            "owner:vocab",
            json!({"action":"alias_value","value_id":b,"canonical_id":a})
        )
        .await
        .is_err());
        assert!(call(
            &db,
            "owner:vocab",
            json!({"action":"delete_value","value_id":b})
        )
        .await
        .is_err());
        let read = json!({"action":"list_values","vocabulary":"rec:voc:local-status"});
        let before = call(&db, "owner:vocab", read.clone()).await.unwrap();
        assert_eq!(before["values"][0]["status"], "active");
        assert_eq!(before["values"][1]["canonical"]["value"], "ready");
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, call(&db, "owner:vocab", read).await.unwrap());
        call(
            &db,
            "owner:vocab",
            json!({"action":"deprecate_value","value_id":b}),
        )
        .await
        .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"delete_value","value_id":a}),
        )
        .await
        .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"delete_value","value_id":b}),
        )
        .await
        .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"delete_vocabulary","vocabulary":"local-status"}),
        )
        .await
        .unwrap();
        let frozen: Vec<String> = sqlx::query_scalar("SELECT name FROM sqlite_schema WHERE type='table' AND name IN ('vocabularies','vocabulary_values','schema_config','meta_events') ORDER BY name").fetch_all(db.pool()).await.unwrap();
        assert_eq!(
            frozen,
            vec!["meta_events".to_owned()],
            "v2 retains only its registry log, never the frozen v1 metadata projections"
        );
        let meta_after: Vec<String> = sqlx::query_scalar(
            "SELECT json_array(seq,id,subject_id,type,payload,actor,created_at,act) FROM meta_events ORDER BY seq",
        ).fetch_all(db.pool()).await.unwrap();
        assert_eq!(
            meta_before, meta_after,
            "native vocabulary writes never mutate the registry log"
        );
    }

    #[tokio::test]
    async fn vocabulary_owner_revision_and_validation_fail_without_effects() {
        let (_dir, db, owner) = setup().await;
        let registry = super::super::tests::registry();
        let descriptor = registry.get("manage_vocabularies").unwrap();
        assert!(descriptor.input_schema["properties"]
            .get("if_schema_state_revision")
            .is_none());
        assert_eq!(
            descriptor.input_schema_for_engine(EngineKind::KernelV2)["properties"]
                ["if_schema_state_revision"]["type"],
            "string"
        );
        kernel::create_principal(&db, "account", "Member", "member:vocab", &owner)
            .await
            .unwrap();
        let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        for (actor, args) in [
            (
                "member:vocab",
                json!({"action":"create_vocabulary","name":"forbidden"}),
            ),
            (
                "owner:vocab",
                json!({"action":"create_vocabulary","name":"stale","if_schema_state_revision":"schema-state-v1:meta:0:content:0"}),
            ),
            (
                "owner:vocab",
                json!({"action":"create_vocabulary","name":"extra","unexpected":true}),
            ),
        ] {
            assert!(call(&db, actor, args).await.is_err());
        }
        assert_eq!(
            head,
            sqlx::query_scalar::<_, i64>("SELECT max(seq) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap()
        );
        call(
            &db,
            "owner:vocab",
            json!({"action":"create_vocabulary","name":"kind:WorkItem"}),
        )
        .await
        .unwrap();
        assert!(call(
            &db,
            "owner:vocab",
            json!({"action":"propose_value","vocabulary":"kind:WorkItem","value":"bad-metadata"})
        )
        .await
        .is_err());
        assert!(call(
            &db,
            "owner:vocab",
            json!({"action":"delete_vocabulary","vocabulary":"kind:WorkItem"})
        )
        .await
        .is_err());
    }
    #[tokio::test]
    async fn imported_vocabulary_identity_and_kind_metadata_survive_native_edit_and_replay() {
        let (_dir, db, _owner) = setup().await;
        let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        let row = kernel::v1_state::ImportedState {
            section:"vocabularies".into(),source_id:"[\"voc:kind:WorkItem\"]".into(),origin:"source:v1".into(),
            value_json:Some(json!({"id":"voc:kind:WorkItem","name":"kind:WorkItem","created_at":"2026-01-01T00:00:00Z"}).to_string()),
            account_principal:None,record_id:None,observed_at:"2026-01-01T00:00:00Z".into(),snapshot:json!({}),
        };
        kernel::v1_state::import_state_batch_as(&db, &host, std::slice::from_ref(&row))
            .await
            .unwrap();
        let mut metadata = crate::meta::kind::core_kind_manifest()
            .unwrap()
            .kinds
            .into_iter()
            .find(|k| k.record_type == "WorkItem")
            .unwrap()
            .metadata;
        let proposed = call(&db,"owner:vocab",json!({"action":"propose_value","vocabulary":"kind:WorkItem","value":"local-task","metadata":metadata})).await.unwrap();
        let id = proposed["value_id"].clone();
        metadata.definition = "A locally maintained task kind".into();
        call(
            &db,
            "owner:vocab",
            json!({"action":"set_metadata","value_id":id,"metadata":metadata}),
        )
        .await
        .unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"promote_value","value_id":id}),
        )
        .await
        .unwrap();
        // Native editing closes source reconciliation: a stale importer cannot
        // replace edited catalogue state with its old source snapshot.
        assert!(kernel::v1_state::import_state_batch_as(&db, &host, &[row])
            .await
            .is_err());
        let read = json!({"action":"list_values","vocabulary":"kind:WorkItem"});
        let before = call(&db, "owner:vocab", read.clone()).await.unwrap();
        assert_eq!(
            before["values"][0]["metadata"]["definition"],
            metadata.definition
        );
        let identities: Vec<(String, String)> = sqlx::query_as(
            "SELECT source_id,origin FROM kernel_v1_state WHERE section='vocabularies'",
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert_eq!(
            identities,
            vec![("[\"voc:kind:WorkItem\"]".into(), "source:v1".into())]
        );
        kernel::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, call(&db, "owner:vocab", read).await.unwrap());
        let mut tx = db.pool().begin().await.unwrap();
        let interpreter = kernel::v1_state::interpreter_on(&mut tx, &_owner)
            .await
            .unwrap();
        assert_eq!(
            interpreter.canonical_imported_kind("WorkItem", "local-task"),
            "local-task"
        );
    }
    #[tokio::test]
    async fn vocabulary_deletion_preserves_imported_schema_references_and_facet_assignments() {
        let (_dir, db, owner) = setup().await;
        let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
        kernel::v1_state::import_state_batch_as(&db,&host,&[kernel::v1_state::ImportedState {
            section:"schema_config".into(),source_id:"schema-reference".into(),origin:"source:v1".into(),
            value_json:Some(json!({"id":"sc:references","layer":"pack","pack_name":"local","data":json!({"shapes":{"Document":{"facets":{"workflow":{"vocab_ref":"rec:local-status"}}}}}).to_string(),"applies_to_collection_id":null,"created_at":"2026-01-01T00:00:00Z"}).to_string()),
            account_principal:None,record_id:None,observed_at:"2026-01-01T00:00:00Z".into(),snapshot:json!({}),
        }]).await.unwrap();
        call(
            &db,
            "owner:vocab",
            json!({"action":"create_vocabulary","name":"local-status"}),
        )
        .await
        .unwrap();
        assert!(call(
            &db,
            "owner:vocab",
            json!({"action":"delete_vocabulary","vocabulary":"local-status"})
        )
        .await
        .is_err());
        call(
            &db,
            "owner:vocab",
            json!({"action":"create_vocabulary","name":"assignment-status"}),
        )
        .await
        .unwrap();
        let value = call(
            &db,
            "owner:vocab",
            json!({"action":"propose_value","vocabulary":"assignment-status","value":"live"}),
        )
        .await
        .unwrap();
        let definition = json!({"family":"fixture.catalogue","version":1,"interpreter":"native.defn/2","primary_type":"Document","kinds":[{"token":"note","description":"Catalogue reference fixture","maturity":"current","identity":{"field":"title"},"fields":[{"name":"title","type":"text","required":true}],"links":[]}]});
        let pin = kernel::install_definition_as(
            &db,
            &owner,
            "fixture.catalogue",
            1,
            &serde_json::to_vec(&definition).unwrap(),
        )
        .await
        .unwrap();
        kernel::adopt_definition_as(&db, &owner, &pin.family, Some(&pin))
            .await
            .unwrap();
        let record = kernel::create_as(
            &db,
            &owner,
            "fixture.catalogue",
            "note",
            json!({"title":"Reference"}).as_object().unwrap(),
            crate::events::KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        kernel::hq::observe_facet_as(
            &db,
            &owner,
            &record,
            &kernel::hq::FacetObservation {
                key: "workflow".into(),
                value: Some("live".into()),
                value_num: None,
                vocab_ref: Some("rec:voc:assignment-status".into()),
                as_of: "2026-01-01T00:00:00Z".into(),
            },
            None,
        )
        .await
        .unwrap();
        assert!(call(
            &db,
            "owner:vocab",
            json!({"action":"delete_value","value_id":value["value_id"]})
        )
        .await
        .is_err());
        assert!(call(
            &db,
            "owner:vocab",
            json!({"action":"delete_vocabulary","vocabulary":"assignment-status"})
        )
        .await
        .is_err());
    }
}
