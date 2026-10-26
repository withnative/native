//! This integration target compiles native-ce without cfg(test), including
//! when run without v2-kernel-probe. Do not move this check into lib tests.
use native_ce::{
    events::{CausalEnvelopeV1, EventRow},
    projector,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::Connection;

fn schema_digest() -> String {
    format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &json!([{"name":"id","type":"identifier","nullable":false}])
        ))
    )
}
fn definition_fixture() -> serde_json::Value {
    use native_query_contract::sql_contract as q;
    let profile = q::QuerySqlProfile::SqliteLocal.contract();
    let records = q::LOGICAL_RELATIONS
        .iter()
        .find(|r| r.name == "records")
        .unwrap();
    json!({"query":{"v":"1.2","kind":"governed_sql","profile":{"id":profile.id,"revision":profile.revision},"catalog_revision":q::LOGICAL_CATALOG_REVISION,
        "relations":{"records":{"identity":records.identity,"semantic_version":records.semantic_version}},"sql":"SELECT id FROM records","parameters":[],
        "output":{"columns":[{"name":"id","type":"identifier","nullable":false}],"schema_sha256":schema_digest(),"row_identity":["id"],"order":[{"column":"id","direction":"asc"}]},"bounds":{"rows":100}},
        "origin":{"kind":"authored"},"description":"Visible record identities","scope":{"description":"Caller-visible records","cardinality":"one row per record","default_inclusion":"all caller-visible records"},
        "columns":{"id":{"meaning":"Stable record identity","source_mapping":"records.id","vocabulary":null,"unit":null,"encoding":null}},"source_pins":[]})
}
#[tokio::test]
async fn named_view_events_fold_without_probe() {
    let mut conn = sqlx::SqliteConnection::connect(":memory:").await.unwrap();
    sqlx::query("CREATE TABLE content_events(seq INTEGER PRIMARY KEY,id TEXT UNIQUE,record_id TEXT,type TEXT,payload TEXT,actor TEXT,created_at TEXT)").execute(&mut conn).await.unwrap();
    sqlx::query("CREATE TABLE kernel_record_metadata(record_id TEXT,last_activity_at TEXT,event_seq INTEGER)").execute(&mut conn).await.unwrap();
    sqlx::query("CREATE TABLE kernel_facets(record_id TEXT,key TEXT,value TEXT,as_of TEXT,event_seq INTEGER)").execute(&mut conn).await.unwrap();
    let view = "native.named-view:bearer";
    let def = definition_fixture();
    let digest = format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &json!(["native.named-view-revision.v1", 1, view, def])
        ))
    );
    let revision = uuid::Uuid::new_v4().to_string();
    let binding = uuid::Uuid::new_v4().to_string();
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../src/named_views/fixtures/facet-manifest-v1.json"
    ))
    .unwrap();
    let selector = String::from_utf8(native_artifact_runtime::mdx_v2::canonical_json_bytes(
        &json!({"context":manifest["context"],"selection":manifest["selection"]}),
    ))
    .unwrap();
    let generator = "native.declared-relational-defaults";
    let source_identity = "fixture-task";
    let generated_name = format!(
        "view_gen_{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &json!([
                manifest["workspace_id"],
                generator,
                source_identity,
                selector
            ])
        ))
    );
    let mut generated = definition_fixture();
    generated["origin"] = json!({"kind":"generated","generator":generator,"version":"facet-1","source_identity":source_identity,"selector":selector});
    generated["generated"] = manifest;
    let generated_digest = format!(
        "{:x}",
        Sha256::digest(native_artifact_runtime::mdx_v2::canonical_json_bytes(
            &json!(["native.named-view-revision.v1", 2, view, generated])
        ))
    );
    let generated_revision = uuid::Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO kernel_record_metadata VALUES('bearer', '', 0)")
        .execute(&mut conn)
        .await
        .unwrap();
    let payloads = [
        (
            "kernel.named_view_revision_recorded.v1",
            revision.clone(),
            json!({"v":1,"view_id":view,"definition_sha256":digest,"definition":def}),
        ),
        (
            "kernel.named_view_binding_changed.v1",
            binding.clone(),
            json!({"v":1,"view_id":view,"expected":null,"action":"activate","name":"view_tasks","pin":{"view_id":view,"revision_id":revision,"definition_sha256":digest,"schema_sha256":schema_digest()}}),
        ),
        (
            "kernel.named_view_revision_recorded.v1",
            generated_revision.clone(),
            json!({"v":2,"view_id":view,"definition_sha256":generated_digest,"definition":generated}),
        ),
        (
            "kernel.named_view_binding_changed.v1",
            uuid::Uuid::new_v4().to_string(),
            json!({"v":1,"view_id":view,"expected":binding,"action":"activate","name":generated_name,"pin":{"view_id":view,"revision_id":generated_revision,"definition_sha256":generated_digest,"schema_sha256":schema_digest()}}),
        ),
        (
            "kernel.named_view_admitted.v1",
            uuid::Uuid::new_v4().to_string(),
            json!({"v":1,"name":"view_legacy","definition_sha256":"b".repeat(64),"origin":"authored"}),
        ),
    ];
    for (i, (kind, id, payload)) in payloads.into_iter().enumerate() {
        let e = EventRow {
            local_seq: i as i64 + 1,
            id,
            record_id: "bearer".into(),
            event_type: kind.into(),
            payload: Some(payload.to_string()),
            actor: None,
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: "2026-10-25T00:00:00Z".into(),
            causal_envelope: CausalEnvelopeV1::legacy_unknown(),
            act: None,
        };
        sqlx::query("INSERT INTO content_events VALUES(?,?,?,?,?,?,?)")
            .bind(e.local_seq)
            .bind(&e.id)
            .bind(&e.record_id)
            .bind(&e.event_type)
            .bind(&e.payload)
            .bind(&e.actor)
            .bind(&e.created_at)
            .execute(&mut conn)
            .await
            .unwrap();
        projector::project(&mut conn, &e).await.unwrap();
        if matches!(e.local_seq, 3 | 4) {
            let projected: i64 = sqlx::query_scalar(
                "SELECT event_seq FROM kernel_record_metadata WHERE record_id='bearer'",
            )
            .fetch_one(&mut conn)
            .await
            .unwrap();
            assert_eq!(projected, e.local_seq, "v2 revision and activation project");
        }
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_facets")
        .fetch_one(&mut conn)
        .await
        .unwrap();
    assert_eq!(count, 1);
}
