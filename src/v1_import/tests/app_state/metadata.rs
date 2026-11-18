use super::*;
use crate::mcp::{app_attribution::AppAttribution, Caller, EngineHandle, ToolRegistry};

#[tokio::test]
async fn native_app_query_record_metadata_500_large_bodies() {
    let f = Fixture::new().await;
    let bundle = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Docs list</title></head><body><main>Sample</main><!--{}--></body></html>"#,
        "app bundle ".repeat(38_000)
    );
    native_install_source(&f, &bundle).await;
    let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
        .await
        .unwrap();
    let body = "Large retained document. ".repeat(2800); // 67.2 KB, over 32 MB across 500 rows.
    let ids: Vec<String> = (0..500).map(|i| format!("metadata-{i:03}")).collect();
    for (i, id) in ids.iter().enumerate() {
        sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,lifecycle,summary,created_at,updated_at,archived,policy_anchor_id) SELECT ?,'Document',?,?,?,home_id,owner_id,lifecycle,summary,created_at,updated_at,0,policy_anchor_id FROM records WHERE id='note'")
            .bind(id).bind(if i % 5 == 0 { "artifact" } else { "note" }).bind(format!("Document {i:03}")).bind(&body).execute(&mut source).await.unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','original-creator','2026-01-01T00:00:00Z')")
            .bind(format!("created:{id}")).bind(id).execute(&mut source).await.unwrap();
        if i % 5 == 0 {
            let facet_seq: i64 = sqlx::query_scalar("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'facet.set',?,'original-creator','2026-01-01T00:00:00Z') RETURNING seq")
                .bind(format!("runtime:{id}")).bind(id).bind(json!({"key":"runtime","value":"native.mdx.v2"}).to_string()).fetch_one(&mut source).await.unwrap();
            sqlx::query("INSERT INTO facet_values VALUES(?,'runtime','native.mdx.v2',NULL,NULL,'2026-01-01T00:00:00Z')").bind(id).execute(&mut source).await.unwrap();
            sqlx::query(
                "INSERT INTO facet_observations VALUES(?,'runtime','2026-01-01T00:00:00Z',?)",
            )
            .bind(id)
            .bind(facet_seq)
            .execute(&mut source)
            .await
            .unwrap();
        }
    }
    source.close().await.unwrap();
    let mut seeds: Vec<&str> = ids.iter().map(String::as_str).collect();
    seeds.extend(["secret", "note"]);
    let report = run(f.options(&seeds, false)).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert!(
        report.review.is_empty(),
        "{}",
        serde_json::to_string(&report.review).unwrap()
    );
    let db = f.db().await;
    app_roster(&db, "account-a", &["account-a", "account-b"]).await;
    let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    k::app_installs::activate_as(&db, &host, app_activation_proof(&db).await)
        .await
        .unwrap();
    let mut registry = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let caller = || {
        Caller::authenticated("account-a")
            .with_host_asserted_app(AppAttribution::new("agent.docs", "0.8.2", "install").unwrap())
    };
    // The extended SQL path caps bound parameters at 256, so list by type
    // and fixture name rather than expanding 500 ids into SQL parameters.
    for (query_index, mut query) in [
        json!({"steps":[{"step":"filter","types":["Document"],"kinds":["note","artifact"],"name_contains":"Document "}],"order":"updated_desc","limit":500}),
        json!({"steps":[{"step":"filter","types":["Document"],"kinds":["artifact"],"facets":[{"key":"runtime","in":["native.mdx.v1","native.mdx.v2"]}]}],"order":"name_asc","limit":200}),
        json!({"steps":[{"step":"filter","types":["Document"],"kinds":["note","artifact"],"name_contains":"Document "}],"order":"last_activity_desc","limit":11,"offset":9}),
        json!({"steps":[{"step":"filter","ids":&ids[..30]}],"limit":13,"offset":7}),
    ]
    .into_iter()
    .enumerate()
    {
        let full = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller(),
                "query_record",
                query.clone(),
            )
            .await
            .unwrap();
        assert_eq!(full["returned"], [500, 100, 11, 13][query_index]);
        if query_index == 1 {
            assert_eq!(full["total"], 100);
        }
        query["projection"] = json!("metadata");
        let metadata = registry
            .call_engine(
                EngineHandle::KernelV2(db.clone()),
                caller(),
                "query_record",
                query,
            )
            .await
            .unwrap();
        for key in ["shape", "total", "returned", "offset", "has_more"] {
            assert_eq!(metadata[key], full[key], "{key}");
        }
        let mut expected = full.clone();
        crate::mcp::tools::querying::project_record_metadata(&mut expected);
        assert_eq!(metadata["records"], expected["records"]);
        assert!(metadata["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r.get("body").is_none()
                && r.get("body_digest").is_none()
                && r.get("fields").is_none()));
        if full["returned"] == 500 {
            assert_eq!(full["total"], 500);
            let returned_ids: BTreeSet<_> = full["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|record| record["id"].as_str().unwrap())
                .collect();
            assert_eq!(returned_ids, ids.iter().map(String::as_str).collect());
            let full_bytes = serde_json::to_vec(&full).unwrap().len();
            let metadata_bytes = serde_json::to_vec(&metadata).unwrap().len();
            eprintln!("500 app-attributed rows: full={full_bytes} metadata={metadata_bytes} bytes");
            assert!(full_bytes > 32_000_000);
            assert!(metadata_bytes < 512_000);
            assert!(metadata_bytes * 50 < full_bytes);
        }
    }
    // Exercise the actual pinned request cache in both orders: a metadata
    // view must not poison a full read, nor borrow a cached body's bytes.
    let mut conn = db.pool().begin().await.unwrap();
    let actor = &report.principals["account-a"];
    k::read_cache::scope_request(k::read_cache::with_capabilities(async {
        let key = k::read_cache::key_on(&mut conn, actor, "metadata-cache-proof")
            .await
            .unwrap();
        assert!(
            key.is_some(),
            "file-backed fixture must exercise real memoization"
        );
        let connection = k::read_cache::connection_id(&mut conn);
        k::read_cache::in_pinned_snapshot(key, connection, async {
            let metadata = k::read_record_metadata_on(&mut conn, actor, &ids[0])
                .await
                .unwrap()
                .unwrap();
            assert!(metadata.body.is_none());
            assert!(!metadata.fields.contains_key("body"));
            let full = k::read_record_on(&mut conn, actor, &ids[0])
                .await
                .unwrap()
                .unwrap();
            assert_eq!(full.body.as_deref(), Some(body.as_str()));
            let metadata = k::read_record_metadata_on(&mut conn, actor, &ids[0])
                .await
                .unwrap()
                .unwrap();
            assert!(metadata.body.is_none());
            assert!(!metadata.fields.contains_key("body"));
            let cached_full = k::read_record_on(&mut conn, actor, &ids[0])
                .await
                .unwrap()
                .unwrap();
            assert_eq!(cached_full.body.as_deref(), Some(body.as_str()));
        })
        .await;
    }))
    .await;
    conn.rollback().await.unwrap();
    db.close().await;
}
