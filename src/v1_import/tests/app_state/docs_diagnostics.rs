//! Shipping Docs declarations through the installed, consented app-data path.
//! Opt in to larger projection fixtures with NATIVE_DOCS_READ_RECORDS (100..10000)
//! and NATIVE_DOCS_READ_EDITS (0..100). Not a replay or browser latency proof.
use super::*;
use crate::mcp::{kernel_v2::sql, Caller};

fn dimension(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .map(|v| v.parse::<usize>().expect(name))
        .unwrap_or(default)
        .clamp(min, max)
}

#[test]
fn installed_docs_shipping_read_diagnostics() {
    // The installed-source fixture and registry dispatcher build large debug
    // futures. Keep the diagnostic independent of the harness thread's 2 MiB
    // stack, without imposing RUST_MIN_STACK on every test in the binary.
    std::thread::Builder::new()
        .name("installed-docs-diagnostic".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(docs_shipping_read_diagnostic())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn docs_shipping_read_diagnostic() {
    let records = dimension("NATIVE_DOCS_READ_RECORDS", 100, 100, 10000);
    let edits = dimension("NATIVE_DOCS_READ_EDITS", 4, 0, 100);
    let declaration: Value = serde_json::from_str(include_str!(
        "../../../../web/apps/src/apps/docs/declaration.json"
    ))
    .unwrap();
    // V2 buildApp ships this native contract and sends the templates below
    // through app-attributed query_sql (see browser-check-docs-v2.mjs).
    // The source bundle/package is synthetic; install and consent are real.
    let (_f, db, report) = super::declarative_apps::fixture(
        &json!({"contract":"native.app.v2","needs":[],"effects":[]}),
    )
    .await;
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    crate::mcp::kernel_v2::register_kernel_v2_tools(&mut registry).unwrap();
    let a = &report.principals["account-a"];
    let b = &report.principals["account-b"];
    let note = k::read_record_as(&db, a, "note").await.unwrap().unwrap();
    k::replace_home_policy(&db, a, &note.home_id, &[(a, "manage"), (b, "view")])
        .await
        .unwrap();
    let hidden = k::create_home(&db, &note.home_id, Some(&[]), a)
        .await
        .unwrap();
    let mut tx = db.write_pool().begin().await.unwrap();
    // Synthetic serving projections plus header density, without expensive
    // unrelated per-record admissions. Every tenth background record is private.
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('docs-diag:%05d',x),CASE WHEN x%10=0 THEN ?2 ELSE r.home_id END,r.owner_id,r.primary_type,r.kind,printf('docs-diag:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id='note'")
        .bind(records as i64).bind(&hidden).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields SELECT r.id,f.name,f.value_json,r.created_seq FROM kernel_records r CROSS JOIN kernel_record_fields f WHERE r.id LIKE 'docs-diag:%' AND f.record_id='note'")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE kernel_record_fields SET value_json=json_quote(?1) WHERE record_id LIKE 'docs-diag:%' AND name='body'")
        .bind("Synthetic paragraph.\n".repeat(200)).execute(&mut *tx).await.unwrap();
    // Visible root/reply and a private root make multiplexed thread reads
    // nonempty and give the member a concrete disclosure boundary.
    sqlx::query("UPDATE kernel_records SET primary_type='Annotation',kind='comment' WHERE id IN ('docs-diag:00001','docs-diag:00002','docs-diag:00010'); INSERT OR REPLACE INTO kernel_record_fields SELECT id,'v1_type','\"Annotation\"',created_seq FROM kernel_records WHERE id IN ('docs-diag:00001','docs-diag:00002','docs-diag:00010'); INSERT OR REPLACE INTO kernel_record_fields SELECT id,'v1_kind','\"comment\"',created_seq FROM kernel_records WHERE id IN ('docs-diag:00001','docs-diag:00002','docs-diag:00010')")
        .execute(&mut *tx).await.unwrap();
    let carrier = crate::v2_standard::v1_compat::package();
    sqlx::query("UPDATE kernel_records SET primary_type='V1',kind='record',pin_family=?1,pin_version=1,pin_digest=?2,interpreter='native.defn/5' WHERE id IN ('docs-diag:00001','docs-diag:00002','docs-diag:00010')")
        .bind(crate::v2_standard::v1_compat::FAMILY).bind(&carrier.definitions[0].digest).execute(&mut *tx).await.unwrap();
    let selectors = json!([{ "type":"TextQuoteSelector", "exact":"Before" }]).to_string();
    sqlx::query("INSERT INTO kernel_comment_anchors(annotation_id,target_record_id,source_slot,selectors,body_revision,body_revision_source,body_sha256,purpose,created_at,actor,event_seq) SELECT id,CASE WHEN id='docs-diag:00010' THEN 'docs-diag:00020' ELSE 'note' END,'body',?1,created_seq,'v1_source_seq',?2,'commenting',created_at,?3,created_seq FROM kernel_records WHERE id IN ('docs-diag:00001','docs-diag:00010')")
        .bind(&selectors).bind(native_artifact_runtime::mdx::sha256_hex(b"Before")).bind(a).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_generic_links(link_id,source_id,target_id,relationship,created_at,active,event_seq,imported) SELECT 'docs-link:'||id,id,CASE WHEN id='docs-diag:00002' THEN 'docs-diag:00001' WHEN id='docs-diag:00010' THEN 'docs-diag:00020' ELSE 'note' END,'part_of',created_at,1,created_seq,1 FROM kernel_records WHERE id IN ('docs-diag:00001','docs-diag:00002','docs-diag:00010')")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'docs-birth:'||id,id,'kernel.record_created.v1',json_object('home_id',home_id),?1,'2026-11-08T01:00:00Z',1,'legacy_unknown' FROM kernel_records WHERE id LIKE 'docs-diag:%'")
        .bind(a).execute(&mut *tx).await.unwrap();
    if edits > 0 {
        sqlx::query("WITH RECURSIVE n(k) AS (VALUES(1) UNION ALL SELECT k+1 FROM n WHERE k<?1) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'docs-edit:'||r.id||':'||k,r.id,CASE WHEN k%2=0 THEN 'kernel.legacy_recorded.v1' ELSE 'kernel.body_set.v1' END,'{}',?2,'2026-11-08T02:00:00Z',1,'legacy_unknown' FROM n CROSS JOIN kernel_records r WHERE r.id LIKE 'docs-diag:%' OR r.id='note'")
            .bind(edits as i64).bind(a).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.updated','v1:account-a',NULL,NULL,created_at,'content_events' FROM content_events WHERE id LIKE 'docs-edit:%' AND type='kernel.legacy_recorded.v1'; INSERT INTO kernel_legacy_history SELECT seq,'record.updated',json_array(record_id),NULL,0,0,0,2 FROM content_events WHERE id LIKE 'docs-edit:%' AND type='kernel.legacy_recorded.v1'; INSERT INTO kernel_legacy_subjects SELECT record_id,seq FROM content_events WHERE id LIKE 'docs-edit:%' AND type='kernel.legacy_recorded.v1'; INSERT OR REPLACE INTO kernel_legacy_sql_progress VALUES(1,(SELECT coalesce(max(seq),0) FROM content_events WHERE type='kernel.legacy_recorded.v1'),1,1)")
            .execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    k::ensure_record_metadata(&db).await.unwrap();
    let counts: (i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM kernel_records),(SELECT count(*) FROM content_events),(SELECT count(*) FROM kernel_legacy_sql_events)").fetch_one(db.pool()).await.unwrap();
    eprintln!(
        "{}",
        json!({"docs_fixture":{"records":counts.0,"events":counts.1,"legacy_headers":counts.2,"edits_per_record":edits,"debug_assertions":cfg!(debug_assertions),"package":"synthetic agent.notion-pages; shipping Docs declaration"}})
    );
    for (account, generation) in [("account-a", "install"), ("account-b", "install-b")] {
        let caller = Caller::authenticated(account).with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new(
                "agent.notion-pages",
                "999.42.0",
                generation,
            )
            .unwrap(),
        );
        for (key, section) in [
            ("docs.page", ""),
            ("docs.body", ""),
            ("docs.links", "details"),
            ("docs.links", "threads"),
            ("docs.links", "history"),
            ("docs.stamp", ""),
            ("docs.pulse", ""),
            ("docs.recent", ""),
        ] {
            let need = declaration["needs"]
                .as_array()
                .unwrap()
                .iter()
                .find(|need| need["key"] == key)
                .unwrap();
            let parameters: Vec<_> = need["params"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|param| {
                    let value = match param["name"].as_str().unwrap() {
                        "record_id" => "note",
                        "section" => section,
                        other => panic!("unknown shipping parameter {other}"),
                    };
                    json!({"type":"text","value":value})
                })
                .collect();
            let request = json!({"sql":need["sql"],"parameters":parameters});
            let mut expected = None;
            let mut admission_counts = Vec::new();
            // Alternate the oracle order on member reads; no retries or
            // warmed-request cache is hidden from the per-call measurements.
            for full in if account == "account-a" {
                [false, true]
            } else {
                [true, false]
            } {
                let started = std::time::Instant::now();
                let ((answer, admissions), stats) =
                    sql::measured(k::app_installs::with_source_admission_count(async {
                        let work = registry.call_engine(
                            crate::mcp::EngineHandle::KernelV2(db.clone()),
                            caller.clone(),
                            "query_sql",
                            request.clone(),
                        );
                        if full {
                            sql::with_full_union_staging(sql::with_full_record_scope_staging(work))
                                .await
                        } else {
                            work.await
                        }
                    }))
                    .await;
                let elapsed_us = started.elapsed().as_micros();
                let failure = answer.as_ref().err().map(ToString::to_string);
                eprintln!(
                    "{}",
                    json!({"docs_read":{"account":account,"need":key,"section":section,"full_record_oracle":full,"elapsed_us":elapsed_us,"pool_wait_us":stats.pool_wait_us,"sql_admission_us":stats.sql_admission_us,"staging_us":stats.staging_us,"staging_vm_ops":stats.staging_vm_ops,"source_admissions":admissions,"installations":stats.installations,"home_checks":stats.home_checks,"staged_records":stats.staged_records,"staged_metadata_records":stats.staged_metadata_records,"native_event_rows":stats.native_event_rows,"legacy_event_rows":stats.legacy_event_rows,"failure":failure,"retries":0}})
                );
                let answer = answer.unwrap_or_else(|error| {
                    panic!("{account} {key} {section} full={full}: {error}")
                });
                if let Some(prior) = &expected {
                    assert_eq!(prior, &answer, "{account} {key} {section}");
                } else {
                    expected = Some(answer.clone());
                }
                assert!(admissions > 0, "must exercise installed source admission");
                admission_counts.push(admissions);
                if key == "docs.links" && section == "details" {
                    assert!(
                        answer.to_string().contains("TextQuoteSelector"),
                        "anchor missing: {answer}"
                    );
                    if full {
                        assert!(stats.native_event_rows + stats.legacy_event_rows > 0);
                    } else {
                        assert_eq!(
                            stats.native_event_rows + stats.legacy_event_rows,
                            0,
                            "{stats:?}"
                        );
                    }
                }
                if account == "account-b" {
                    assert!(
                        !answer.to_string().contains("docs-diag:00010"),
                        "private record leaked"
                    );
                }
                if key == "docs.links" && section == "threads" {
                    assert!(
                        answer.to_string().contains("docs-diag:00002"),
                        "missing visible reply: {answer}"
                    );
                }
                if key == "docs.body" && !full {
                    assert!(stats.staged_records <= 2, "finite body target: {stats:?}");
                }
            }
            assert_eq!(
                admission_counts[0], admission_counts[1],
                "source admission must not increase"
            );
        }
    }

    for (account, generation) in [("account-a", "install"), ("account-b", "install-b")] {
        let caller = Caller::authenticated(account).with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new(
                "agent.notion-pages",
                "999.42.0",
                generation,
            )
            .unwrap(),
        );
        let started = std::time::Instant::now();
        let ((answer, admissions), stats) = sql::measured(
            k::app_installs::with_source_admission_count(registry.call_engine(
                crate::mcp::EngineHandle::KernelV2(db.clone()),
                caller,
                "get_history",
                json!({"record_id":"note","limit":12,"detail":"metadata","order":"newest_first"}),
            )),
        )
        .await;
        eprintln!(
            "{}",
            json!({"docs_history":{"account":account,"elapsed_us":started.elapsed().as_micros(),"pool_wait_us":null,"sql_admission_us":null,"counter_scope":"SQL staging only; record history has no SQL staging","staging_us":stats.staging_us,"staging_vm_ops":stats.staging_vm_ops,"source_admissions":admissions,"staged_records":stats.staged_records,"native_event_rows":stats.native_event_rows,"legacy_event_rows":stats.legacy_event_rows,"failure":answer.as_ref().err().map(ToString::to_string),"retries":0}})
        );
        assert!(answer.is_ok(), "{account} app history: {answer:?}");
        assert!(admissions > 0);
    }
    let app = || {
        Caller::authenticated("account-b").with_host_asserted_app(
            crate::mcp::app_attribution::AppAttribution::new(
                "agent.notion-pages",
                "999.42.0",
                "install-b",
            )
            .unwrap(),
        )
    };
    let probe = "SELECT id FROM (SELECT id FROM records) d WHERE ?1='details' UNION ALL SELECT id FROM (SELECT id FROM content_events) h WHERE ?1='history' ORDER BY id LIMIT 20";
    // Valid but unrecognized predicates and unknown section values keep broad
    // population. The identical original SQL still determines their results.
    for (statement, value) in [
        (
            probe.replace("?1='details'", "?1=lower('details')"),
            "details",
        ),
        (
            probe.replace("?1='details'", "?1='details' OR 0"),
            "details",
        ),
        (probe.into(), "unknown"),
    ] {
        let request = json!({"sql":statement,"parameters":[{"type":"text","value":value}]});
        let (normal, stats) = sql::measured(registry.call_engine(
            crate::mcp::EngineHandle::KernelV2(db.clone()),
            app(),
            "query_sql",
            request.clone(),
        ))
        .await;
        let broad = sql::with_full_union_staging(registry.call_engine(
            crate::mcp::EngineHandle::KernelV2(db.clone()),
            app(),
            "query_sql",
            request,
        ))
        .await
        .unwrap();
        assert_eq!(normal.unwrap(), broad);
        assert!(
            stats.native_event_rows + stats.legacy_event_rows > 0,
            "fallback: {stats:?}"
        );
    }
    // Ordinary SQL keeps its existing staging and deadline profile.
    let (ordinary, ordinary_stats) = sql::measured(registry.call_engine(
        crate::mcp::EngineHandle::KernelV2(db.clone()),
        Caller::authenticated("account-b"),
        "query_sql",
        json!({"sql":probe,"parameters":[{"type":"text","value":"details"}]}),
    ))
    .await;
    assert!(ordinary.is_ok());
    assert!(ordinary_stats.native_event_rows + ordinary_stats.legacy_event_rows > 0);
    // False arms cannot hide forbidden physical relations or invalid columns.
    for invalid in [
        probe.replace("FROM content_events", "FROM kernel_records"),
        probe.replace(
            "SELECT id FROM content_events",
            "SELECT nonexistent AS id FROM content_events",
        ),
    ] {
        let request = json!({"sql":invalid,"parameters":[{"type":"text","value":"details"}]});
        let (normal, stats) = sql::measured(registry.call_engine(
            crate::mcp::EngineHandle::KernelV2(db.clone()),
            app(),
            "query_sql",
            request.clone(),
        ))
        .await;
        let broad = sql::with_full_union_staging(registry.call_engine(
            crate::mcp::EngineHandle::KernelV2(db.clone()),
            app(),
            "query_sql",
            request,
        ))
        .await
        .unwrap_err();
        assert_eq!(normal.unwrap_err().to_string(), broad.to_string());
        assert_eq!(stats.installations, 0);
    }
    // Source/data View is checked afresh even after repeated admitted reads.
    k::replace_home_policy(&db, a, &note.home_id, &[(a, "manage")])
        .await
        .unwrap();
    let (revoked, stats) = sql::measured(registry.call_engine(
        crate::mcp::EngineHandle::KernelV2(db.clone()),
        app(),
        "query_sql",
        json!({"sql":probe,"parameters":[{"type":"text","value":"details"}]}),
    ))
    .await;
    assert!(revoked.is_err());
    assert_eq!(stats.installations, 0);
    k::replace_home_policy(&db, a, &note.home_id, &[(a, "manage"), (b, "view")])
        .await
        .unwrap();
    assert!(registry
        .call_engine(
            crate::mcp::EngineHandle::KernelV2(db.clone()),
            app(),
            "query_sql",
            json!({"sql":probe,"parameters":[{"type":"text","value":"details"}]})
        )
        .await
        .is_ok());
    // Neither a claim nor a prior successful specialization survives removal.
    k::app_installs::remove_as(&db, b, "agent.notion-pages", "install-b")
        .await
        .unwrap();
    let (removed, stats) = sql::measured(registry.call_engine(
        crate::mcp::EngineHandle::KernelV2(db.clone()),
        app(),
        "query_sql",
        json!({"sql":probe,"parameters":[{"type":"text","value":"details"}]}),
    ))
    .await;
    assert!(removed.is_err());
    assert_eq!(stats.installations, 0);
    db.close().await;
}
