//! Assumed mixes, not measured HQ proportions. Projection generation follows
//! legacy_history::{project_at,project_sql_header}; fixture setup is unmeasured.
use super::super::super::sql;
use super::*;

pub(super) async fn prepare_carrier(w: &World) -> String {
    install_comment_carrier(w).await;
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let host: String =
        sqlx::query_scalar("SELECT principal_id FROM kernel_principals WHERE auth_binding=?")
            .bind(kernel::hq::HOST_IMPORT_BINDING)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    kernel::create_principal(&w.db, "account", "Undisclosed", "acct:foreign", &w.admin)
        .await
        .unwrap();
    let mut carrier = String::new();
    for (principal, binding) in [(&w.admin, "acct:admin"), (&w.viewer, "acct:viewer")] {
        let person = kernel::create_json_as(
            &w.db,
            &w.admin,
            "native.v1.record",
            "record",
            &json!({"v1_type":"Entity","v1_kind":"person","title":binding}).to_string(),
            &home,
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO kernel_message_people VALUES(?,?)")
            .bind(&person)
            .bind(principal)
            .execute(w.db.write_pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?1,?2,'kernel.import_state.v1','{}',?3,1,'legacy_unknown')")
            .bind(format!("bench-directory:{binding}")).bind(&person).bind(&host).execute(w.db.write_pool()).await.unwrap();
        sqlx::query("INSERT INTO kernel_v1_state SELECT 'account_directory',?1,'bench','{}',?2,?3,created_at,seq FROM content_events WHERE id=?4")
            .bind(binding).bind(principal).bind(&person).bind(format!("bench-directory:{binding}")).execute(w.db.write_pool()).await.unwrap();
        carrier = person;
    }
    carrier
}

pub(super) async fn mixed_events(
    w: &World,
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    carrier: &str,
    percent: u32,
    record_count: u32,
) {
    // Three quarters of records use the actual reserved V1 compatibility pin.
    // The first 100 hot records are Messages with real MessageState JSON.
    sqlx::query("UPDATE kernel_records AS r SET (primary_type,kind,pin_family,pin_version,pin_digest,interpreter)=(SELECT primary_type,kind,pin_family,pin_version,pin_digest,interpreter FROM kernel_records WHERE id=?1) WHERE r.id GLOB 'hq:*' AND (CAST(substr(r.id,4) AS INTEGER)%4!=0 OR CAST(substr(r.id,4) AS INTEGER)<=100)")
        .bind(carrier).execute(&mut **tx).await.unwrap();
    sqlx::query("DELETE FROM kernel_record_fields WHERE name='body' AND record_id IN (SELECT id FROM kernel_records WHERE id GLOB 'hq:*' AND pin_family='native.v1.record')")
        .execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields SELECT r.id,'v1_type',json_quote(CASE WHEN CAST(substr(r.id,4) AS INTEGER)<=100 THEN 'Message' ELSE 'WorkItem' END),r.created_seq FROM kernel_records r WHERE r.id GLOB 'hq:*' AND r.pin_family='native.v1.record' UNION ALL SELECT r.id,'v1_kind',json_quote(CASE WHEN CAST(substr(r.id,4) AS INTEGER)<=100 THEN 'message' ELSE 'task' END),r.created_seq FROM kernel_records r WHERE r.id GLOB 'hq:*' AND r.pin_family='native.v1.record'")
        .execute(&mut **tx).await.unwrap();
    let state = kernel::messaging::MessageState {
        author: Some(w.admin.clone()),
        ..Default::default()
    };
    let state_json = serde_json::to_string(&state).unwrap();
    sqlx::query("INSERT INTO kernel_messages SELECT id,?1,created_seq FROM kernel_records WHERE id GLOB 'hq:*' AND CAST(substr(id,4) AS INTEGER)<=100")
        .bind(&state_json).execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status,created_at) SELECT 'bench-message-birth:'||id,id,'kernel.message_created.v1',?1,?2,1,'legacy_unknown',created_at FROM kernel_records WHERE id GLOB 'hq:*' AND CAST(substr(id,4) AS INTEGER)<=100")
        .bind(&state_json).bind(&w.admin).execute(&mut **tx).await.unwrap();
    // Event ordinals are interleaved across records; the mix is independent of
    // event class, actor and disclosure flags. All 308k source rows are retained.
    sqlx::query("CREATE TEMP TABLE bench_seed AS SELECT row_number() OVER(ORDER BY n.x,r.id) AS event_no,r.id AS record_id,r.created_at,n.x AS ordinal FROM kernel_records r CROSS JOIN bench_events n WHERE (r.id GLOB 'hq:*' AND (n.x<=4 OR CAST(substr(r.id,4) AS INTEGER)<=100)) OR (r.id GLOB 'private:*' AND n.x<=4)")
        .execute(&mut **tx).await.unwrap();
    let foreign: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding='acct:foreign'",
    )
    .fetch_one(&mut **tx)
    .await
    .unwrap();
    sqlx::query(&format!("CREATE TEMP TABLE bench_source AS SELECT *,event_no%100<?1 AS imported,(event_no/100)%100 AS class,CASE event_no%3 WHEN 0 THEN ?2 WHEN 1 THEN ?3 ELSE ?4 END AS actor,CASE event_no%3 WHEN 0 THEN 'acct:viewer' WHEN 1 THEN 'acct:admin' ELSE 'acct:foreign' END AS binding,printf('hq:%05d',(CAST(substr(record_id,4) AS INTEGER)%{record_count})+1) AS neighbor,CASE WHEN event_no%100=0 THEN hex(zeroblob(8192)) ELSE hex(zeroblob(512)) END AS body FROM bench_seed"))
        .bind(percent as i64).bind(&w.viewer).bind(&w.admin).bind(&foreign).execute(&mut **tx).await.unwrap();
    sqlx::query(&format!("INSERT INTO kernel_generic_links SELECT 'bench-link:'||r.id,r.id,printf('hq:%05d',(CAST(substr(r.id,4) AS INTEGER)%{record_count})+1),'related_to',NULL,r.created_at,?1,1,r.created_seq,0 FROM kernel_records r WHERE r.id GLOB 'hq:*'"))
        .bind(&w.admin).execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_provider_subjects SELECT record_id,record_id FROM bench_source WHERE NOT imported AND class BETWEEN 10 AND 14 GROUP BY record_id UNION SELECT CASE WHEN CAST(substr(record_id,4) AS INTEGER)%29=0 THEN 'private:00001' ELSE neighbor END,record_id FROM bench_source WHERE NOT imported AND class BETWEEN 10 AND 14 GROUP BY record_id")
        .execute(&mut **tx).await.unwrap();
    // Imported rows precede post-cutover native writes in local sequence.
    // Imported envelopes retain ordinary body payloads and complete source
    // metadata. Header/subject projections below deliberately avoid importing
    // 278k rows through per-event Rust admission in fixture setup.
    sqlx::query(r#"INSERT INTO content_events(id,record_id,type,payload,actor,run_key,parent_key,causal_envelope_version,causal_status,created_at)
      SELECT 'hq-event:'||event_no,record_id,
       CASE WHEN imported THEN 'kernel.legacy_recorded.v1' WHEN class<5 THEN 'kernel.link_added.v1' WHEN class<10 THEN 'kernel.generic_link_added.v1' WHEN class<15 THEN 'kernel.provider_outcome.v1' WHEN class<20 AND CAST(substr(record_id,4) AS INTEGER)<=100 THEN 'kernel.message_state.v1' ELSE 'kernel.record_revised.v1' END,
       CASE WHEN imported THEN json_object('legacy',json_object('id','v1-event:'||event_no,'event_type',CASE WHEN class<10 THEN 'link.added' WHEN class<15 THEN 'receipt.committed.v1' ELSE 'record.updated' END,'created_at',created_at,'actor',binding,'run_key',printf('bench-run:%d',event_no%31),'payload',json_patch(json_object('body',body,'record_id',record_id,'source_id',record_id,'target_id',CASE WHEN class<10 THEN neighbor END),json_object('claimed_run_key',CASE WHEN event_no%13=0 THEN 'bench-claimed-run' END)),'source',json_object('stream','content_events','subjects',CASE WHEN event_no%101=0 THEN json_array(record_id,'private:00001') WHEN class<10 THEN json_array(record_id,neighbor) ELSE json_array(record_id) END,'hidden_acknowledgement',json(CASE WHEN event_no%211=0 THEN 'true' ELSE 'false' END),'metadata',json_object('record_id',record_id,'parent_key','bench-parent'),'row_sha256',hex(zeroblob(32)))))
       WHEN class BETWEEN 15 AND 19 AND CAST(substr(record_id,4) AS INTEGER)<=100 THEN json_set(?1,'$.reactions',json(CASE WHEN ordinal%2=0 THEN json_object(actor,json_array('thumbsup')) ELSE '{}' END))
       ELSE json_object('fields',json_object('body',body),'target_id',CASE WHEN event_no%101=0 THEN 'private:00001' ELSE neighbor END,'link_id','bench-link:'||record_id,'subjects',json_array(record_id,neighbor)) END,
       actor,printf('bench-run:%d',event_no%31),'bench-parent',1,'legacy_unknown',created_at FROM bench_source ORDER BY imported DESC,event_no"#)
        .bind(&state_json).execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT e.seq,json_extract(e.payload,'$.legacy.id'),e.record_id,json_extract(e.payload,'$.legacy.event_type'),'v1:'||json_extract(e.payload,'$.legacy.actor'),json_extract(e.payload,'$.legacy.run_key'),'bench-parent',e.created_at,'content_events' FROM content_events e WHERE e.id GLOB 'hq-event:*' AND e.type='kernel.legacy_recorded.v1'")
        .execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_history SELECT e.seq,m.event_type,(SELECT json_group_array(value) FROM (SELECT DISTINCT value FROM json_each(json_extract(e.payload,'$.legacy.source.subjects')) UNION SELECT json_extract(e.payload,'$.legacy.payload.target_id') WHERE json_extract(e.payload,'$.legacy.payload.target_id') IS NOT NULL ORDER BY value)),NULL,CAST(substr(e.id,10) AS INTEGER)%211=0,0,CAST(substr(e.id,10) AS INTEGER)%13=0,2 FROM content_events e JOIN kernel_legacy_sql_events m ON m.seq=e.seq WHERE e.id GLOB 'hq-event:*'")
        .execute(&mut **tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_sql_progress SELECT 1,max(seq),1,1 FROM content_events WHERE type='kernel.legacy_recorded.v1' ON CONFLICT(singleton) DO UPDATE SET scanned_seq=excluded.scanned_seq,gap_free=1,provenance_headers=1")
        .execute(&mut **tx).await.unwrap();
    sqlx::query("DROP TABLE bench_seed; DROP TABLE bench_source")
        .execute(&mut **tx)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "HQ mixed retained/native event phase and copy-floor benchmark"]
async fn kernel_v2_sql_hq_event_profile_bench() {
    for percent in [90, 50] {
        let w = hq_world(Some(percent)).await;
        let args = json!({"sql":"SELECT r.type, count(e.local_seq) FROM records r JOIN content_events e ON e.record_id = r.id GROUP BY r.type"});
        let started = std::time::Instant::now();
        let (result, stats) = sql::measured(call(&w, "query_sql", args)).await;
        eprintln!(
            "HQ_MIX_MCP {}",
            json!({"imported_percent":percent,"wall_ms":started.elapsed().as_secs_f64()*1000.0,"outcome":match result {Ok(v)=>v,Err(e)=>json!({"error":e.to_string()})},"stats":stats})
        );
        let baseline =
            sql::event_equivalence::slice_a_scope(sql::event_profile::run(&w.db, &w.viewer)).await;
        eprintln!(
            "HQ_SLICE_B_BEFORE {}",
            json!({"imported_percent":percent,"profile":baseline})
        );
        w.db.settle_sql_event_projection().await;
        kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        let mut reset = w.db.write_pool().begin().await.unwrap();
        sqlx::query(
            "DROP TABLE kernel_sql_event_projection; DROP TABLE kernel_sql_event_subject_sets",
        )
        .execute(&mut *reset)
        .await
        .unwrap();
        reset.commit().await.unwrap();
        let cold = std::time::Instant::now();
        let fold = kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        eprintln!(
            "HQ_SLICE_B_FOLD {}",
            json!({"imported_percent":percent,"cold_rebuild_ms":cold.elapsed().as_secs_f64()*1000.0,"fold":fold})
        );
        let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        for (label, frontier) in [("head", head), ("tail_1000", head - 1000)] {
            projection_frontier(&w, frontier).await;
            let profiled = sql::event_profile::run(&w.db, &w.viewer).await;
            eprintln!(
                "HQ_SLICE_B_AFTER {}",
                json!({"imported_percent":percent,"frontier":label,"profile":profiled})
            );
        }
        if percent == 90 {
            let positions = oracle_positions(&w).await;
            for count in [1, 50] {
                let head = install_oracle_mode(&w, &positions[..count]).await;
                let control = sql::event_equivalence::slice_a_scope(sql::event_profile::run(
                    &w.db, &w.viewer,
                ))
                .await;
                eprintln!(
                    "HQ_SLICE_B_ORACLE_CONTROL {}",
                    json!({"oracle_count":count,"profile":control})
                );
                for (label, frontier) in [("head", head), ("tail_1000", head - 1000)] {
                    assert_eq!(count as i64,sqlx::query_scalar::<_,i64>("SELECT count(*) FROM kernel_sql_event_projection WHERE selector='oracle-only' AND seq<=?").bind(frontier).fetch_one(w.db.pool()).await.unwrap());
                    projection_frontier(&w, frontier).await;
                    let profile = sql::event_profile::run(&w.db, &w.viewer).await;
                    eprintln!(
                        "HQ_SLICE_B_ORACLE {}",
                        json!({"oracle_count":count,"frontier":label,"profile":profile})
                    );
                }
            }
        }
        w.db.close().await;
    }
}

#[tokio::test]
#[ignore = "HQ-scale full staged-relation equivalence against frozen e586c99cf"]
async fn kernel_v2_sql_event_slice_a_equivalence() {
    for percent in [90, 50] {
        let w = hq_world(Some(percent)).await;
        slice_a_edge_cases(&w).await;
        slice_a_window_cases(&w).await;
        let restricted =
            kernel::create_principal(&w.db, "account", "Restricted", "acct:restricted", &w.admin)
                .await
                .unwrap();
        let homes:Vec<String>=sqlx::query_scalar("SELECT DISTINCT home_id FROM kernel_records WHERE id IN ('hq:00001','hq:00002','hq:00003','hq:00004')")
            .fetch_all(w.db.pool()).await.unwrap();
        assert_eq!(homes.len(), 4);
        let common_home: String =
            sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
                .bind(&w.first)
                .fetch_one(w.db.pool())
                .await
                .unwrap();
        for home in homes.iter().chain(std::iter::once(&common_home)) {
            kernel::replace_home_policy(
                &w.db,
                &w.admin,
                home,
                &[(&w.viewer, "view"), (&restricted, "view")],
            )
            .await
            .unwrap();
        }
        for (label, actor) in [
            ("owner", &w.admin),
            ("viewer", &w.viewer),
            ("restricted", &restricted),
        ] {
            let digests = sql::event_equivalence::compare(&w.db, actor).await;
            if label == "restricted" {
                assert!(digests["records"]["rows"].as_u64().unwrap() < 11713);
                assert!(digests["records"]["rows"].as_u64().unwrap() > 4000);
            }
            eprintln!(
                "HQ_SLICE_A_EQ {}",
                json!({"imported_percent":percent,"caller":label,"relations":digests,"baseline":"e586c99cf"})
            );
        }
        // Reuse the same HQ fixture and oracle, now with four distinct caller
        // regimes and the prefix/tail boundaries used by Slice B.
        let owner =
            kernel::create_principal(&w.db, "account", "Header owner", "acct:owner", &w.admin)
                .await
                .unwrap();
        let owner_homes:Vec<String>=sqlx::query_scalar("SELECT DISTINCT home_id FROM kernel_records WHERE id GLOB 'hq:*' UNION SELECT home_id FROM kernel_records WHERE id=?").bind(&w.first).fetch_all(w.db.pool()).await.unwrap();
        for home in owner_homes {
            let mut entries = vec![(&*w.viewer, "view"), (&*owner, "view")];
            if homes.contains(&home) || home == common_home {
                entries.push((&*restricted, "view"));
            }
            kernel::replace_home_policy(&w.db, &w.admin, &home, &entries)
                .await
                .unwrap();
        }
        sqlx::query("UPDATE kernel_legacy_history SET owner='acct:owner' WHERE seq=(SELECT seq FROM content_events WHERE id='slice-a:window-a:00')").execute(w.db.write_pool()).await.unwrap();
        let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        let reaction: i64 =
            sqlx::query_scalar("SELECT seq FROM content_events WHERE id='slice-a:reaction-mixed'")
                .fetch_one(w.db.pool())
                .await
                .unwrap();
        for frontier in [0, head / 2, reaction - 1, head] {
            projection_frontier(&w, frontier).await;
            for (label, actor) in [
                ("owner", &owner),
                ("viewer", &w.viewer),
                ("restricted", &restricted),
                ("admin", &w.admin),
            ] {
                let digests = sql::event_equivalence::compare_projection(&w.db, actor).await;
                eprintln!(
                    "HQ_SLICE_B_EQ {}",
                    json!({"imported_percent":percent,"frontier":frontier,"caller":label,"relations":digests})
                );
            }
        }
        if percent == 90 {
            let positions = oracle_positions(&w).await;
            for count in [1, 50] {
                let head = install_oracle_mode(&w, &positions[..count]).await;
                for frontier in [head, head - 1000] {
                    projection_frontier(&w, frontier).await;
                    for (label, actor) in [
                        ("owner", &owner),
                        ("viewer", &w.viewer),
                        ("restricted", &restricted),
                        ("admin", &w.admin),
                    ] {
                        let digests =
                            sql::event_equivalence::compare_projection(&w.db, actor).await;
                        eprintln!(
                            "HQ_SLICE_B_ORACLE_EQ {}",
                            json!({"imported_percent":percent,"oracle_count":count,"frontier":frontier,"caller":label,"relations":digests})
                        );
                    }
                }
            }
        }
        w.db.close().await;
    }
}

// Invalid UTF-8 timestamps cause SQLx header decoding to fail while the
// permanent public view still applies SQLite strftime and returns NULL. These
// are genuine, successful oracle-only reads, spanning retained/native families.
async fn oracle_positions(w: &World) -> Vec<(i64, String)> {
    w.db.settle_sql_event_projection().await;
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let positions: Vec<(i64,String)> = sqlx::query_as("SELECT seq,origin FROM (SELECT seq,origin,selector,row_number() OVER(PARTITION BY origin,selector ORDER BY seq) AS n FROM kernel_sql_event_projection WHERE origin IN ('native','legacy') AND selector NOT IN ('invalid-subjects','reaction')) ORDER BY n,origin,selector LIMIT 50").fetch_all(w.db.pool()).await.unwrap();
    assert_eq!(50, positions.len());
    positions
}

async fn install_oracle_mode(w: &World, positions: &[(i64, String)]) -> i64 {
    w.db.settle_sql_event_projection().await;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    for (seq, origin) in positions {
        let id = format!("slice-b:oracle:{seq}");
        // Exercise decode fallback through real append-only source rows. The
        // 50-row mode reuses the first marker and appends the remaining 49.
        let inserted=sqlx::query("INSERT OR IGNORE INTO content_events(id,record_id,type,payload,actor,run_key,parent_key,created_at,causal_envelope_version,causal_status) SELECT ?,record_id,type,payload,actor,run_key,parent_key,x'80',causal_envelope_version,causal_status FROM content_events WHERE seq=?").bind(&id).bind(seq).execute(&mut *tx).await.unwrap().rows_affected();
        if inserted > 0 && origin == "legacy" {
            sqlx::query("INSERT INTO kernel_legacy_sql_events(seq,source_id,record_id,event_type,actor,run_key,parent_key,created_at,source_stream) SELECT e.seq,?1,m.record_id,m.event_type,m.actor,m.run_key,m.parent_key,x'80',m.source_stream FROM kernel_legacy_sql_events m JOIN content_events e ON e.id=?1 WHERE m.seq=?2").bind(&id).bind(seq).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO kernel_legacy_history(seq,event_type,subjects,owner,hidden,restricted,claim_sensitive,disclosure_version) SELECT e.seq,h.event_type,h.subjects,h.owner,h.hidden,h.restricted,h.claim_sensitive,h.disclosure_version FROM kernel_legacy_history h JOIN content_events e ON e.id=?1 WHERE h.seq=?2").bind(&id).bind(seq).execute(&mut *tx).await.unwrap();
        }
    }
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1')").execute(&mut *tx).await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000) INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) SELECT 'slice-b:oracle-tail:'||?1||':'||x,?2,'kernel.record_revised.v1','{}',?3,1,'legacy_unknown' FROM n").bind(positions.len() as i64).bind(&w.first).bind(&w.admin).execute(&mut *tx).await.unwrap();
    kernel::sql_event_projection::reset_on(&mut tx, 0)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    assert_eq!(
        positions.len() as i64,
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM kernel_sql_event_projection WHERE selector='oracle-only'"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap()
    );
    sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_sparse_oracle_candidates() {
    let w = small_world(90).await;
    slice_a_edge_cases(&w).await;
    slice_a_window_cases(&w).await;
    let callers = projection_callers(&w).await;
    let positions = oracle_positions(&w).await;
    for count in [1, 50] {
        let head = install_oracle_mode(&w, &positions[..count]).await;
        for frontier in [head, head - 1000] {
            assert_eq!(count as i64,sqlx::query_scalar::<_,i64>("SELECT count(*) FROM kernel_sql_event_projection WHERE selector='oracle-only' AND seq<=?").bind(frontier).fetch_one(w.db.pool()).await.unwrap());
            projection_frontier(&w, frontier).await;
            for actor in &callers {
                sql::event_equivalence::compare_projection(&w.db, actor).await;
            }
        }
    }
    w.db.close().await;
}

// Small, explicit semantic witnesses supplement the scale distribution.
async fn slice_a_edge_cases(w: &World) {
    let mut comments = Vec::new();
    for target in [&w.first, &w.hidden] {
        call_as(
            w,
            "acct:admin",
            "update_record",
            json!({"id":target,"body_set":"alpha brave revised passage"}),
        )
        .await
        .unwrap();
        let comment = call_as(
            w,
            "acct:admin",
            "create_record",
            json!({
                "type":"Annotation","kind":"comment","body":"Slice A anchor witness",
                "links":[{"target_id":target,"relationship":"part_of"}],
                "target":anchored_target(target,"revised",12,19)
            }),
        )
        .await
        .unwrap();
        comments.push(comment["id"].as_str().unwrap().to_owned());
    }
    let mut tx = w.db.write_pool().begin().await.unwrap();
    for (id, binding, subjects, sensitive) in [
        ("slice-a:claim-admin", "acct:admin", json!([w.first]), true),
        (
            "slice-a:claim-viewer",
            "acct:viewer",
            json!([w.first]),
            true,
        ),
        (
            "slice-a:comment-visible",
            "acct:admin",
            json!([w.first, comments[0]]),
            false,
        ),
        (
            "slice-a:comment-hidden",
            "acct:admin",
            json!([w.first, comments[1]]),
            false,
        ),
    ] {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?1,?2,'kernel.legacy_recorded.v1','{}',?3,1,'legacy_unknown')")
            .bind(id).bind(&w.first).bind(&w.admin).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.updated','v1:'||?2,'slice-run','slice-parent',created_at,'content_events' FROM content_events WHERE id=?1")
            .bind(id).bind(binding).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_history SELECT seq,'record.updated',?2,NULL,0,0,?3,2 FROM content_events WHERE id=?1")
            .bind(id).bind(subjects.to_string()).bind(sensitive).execute(&mut *tx).await.unwrap();
    }
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(&w.first)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    for (label, anchor) in [
        ("home", home.as_str()),
        ("native-root", "native:root"),
        ("kernel-root", KERNEL_ROOT_ID),
        ("hidden-record", w.hidden.as_str()),
        ("visible-other", w.second.as_str()),
    ] {
        let id = format!("slice-b:outer-anchor:{label}");
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?1,?2,'kernel.legacy_recorded.v1','{}',?3,1,'legacy_unknown')").bind(&id).bind(anchor).bind(&w.admin).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_sql_events(seq,source_id,record_id,event_type,actor,run_key,parent_key,created_at,source_stream) SELECT seq,?2,?3,'record.updated','v1:acct:admin','anchor-run','anchor-parent',created_at,'content_events' FROM content_events WHERE id=?1").bind(&id).bind(format!("source:{id}")).bind(&w.first).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_history(seq,event_type,subjects,owner,hidden,restricted,claim_sensitive,disclosure_version) SELECT seq,'record.updated',?2,NULL,0,0,0,2 FROM content_events WHERE id=?1").bind(&id).bind(json!([w.second,w.first]).to_string()).execute(&mut *tx).await.unwrap();
    }
    let subjects: i64 =
        sqlx::query_scalar("SELECT count(*) FROM kernel_provider_subjects WHERE aggregate_id=?")
            .bind(&w.first)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    assert_eq!(subjects, 0);
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-a:provider-empty',?1,'kernel.provider_outcome.v1','{}',?2,1,'legacy_unknown')")
        .bind(&w.first).bind(&w.admin).execute(&mut *tx).await.unwrap();
    for (id, emoji) in [
        ("slice-a:reaction-before", "old"),
        ("slice-a:reaction-mixed", "new"),
    ] {
        let state = kernel::messaging::MessageState {
            author: Some(w.admin.clone()),
            ..Default::default()
        };
        let payload = json!({"reactions":{w.admin.clone():[emoji]}});
        let state = kernel::messaging::MessageState {
            reactions: serde_json::from_value(payload["reactions"].clone()).unwrap(),
            ..state
        };
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?1,'hq:00001','kernel.message_state.v1',?2,?3,1,'legacy_unknown')")
            .bind(id).bind(serde_json::to_string(&state).unwrap()).bind(&w.admin).execute(&mut *tx).await.unwrap();
    }
    let literals = regex::Regex::new(r"'(kernel\.[A-Za-z0-9_.%*]+)'").unwrap();
    let mut event_types: std::collections::BTreeSet<String> = literals
        .captures_iter(include_str!("sql.rs"))
        .map(|c| c[1].replace(['%', '*'], "selection_witness"))
        .collect();
    event_types.extend(
        crate::mcp::kernel_v2::IMPORTED_EVENTS
            .iter()
            .map(|s| (*s).to_owned()),
    );
    event_types.extend(
        crate::mcp::kernel_v2::LOGICAL_EVENT_TYPES
            .iter()
            .map(|(s, _)| (*s).to_owned()),
    );
    let link: String = sqlx::query_scalar(
        "SELECT link_id FROM kernel_generic_links WHERE source_id='hq:00001' LIMIT 1",
    )
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    for (n, event_type) in event_types
        .into_iter()
        .filter(|t| t != "kernel.legacy_recorded.v1")
        .enumerate()
    {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')").bind(format!("slice-b:selection:{n}")).bind(&w.first).bind(event_type).bind(json!({"target_id":w.second,"link_id":link}).to_string()).bind(&w.admin).execute(&mut *tx).await.unwrap();
    }
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1'),gap_free=1,provenance_headers=1").execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

// Share the mixed projection generator with HQ, but keep ordinary CI tiny.
async fn small_world(percent: u32) -> World {
    let w = world().await;
    let carrier = prepare_carrier(&w).await;
    let mut homes = Vec::new();
    for _ in 0..9 {
        homes.push(
            kernel::create_home(
                &w.db,
                KERNEL_ROOT_ID,
                Some(&[(&w.viewer, "view")]),
                &w.admin,
            )
            .await
            .unwrap(),
        );
    }
    let mut tx = w.db.write_pool().begin().await.unwrap();
    for n in 1..=12 {
        sqlx::query("INSERT INTO kernel_records SELECT printf('hq:%05d',?1),?2,owner_id,primary_type,kind,printf('small:%d',?1),pin_family,pin_version,pin_digest,interpreter,created_seq,created_at FROM kernel_records WHERE id=?3")
            .bind(n).bind(&homes[(n as usize-1)%9]).bind(&w.first).execute(&mut *tx).await.unwrap();
    }
    sqlx::query("INSERT INTO kernel_record_fields SELECT r.id,f.name,f.value_json,r.created_seq FROM kernel_records r CROSS JOIN kernel_record_fields f WHERE r.id GLOB 'hq:*' AND f.record_id=?").bind(&w.first).execute(&mut *tx).await.unwrap();
    sqlx::query("CREATE TEMP TABLE bench_events AS WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<24) SELECT x FROM n").execute(&mut *tx).await.unwrap();
    mixed_events(&w, &mut tx, &carrier, percent, 12).await;
    sqlx::query("DROP TABLE bench_events")
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    kernel::ensure_record_metadata(&w.db).await.unwrap();
    w
}

#[tokio::test]
async fn kernel_v2_sql_event_staging_equivalence_default() {
    for percent in [90, 50] {
        let w = small_world(percent).await;
        slice_a_edge_cases(&w).await;
        slice_a_window_cases(&w).await;
        let restricted =
            kernel::create_principal(&w.db, "account", "Restricted", "acct:restricted", &w.admin)
                .await
                .unwrap();
        let homes:Vec<String>=sqlx::query_scalar("SELECT DISTINCT home_id FROM kernel_records WHERE id IN ('hq:00001','hq:00002','hq:00003','hq:00004') UNION SELECT home_id FROM kernel_records WHERE id=?").bind(&w.first).fetch_all(w.db.pool()).await.unwrap();
        for home in homes {
            kernel::replace_home_policy(
                &w.db,
                &w.admin,
                &home,
                &[(&w.viewer, "view"), (&restricted, "view")],
            )
            .await
            .unwrap();
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        assert!(
            count < 500,
            "default guard must stay fixture-sized: {count}"
        );
        let mut viewer_rows = 0;
        for actor in [&w.admin, &w.viewer, &restricted] {
            let result = sql::event_equivalence::compare(&w.db, actor).await;
            let records = result["records"]["rows"].as_u64().unwrap();
            if actor == &w.viewer {
                viewer_rows = records;
            }
            if actor == &restricted {
                assert!(
                    records < viewer_rows,
                    "restricted fixture must exclude some homes"
                );
            }
        }
        // The synthetic fence witness remains in the source. Exercise the
        // certified projection path as well as the staged/history/scan paths;
        // the comparison helper independently rejects public private-event rows.
        kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        for actor in [&w.admin, &w.viewer, &restricted] {
            sql::event_equivalence::compare_projection(&w.db, actor).await;
        }
        w.db.close().await;
    }
}

#[tokio::test]
async fn kernel_v2_sql_bound_event_demands_preserve_retained_headers() {
    let w = small_world(50).await;
    slice_a_edge_cases(&w).await;
    for projected in [false, true] {
        if projected {
            kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        }
        for actor in [&w.admin, &w.viewer] {
            for subject in ["hq:00001", "hq:00002", "missing"] {
                let args = json!({"sql":"SELECT * FROM content_events e WHERE e.record_id=?1 ORDER BY e.local_seq","parameters":[{"type":"text","value":subject}]});
                let expected =
                    sql::with_full_event_staging(sql::query_sql(&w.db, actor, args.clone()))
                        .await
                        .unwrap();
                let actual = sql::with_bound_query_read_session(
                    &w.db,
                    actor,
                    std::slice::from_ref(&args),
                    sql::query_sql(&w.db, actor, args.clone()),
                )
                .await
                .unwrap();
                assert_eq!(
                    actual["rows"], expected["rows"],
                    "{subject} projected={projected}"
                );
                assert_eq!(actual["columns"], expected["columns"]);
            }
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_correlated_event_counts_preserve_full_staging_results() {
    let w = small_world(90).await;
    slice_a_edge_cases(&w).await;
    // A retained logical header may name a different carrier than its source
    // event. Demand must preserve it, not assume those identities coincide.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('count-carrier',?,'kernel.legacy_recorded.v1','{}',?,1,'legacy_unknown')")
        .bind(&w.first).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,'hq:00001','record.updated',NULL,NULL,NULL,created_at,'content_events' FROM content_events WHERE id='count-carrier'")
        .execute(w.db.write_pool()).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_history SELECT seq,'record.updated','[\"hq:00001\"]',NULL,0,0,0,2 FROM content_events WHERE id='count-carrier'")
        .execute(w.db.write_pool()).await.unwrap();
    // These fixture headers are projected explicitly above, as in the shared
    // edge fixtures. Advance their matching readiness frontier too.
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1'),gap_free=1,provenance_headers=1").execute(w.db.write_pool()).await.unwrap();
    for actor in [&w.admin, &w.viewer] {
        for selection in [
            format!("r.id IN ('{}','hq:00001','{}')", w.first, w.hidden),
            "r.id IN (SELECT id FROM shared_records ORDER BY id LIMIT 5)".into(),
            // Mirrors Prism's bounded latest-by-kind union. The cloned hq
            // Messages share created_at; use their fixture kind to make the
            // latest selection nonempty and require an id tiebreaker.
            "r.id IN (SELECT id FROM (SELECT t.id FROM shared_records t WHERE t.deleted_at IS NULL AND t.kind='message' ORDER BY t.created_at DESC,t.id LIMIT 5) UNION ALL SELECT id FROM (SELECT p.id FROM shared_records p WHERE p.kind='epic' ORDER BY p.created_at DESC,p.id LIMIT 2))".into(),
        ] {
            let statement=format!("WITH shared_records AS MATERIALIZED (SELECT id,type,kind,name,created_at,deleted_at FROM records) SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) AS events FROM shared_records r WHERE {selection} ORDER BY r.id");
            let evaluate = || async {
                sql::with_query_read_session(&w.db, actor, &[&statement], async {
                    let counts = sql::in_snapshot(&w.db, actor, |conn| Box::pin(async move {
                        let scoped:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE name='_v2_event_subjects')").fetch_one(&mut *conn).await?;
                        let unique:bool=sqlx::query_scalar("SELECT count(*)=count(DISTINCT id) FROM temp.records").fetch_one(&mut *conn).await?;
                        assert!(unique, "record identity must be unique before demand selection");
                        let positions:i64=sqlx::query_scalar("SELECT count(*) FROM temp._v2_event_ids").fetch_one(conn).await?;
                        Ok((scoped,positions))
                    })).await?;
                    let result=sql::query_sql(&w.db,actor,json!({"sql":statement})).await?;
                    Ok((result,counts))
                }).await.unwrap()
            };
            let (full, (full_scoped, full_positions)) =
                sql::with_full_event_staging(evaluate()).await;
            let (narrowed, (scoped, positions)) = evaluate().await;
            assert_eq!(full, narrowed);
            if actor == &w.admin {
                assert!(full["row_count"].as_u64().unwrap() > 0, "equivalence must exercise returned rows");
            }
            assert!(!full_scoped);
            assert!(scoped);
            assert!(
                positions < full_positions,
                "narrowing must remove unrelated history"
            );
        }
    }
    for statement in [
        "SELECT r.id,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) AS events FROM records r WHERE r.id IN (SELECT message_id FROM my_message_state) ORDER BY r.id",
        "SELECT r.id,r.type,r.kind,r.deleted_at,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) AS events FROM records r WHERE r.id IN (SELECT id FROM blobs) ORDER BY r.id",
        "SELECT r.id AS rid,(SELECT count(*) FROM content_events e WHERE e.record_id=r.id) AS events FROM records r WHERE rid='hq:00001' ORDER BY r.id",
    ] {
        let evaluate = || async {
            sql::with_query_read_session(&w.db, &w.admin, &[statement], async {
                let scoped = sql::in_snapshot(&w.db, &w.admin, |conn| Box::pin(async move {
                    Ok(sqlx::query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM sqlite_temp_master WHERE name='_v2_event_subjects')").fetch_one(conn).await?)
                })).await?;
                assert!(!scoped, "fallback must not leave subject state");
                sql::query_sql(&w.db, &w.admin, json!({"sql":statement})).await
            }).await.unwrap()
        };
        assert_eq!(sql::with_full_event_staging(evaluate()).await, evaluate().await);
    }
    w.db.close().await;
}

async fn slice_a_window_cases(w: &World) {
    let mut tx = w.db.write_pool().begin().await.unwrap();
    // Two consecutive sixteen-position windows; subject visibility and raw
    // subject-set texts differ, exercising clearing/rebuilding both caches.
    for (batch, record, subjects, other_text) in [
        (
            "a",
            w.first.as_str(),
            json!([w.first, w.second, w.first]),
            json!([w.second, w.first]),
        ),
        (
            "b",
            "hq:00002",
            json!(["hq:00002", "hq:00003", "hq:00002"]),
            json!(["hq:00003", "hq:00002"]),
        ),
    ] {
        for n in 0..16 {
            let id = format!("slice-a:window-{batch}:{n:02}");
            let owner = [
                "acct:viewer",
                "acct:foreign",
                "acct:restricted",
                "acct:admin",
            ][n % 4];
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?1,?2,'kernel.legacy_recorded.v1','{}',?3,1,'legacy_unknown')").bind(&id).bind(record).bind(&w.admin).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.updated','v1:acct:admin','window-run','window-parent',created_at,'content_events' FROM content_events WHERE id=?").bind(&id).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO kernel_legacy_history SELECT seq,'record.updated',?2,?3,0,1,0,2 FROM content_events WHERE id=?1").bind(&id).bind(if n%2==0 {subjects.to_string()} else {other_text.to_string()}).bind(owner).execute(&mut *tx).await.unwrap();
        }
    }
    // Each caller's newest authored header is hidden, forcing scan's older
    // authored-position staging pass to find the admitted predecessor.
    for binding in ["acct:admin", "acct:viewer", "acct:restricted"] {
        for hidden in [false, true] {
            let id = format!("slice-a:scan:{binding}:{hidden}");
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?1,'hq:00004','kernel.legacy_recorded.v1','{}',?2,1,'legacy_unknown')").bind(&id).bind(&w.admin).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.updated','v1:'||?2,NULL,NULL,created_at,'content_events' FROM content_events WHERE id=?1").bind(&id).bind(binding).execute(&mut *tx).await.unwrap();
            sqlx::query("INSERT INTO kernel_legacy_history SELECT seq,'record.updated',?2,NULL,?3,0,0,2 FROM content_events WHERE id=?1").bind(&id).bind(if hidden {json!([w.first])} else {json!(["hq:00004"])}.to_string()).bind(hidden).execute(&mut *tx).await.unwrap();
        }
    }
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-a:generic-mismatch',?1,'kernel.generic_link_added.v1','{\"link_id\":\"bench-link:hq:00001\"}',?2,1,'legacy_unknown')").bind(&w.hidden).bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1'),gap_free=1,provenance_headers=1").execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
}

async fn projection_frontier(w: &World, frontier: i64) {
    w.db.settle_sql_event_projection().await;
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    kernel::sql_event_projection::reset_on(&mut tx, frontier + 1)
        .await
        .unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT generation FROM kernel_sql_event_projection_state")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.commit().await.unwrap();
    w.db.trust_sql_event_projection_generation(generation);
}

async fn projection_callers(w: &World) -> Vec<String> {
    let restricted =
        kernel::create_principal(&w.db, "account", "Restricted", "acct:restricted", &w.admin)
            .await
            .unwrap();
    let owner = kernel::create_principal(&w.db, "account", "Header owner", "acct:owner", &w.admin)
        .await
        .unwrap();
    let homes: Vec<String> = sqlx::query_scalar("SELECT DISTINCT home_id FROM kernel_records WHERE id GLOB 'hq:*' UNION SELECT home_id FROM kernel_records WHERE id=?").bind(&w.first).fetch_all(w.db.pool()).await.unwrap();
    for home in homes {
        let included: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE home_id=? AND id IN ('hq:00001','hq:00002','hq:00003','hq:00004',?))").bind(&home).bind(&w.first).fetch_one(w.db.pool()).await.unwrap();
        let mut entries = vec![(&*w.viewer, "view"), (&*owner, "view")];
        if included {
            entries.push((&*restricted, "view"));
        }
        kernel::replace_home_policy(&w.db, &w.admin, &home, &entries)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE kernel_legacy_history SET owner='acct:owner' WHERE seq=(SELECT seq FROM content_events WHERE id='slice-a:window-a:00')").execute(w.db.write_pool()).await.unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    kernel::sql_event_projection::reset_on(&mut tx, 0)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    vec![owner, w.viewer.clone(), restricted, w.admin.clone()]
}

async fn projection_reaction_cases(w: &World) {
    let mut tx = w.db.write_pool().begin().await.unwrap();
    // A retained Message with no earlier state: its first reaction state has
    // no predecessor, and an identical next state must synthesize no event.
    sqlx::query("INSERT INTO kernel_messages VALUES(?,'{}',1)")
        .bind(&w.second)
        .execute(&mut *tx)
        .await
        .unwrap();
    for (id, reactions) in [
        ("slice-b:reaction-first", json!({w.admin.clone():["a"]})),
        ("slice-b:reaction-noop", json!({w.admin.clone():["a"]})),
        ("slice-b:reaction-removed", json!({})),
    ] {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?1,?2,'kernel.message_state.v1',?3,?4,1,'legacy_unknown')")
            .bind(id).bind(&w.second).bind(json!({"reactions":reactions}).to_string()).bind(&w.admin).execute(&mut *tx).await.unwrap();
    }
    for (n, timestamp) in [
        "bad timestamp",
        "2026-11-09T00:00:00.9999+02:30",
        "2451545",
        "9999-12-31T23:59:59.9999Z",
    ]
    .into_iter()
    .enumerate()
    {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?1,?2,'kernel.record_revised.v1','{}',?3,?4,1,'legacy_unknown')").bind(format!("slice-b:timestamp:{n}")).bind(&w.first).bind(&w.admin).bind(timestamp).execute(&mut *tx).await.unwrap();
    }
    // SQLite applies the TEXT endpoint/identity affinity to JSON numbers too.
    sqlx::query("INSERT INTO kernel_records SELECT '123',home_id,owner_id,primary_type,kind,'slice-b:123',pin_family,pin_version,pin_digest,interpreter,created_seq,created_at FROM kernel_records WHERE id=?").bind(&w.first).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields SELECT '123',name,value_json,created_seq FROM kernel_record_fields WHERE record_id=?").bind(&w.first).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_generic_links SELECT '123',?1,?2,'related_to',NULL,created_at,?3,1,created_seq,0 FROM kernel_records WHERE id=?1").bind(&w.first).bind(&w.second).bind(&w.admin).execute(&mut *tx).await.unwrap();
    for (id, record, kind, payload) in [
        (
            "slice-b:number-target",
            &w.first,
            "kernel.link_added.v1",
            json!({"target_id":123}),
        ),
        (
            "slice-b:number-link",
            &w.hidden,
            "kernel.generic_link_added.v1",
            json!({"link_id":123}),
        ),
    ] {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,1,'legacy_unknown')").bind(id).bind(record).bind(kind).bind(payload.to_string()).bind(&w.admin).execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_equivalence_default() {
    for percent in [90, 50] {
        let w = small_world(percent).await;
        slice_a_edge_cases(&w).await;
        slice_a_window_cases(&w).await;
        projection_reaction_cases(&w).await;
        let mut tx = w.db.write_pool().begin().await.unwrap();
        let legacy = json!({"id":"slice-b:rescan","event_type":"record.updated","payload":{},"created_at":"2026-11-09T00:00:00Z","actor":"acct:admin","run_key":null,"source":{"stream":"content_events","subjects":[w.first],"metadata":{"record_id":w.first}}});
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-b:rescan',?1,'kernel.legacy_recorded.v1',?2,?3,1,'legacy_unknown')").bind(&w.first).bind(json!({"legacy":legacy}).to_string()).bind(&w.admin).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.updated','v1:acct:admin',NULL,NULL,'2026-11-09T00:00:00Z','content_events' FROM content_events WHERE id='slice-b:rescan'").execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_history SELECT seq,'record.updated',?1,NULL,0,0,0,2 FROM content_events WHERE id='slice-b:rescan'").bind(json!([w.first]).to_string()).execute(&mut *tx).await.unwrap();
        sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1')").execute(&mut *tx).await.unwrap();
        tx.commit().await.unwrap();
        let callers = projection_callers(&w).await;
        let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        let reaction: i64 =
            sqlx::query_scalar("SELECT seq FROM content_events WHERE id='slice-a:reaction-mixed'")
                .fetch_one(w.db.pool())
                .await
                .unwrap();
        for frontier in [0, head / 2, reaction - 1, head] {
            projection_frontier(&w, frontier).await;
            for actor in &callers {
                sql::event_equivalence::compare_projection(&w.db, actor).await;
            }
        }
        // No-op/rescan filling retained SQL headers at an older position must
        // invalidate the cache even when the canonical event head is unchanged.
        let mut tx = w.db.write_pool().begin().await.unwrap();
        let prior:i64=sqlx::query_scalar("SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1' AND id!='slice-b:rescan'").fetch_one(&mut *tx).await.unwrap();
        sqlx::query("DELETE FROM kernel_legacy_sql_events WHERE source_id='slice-b:rescan'")
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=?")
            .bind(prior)
            .execute(&mut *tx)
            .await
            .unwrap();
        kernel::legacy_history::ensure_schema(&mut tx)
            .await
            .unwrap();
        let frontier: i64 =
            sqlx::query_scalar("SELECT frontier_seq FROM kernel_sql_event_projection_state")
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(frontier, 0);
        tx.commit().await.unwrap();
        for actor in &callers {
            sql::event_equivalence::compare_projection(&w.db, actor).await;
        }
        kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        for actor in &callers {
            sql::event_equivalence::compare_projection(&w.db, actor).await;
        }
        for table in kernel::sql_event_projection::TABLES {
            assert!(
                call(
                    &w,
                    "query_sql",
                    json!({"sql":format!("SELECT * FROM {table}")})
                )
                .await
                .is_err(),
                "cache must remain outside caller allowlist: {table}"
            );
        }
        w.db.close().await;
    }
}

/// Creating the visible-set cache's access epoch (a serving handle's first
/// write) is not a source-schema change for Slice B: its projection
/// generation and frontier survive it, so no cache reset or cold rebuild.
#[tokio::test]
async fn kernel_v2_sql_event_projection_survives_access_epoch_creation() {
    let w = small_world(90).await;
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    projection_frontier(&w, head).await;
    let generation = w.db.sql_event_projection_generation();
    let frontier_before = {
        let mut conn = w.db.pool().acquire().await.unwrap();
        kernel::sql_event_projection::frontier_on(&mut conn, generation)
            .await
            .unwrap()
    };
    assert!(
        frontier_before.is_some(),
        "fixture projection must be valid"
    );
    let mut tx = w.db.write_pool().begin().await.unwrap();
    kernel::access_fence::ensure_epoch_on(&mut tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(w.db.sql_event_projection_generation(), generation);
    let frontier_after = {
        let mut conn = w.db.pool().acquire().await.unwrap();
        kernel::sql_event_projection::frontier_on(&mut conn, generation)
            .await
            .unwrap()
    };
    assert_eq!(
        frontier_after, frontier_before,
        "epoch creation must not reset Slice B"
    );
    w.db.close().await;
}

/// The visible-set cache (#3268) under Slice B's event projection (#3234):
/// for every caller and projection frontier, the staged-relation digest with
/// the cache on equals the uncached digest.
#[tokio::test]
async fn kernel_v2_sql_event_projection_equivalent_with_visible_cache() {
    let w = small_world(90).await;
    slice_a_edge_cases(&w).await;
    slice_a_window_cases(&w).await;
    projection_reaction_cases(&w).await;
    let callers = projection_callers(&w).await;
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    for frontier in [0, head / 2, head] {
        projection_frontier(&w, frontier).await;
        for actor in &callers {
            sql::event_equivalence::compare_cached(&w.db, actor).await;
        }
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_reset_fences_and_inventory() {
    let w = small_world(90).await;
    slice_a_edge_cases(&w).await;
    slice_a_window_cases(&w).await;
    let callers = projection_callers(&w).await;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    kernel::facet_time_reads::prepare_on(&mut tx).await.unwrap();
    tx.commit().await.unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let digest = kernel::projection_dump::dump_on(&mut tx).await.unwrap();
    let generation = crate::standby::kernel_v2::coordinates(&mut tx)
        .await
        .unwrap();
    let old: i64 = sqlx::query_scalar("SELECT generation FROM kernel_sql_event_projection_state")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    kernel::sql_event_projection::reset_on(&mut tx, 0)
        .await
        .unwrap();
    assert!(
        !kernel::sql_event_projection::batch_on(&mut tx, old, 100)
            .await
            .unwrap(),
        "old worker must not publish after reset"
    );
    assert_eq!(
        digest,
        kernel::projection_dump::dump_on(&mut tx).await.unwrap()
    );
    assert_eq!(
        generation,
        crate::standby::kernel_v2::coordinates(&mut tx)
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    // A version mismatch falls back without a read-side write, then a writer
    // resets/rebuilds with a strictly newer generation.
    sqlx::query("UPDATE kernel_sql_event_projection_state SET projector_version=0")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert_eq!(
        kernel::sql_event_projection::frontier_on(
            &mut conn,
            w.db.sql_event_projection_generation()
        )
        .await
        .unwrap(),
        None
    );
    drop(conn);
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let new: i64 = sqlx::query_scalar("SELECT generation FROM kernel_sql_event_projection_state")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert!(new > old + 1);
    sqlx::query("CREATE INDEX slice_b_schema_change ON content_events(id,seq)")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert_eq!(
        kernel::sql_event_projection::frontier_on(
            &mut conn,
            w.db.sql_event_projection_generation()
        )
        .await
        .unwrap(),
        None
    );
    drop(conn);
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    sqlx::query("DROP TABLE kernel_sql_event_subject_sets")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert_eq!(
        kernel::sql_event_projection::frontier_on(
            &mut conn,
            w.db.sql_event_projection_generation()
        )
        .await
        .unwrap(),
        None
    );
    drop(conn);
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert!(kernel::sql_event_projection::frontier_on(
        &mut conn,
        w.db.sql_event_projection_generation()
    )
    .await
    .unwrap()
    .is_some());
    drop(conn);
    sqlx::query("DROP INDEX slice_b_schema_change")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    // A reopen verifies canonical headers before reuse; only mismatches reset.
    // Every caller must agree both while verification is pending and after it.
    for (number,tamper) in [
        "UPDATE kernel_sql_event_projection_state SET projector_version=0",
        "UPDATE kernel_sql_event_projection_state SET frontier_seq=(SELECT max(seq)+1 FROM content_events)",
        "DELETE FROM kernel_sql_event_projection",
        "INSERT INTO kernel_sql_event_projection(seq,id,record_id,type,created_at,created_at_ms,actor,run_key,parent_key,origin,source_stream,hidden,restricted,owner,claim_sensitive,selector,source_id,target_id,link_id,subject_set,outer_anchor) VALUES(-1,'tampered','hq:00001','record.updated',NULL,NULL,NULL,NULL,NULL,'native',NULL,0,0,NULL,0,'record','hq:00001',NULL,NULL,0,'hq:00001')",
        "UPDATE kernel_sql_event_projection SET outer_anchor='native:root' WHERE origin='legacy'",
        "CREATE INDEX slice_b_unexpected_cache_index ON kernel_sql_event_projection(actor)",
        "CREATE TRIGGER slice_b_unexpected_cache_trigger AFTER DELETE ON kernel_sql_event_projection BEGIN SELECT RAISE(ABORT,'unexpected cache trigger fired'); END",
        "ALTER TABLE kernel_sql_event_projection ADD COLUMN unexpected_column TEXT",
    ].into_iter().enumerate() {
        let path=w._dir.path().join(format!("tampered-copy-{number}.db"));
        sqlx::query("VACUUM INTO ?").bind(path.to_str().unwrap()).execute(w.db.pool()).await.unwrap();
        let options=sqlx::sqlite::SqliteConnectOptions::new().filename(&path).create_if_missing(false);
        let mut conn=<sqlx::SqliteConnection as sqlx::Connection>::connect_with(&options).await.unwrap();
        let schema_before=kernel::sql_event_projection::schema_digest_on(&mut conn).await.unwrap();
        sqlx::query(tamper).execute(&mut conn).await.unwrap();
        assert_eq!(digest,kernel::projection_dump::dump_on(&mut conn).await.unwrap());
        if tamper.starts_with("CREATE ") {
            assert_ne!(schema_before,kernel::sql_event_projection::schema_digest_on(&mut conn).await.unwrap());
            assert!(crate::standby::kernel_v2::coordinates(&mut conn).await.is_err(),"unexpected cache object must remain visible to certification");
        } else {
            assert_eq!(schema_before,kernel::sql_event_projection::schema_digest_on(&mut conn).await.unwrap());
            assert_eq!(generation,crate::standby::kernel_v2::coordinates(&mut conn).await.unwrap());
            if tamper.starts_with("ALTER ") {assert!(!kernel::sql_event_projection::schema_valid_on(&mut conn).await.unwrap());}
        }
        <sqlx::SqliteConnection as sqlx::Connection>::close(conn).await.unwrap();
        let copy=kernel::open_marked_v2_database(path.to_str().unwrap()).await.unwrap();
        for actor in &callers {sql::event_equivalence::compare_projection(&copy,actor).await;}
        copy.start_serving_sql_event_projection();
        copy.settle_sql_event_projection().await;
        for actor in &callers {sql::event_equivalence::compare_projection(&copy,actor).await;}
        copy.close().await;
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_two_handles_and_real_reset_race() {
    let w = small_world(90).await;
    slice_a_edge_cases(&w).await;
    slice_a_window_cases(&w).await;
    let callers = projection_callers(&w).await;
    let mut prepare = w.db.write_pool().begin().await.unwrap();
    kernel::facet_time_reads::prepare_on(&mut prepare)
        .await
        .unwrap();
    prepare.commit().await.unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let generation: i64 = sqlx::query_scalar(
        "SELECT generation FROM kernel_sql_event_projection_state WHERE singleton=1",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let path = w._dir.path().join("v2.db");
    let other = kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    other.settle_sql_event_projection().await;
    assert_eq!(
        generation,
        sqlx::query_scalar::<_, i64>(
            "SELECT generation FROM kernel_sql_event_projection_state WHERE singleton=1"
        )
        .fetch_one(other.pool())
        .await
        .unwrap(),
        "a valid second opener must not reset the first handle's generation"
    );
    assert_eq!(
        kernel::sql_event_projection::catch_up(&other)
            .await
            .unwrap()
            .batches,
        0
    );
    // An old worker pins its read snapshot before a different connection resets.
    let mut stale = w.db.pool().begin().await.unwrap();
    let captured: i64 = sqlx::query_scalar(
        "SELECT generation FROM kernel_sql_event_projection_state WHERE singleton=1",
    )
    .fetch_one(&mut *stale)
    .await
    .unwrap();
    let mut reset = other.write_pool().begin().await.unwrap();
    kernel::sql_event_projection::reset_on(&mut reset, 0)
        .await
        .unwrap();
    reset.commit().await.unwrap();
    assert_eq!(
        captured,
        sqlx::query_scalar::<_, i64>(
            "SELECT generation FROM kernel_sql_event_projection_state WHERE singleton=1"
        )
        .fetch_one(&mut *stale)
        .await
        .unwrap(),
        "old reader remains on its prior snapshot"
    );
    stale.commit().await.unwrap();
    let head: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let mut obsolete = w.db.write_pool().begin().await.unwrap();
    assert!(
        !kernel::sql_event_projection::batch_on(&mut obsolete, captured, head)
            .await
            .unwrap()
    );
    assert_eq!(
        0,
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM kernel_sql_event_projection")
            .fetch_one(&mut *obsolete)
            .await
            .unwrap()
    );
    obsolete.commit().await.unwrap();
    let (a, b) = tokio::join!(
        kernel::sql_event_projection::catch_up(&w.db),
        kernel::sql_event_projection::catch_up(&other)
    );
    a.unwrap();
    b.unwrap();
    assert_eq!(
        generation + 1,
        sqlx::query_scalar::<_, i64>(
            "SELECT generation FROM kernel_sql_event_projection_state WHERE singleton=1"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap(),
        "handles must not reset each other after a database-owned generation change"
    );
    // Both persistent interners fold a later commit without a reset.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-b:two-handles',?,'kernel.record_revised.v1','{}',?,1,'legacy_unknown')").bind(&w.first).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    let (a, b) = tokio::join!(
        kernel::sql_event_projection::catch_up(&w.db),
        kernel::sql_event_projection::catch_up(&other)
    );
    a.unwrap();
    b.unwrap();
    for actor in callers {
        sql::event_equivalence::compare_projection(&w.db, &actor).await;
        sql::event_equivalence::compare_projection(&other, &actor).await;
    }
    sqlx::query("DROP TABLE kernel_sql_event_projection; DROP TABLE kernel_sql_event_subject_sets; DROP TABLE kernel_sql_event_projection_state").execute(w.db.write_pool()).await.unwrap();
    let reopened = kernel::open_marked_v2_database(path.to_str().unwrap())
        .await
        .unwrap();
    reopened.start_serving_sql_event_projection();
    reopened.settle_sql_event_projection().await;
    let mut conn = reopened.pool().acquire().await.unwrap();
    assert!(kernel::sql_event_projection::schema_valid_on(&mut conn)
        .await
        .unwrap());
    drop(conn);
    let recreated: i64 =
        sqlx::query_scalar("SELECT generation FROM kernel_sql_event_projection_state")
            .fetch_one(reopened.pool())
            .await
            .unwrap();
    assert_ne!(
        generation + 1,
        recreated,
        "lost state must not reuse either handle's old proof"
    );
    let mut stale = w.db.write_pool().begin().await.unwrap();
    assert!(
        !kernel::sql_event_projection::batch_on(&mut stale, generation + 1, head + 2)
            .await
            .unwrap()
    );
    stale.rollback().await.unwrap();
    sql::event_equivalence::compare_projection(&reopened, &w.viewer).await;
    reopened.close().await;
    other.close().await;
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_dynamic_time_and_non_string_subjects() {
    let w = small_world(90).await;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    for (n, value) in ["now", "subsec", "subsecond"].into_iter().enumerate() {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,'kernel.record_revised.v1','{}',?,?,1,'legacy_unknown')").bind(format!("slice-b:clock:{n}")).bind(&w.first).bind(&w.admin).bind(value).execute(&mut *tx).await.unwrap();
    }
    for (n, value) in ["now", "subsec", "subsecond"].into_iter().enumerate() {
        let id = format!("slice-b:clock:legacy:{n}");
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,'kernel.legacy_recorded.v1','{}',?,1,'legacy_unknown')").bind(&id).bind(&w.first).bind(&w.admin).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_sql_events(seq,source_id,record_id,event_type,actor,run_key,parent_key,created_at,source_stream) SELECT seq,?2,record_id,'record.updated','v1:acct:admin','clock-run','clock-parent',?3,'content_events' FROM content_events WHERE id=?1").bind(&id).bind(format!("v1:clock:{n}")).bind(value).execute(&mut *tx).await.unwrap();
        sqlx::query("INSERT INTO kernel_legacy_history(seq,event_type,subjects,hidden,restricted,claim_sensitive,disclosure_version) SELECT seq,'record.updated',?2,0,0,0,2 FROM content_events WHERE id=?1").bind(&id).bind(json!([w.first]).to_string()).execute(&mut *tx).await.unwrap();
    }
    // Hidden malformed subject arrays are accepted by today's selective path;
    // the same admitted array must preserve today's parse error.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-b:non-string-subjects',?,'kernel.legacy_recorded.v1','{}',?,1,'legacy_unknown')").bind(&w.first).bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_sql_events(seq,source_id,record_id,event_type,actor,created_at,source_stream) SELECT seq,id,record_id,'record.updated','v1:acct:admin',created_at,'content_events' FROM content_events WHERE id='slice-b:non-string-subjects'").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_history(seq,event_type,subjects,hidden,restricted,claim_sensitive,disclosure_version) SELECT seq,'record.updated','[123,null,true,{}]',1,0,0,2 FROM content_events WHERE id='slice-b:non-string-subjects'").execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE kernel_legacy_sql_progress SET scanned_seq=(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1')").execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let (frontier,head):(i64,i64)=sqlx::query_as("SELECT frontier_seq,(SELECT max(seq) FROM content_events) FROM kernel_sql_event_projection_state WHERE singleton=1").fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(
        frontier, head,
        "clock values and non-string subjects must not stall maintenance"
    );
    // Compare both installers inside one SQL statement so SQLite's 'now' is
    // pinned once. The stored TEMP rows preserve the raw dynamic time-value.
    let mut conn = w.db.pool().acquire().await.unwrap();
    let mismatches:i64=sqlx::query_scalar("SELECT count(*) FROM kernel_sql_event_projection p JOIN content_events e ON e.seq=p.seq LEFT JOIN kernel_legacy_sql_events m ON m.seq=e.seq WHERE e.id LIKE 'slice-b:clock:%' AND (strftime('%Y-%m-%dT%H:%M:%fZ',p.created_at) IS NOT strftime('%Y-%m-%dT%H:%M:%fZ',coalesce(m.created_at,e.created_at)) OR (CAST(strftime('%s',p.created_at) AS INTEGER)*1000+CAST(substr(strftime('%f',p.created_at),4,3) AS INTEGER)) IS NOT (CAST(strftime('%s',coalesce(m.created_at,e.created_at)) AS INTEGER)*1000+CAST(substr(strftime('%f',coalesce(m.created_at,e.created_at)),4,3) AS INTEGER)))").fetch_one(&mut *conn).await.unwrap();
    assert_eq!(mismatches, 0);
    drop(conn);
    for actor in [&w.viewer, &w.admin] {
        // Wall-clock columns are checked above; all other fields compare at
        // both paths, and neither admits the hidden malformed subject row.
        let result=call_as(&w,if actor==&w.viewer {"acct:viewer"}else{"acct:admin"},"query_sql",json!({"sql":"SELECT id,record_id,type,actor,run_key,parent_key FROM content_events WHERE id LIKE 'slice-b:%' ORDER BY id"})).await.unwrap();
        let expected=sql::event_equivalence::slice_a_scope(call_as(&w,if actor==&w.viewer {"acct:viewer"}else{"acct:admin"},"query_sql",json!({"sql":"SELECT id,record_id,type,actor,run_key,parent_key FROM content_events WHERE id LIKE 'slice-b:%' ORDER BY id"}))).await.unwrap();
        assert_eq!(result, expected);
    }
    sqlx::query("UPDATE kernel_legacy_history SET hidden=0 WHERE seq=(SELECT seq FROM content_events WHERE id='slice-b:non-string-subjects')").execute(w.db.write_pool()).await.unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    kernel::sql_event_projection::reset_on(&mut tx, 0)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let args = json!({"sql":"SELECT id FROM content_events"});
    let actual = call(&w, "query_sql", args.clone()).await.unwrap_err();
    let expected = sql::event_equivalence::slice_a_scope(call(&w, "query_sql", args))
        .await
        .unwrap_err();
    assert_eq!(actual.to_string(), expected.to_string());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_malformed_selector_diagnostic() {
    for (kind, hidden) in [
        ("kernel.generic_link_added.v1", true),
        ("kernel.generic_link_imported.v1", true),
        ("kernel.message_state.v1", true),
        ("kernel.message_state.v1", false),
    ] {
        let w = small_world(90).await;
        slice_a_window_cases(&w).await;
        let callers = projection_callers(&w).await;
        let mut prepare = w.db.write_pool().begin().await.unwrap();
        kernel::facet_time_reads::prepare_on(&mut prepare)
            .await
            .unwrap();
        prepare.commit().await.unwrap();
        // Older ready files may omit this optional JSON expression index.
        sqlx::query("DROP INDEX idx_kernel_realtime_authority")
            .execute(w.db.write_pool())
            .await
            .unwrap();
        kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        let record = if hidden {
            &w.hidden
        } else if kind == "kernel.message_state.v1" {
            &w.second
        } else {
            &w.first
        };
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-b:malformed-selector',?,?,'not json',?,1,'legacy_unknown')").bind(record).bind(kind).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
        // A later healthy position must not be trapped behind the bad payload.
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-b:after-malformed',?,'kernel.record_revised.v1','{}',?,1,'legacy_unknown')").bind(&w.first).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
        kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        let state: (i64,i64,i64) = sqlx::query_as("SELECT frontier_seq,generation,(SELECT max(seq) FROM content_events) FROM kernel_sql_event_projection_state").fetch_one(w.db.pool()).await.unwrap();
        assert_eq!(state.0, state.2);
        assert_eq!(
            1,
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM kernel_sql_event_projection WHERE selector='oracle-only'"
            )
            .fetch_one(w.db.pool())
            .await
            .unwrap()
        );
        // The marker is durable: neither another commit nor a new handle
        // retries/logs the bad position or discards the healthy prefix.
        assert_eq!(
            0,
            kernel::sql_event_projection::catch_up(&w.db)
                .await
                .unwrap()
                .batches
        );
        let path = w._dir.path().join("v2.db");
        let other = kernel::open_marked_v2_database(path.to_str().unwrap())
            .await
            .unwrap();
        other.settle_sql_event_projection().await;
        assert_eq!(
            state.1,
            sqlx::query_scalar::<_, i64>(
                "SELECT generation FROM kernel_sql_event_projection_state"
            )
            .fetch_one(other.pool())
            .await
            .unwrap()
        );
        other.close().await;
        let args = json!({"sql":"SELECT id FROM content_events ORDER BY local_seq"});
        for actor in &callers {
            let binding: String = sqlx::query_scalar(
                "SELECT auth_binding FROM kernel_principals WHERE principal_id=?",
            )
            .bind(actor)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
            let actual = call_as(&w, &binding, "query_sql", args.clone()).await;
            let expected = sql::event_equivalence::slice_a_scope(call_as(
                &w,
                &binding,
                "query_sql",
                args.clone(),
            ))
            .await;
            match (actual, expected) {
                (Ok(a), Ok(b)) => assert_eq!(a, b),
                (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
                (a, b) => panic!("fallback changed malformed selector behavior: {a:?} / {b:?}"),
            }
        }
        w.db.close().await;
    }
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_non_v2_never_folds_existing_cache() {
    let w = small_world(90).await;
    w.db.settle_sql_event_projection().await;
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let before: (i64, i64) =
        sqlx::query_as("SELECT frontier_seq,generation FROM kernel_sql_event_projection_state")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert!(w.db.sql_event_projection_generation().is_some());
    sqlx::query("PRAGMA application_id=0")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        0,
        kernel::sql_event_projection::catch_up(&w.db)
            .await
            .unwrap()
            .batches
    );
    assert_eq!(
        before,
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT frontier_seq,generation FROM kernel_sql_event_projection_state"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap()
    );
    assert!(w.db.sql_event_projection_generation().is_none());
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_mixed_fingerprint_lease() {
    let w = small_world(90).await;
    let callers = projection_callers(&w).await;
    w.db.settle_sql_event_projection().await;
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let original = kernel::sql_event_projection::projector_version();
    let other = (original ^ 1).max(1);
    sqlx::query("UPDATE kernel_sql_event_projection_state SET projector_version=?,fingerprint_written_at=unixepoch()").bind(other).execute(w.db.write_pool()).await.unwrap();
    let generation: i64 =
        sqlx::query_scalar("SELECT generation FROM kernel_sql_event_projection_state")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    // Repeated calls by an incompatible build neither reset nor renew ownership.
    for attempt in 0..3 {
        let stats = kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
        assert_eq!(0, stats.batches);
        assert_eq!(
            u64::from(attempt == 0),
            stats.lease_yields,
            "warn only on transition into yielding"
        );
        assert_eq!(
            (generation, other),
            sqlx::query_as::<_, (i64, i64)>(
                "SELECT generation,projector_version FROM kernel_sql_event_projection_state"
            )
            .fetch_one(w.db.pool())
            .await
            .unwrap()
        );
    }
    for actor in &callers {
        sql::event_equivalence::compare_projection(&w.db, actor).await;
    }
    sqlx::query(
        "UPDATE kernel_sql_event_projection_state SET fingerprint_written_at=unixepoch()-301",
    )
    .execute(w.db.write_pool())
    .await
    .unwrap();
    assert!(
        kernel::sql_event_projection::catch_up(&w.db)
            .await
            .unwrap()
            .batches
            > 0
    );
    assert_eq!(
        (generation + 1, original),
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT generation,projector_version FROM kernel_sql_event_projection_state"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap()
    );
    for actor in &callers {
        sql::event_equivalence::compare_projection(&w.db, actor).await;
    }
    // Returning to a foreign owner is a new transition, but renewals are not.
    sqlx::query("UPDATE kernel_sql_event_projection_state SET projector_version=?,fingerprint_written_at=unixepoch()").bind(other).execute(w.db.write_pool()).await.unwrap();
    assert_eq!(
        1,
        kernel::sql_event_projection::catch_up(&w.db)
            .await
            .unwrap()
            .lease_yields
    );
    assert_eq!(
        0,
        kernel::sql_event_projection::catch_up(&w.db)
            .await
            .unwrap()
            .lease_yields
    );
    // A future-dated foreign lease must never prevent takeover indefinitely.
    sqlx::query(
        "UPDATE kernel_sql_event_projection_state SET fingerprint_written_at=unixepoch()+3600",
    )
    .execute(w.db.write_pool())
    .await
    .unwrap();
    let stats = kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    assert!(stats.batches > 0);
    assert_eq!(0, stats.lease_yields);
    assert_eq!(
        (generation + 2, original),
        sqlx::query_as::<_, (i64, i64)>(
            "SELECT generation,projector_version FROM kernel_sql_event_projection_state"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap()
    );
    // The current owner also corrects its own future clock, without a reset.
    sqlx::query(
        "UPDATE kernel_sql_event_projection_state SET fingerprint_written_at=unixepoch()+3600",
    )
    .execute(w.db.write_pool())
    .await
    .unwrap();
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    assert_eq!(generation+2,sqlx::query_scalar::<_,i64>("SELECT generation FROM kernel_sql_event_projection_state WHERE fingerprint_written_at<=unixepoch()+60").fetch_one(w.db.pool()).await.unwrap());
    for actor in &callers {
        sql::event_equivalence::compare_projection(&w.db, actor).await;
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_sqlite_json5_and_jsonb() {
    let w = small_world(90).await;
    slice_a_window_cases(&w).await;
    let callers = projection_callers(&w).await;
    for (number, kind, expression) in [
        (0, "kernel.link_added.v1", "'{target_id:123,}'"),
        (1, "kernel.link_added.v1", "jsonb('{target_id:123}')"),
        (2, "kernel.generic_link_added.v1", "'{link_id:123,}'"),
        (3, "kernel.generic_link_added.v1", "jsonb('{link_id:123}')"),
        (
            4,
            "kernel.message_state.v1",
            "'{reactions:{someone:[\"wave\"]},}'",
        ),
        (
            5,
            "kernel.message_state.v1",
            "jsonb('{reactions:{someone:[\"clap\"]}}')",
        ),
    ] {
        sqlx::query(&format!("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES(?,?,?,{expression},?,1,'legacy_unknown')")).bind(format!("slice-b:sqlite-json:{number}")).bind(if kind=="kernel.message_state.v1" {&w.second} else {&w.first}).bind(kind).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    }
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    assert_eq!(
        0,
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM kernel_sql_event_projection WHERE selector='oracle-only'"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap()
    );
    assert!(sqlx::query_scalar::<_,bool>("SELECT frontier_seq=(SELECT max(seq) FROM content_events) FROM kernel_sql_event_projection_state").fetch_one(w.db.pool()).await.unwrap());
    for actor in &callers {
        sql::event_equivalence::compare_projection(&w.db, actor).await;
    }
    w.db.close().await;
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_transient_read_failure() {
    let w = small_world(90).await;
    w.db.settle_sql_event_projection().await;
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    let before: (i64,i64,i64) = sqlx::query_as("SELECT frontier_seq,generation,(SELECT count(*) FROM kernel_sql_event_projection) FROM kernel_sql_event_projection_state").fetch_one(w.db.pool()).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status) VALUES('slice-b:retry-io',?,'kernel.record_revised.v1','{}',?,1,'legacy_unknown')").bind(&w.first).bind(&w.admin).execute(w.db.write_pool()).await.unwrap();
    // The write batch must roll back, rather than persist an oracle marker.
    let result = kernel::sql_event_projection::with_injected_read_failure(
        kernel::sql_event_projection::catch_up(&w.db),
    )
    .await;
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("injected event cache read failure"));
    assert_eq!(before,sqlx::query_as::<_,(i64,i64,i64)>("SELECT frontier_seq,generation,(SELECT count(*) FROM kernel_sql_event_projection) FROM kernel_sql_event_projection_state").fetch_one(w.db.pool()).await.unwrap());
    // A transient open-time verification failure revokes trust, without reset.
    w.db.trust_sql_event_projection_generation(-1);
    assert!(kernel::sql_event_projection::with_injected_read_failure(
        kernel::sql_event_projection::catch_up(&w.db)
    )
    .await
    .is_err());
    assert!(w.db.sql_event_projection_generation().is_none());
    assert_eq!(before,sqlx::query_as::<_,(i64,i64,i64)>("SELECT frontier_seq,generation,(SELECT count(*) FROM kernel_sql_event_projection) FROM kernel_sql_event_projection_state").fetch_one(w.db.pool()).await.unwrap());
    kernel::sql_event_projection::catch_up(&w.db).await.unwrap();
    assert_eq!(Some(before.1), w.db.sql_event_projection_generation());
    assert_eq!(
        0,
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM kernel_sql_event_projection WHERE selector='oracle-only'"
        )
        .fetch_one(w.db.pool())
        .await
        .unwrap()
    );
    sql::event_equivalence::compare_projection(&w.db, &w.viewer).await;
    w.db.close().await;
}

#[test]
fn kernel_v2_sql_event_projection_golden() {
    kernel::sql_event_projection::assert_projection_golden();
}

#[tokio::test]
async fn kernel_v2_sql_event_projection_error_classes() {
    kernel::sql_event_projection::assert_narrow_error_classes().await;
}
