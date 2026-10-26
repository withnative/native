use super::*;

#[tokio::test]
async fn imported_messages_first_native_reaction_reaches_frozen_sql_and_freshness() {
    for resumed in [false, true] {
        let f = Fixture::new().await;
        let mut source = SqliteConnection::connect(f.source.to_str().unwrap())
            .await
            .unwrap();
        source.execute(r#"
          INSERT INTO bindings VALUES('person-a','native-principal','principal-a',1),('person-b','native-principal','principal-b',1);
          INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES
           ('person-a','Entity','person','Owner','Owner Persona','native:root','person-a','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root'),
           ('person-b','Entity','person','Member','Member Persona','native:root','person-b','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root');
          INSERT INTO content_events(id,record_id,type,payload,actor,created_at)
          VALUES('created:person-b','person-b','record.created','{}','account-b','2026-01-01T00:00:00Z');
          CREATE TABLE message_audience_state(message_id TEXT,status TEXT);
          CREATE TABLE message_audiences(message_id TEXT,principal_id TEXT,source TEXT,event_seq INTEGER);
          CREATE TABLE message_origin_state(message_id TEXT,status TEXT,origin_type TEXT,collection_id TEXT,direct_set_digest TEXT,participant_count INTEGER,declaration_event_seq INTEGER,updated_at TEXT);
        "#).await.unwrap();
        for id in ["import-public", "import-private"] {
            sqlx::query("INSERT INTO records(id,type,kind,name,body,home_id,owner_id,created_at,updated_at,archived,policy_anchor_id) VALUES(?,'Message','text',?,'Imported message','folder','person-a','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0,'native:root')")
                .bind(id).bind(id).execute(&mut source).await.unwrap();
            sqlx::query("INSERT INTO message_audience_state VALUES(?,'declared')")
                .bind(id)
                .execute(&mut source)
                .await
                .unwrap();
            sqlx::query("INSERT INTO message_audiences VALUES(?,'principal-a','sender',1)")
                .bind(id)
                .execute(&mut source)
                .await
                .unwrap();
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES(?,?,'record.created','{}','account-a','2026-01-01T00:00:00Z')")
                .bind(format!("created:{id}")).bind(id).execute(&mut source).await.unwrap();
        }
        // Audience rows are addressing facts, not ACLs. This message is hidden
        // by its actual v1 private bearer policy, not by omitting member B.
        source.execute("UPDATE records SET home_id='private',policy_anchor_id='private' WHERE id='import-private'").await.unwrap();
        source.execute("INSERT INTO message_origin_state VALUES('import-public','declared','collection','folder',NULL,0,1,'2026-01-01T00:00:00Z')").await.unwrap();
        let options = |resume| {
            let mut options = f.options(
                &["import-public", "import-private", "person-a", "person-b"],
                resume,
            );
            options.history = true;
            options
        };
        let report = run(options(false)).await.unwrap();
        assert!(
            report.refusals.is_empty(),
            "{}",
            serde_json::to_string(&report.refusals).unwrap()
        );
        if resumed {
            source.execute("UPDATE records SET body='Updated before freeze',updated_at='2026-02-01T00:00:00Z' WHERE id='import-public'").await.unwrap();
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at) VALUES('updated-public','import-public','record.updated','{}','account-a','2026-02-01T00:00:00Z')").execute(&mut source).await.unwrap();
            let report = run(options(true)).await.unwrap();
            assert!(
                report.refusals.is_empty(),
                "{}",
                serde_json::to_string(&report.refusals).unwrap()
            );
        }
        let db = f.db().await;
        super::app_state::app_roster(&db, "account-a", &["account-a", "account-b"]).await;
        let directory = || {
            ordinary_kernel_call(
                &db,
                "account-b",
                "query_sql",
                json!({"sql":"SELECT actor,person_id FROM actors WHERE person_id IN ('person-a','person-b') ORDER BY actor"}),
            )
        };
        let initial_directory = directory().await.unwrap()["rows"].clone();
        assert_eq!(
            initial_directory.as_array().unwrap().len(),
            2,
            "distinct accounts must not collapse: {initial_directory}"
        );
        for (account, person) in [("account-a", "person-a"), ("account-b", "person-b")] {
            assert!(initial_directory
                .as_array()
                .unwrap()
                .iter()
                .any(
                    |row| row["actor"] == report.principals[account] && row["person_id"] == person
                ));
        }
        let self_event = ordinary_kernel_call(&db,"account-a","query_sql",json!({"sql":"SELECT id FROM content_events WHERE id='created:import-public' AND actor=current_principal()"})).await.unwrap();
        assert_eq!(self_event["rows"].as_array().unwrap().len(), 1);
        let raw: String = sqlx::query_scalar(
            "SELECT actor FROM kernel_legacy_sql_events WHERE source_id='created:import-public'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            raw, "v1:account-a",
            "source history must retain its original actor alias"
        );
        let before: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let states: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM content_events WHERE type='kernel.message_state.v1'",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(
            states, 0,
            "the test must exercise the first native state after import"
        );
        ordinary_kernel_call(&db,"account-a","manage_messages",json!({"action":"add_reaction","message_id":"import-public","emoji":"👍","idempotency_key":"import-first-reaction","reason":"Imported reaction compatibility"})).await.unwrap();
        assert_eq!(
            directory().await.unwrap()["rows"],
            initial_directory,
            "first native activity cannot manufacture an ambiguous second account"
        );
        let frozen = || {
            ordinary_kernel_call(
                &db,
                "account-a",
                "query_sql",
                json!({"sql":include_str!("../../../tests/fixtures/kernel_v2_frozen_slack_dms.sql")}),
            )
        };
        let count = |result: &Value| {
            result["rows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == "import-public")
                .unwrap_or_else(|| panic!("missing public message: {result:#}"))["reactions"]
                .clone()
        };
        assert_eq!(count(&frozen().await.unwrap()), 1, "resumed={resumed}");
        let aliases = ordinary_kernel_call(&db, "account-a", "query_sql",
            json!({"sql":"SELECT identifier FROM bindings WHERE system='account' AND identifier LIKE 'v1:%'"})).await.unwrap();
        assert_eq!(
            aliases["rows"],
            json!([]),
            "synthetic history aliases are not live account bindings"
        );
        let changed = ordinary_kernel_call(
            &db,
            "account-b",
            "whats_changed",
            json!({"after_local_seq":before,"limit":100}),
        )
        .await
        .unwrap();
        assert!(changed.to_string().contains("import-public"), "{changed:#}");
        let after: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        ordinary_kernel_call(&db,"account-a","manage_messages",json!({"action":"set_preference","message_id":"import-public","preference":"mark_read","expected_version":0,"idempotency_key":"import-private-preference","reason":"Private state is not a public reaction"})).await.unwrap();
        ordinary_kernel_call(&db,"account-a","manage_messages",json!({"action":"add_reaction","message_id":"import-private","emoji":"👀","idempotency_key":"import-hidden-reaction","reason":"Private message reaction"})).await.unwrap();
        let changed = ordinary_kernel_call(
            &db,
            "account-b",
            "whats_changed",
            json!({"after_local_seq":after,"limit":100}),
        )
        .await
        .unwrap();
        assert!(
            !changed.to_string().contains("import-private"),
            "{changed:#}"
        );
        assert!(
            !changed.to_string().contains("import-public"),
            "another person's preference stays private: {changed:#}"
        );
        let headers=ordinary_kernel_call(&db,"account-b","query_sql",json!({"sql":"SELECT record_id,type FROM content_events WHERE type IN ('message.reaction.added.v1','message.reaction.removed.v1') ORDER BY local_seq"})).await.unwrap();
        assert_eq!(
            headers["rows"],
            json!([{"record_id":"import-public","type":"message.reaction.added.v1"}])
        );
        let before = k::dump_all_kernel_tables(&db).await.unwrap();
        k::replay_all_projections(&db).await.unwrap();
        assert_eq!(before, k::dump_all_kernel_tables(&db).await.unwrap());
        assert_eq!(count(&frozen().await.unwrap()), 1);
        assert_eq!(directory().await.unwrap()["rows"], initial_directory);
        db.close().await;
    }
}
