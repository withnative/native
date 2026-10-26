use super::*;

pub(super) async fn dimensional(
    h: &Harness,
    who: &Caller,
    declared: &str,
    dimension: &str,
    text: &str,
) -> Value {
    let mut args = json!({"category":"general_preferences","preference":text,
        "declarationType":declared,"dimension":dimension,"sourceContext":"test:c2"});
    if declared == "model-inferred" {
        args["confidence"] = json!("high");
        args["assertedBy"] = json!("test:model");
    }
    h.ok(who, ADD_PREFERENCE, args).await
}

pub(super) async fn audit(h: &Harness, who: &Caller, args: Value) -> Value {
    h.native
        .call(h.db.clone(), who.clone(), AUDIT_TOOL, args)
        .await
        .unwrap()
}

async fn state_count(h: &Harness) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM control_events WHERE type LIKE 'hcp.%'")
        .fetch_one(h.db.write_pool())
        .await
        .unwrap()
}

async fn search_entry(h: &Harness, who: &Caller, entry: &Value) -> Value {
    h.search(
        who,
        entry["claim"]["subject"]["preference"].as_str().unwrap(),
        json!([entry["record"]["category"]]),
    )
    .await
}

#[tokio::test]
async fn c2_add_and_update_receipts_never_reveal_conflict_status() {
    for counterpart in [false, true] {
        let h = harness().await;
        if counterpart {
            dimensional(&h, &alice_two(), "user-declared", "tone", "Declared tone").await;
        }
        let added = dimensional(&h, &alice(), "model-inferred", "tone", "Inferred tone").await;
        assert_eq!(added["record"]["status"], "active");
        let revised = h
            .ok(
                &alice(),
                UPDATE_PREFERENCE,
                json!({
                    "entryId":added["id"],"updatedPreference":"Revised inferred tone",
                    "confidence":"high","assertedBy":"test:model","reason":"revise"
                }),
            )
            .await;
        assert_eq!(revised["record"]["status"], "active");
        assert!(!revised.to_string().contains("conflict"));
        assert_eq!(
            h.store(&alice())
                .entry(added["id"].as_str().unwrap())
                .await
                .unwrap()
                .unwrap()
                .entry
                .status(),
            if counterpart { "conflicted" } else { "active" }
        );
        if counterpart {
            assert_eq!(
                h.err(&alice(), GET_PREFERENCE, get_args(&added)).await["type"],
                SCOPE_DENIED
            );
        } else {
            assert_eq!(
                h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await["entry"],
                revised
            );
        }
    }
}

#[tokio::test]
async fn c2_client_writes_disclose_without_a_read_event_and_survive_replay() {
    let h = harness().await;
    let added = h
        .add(&alice(), "general_preferences", "Own write disclosure")
        .await;
    let reads: i64 =
        sqlx::query_scalar("SELECT count(*) FROM control_events WHERE type = 'hcp.read.v1'")
            .fetch_one(h.db.write_pool())
            .await
            .unwrap();
    assert_eq!(reads, 0, "the version event owns write disclosure");
    let replayed = replayed_elsewhere(&h).await;
    let mut tx = replayed.store(&alice()).begin().await.unwrap();
    assert!(replayed
        .store(&alice())
        .disclosed_in(&mut tx, added["id"].as_str().unwrap())
        .await
        .unwrap());
    assert!(!replayed
        .store(&alice_two())
        .disclosed_in(&mut tx, added["id"].as_str().unwrap())
        .await
        .unwrap());
    tx.rollback().await.unwrap();
    assert_eq!(
        h.ok(&alice(), GET_PREFERENCE, get_args(&added)).await["entry"],
        added
    );
    assert_eq!(
        h.err(&alice_two(), GET_PREFERENCE, get_args(&added)).await["type"],
        SCOPE_DENIED
    );
    // Update is intentionally not discovery-gated; its receipt now discloses.
    let revised = h
        .ok(
            &alice_two(),
            UPDATE_PREFERENCE,
            json!({"entryId":added["id"],
        "updatedPreference":"Other client wrote revision","reason":"revise"}),
        )
        .await;
    assert_eq!(
        h.ok(&alice_two(), GET_PREFERENCE, get_args(&added)).await["entry"],
        revised
    );
    assert_eq!(
        audit(&h, &alice(), json!({"event_type":"preference.updated"})).await["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn c2_native_edit_is_not_disclosure_to_the_noticing_client() {
    let h = harness().await;
    let added = h
        .add(
            &alice_two(),
            "general_preferences",
            "Original private phrase",
        )
        .await;
    h.edit_view(&alice(), &record_id_of_entry(&added), |body| {
        body["claim"]["subject"]["preference"] = json!("Native revised phrase");
    })
    .await;
    let found = h
        .search(&alice(), "unrelatedquery", json!(["general_preferences"]))
        .await;
    assert!(found["entries"].as_array().unwrap().is_empty());
    assert_eq!(
        h.store(&alice())
            .entry(added["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .version(),
        2
    );
    assert_eq!(
        h.err(&alice(), GET_PREFERENCE, get_args(&added)).await["type"],
        SCOPE_DENIED
    );
    assert_eq!(
        audit(
            &h,
            &alice(),
            json!({"client_id":"native","event_type":"preference.updated"})
        )
        .await["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        h.ok(&alice_two(), GET_PREFERENCE, get_args(&added)).await["entry"]["record"]["version"],
        2
    );
}

#[tokio::test]
async fn c2_failed_or_rejected_version_cannot_establish_disclosure() {
    let h = harness().await;
    let added = h
        .add(
            &alice_two(),
            "general_preferences",
            "Original private phrase",
        )
        .await;
    sqlx::query("CREATE TRIGGER c2_fail_version BEFORE INSERT ON control_events WHEN NEW.type = 'hcp.entry.versioned.v1' BEGIN SELECT RAISE(ABORT,'write audit unavailable'); END")
        .execute(h.db.write_pool()).await.unwrap();
    let count = state_count(&h).await;
    assert_eq!(
        h.err(
            &alice(),
            UPDATE_PREFERENCE,
            json!({"entryId":added["id"],
        "updatedPreference":"Failed revision","reason":"revise"})
        )
        .await["type"],
        INTERNAL_ERROR
    );
    assert_eq!(state_count(&h).await, count);
    assert_eq!(
        h.err(&alice(), GET_PREFERENCE, get_args(&added)).await["type"],
        SCOPE_DENIED
    );
    sqlx::query("DROP TRIGGER c2_fail_version")
        .execute(h.db.write_pool())
        .await
        .unwrap();
    let mut forged = events_of(&h, &alice_two()).await[0].1.clone();
    forged.as_object_mut().unwrap().remove("_actor");
    forged.as_object_mut().unwrap().remove("_reason");
    forged["client"]["id"] = json!("client_one");
    // A duplicate first version fails the chain, even if it names the caller.
    insert_raw_event(
        &h,
        "acct:alice",
        "rejected-write-disclosure",
        "hcp.entry.versioned.v1",
        forged,
    )
    .await;
    assert_eq!(
        h.store(&alice()).fold_all().await.unwrap().rejected.len(),
        1
    );
    assert_eq!(
        h.err(&alice(), GET_PREFERENCE, get_args(&added)).await["type"],
        SCOPE_DENIED
    );
    assert_eq!(
        audit(&h, &alice(), json!({})).await["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn c2_fold_candidates_ignore_forged_facets_and_quarantine_in_both_write_orders() {
    for first in ["user-declared", "model-inferred"] {
        let h = harness().await;
        let one = dimensional(
            &h,
            &alice(),
            first,
            "  Footwear Support ",
            "First footwear choice",
        )
        .await;
        h.edit_view(&alice(), &record_id_of_entry(&one), |body| {
            body["record"]["status"] = json!("deleted");
            body["record"]["provenance"]["assertedBy"]["assurance"] = json!("authenticated");
        })
        .await;
        h.native.call(h.db.clone(), alice(), "update_record", json!({"id":record_id_of_entry(&one),
            "facets":{"hcp2.category":"forged","hcp2.dimension":"different","hcp2.status":"deleted"},
            "reason":"forge conflict index","sources":[]})).await.unwrap();
        let other = if first == "user-declared" {
            "model-inferred"
        } else {
            "user-declared"
        };
        let two = dimensional(
            &h,
            &alice(),
            other,
            "footwear_support",
            "Second footwear choice",
        )
        .await;
        assert_eq!(
            two["record"]["status"], "active",
            "write receipt hides conflicts"
        );
        let acts: i64 = sqlx::query_scalar("SELECT count(DISTINCT act) FROM control_events
            WHERE type IN ('hcp.entry.versioned.v1','hcp.entry.status_set.v1') AND seq >= (SELECT seq FROM control_events
            WHERE type = 'hcp.entry.versioned.v1' AND json_extract(payload,'$.entry_id') = ? ORDER BY seq DESC LIMIT 1)")
            .bind(two["id"].as_str().unwrap()).fetch_one(h.db.write_pool()).await.unwrap();
        assert_eq!(
            acts, 1,
            "version and both quarantine events share the writer act"
        );
        for id in [&one["id"], &two["id"]] {
            let state = h
                .store(&alice())
                .entry(id.as_str().unwrap())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(state.entry.status(), "conflicted");
            let denied = h
                .err(
                    &alice(),
                    GET_PREFERENCE,
                    json!({"entryId":id,"purpose":"probe","version":1}),
                )
                .await;
            assert_eq!(denied["type"], SCOPE_DENIED);
        }
        assert!(h
            .search(&alice(), "footwear", json!(["general_preferences"]))
            .await["entries"]
            .as_array()
            .unwrap()
            .is_empty());
        let log = audit(&h, &alice(), json!({"event_type":"conflict.detected"})).await;
        assert_eq!(log["events"].as_array().unwrap().len(), 2);
        for event in log["events"].as_array().unwrap() {
            assert!(event["relatedEntryId"].is_string());
            assert_eq!(event["category"], "general_preferences");
            assert_eq!(event["participants"]["initiator"]["role"], "hcp-provider");
        }
    }
}

#[tokio::test]
async fn c2_literal_active_and_delete_gap_survive_until_relevant_revision() {
    let h = harness().await;
    let declared = dimensional(
        &h,
        &alice(),
        "user-declared",
        "tone",
        "I like direct replies",
    )
    .await;
    let inferred = dimensional(
        &h,
        &alice(),
        "model-inferred",
        "tone",
        "Likely likes elaborate replies",
    )
    .await;
    let third = dimensional(
        &h,
        &alice(),
        "model-inferred",
        "tone",
        "Third inference stays active",
    )
    .await;
    // §15.2 literal active: the declaration is already conflicted.
    assert_eq!(third["record"]["status"], "active");
    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({"entryId":declared["id"],"reason":"remove declaration"}),
    )
    .await;
    assert_eq!(
        h.store(&alice())
            .entry(inferred["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "conflicted"
    );
    h.ok(&alice(), UPDATE_PREFERENCE, json!({"entryId":third["id"],"updatedPreference":"Unrelated inference revision","reason":"unrelated","confidence":"high","assertedBy":"test:model"})).await;
    assert_eq!(
        h.store(&alice())
            .entry(inferred["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "conflicted"
    );
    let revised = h.ok(&alice(), UPDATE_PREFERENCE, json!({"entryId":inferred["id"],"updatedPreference":"Revised inference","reason":"re-evaluate","confidence":"high","assertedBy":"test:model"})).await;
    assert_eq!(revised["record"]["status"], "active");
    assert_eq!(
        audit(&h, &alice(), json!({"event_type":"conflict.resolved"})).await["events"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn c2_native_revision_conflicts_and_releases_former_counterpart_atomically() {
    let h = harness().await;
    let one = dimensional(
        &h,
        &alice(),
        "user-declared",
        "other",
        "Brief concise replies",
    )
    .await;
    let two = dimensional(
        &h,
        &alice(),
        "model-inferred",
        "reply style",
        "Detailed verbose replies",
    )
    .await;
    h.edit_view(&alice(), &record_id_of_entry(&one), |body| {
        body["record"]["dimension"] = json!("REPLY STYLE")
    })
    .await;
    h.search(&alice(), "replies", json!(["general_preferences"]))
        .await;
    assert_eq!(
        h.store(&alice())
            .entry(one["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "conflicted"
    );
    h.edit_view(&alice(), &record_id_of_entry(&one), |body| {
        body["record"]["dimension"] = json!("separate dimension")
    })
    .await;
    h.search(&alice(), "replies", json!(["general_preferences"]))
        .await;
    for entry in [&one, &two] {
        assert_eq!(
            h.store(&alice())
                .entry(entry["id"].as_str().unwrap())
                .await
                .unwrap()
                .unwrap()
                .entry
                .status(),
            "active"
        );
    }
    let log = audit(
        &h,
        &alice(),
        json!({"client_id":"native","event_type":"preference.updated"}),
    )
    .await;
    assert_eq!(log["events"].as_array().unwrap().len(), 2);
    for event in log["events"].as_array().unwrap() {
        assert_eq!(event["participants"]["clientOperator"]["name"], "Native");
    }
}

#[tokio::test]
async fn c2_undisclosed_get_has_no_observable_reconciliation_even_with_forged_ledger() {
    let h = harness().await;
    let one = h
        .add(&alice_two(), "general_preferences", "Prefer short replies")
        .await;
    h.edit_view(&alice(), &record_id_of_entry(&one), |body| {
        body["claim"]["subject"]["preference"] = json!("Prefer long replies")
    })
    .await;
    h.native
        .call(
            h.db.clone(),
            alice(),
            "update_record",
            json!({"id":record_id_of_entry(&one),
        "facets":{"hcp2.disclosed.client_one":one["id"],"hcp2.status":"active"},
        "reason":"forge disclosure","sources":[]}),
        )
        .await
        .unwrap();
    let before = state_count(&h).await;
    let bodies: Vec<(String,)> = sqlx::query_as("SELECT body FROM records WHERE id = ?")
        .bind(record_id_of_entry(&one))
        .fetch_all(h.db.write_pool())
        .await
        .unwrap();
    let denied = h.err(&alice(), GET_PREFERENCE, get_args(&one)).await;
    assert_eq!(denied["type"], SCOPE_DENIED);
    assert_eq!(state_count(&h).await, before);
    let after: Vec<(String,)> = sqlx::query_as("SELECT body FROM records WHERE id = ?")
        .bind(record_id_of_entry(&one))
        .fetch_all(h.db.write_pool())
        .await
        .unwrap();
    assert_eq!(after, bodies);
    h.search(&alice(), "replies", json!(["general_preferences"]))
        .await;
    assert_eq!(
        h.ok(&alice(), GET_PREFERENCE, get_args(&one)).await["entry"]["record"]["version"],
        2
    );
    assert_eq!(
        h.err(
            &caller("acct:alice", Some("client_three")),
            GET_PREFERENCE,
            get_args(&one)
        )
        .await,
        denied
    );
    h.search(
        &caller("acct:alice", Some("client_three")),
        "replies",
        json!(["general_preferences"]),
    )
    .await;
    assert_eq!(
        h.ok(
            &caller("acct:alice", Some("client_three")),
            GET_PREFERENCE,
            get_args(&one)
        )
        .await["entry"]["record"]["version"],
        2
    );
}

#[tokio::test]
async fn c2_read_append_failure_never_discloses_and_retry_is_durable() {
    let h = harness().await;
    let one = h
        .add(
            &alice_two(),
            "general_preferences",
            "Unique atomic disclosure",
        )
        .await;
    sqlx::query("CREATE TRIGGER c2_fail_read BEFORE INSERT ON control_events WHEN NEW.type = 'hcp.read.v1' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
        .execute(h.db.write_pool()).await.unwrap();
    let failed = h.err(&alice(),SEARCH_PREFERENCES,json!({"query":"atomic","categories":["general_preferences"],"purpose":"fail read audit"})).await;
    assert_eq!(failed["type"], INTERNAL_ERROR);
    let count = state_count(&h).await;
    assert_eq!(
        h.err(&alice_two(), GET_PREFERENCE, get_args(&one)).await["type"],
        INTERNAL_ERROR,
        "an already disclosed entry still cannot be returned without its read audit"
    );
    assert_eq!(state_count(&h).await, count);
    assert_eq!(
        h.err(&alice(), GET_PREFERENCE, get_args(&one)).await["type"],
        SCOPE_DENIED
    );
    sqlx::query("DROP TRIGGER c2_fail_read")
        .execute(h.db.write_pool())
        .await
        .unwrap();
    let retrieved = search_entry(&h, &alice(), &one).await;
    let log = audit(&h, &alice(), json!({"event_type":"preference.read"})).await;
    assert_eq!(log["events"].as_array().unwrap().len(), 1);
    let event = &log["events"][0];
    assert_eq!(
        event["participants"]["retrievalId"],
        retrieved["retrievalId"]
    );
    assert_eq!(event["purpose"], "test");
    assert_eq!(event["disclosedEntries"], json!([one["id"]]));
    assert_eq!(log["durabilityWindowMs"], 0);
    let mut conn = h.db.write_pool().acquire().await.unwrap();
    let events = crate::control::read_all_control_events(&mut conn)
        .await
        .unwrap();
    for event in events.iter().filter(|e| e.event_type == "hcp.read.v1") {
        crate::control::validate_stored_control_event(event).unwrap();
        assert!(crate::control::validate_control_event(event).is_err());
    }
    drop(conn);
    assert_eq!(
        h.ok(&alice(), GET_PREFERENCE, get_args(&one)).await["entry"]["id"],
        one["id"]
    );
}

#[tokio::test]
async fn c2_conflict_append_failure_rolls_back_client_and_native_versions() {
    let h = harness().await;
    let one = dimensional(&h, &alice(), "user-declared", "tone", "Declared tone").await;
    sqlx::query("CREATE TRIGGER c2_fail_conflict BEFORE INSERT ON control_events WHEN NEW.type = 'hcp.entry.status_set.v1' BEGIN SELECT RAISE(ABORT,'conflict audit unavailable'); END")
        .execute(h.db.write_pool()).await.unwrap();
    let count = state_count(&h).await;
    let fail = h.err(&alice(),ADD_PREFERENCE,json!({"category":"general_preferences","preference":"Inferred tone","dimension":"tone",
        "declarationType":"model-inferred","assertedBy":"test:model","confidence":"high","sourceContext":"test"})).await;
    assert_eq!(fail["type"], INTERNAL_ERROR);
    assert_eq!(state_count(&h).await, count);
    let two = dimensional(
        &h,
        &alice(),
        "model-inferred",
        "other",
        "Other tone inference",
    )
    .await;
    h.edit_view(&alice(), &record_id_of_entry(&one), |body| {
        body["record"]["dimension"] = json!("other")
    })
    .await;
    let count = state_count(&h).await;
    assert_eq!(
        h.err(
            &alice(),
            SEARCH_PREFERENCES,
            json!({"query":"tone","categories":["general_preferences"],"purpose":"reconcile"})
        )
        .await["type"],
        INTERNAL_ERROR
    );
    assert_eq!(state_count(&h).await, count);
    assert_eq!(
        h.store(&alice())
            .entry(one["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "active"
    );
    assert_eq!(
        h.store(&alice())
            .entry(two["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .version(),
        1
    );
}

#[tokio::test]
async fn c2_audit_is_per_person_filterable_paginated_and_main_only() {
    let h = harness().await;
    let one = h
        .add(&alice(), "general_preferences", "Alice audit phrase")
        .await;
    h.add(&bob(), "general_preferences", "Bob audit phrase")
        .await;
    search_entry(&h, &alice(), &one).await;
    let all = audit(&h, &alice(), json!({})).await;
    assert_eq!(all["events"].as_array().unwrap().len(), 2);
    assert!(!all.to_string().contains("Bob audit phrase"));
    let bobs = audit(&h, &bob(), json!({})).await;
    assert_eq!(bobs["events"].as_array().unwrap().len(), 1);
    assert_ne!(bobs["events"][0]["entryId"], one["id"]);
    let page = audit(&h, &alice(), json!({"limit":1})).await;
    assert_eq!(page["has_more"], true);
    let next = audit(
        &h,
        &alice(),
        json!({"after_cursor":page["next_cursor"],"limit":1}),
    )
    .await;
    assert_eq!(next["events"][0], all["events"][1]);
    let filtered = audit(&h,&alice(),json!({"client_id":"client_one","category":"general_preferences","event_type":"preference.read",
        "from":"2000-01-01T00:00:00Z","through":"2100-01-01T00:00:00Z"})).await;
    assert_eq!(filtered["events"].as_array().unwrap().len(), 1);
    assert!(h
        .native
        .call(
            h.db.clone(),
            alice(),
            AUDIT_TOOL,
            json!({"account_id":"acct:bob"})
        )
        .await
        .is_err());
    assert!(h.registry.get(AUDIT_TOOL).is_none());
    let lens = crate::mcp::lens_descriptor_projection(
        &h.native,
        crate::mcp::interactions::ExposureProfile::Complete,
    )
    .unwrap();
    assert!(!lens.iter().any(|d| d.name == AUDIT_TOOL));
    h.edit_view(&alice(), &record_id_of_entry(&one), |body| {
        body["record"]["status"] = json!("deleted");
        body["record"]["provenance"]["confirmations"] = json!([{"disposition":"confirmed"}]);
    })
    .await;
    assert_eq!(
        audit(&h, &alice(), json!({})).await,
        all,
        "editable view is not audit authority"
    );
    // A fresh replay preserves both the audit and disclosure authority.
    let replayed = replayed_elsewhere(&h).await;
    assert_eq!(audit(&replayed, &alice(), json!({})).await, all);
    let who = alice();
    let store = replayed.store(&who);
    let mut tx = store.begin().await.unwrap();
    assert!(store
        .disclosed_in(&mut tx, one["id"].as_str().unwrap())
        .await
        .unwrap());
}

#[tokio::test]
async fn c2_audit_event_cursors_are_private_ordered_filterable_and_replayable() {
    let h = harness().await;
    let empty = audit(&h, &alice(), json!({})).await;
    assert_eq!(empty["next_cursor"], Value::Null);
    assert!(crate::mcp::counter_fence::find_counters(&empty).is_empty());
    let one = h.add(&alice(), "general_preferences", "Alice first").await;
    let foreign = h.add(&bob(), "general_preferences", "Bob between").await;
    search_entry(&h, &bob(), &foreign).await;
    search_entry(&h, &alice(), &one).await;
    h.add(&bob(), "general_preferences", "Bob again").await;
    h.add(&alice_two(), "general_preferences", "Alice last")
        .await;
    let all = audit(&h, &alice(), json!({})).await;
    let events = all["events"].as_array().unwrap();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["entryId"], one["id"]);
    assert_eq!(events[1]["eventType"], "preference.read");
    assert_eq!(events[2]["native_client_id"], "client_two");
    assert_eq!(all["durabilityWindowMs"], 0);
    assert!(crate::mcp::counter_fence::find_counters(&all).is_empty());
    assert!(events.iter().all(|e| e["entryId"] != foreign["id"]));
    let mut collected = Vec::new();
    let mut args = json!({"limit":1});
    loop {
        let page = audit(&h, &alice(), args).await;
        assert!(crate::mcp::counter_fence::find_counters(&page).is_empty());
        assert_eq!(page["events"].as_array().unwrap().len(), 1);
        let event = page["events"][0].clone();
        assert_eq!(page["next_cursor"], event["eventId"]);
        uuid::Uuid::parse_str(
            event["eventId"]
                .as_str()
                .unwrap()
                .strip_prefix("urn:uuid:")
                .unwrap(),
        )
        .unwrap();
        collected.push(event);
        if page["has_more"] == false {
            break;
        }
        args = json!({"limit":1,"after_cursor":page["next_cursor"]});
    }
    assert_eq!(&collected, events);
    let filtered_args =
        json!({"after_cursor":events[0]["eventId"],"event_type":"preference.read","limit":1});
    let filtered = audit(&h, &alice(), filtered_args.clone()).await;
    assert_eq!(filtered["events"], json!([events[1]]));
    assert_eq!(filtered["has_more"], false);
    let exhausted = audit(&h, &alice(), json!({"after_cursor":events[2]["eventId"]})).await;
    assert_eq!(exhausted["events"], json!([]));
    assert_eq!(exhausted["next_cursor"], events[2]["eventId"]);
    let bobs = audit(&h, &bob(), json!({})).await;
    for cursor in [
        bobs["events"][0]["eventId"].as_str().unwrap(),
        bobs["events"][1]["eventId"].as_str().unwrap(),
        "urn:uuid:00000000-0000-4000-8000-000000000001",
        "not-a-cursor",
        "urn:uuid:broken",
    ] {
        let error = h
            .native
            .call(
                h.db.clone(),
                alice(),
                AUDIT_TOOL,
                json!({"after_cursor":cursor}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, "invalid HCP audit cursor");
    }
    for cursor in [Value::Null, json!(42), json!({"seq":42}), json!([])] {
        let error = h
            .native
            .call(
                h.db.clone(),
                alice(),
                AUDIT_TOOL,
                json!({"after_cursor":cursor}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, "invalid HCP audit cursor");
    }
    assert!(h
        .native
        .call(h.db.clone(), alice(), AUDIT_TOOL, json!({"after_seq":0}))
        .await
        .is_err());
    let replayed = replayed_elsewhere(&h).await;
    assert_eq!(audit(&replayed, &alice(), json!({})).await, all);
    assert_eq!(audit(&replayed, &alice(), filtered_args).await, filtered);
}

#[tokio::test]
async fn c2_authoritative_delete_and_rejection_do_not_release_counterpart() {
    let h = harness().await;
    let declared = dimensional(&h, &alice(), "user-declared", "tone", "Authoritative tone").await;
    h.inject_version(&alice(), declared["id"].as_str().unwrap(), |b| {
        b["record"]["provenance"]["assertedBy"]["assurance"] = json!("authenticated")
    })
    .await;
    let inferred = dimensional(
        &h,
        &alice(),
        "model-inferred",
        "tone",
        "Contradictory inference",
    )
    .await;
    assert_eq!(
        h.store(&alice())
            .entry(declared["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "active"
    );
    assert_eq!(inferred["record"]["status"], "active");
    assert_eq!(
        h.store(&alice())
            .entry(inferred["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "conflicted"
    );
    h.ok(
        &alice(),
        DELETE_PREFERENCE,
        json!({"entryId":declared["id"],"reason":"remove authority"}),
    )
    .await;
    assert_eq!(
        h.store(&alice())
            .entry(inferred["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "conflicted"
    );

    let h = harness().await;
    let declared = dimensional(
        &h,
        &alice(),
        "user-declared",
        "tone",
        "Unverified declaration",
    )
    .await;
    let inferred = dimensional(
        &h,
        &alice(),
        "model-inferred",
        "tone",
        "Unverified inference",
    )
    .await;
    // Exercise the rejection status seam; C3 owns the human workflow/event.
    h.inject_status(
        &alice(),
        inferred["id"].as_str().unwrap(),
        "deleted",
        "rejected",
    )
    .await;
    assert_eq!(
        h.store(&alice())
            .entry(declared["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap()
            .entry
            .status(),
        "conflicted"
    );
}

#[tokio::test]
async fn c2_audit_category_change_names_current_category_and_filters_both() {
    let h = harness().await;
    let entry = h
        .add(&alice(), "general_preferences", "Category audit example")
        .await;
    h.edit_view(&alice(), &record_id_of_entry(&entry), |body| {
        body["record"]["category"] = json!("values_and_ethics")
    })
    .await;
    h.search(&alice(), "example", json!(["values_and_ethics"]))
        .await;
    for category in ["general_preferences", "values_and_ethics"] {
        let log = audit(
            &h,
            &alice(),
            json!({"event_type":"preference.updated","category":category}),
        )
        .await;
        assert_eq!(log["events"].as_array().unwrap().len(), 1);
        assert_eq!(log["events"][0]["category"], "values_and_ethics");
        assert_eq!(
            log["events"][0]["participants"]["clientOperator"]["name"],
            "Native"
        );
    }
}
