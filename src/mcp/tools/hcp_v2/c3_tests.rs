use super::*;

async fn pair(h: &Harness) -> (Value, Value, String) {
    let declared =
        super::c2::dimensional(h, &alice(), "user-declared", "c3-tone", "Declared tone").await;
    let inferred =
        super::c2::dimensional(h, &alice(), "model-inferred", "c3-tone", "Inferred tone").await;
    let fold = h.store(&alice()).fold_all().await.unwrap();
    let mapping = fold
        .suggestions
        .values()
        .find(|p| p.entry_id == inferred["id"])
        .expect("sealed suggestion mapping");
    (declared, inferred, mapping.suggestion_id.clone())
}

async fn resolve(h: &Harness, id: &str, action: &str, human: bool) -> Value {
    let args = json!({"action":action,"suggestion_ids":[id],"reason":"C3 review"});
    let mut who = alice().with_channel(Channel::Web);
    if human {
        let issuer = crate::provenance::ProvenanceInteractionTokenIssuer::random("test-workbench");
        let scope = crate::provenance::verified_action_scope("resolve_suggestions", &args);
        let token = issuer.issue(who.credential(), &scope, 60).unwrap();
        who = who
            .with_provenance_interaction_token(&issuer, &token, &scope)
            .unwrap();
    }
    h.native
        .call(h.db.clone(), who, "resolve_suggestions", args)
        .await
        .unwrap()
}

async fn touch(h: &Harness) {
    h.search(&alice(), "tone", json!(["general_preferences"]))
        .await;
}

#[tokio::test]
async fn c3_genuine_accept_is_version_bound_idempotent_and_replayable() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    assert_eq!(resolve(&h, &id, "accept", true).await["status"], "accepted");
    touch(&h).await;
    let before = h.store(&alice()).fold_all().await.unwrap();
    let entry = before.entries[inferred["id"].as_str().unwrap()].current();
    assert!(entry.confirmed());
    assert_eq!(entry.status(), "active");
    assert_eq!(entry.version(), 1);
    assert_eq!(entry.declaration_type(), "model-inferred");
    assert_eq!(entry.assurance(), "unverified");
    for _ in 0..3 {
        touch(&h).await;
    }
    assert_eq!(
        h.store(&alice())
            .fold_all()
            .await
            .unwrap()
            .resolutions
            .len(),
        1
    );
    let replayed = replayed_elsewhere(&h).await;
    let after = replayed.store(&alice()).fold_all().await.unwrap();
    assert_eq!(
        after.entries[inferred["id"].as_str().unwrap()].current().0,
        entry.0
    );
    assert!(after.rejected.is_empty(), "{:?}", after.rejected);
    let audit = super::c2::audit(&h, &alice(), json!({"event_type":"preference.confirmed"})).await;
    assert_eq!(audit["events"].as_array().unwrap().len(), 1);
    assert_eq!(audit["events"][0]["detail"], "confirmed");
    assert_eq!(audit["events"][0]["version"], 1);
    assert_eq!(audit["next_cursor"], audit["events"][0]["eventId"]);
    assert!(crate::mcp::counter_fence::find_counters(&audit).is_empty());
    assert_eq!(
        audit["events"][0]["participants"]["initiator"]["role"],
        "management-client"
    );
}

#[tokio::test]
async fn c3_web_bearer_resolution_is_not_a_confirmation() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    assert_eq!(
        resolve(&h, &id, "reject", false).await["status"],
        "rejected"
    );
    touch(&h).await;
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert!(fold.resolutions.is_empty());
    assert_eq!(
        fold.entries[inferred["id"].as_str().unwrap()]
            .current()
            .status(),
        "conflicted"
    );
}

#[tokio::test]
async fn c3_pending_rejection_precedes_update_and_preserves_counterpart_gap() {
    let h = harness().await;
    let (declared, inferred, id) = pair(&h).await;
    resolve(&h, &id, "reject", true).await;
    assert_eq!(h.err(&alice(), UPDATE_PREFERENCE, json!({"entryId":inferred["id"],"updatedPreference":"replacement","confidence":"high","assertedBy":"test:model","reason":"revise"})).await["type"], SCOPE_DENIED);
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert!(fold.entries[inferred["id"].as_str().unwrap()]
        .current()
        .rejected());
    assert_eq!(
        fold.entries[inferred["id"].as_str().unwrap()]
            .current()
            .version(),
        1
    );
    assert_eq!(
        fold.entries[declared["id"].as_str().unwrap()]
            .current()
            .status(),
        "conflicted"
    );
}

#[tokio::test]
async fn c3_pending_accept_precedes_native_edit_and_new_version_has_no_endorsement() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    resolve(&h, &id, "accept", true).await;
    let record = super::store::record_id_of(inferred["id"].as_str().unwrap()).unwrap();
    let mut body: Value = serde_json::from_str(
        &sqlx::query_scalar::<_, String>("SELECT body FROM records WHERE id=?")
            .bind(&record)
            .fetch_one(h.db.write_pool())
            .await
            .unwrap(),
    )
    .unwrap();
    body["claim"]["subject"]["preference"] = json!("Person revised tone");
    replace_view_body(&h, &alice(), &record, &body.to_string()).await;
    touch(&h).await;
    let fold = h.store(&alice()).fold_all().await.unwrap();
    let entry = &fold.entries[inferred["id"].as_str().unwrap()];
    assert_eq!(fold.resolutions.len(), 1);
    assert!(entry.versions[0].confirmed());
    assert_eq!(entry.current().version(), 2);
    assert!(!entry.current().confirmed());
    assert_eq!(entry.current().preference(), "Person revised tone");
}

#[tokio::test]
async fn c3_obsolete_version_and_reworded_restored_suggestions_cannot_confirm() {
    for obsolete in [true, false] {
        let h = harness().await;
        let (_, inferred, id) = pair(&h).await;
        if obsolete {
            h.ok(&alice(),UPDATE_PREFERENCE,json!({"entryId":inferred["id"],"updatedPreference":"New inferred tone","confidence":"high","assertedBy":"test:model","reason":"revise"})).await;
            let archived: bool = sqlx::query_scalar("SELECT archived FROM records WHERE id=?")
                .bind(&id)
                .fetch_one(h.db.write_pool())
                .await
                .unwrap();
            assert!(archived, "obsolete suggestion withdrawn");
            // Even restoring it and resolving with genuine human evidence
            // cannot move its version-bound endorsement onto version two.
            h.native
                .call(
                    h.db.clone(),
                    alice(),
                    "archive_record",
                    json!({"id":id,"archived":false,"reason":"restore old question"}),
                )
                .await
                .unwrap();
        } else {
            let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
                .bind(&id)
                .fetch_one(h.db.write_pool())
                .await
                .unwrap();
            for text in [format!("{body} "), body] {
                replace_view_body(&h, &alice(), &id, &text).await;
            }
        }
        resolve(&h, &id, "reject", true).await;
        touch(&h).await;
        assert!(h
            .store(&alice())
            .fold_all()
            .await
            .unwrap()
            .resolutions
            .is_empty());
    }
}

#[tokio::test]
async fn c3_control_failure_rolls_back_confirmation_and_status_audit_together() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    resolve(&h, &id, "accept", true).await;
    sqlx::query("CREATE TRIGGER fail_c3_status BEFORE INSERT ON control_events WHEN NEW.type='hcp.entry.status_set.v1' AND json_extract(NEW.payload,'$.cause')='confirmed' BEGIN SELECT RAISE(ABORT,'c3 failure'); END").execute(h.db.write_pool()).await.unwrap();
    let error = h
        .frame(
            &alice(),
            SEARCH_PREFERENCES,
            json!({"query":"tone","categories":["general_preferences"],"purpose":"test rollback"}),
        )
        .await;
    assert_eq!(error["isError"], true);
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert!(fold.resolutions.is_empty());
    assert!(!fold.entries[inferred["id"].as_str().unwrap()]
        .current()
        .confirmed());
    assert_eq!(
        fold.entries[inferred["id"].as_str().unwrap()]
            .current()
            .status(),
        "conflicted"
    );
    sqlx::query("DROP TRIGGER fail_c3_status")
        .execute(h.db.write_pool())
        .await
        .unwrap();
    touch(&h).await;
    assert_eq!(
        h.store(&alice())
            .fold_all()
            .await
            .unwrap()
            .resolutions
            .len(),
        1
    );
}

#[tokio::test]
async fn c3_direct_get_checks_disclosure_before_confirmation_side_effects() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    resolve(&h, &id, "accept", true).await;
    assert_eq!(
        h.err(&alice_two(), GET_PREFERENCE, get_args(&inferred))
            .await["type"],
        SCOPE_DENIED
    );
    assert!(h
        .store(&alice())
        .fold_all()
        .await
        .unwrap()
        .resolutions
        .is_empty());
    h.ok(&alice(), GET_PREFERENCE, get_args(&inferred)).await;
    assert_eq!(
        h.store(&alice())
            .fold_all()
            .await
            .unwrap()
            .resolutions
            .len(),
        1
    );
}

#[test]
fn c3_confirmation_view_is_bounded_even_at_the_existing_entry_size_ceiling() {
    let subject = super::store::stored_subject_id_of("acct:alice");
    let client = ClientIdentity::native();
    let mut entry = super::model::new_entry(
        "urn:uuid:00000000-0000-4000-8000-000000000001",
        "general_preferences",
        None,
        &subject,
        &super::model::Assertion {
            preference: &json!("tone"),
            declaration_type: "model-inferred",
            confidence: Some("high"),
            asserted_by: "test:model",
            source: "test",
            client: &client,
            recorded_at: "2026-10-24T00:00:00Z",
            asserted_at: None,
        },
    );
    entry.0["record"]["metadata"] = json!({"padding":"x".repeat(60000)});
    let encoded = serde_json::to_string(&entry.0.to_string()).unwrap().len();
    let spare = crate::control::HCP_ENTRY_MAX_ENCODED_BYTES - encoded;
    entry.0["record"]["metadata"]["padding"] = json!("x".repeat(60000 + spare));
    assert!(crate::control::hcp_entry_fits(&entry.0.to_string()));
    for _ in 0..20 {
        entry.add_confirmation("confirmed", &subject, "2026-10-24T00:00:00Z");
    }
    assert!(
        entry.confirmed(),
        "trusted standing is retained independently of view trimming"
    );
    assert_eq!(
        entry.0["record"]["provenance"]["confirmations"]
            .as_array()
            .unwrap()
            .len(),
        20
    );
    assert!(crate::control::hcp_entry_fits(&entry.view_body()));
    entry.set_status("deleted");
    assert!(crate::control::hcp_entry_fits(&entry.view_body()));
    assert!(super::model::Entry::parse(&entry.view_body()).is_some());
}

#[tokio::test]
async fn c3_planted_transplanted_and_relinked_suggestions_cannot_confirm() {
    for relink in [false, true] {
        let h = harness().await;
        let (_, inferred, id) = pair(&h).await;
        let target = super::store::record_id_of(inferred["id"].as_str().unwrap()).unwrap();
        let selected = if relink {
            h.native.call(h.db.clone(),alice(),"manage_links",json!({"action":"remove","source_id":id,"target_id":target,"relationship":"part_of"})).await.unwrap();
            // Without its bearer the derived record is inaccessible. That
            // ordinary authorization refusal prevents a resolution output;
            // the later HCP touch heals a fresh, correctly attached question.
            let args = json!({"action":"reject","suggestion_ids":[id],"reason":"resolve detached question"});
            let issuer =
                crate::provenance::ProvenanceInteractionTokenIssuer::random("test-workbench");
            let scope = crate::provenance::verified_action_scope("resolve_suggestions", &args);
            let token = issuer.issue(alice().credential(), &scope, 60).unwrap();
            let human = alice()
                .with_provenance_interaction_token(&issuer, &token, &scope)
                .unwrap();
            assert!(h
                .native
                .call(h.db.clone(), human, "resolve_suggestions", args)
                .await
                .is_err());
            touch(&h).await;
            let fold = h.store(&alice()).fold_all().await.unwrap();
            assert!(fold.resolutions.is_empty());
            assert_eq!(
                fold.suggestions.len(),
                2,
                "a valid replacement is projected"
            );
            continue;
        } else {
            let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
                .bind(&id)
                .fetch_one(h.db.write_pool())
                .await
                .unwrap();
            let cloned = h.native.call(h.db.clone(),alice(),"create_record",json!({"type":"Annotation","kind":"suggestion","name":"Copied inference question","body":body,"lifecycle":"open","links":[{"target_id":target,"relationship":"part_of"}],"facets":{"proposal.precondition":"digest","anchor.base_digest":super::store::sha256_hex(&body)},"reason":"plant copy","confirm":true})).await.unwrap();
            cloned["id"].as_str().unwrap().to_string()
        };
        resolve(&h, &selected, "reject", true).await;
        touch(&h).await;
        assert!(h
            .store(&alice())
            .fold_all()
            .await
            .unwrap()
            .resolutions
            .is_empty());
    }
}

#[tokio::test]
async fn c3_invalidated_or_wrong_owner_human_evidence_is_ignored() {
    for wrong_owner in [false, true] {
        let h = harness().await;
        let (_, _, id) = pair(&h).await;
        if wrong_owner {
            // A different account's valid human receipt cannot be transplanted
            // onto Alice's suggestion, even if that account can resolve it.
            let target = super::store::record_id_of(
                h.store(&alice()).fold_all().await.unwrap().suggestions[&id]
                    .entry_id
                    .as_str(),
            )
            .unwrap();
            hand_view_to(&h, &target, &["acct:alice", "acct:bob"]).await;
            let args = json!({"action":"reject","suggestion_ids":[id],"reason":"other owner"});
            let issuer =
                crate::provenance::ProvenanceInteractionTokenIssuer::random("test-workbench");
            let scope = crate::provenance::verified_action_scope("resolve_suggestions", &args);
            let token = issuer.issue(bob().credential(), &scope, 60).unwrap();
            let other = bob()
                .with_provenance_interaction_token(&issuer, &token, &scope)
                .unwrap();
            let result = h
                .native
                .call(h.db.clone(), other, "resolve_suggestions", args)
                .await
                .unwrap();
            assert_eq!(result["status"], "rejected");
            hand_view_to(&h, &target, &["acct:alice"]).await;
        } else {
            resolve(&h, &id, "reject", true).await;
            sqlx::query("INSERT INTO provenance_attestation_validity_events(id,attestation_id,ordinal,status,reason,issuer,issued_at) SELECT 'c3-invalid-'||id,id,0,'invalidated','test invalidation','operator','2026-10-24T00:00:00Z' FROM provenance_action_attestations WHERE operation='resolve_suggestions'").execute(h.db.write_pool()).await.unwrap();
        }
        touch(&h).await;
        assert!(h
            .store(&alice())
            .fold_all()
            .await
            .unwrap()
            .resolutions
            .is_empty());
    }
}

async fn authoritative_pair(h: &Harness) -> (String, Value, String) {
    let who = alice();
    let store = h.store(&who);
    let client = ClientIdentity::native();
    let urn = super::store::entry_urn(&uuid::Uuid::new_v4().to_string());
    let mut declared = super::model::new_entry(
        &urn,
        "general_preferences",
        Some("authority-tone"),
        &store.stored_subject_id(),
        &super::model::Assertion {
            preference: &json!("Authoritative declared tone"),
            declaration_type: "user-declared",
            confidence: None,
            asserted_by: &store.stored_subject_id(),
            source: "test:management",
            client: &client,
            recorded_at: &super::model::timestamp(chrono::Utc::now()),
            asserted_at: None,
        },
    );
    // A fixture for an authenticated management statement. MCP never elevates
    // client declarations this way; it is testing the retained standing rule.
    declared.0["record"]["provenance"]["assertedBy"]["assurance"] = json!("authenticated");
    let mut tx = store.begin().await.unwrap();
    store
        .append_add(&mut tx, &mut crate::act::ActAllocation::new(), &declared)
        .await
        .unwrap();
    store.commit(tx).await.unwrap();
    store.sync_version_views(&urn).await;
    let inferred = super::c2::dimensional(
        h,
        &who,
        "model-inferred",
        "authority-tone",
        "Inferred authoritative tone",
    )
    .await;
    let fold = store.fold_all().await.unwrap();
    let id = fold
        .suggestions
        .values()
        .find(|p| p.entry_id == inferred["id"])
        .unwrap()
        .suggestion_id
        .clone();
    (urn, inferred, id)
}

#[tokio::test]
async fn c3_accept_deprecates_authoritative_counterpart_in_same_act() {
    let h = harness().await;
    let (declared, inferred, id) = authoritative_pair(&h).await;
    resolve(&h, &id, "accept", true).await;
    touch(&h).await;
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert_eq!(fold.entries[&declared].current().status(), "deprecated");
    assert_eq!(
        fold.entries[inferred["id"].as_str().unwrap()]
            .current()
            .status(),
        "active"
    );
    let acts:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT act FROM control_events WHERE type='hcp.entry.confirmed.v1' OR (type='hcp.entry.status_set.v1' AND json_extract(payload,'$.cause') IN ('deprecated','confirmed'))").fetch_all(h.db.write_pool()).await.unwrap();
    assert_eq!(acts.len(), 1);
}

#[tokio::test]
async fn c3_counterpart_append_failure_rolls_back_confirmation() {
    let h = harness().await;
    let (declared, inferred, id) = authoritative_pair(&h).await;
    resolve(&h, &id, "accept", true).await;
    sqlx::query("CREATE TRIGGER fail_c3_deprecate BEFORE INSERT ON control_events WHEN NEW.type='hcp.entry.status_set.v1' AND json_extract(NEW.payload,'$.cause')='deprecated' BEGIN SELECT RAISE(ABORT,'counterpart failure'); END").execute(h.db.write_pool()).await.unwrap();
    assert!(h
        .store(&alice())
        .consume_resolutions(inferred["id"].as_str().unwrap())
        .await
        .is_err());
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert!(fold.resolutions.is_empty());
    assert_eq!(fold.entries[&declared].current().status(), "active");
    assert_eq!(
        fold.entries[inferred["id"].as_str().unwrap()]
            .current()
            .status(),
        "conflicted"
    );
}

#[tokio::test]
async fn c3_stale_suggestion_never_overwrites_an_unaccepted_native_edit() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    let target = super::store::record_id_of(inferred["id"].as_str().unwrap()).unwrap();
    let text = "My unfinished edit stays here, even though it is not grouped JSON";
    replace_view_body(&h, &alice(), &target, text).await;
    assert_eq!(resolve(&h, &id, "accept", true).await["status"], "stale");
    touch(&h).await;
    let held: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&target)
        .fetch_one(h.db.write_pool())
        .await
        .unwrap();
    assert_eq!(held, text);
    assert!(h
        .store(&alice())
        .fold_all()
        .await
        .unwrap()
        .resolutions
        .is_empty());
}

#[tokio::test]
async fn c3_concurrent_touches_heal_one_withdrawn_suggestion_without_duplicates() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    h.native
        .call(
            h.db.clone(),
            alice(),
            "archive_record",
            json!({"id":id,"reason":"withdraw old UI projection"}),
        )
        .await
        .unwrap();
    tokio::join!(touch(&h), touch(&h));
    let target = super::store::record_id_of(inferred["id"].as_str().unwrap()).unwrap();
    let count:i64=sqlx::query_scalar("SELECT count(*) FROM records r JOIN links l ON l.source_id=r.id AND l.target_id=? AND l.relationship='part_of' WHERE r.kind='suggestion' AND r.lifecycle='open' AND r.archived=0").bind(&target).fetch_one(h.db.write_pool()).await.unwrap();
    assert_eq!(count, 1);
    let fold = h.store(&alice()).fold_all().await.unwrap();
    assert_eq!(
        fold.suggestions.len(),
        2,
        "both immutable mappings retained"
    );
    assert!(fold.rejected.is_empty());
}

#[tokio::test]
async fn c3_mapping_and_confirmation_are_reserved_and_validate_on_replay() {
    use crate::control::{ControlEventPayload, NewControlEvent};
    let h = harness().await;
    let (_, _, id) = pair(&h).await;
    resolve(&h, &id, "accept", true).await;
    touch(&h).await;
    let mut conn = h.db.write_pool().acquire().await.unwrap();
    let rows = crate::control::read_all_control_events(&mut conn)
        .await
        .unwrap();
    drop(conn);
    for row in rows.into_iter().filter(|r| {
        matches!(
            r.event_type.as_str(),
            "hcp.entry.suggestion.v1" | "hcp.entry.confirmed.v1"
        )
    }) {
        crate::control::validate_stored_control_event(&row).unwrap();
        assert!(crate::control::validate_control_event(&row)
            .unwrap_err()
            .to_string()
            .contains("reserved for the HCP v2 handler"));
        let payload = if row.event_type == "hcp.entry.suggestion.v1" {
            ControlEventPayload::HcpEntrySuggestion(serde_json::from_str(&row.payload).unwrap())
        } else {
            ControlEventPayload::HcpEntryConfirmed(serde_json::from_str(&row.payload).unwrap())
        };
        assert!(NewControlEvent::authored(
            "forged-c3",
            row.aggregate_id.clone(),
            "acct:alice",
            None,
            "forged",
            payload
        )
        .is_err());
        let mut malformed = row;
        let mut payload: Value = serde_json::from_str(&malformed.payload).unwrap();
        if malformed.event_type == "hcp.entry.suggestion.v1" {
            payload["body_digest"] = json!("forged");
        } else {
            payload["disposition"] = json!("trusted-by-model");
        }
        malformed.payload = payload.to_string();
        assert!(crate::control::validate_stored_control_event(&malformed).is_err());
    }
}

#[tokio::test]
async fn c3_resolution_arriving_after_preliminary_touch_is_consumed_inside_revision_snapshot() {
    let h = harness().await;
    let (_, inferred, id) = pair(&h).await;
    let who = alice();
    let store = h.store(&who);
    store
        .pick_up_edit(inferred["id"].as_str().unwrap())
        .await
        .unwrap();
    resolve(&h, &id, "reject", true).await;
    let mut tx = store.begin().await.unwrap();
    assert!(store
        .consume_resolutions_in(
            &mut tx,
            &mut crate::act::ActAllocation::new(),
            inferred["id"].as_str().unwrap()
        )
        .await
        .unwrap());
    let current = store
        .entry_in(&mut tx, inferred["id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(!current
        .entry
        .updatable_by_context_client(chrono::Utc::now()));
    assert!(current.entry.rejected());
    tx.rollback().await.unwrap();
    assert!(
        store.fold_all().await.unwrap().resolutions.is_empty(),
        "writer rollback retains pending evidence for the next touch"
    );
    touch(&h).await;
    assert_eq!(store.fold_all().await.unwrap().resolutions.len(), 1);
}
