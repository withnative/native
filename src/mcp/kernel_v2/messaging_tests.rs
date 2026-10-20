use super::*;
use crate::{events::KERNEL_ROOT_ID, mcp::registry::EngineHandle};
use std::collections::BTreeSet;
struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
    viewer: String,
    outsider: String,
    origin: String,
}

/// The exact polling handshake used by appV2.ts for both Attention and
/// Messages, followed by the ordinary reads their refresh signal re-runs.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn whats_changed_fallback_refreshes_cross_actor_messages_without_private_signals() {
    let w = world().await;
    let baseline = call(
        &w,
        "acct:viewer",
        "whats_changed",
        json!({"actor_scope":"all","limit":1}),
    )
    .await
    .unwrap();
    let after = baseline["high_water_local_seq"].as_i64().unwrap();
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "poll-channel"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let poll = call(
        &w,
        "acct:viewer",
        "whats_changed",
        json!({"actor_scope":"all","limit":1,"after_local_seq":after}),
    )
    .await
    .unwrap();
    assert!(poll["high_water_local_seq"].as_i64().unwrap() > after);
    assert!(!poll["changes"].as_array().unwrap().is_empty());
    // Messages re-reads records; Attention re-reads needs_me. Both see the
    // other actor's send using the same signal, with no sender-local callback.
    let record = call(
        &w,
        "acct:viewer",
        "get_record",
        json!({"id":id,"children_limit":0}),
    )
    .await
    .unwrap();
    assert!(record.to_string().contains(id));
    let context = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_context","origin":{"type":"collection","collection_id":w.origin}}),
    )
    .await
    .unwrap();
    assert!(
        context.to_string().contains(id),
        "refresh discovers the Message without knowing its id"
    );
    let inbox = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"needs_me"}),
    )
    .await
    .unwrap();
    assert!(inbox.to_string().contains(id));
    let mut next = poll;
    let mut sequences = BTreeSet::new();
    loop {
        for change in next["changes"].as_array().unwrap() {
            assert!(sequences.insert(change["first_local_seq"].as_i64().unwrap()));
        }
        if next["has_more"] != true {
            break;
        }
        next = call(
            &w,
            "acct:viewer",
            "whats_changed",
            next["next_request"].clone(),
        )
        .await
        .unwrap();
    }
    let after = next["high_water_local_seq"].as_i64().unwrap();
    let mut private = send_args(&w, "poll-private");
    private["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let private = call(&w, "acct:admin", "manage_messages", private)
        .await
        .unwrap();
    let hidden = call(
        &w,
        "acct:outsider",
        "whats_changed",
        json!({"after_local_seq":after,"actor_scope":"all","limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(
        hidden["changes"],
        json!([]),
        "hidden Message and home/link events must not signal changes: {hidden}"
    );
    assert_eq!(hidden["matched_event_count"], 0);
    assert_eq!(hidden["scanned_event_count"], 0);
    assert_eq!(hidden["has_more"], false);
    assert!(!hidden.to_string().contains(private["id"].as_str().unwrap()));
    let self_only = call(
        &w,
        "acct:viewer",
        "whats_changed",
        json!({"after_local_seq":after,"actor_scope":"self"}),
    )
    .await
    .unwrap();
    assert_eq!(self_only["changes"], json!([]));
    let empty = call(
        &w,
        "acct:viewer",
        "whats_changed",
        json!({"after_local_seq":hidden["high_water_local_seq"]}),
    )
    .await
    .unwrap();
    assert_eq!(empty["changes"], json!([]));

    let after = empty["high_water_local_seq"].clone();
    call(&w,"acct:viewer","manage_messages",json!({"action":"set_preference","message_id":private["id"],"preference":"mark_read","expected_version":0,"idempotency_key":"poll-read","reason":"Read in another client"})).await.unwrap();
    let own = call(
        &w,
        "acct:viewer",
        "whats_changed",
        json!({"after_local_seq":after}),
    )
    .await
    .unwrap();
    assert_eq!(own["changes"].as_array().unwrap().len(), 1);
    assert_eq!(own["changes"][0]["record_id"], private["id"]);
    for account in ["acct:admin", "acct:outsider"] {
        let other = call(
            &w,
            account,
            "whats_changed",
            json!({"after_local_seq":after}),
        )
        .await
        .unwrap();
        assert_eq!(
            other["changes"],
            json!([]),
            "private read state must not signal to {account}"
        );
    }
    let after = own["high_water_local_seq"].clone();
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👀","idempotency_key":"poll-react","reason":"React in another client"})).await.unwrap();
    for account in ["acct:viewer", "acct:outsider"] {
        let public = call(
            &w,
            account,
            "whats_changed",
            json!({"after_local_seq":after}),
        )
        .await
        .unwrap();
        assert_eq!(public["changes"].as_array().unwrap().len(), 1);
        assert_eq!(public["changes"][0]["record_id"], id);
        assert!(!public.to_string().contains("W6 needle"));
    }
    let mut newest = call(
        &w,
        "acct:viewer",
        "whats_changed",
        json!({"order":"newest_first","limit":1}),
    )
    .await
    .unwrap();
    let mut previous = i64::MAX;
    loop {
        for change in newest["changes"].as_array().unwrap() {
            let seq = change["first_local_seq"].as_i64().unwrap();
            assert!(seq < previous);
            previous = seq;
        }
        if newest["has_more"] != true {
            break;
        }
        newest = call(
            &w,
            "acct:viewer",
            "whats_changed",
            newest["next_request"].clone(),
        )
        .await
        .unwrap();
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_realtime_tail_filters_private_messages_and_rings_only_the_recipient() {
    use crate::realtime::RealtimeHub;
    let mut w = world().await;
    let (db, hub) = RealtimeHub::attach(w.db.clone(), None).await.unwrap();
    w.db = db;
    let before = hub.inbox_invalidation_vector().await.unwrap();
    let mut receiver = hub.subscribe();
    let mut private = send_args(&w, "live-private");
    private["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let sent = call(&w, "acct:admin", "manage_messages", private)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let after = hub.inbox_invalidation_vector().await.unwrap();
    crate::realtime::wait_until_published_for_tests(&w.db, after.content).await;
    assert!(hub
        .inbox_addressed_since("acct:viewer", &before, &after)
        .await
        .unwrap());
    assert!(!hub
        .inbox_addressed_since("acct:outsider", &before, &after)
        .await
        .unwrap());
    let mut received = BTreeSet::new();
    while let Ok(envelope) = receiver.try_recv() {
        received.insert(envelope.local_seq);
    }
    assert!(
        received.contains(&after.content),
        "commit must wake the durable hub"
    );
    let rows = hub
        .content_invalidations(before.content, after.content, 256)
        .await
        .unwrap();
    let mut message_seen = false;
    for envelope in &rows {
        assert!(
            !hub.can_view_invalidation_for_account("acct:outsider", true, envelope)
                .await,
            "hidden metadata: {envelope:?}"
        );
        if envelope.record_id == id
            && hub
                .can_view_invalidation_for_account("acct:viewer", true, envelope)
                .await
        {
            assert_ne!(envelope.event_type, "kernel.message_state.v1");
            message_seen = true;
        }
    }
    assert!(message_seen);
    let request = crate::realtime::v2::AppDataRequest {
        package: "agent.attention-cockpit".into(),
        expected_install_event_id: "uninstalled".into(),
        need: None,
        params: json!({}),
    };
    assert!(!hub.has_app_data_needs());
    assert!(hub
        .evaluate_app_data(&Caller::authenticated("acct:viewer"), &request)
        .await
        .unwrap_err()
        .to_string()
        .contains("[evaluator_unavailable]"));
    assert!(hub
        .revalidate_app_data(&Caller::authenticated("acct:viewer"), &request)
        .await
        .unwrap_err()
        .to_string()
        .contains("[evaluator_unavailable]"));
    // Payload-free filtering rechecks current View, including grant loss
    // after a row has already entered the shared tail.
    let state = kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &state.home_id, &[(&w.admin, "manage")])
        .await
        .unwrap();
    for envelope in &rows {
        assert!(
            !hub.can_view_invalidation_for_account("acct:viewer", true, envelope)
                .await
        );
    }
}
async fn call(w: &World, who: &str, tool: &str, args: Value) -> Result<Value> {
    super::super::tests::registry()
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            Caller::authenticated(who),
            tool,
            args,
        )
        .await
}
async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("v2.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let outsider = kernel::create_principal(&db, "account", "Outsider", "acct:outsider", &admin)
        .await
        .unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let identity = package.identity().unwrap();
    kernel::install_package_as(&db, &admin, &package)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    kernel::replace_home_policy(
        &db,
        &admin,
        KERNEL_ROOT_ID,
        &[(&admin, "manage"), (&viewer, "edit"), (&outsider, "view")],
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (id, typ, kind, principal) in [
        ("person:admin", "Entity", "person", Some(admin.clone())),
        ("person:viewer", "Entity", "person", Some(viewer.clone())),
        (
            "person:outsider",
            "Entity",
            "person",
            Some(outsider.clone()),
        ),
        ("origin", "Collection", "folder", None),
    ] {
        kernel::import_record_as(
            &db,
            &host,
            id,
            KERNEL_ROOT_ID,
            Some(&admin),
            &kernel::ImportRecordState {
                message_principal: principal,
                definition: Some(kernel::ImportDefinition {
                    pin: crate::meta::definition_artifact::RevisionIdentity {
                        family: package.definitions[0].family.clone(),
                        version: package.definitions[0].version,
                        digest: package.definitions[0].digest.clone(),
                    },
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        typ,
                        kind,
                        Some(id),
                        None,
                        None,
                    ),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }
    World {
        _dir: dir,
        db,
        admin,
        viewer,
        outsider,
        origin: "origin".into(),
    }
}
fn send_args(w: &World, key: &str) -> Value {
    json!({"action":"send","id":uuid::Uuid::new_v4().to_string(),"body":"W6 sealed needle","addressed_to":["person:viewer"],"origin":{"type":"collection","collection_id":w.origin},"expectation":"reply","idempotency_key":key,"reason":"Messaging proof"})
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_open_routing_and_revoked_access_match_v1() {
    let w = world().await;
    let mut args = send_args(&w, "notification-mention-only");
    args["expectation"] = json!("none");
    args["body"] = json!("@Viewer");
    args["mentions"] = json!([{"mention_id":"only","target_kind":"principal","target_id":"person:viewer","span_start":0,"span_end":7,"authored_label":"@Viewer"}]);
    let sent = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let harvest =
        crate::awareness::harvest_host_notification_candidates(&w.db, "acct:viewer", true, 0, 500)
            .await
            .unwrap();
    assert_eq!(harvest.candidates.len(), 1);
    assert_eq!(harvest.candidates[0].reason, "principal_mention");
    let route = |obligation: &str, executor: &str, version: i64, key: &str| json!({"action":"set_routing","message_id":id,"obligation_state":obligation,"executor_route":executor,"expected_version":version,"idempotency_key":key,"reason":"Choose route"});
    let registry = super::super::tests::registry();
    let human = |nonce: &str| {
        Caller::authenticated("acct:viewer").with_verified_human_interaction(
            crate::awareness::VerifiedHumanInteraction {
                nonce: nonce.into(),
                executor_ref: "proof-host".into(),
            },
        )
    };
    registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            human("route-one"),
            "manage_messages",
            route("open", "human", 0, "notify-human-route"),
        )
        .await
        .unwrap();
    assert_eq!(
        crate::awareness::harvest_host_notification_candidates(&w.db, "acct:viewer", true, 0, 500)
            .await
            .unwrap()
            .candidates
            .len(),
        2
    );
    registry.call_engine(EngineHandle::KernelV2(w.db.clone()),human("opened-one"),"manage_messages",json!({"action":"mutate_human_awareness","message_ids":[id],"expected_versions":{id:0},"stage":"opened","idempotency_key":"notify-opened","reason":"Open message"})).await.unwrap();
    let opened =
        crate::awareness::harvest_host_notification_candidates(&w.db, "acct:viewer", true, 0, 500)
            .await
            .unwrap();
    assert!(opened.candidates.is_empty());
    assert_eq!(
        crate::awareness::host_live_notification_candidate_message_id(
            &w.db,
            &harvest.candidates[0].candidate_id
        )
        .await
        .unwrap(),
        None
    );
    assert_eq!(
        crate::awareness::host_live_notification_candidate_message_id(&w.db, "missing-candidate")
            .await
            .unwrap(),
        None
    );
    assert!(opened.scanned_through > harvest.scanned_through);
    registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            human("route-two"),
            "manage_messages",
            route("none", "unassigned", 1, "notify-route-close"),
        )
        .await
        .unwrap();
    registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            human("route-three"),
            "manage_messages",
            route("open", "human", 2, "notify-route-reopen"),
        )
        .await
        .unwrap();
    assert!(crate::awareness::harvest_host_notification_candidates(
        &w.db,
        "acct:viewer",
        true,
        0,
        500
    )
    .await
    .unwrap()
    .candidates
    .is_empty());
    // A queued proposal cannot authorize delivery after the record is hidden.
    let fresh = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "notify-revocation"),
    )
    .await
    .unwrap();
    let queued = crate::awareness::harvest_host_notification_candidates(
        &w.db,
        "acct:viewer",
        true,
        opened.scanned_through,
        500,
    )
    .await
    .unwrap();
    assert_eq!(queued.candidates.len(), 1);
    kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let denied = crate::awareness::harvest_host_notification_candidates(
        &w.db,
        "acct:viewer",
        true,
        opened.scanned_through,
        500,
    )
    .await
    .unwrap();
    assert!(denied.candidates.is_empty());
    assert_eq!(denied.scanned_through, queued.scanned_through);
    assert!(
        !crate::awareness::revalidate_host_notification_candidate(
            &w.db,
            &queued.candidates[0].candidate_id,
            "acct:viewer",
            true
        )
        .await
        .unwrap()
        .unwrap()
        .effective_viewable_unmuted
    );
    assert!(call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_notification_candidates"})
    )
    .await
    .unwrap()["candidates"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(
        kernel::read_record_as(&w.db, &w.viewer, fresh["id"].as_str().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_candidates_frontiers_preferences_and_replay_are_recipient_private() {
    let w = world().await;
    let initial_vector = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    let mut send = send_args(&w, "notify-send");
    send["body"] = json!("@Viewer please reply");
    send["mentions"] = json!([{"mention_id":"m1","target_kind":"principal","target_id":"person:viewer","span_start":0,"span_end":7,"authored_label":"@Viewer"}]);
    let sent = call(&w, "acct:admin", "manage_messages", send.clone())
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let notified_vector = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    assert!(notified_vector.candidates > initial_vector.candidates);
    assert!(crate::realtime::inbox_addressed_since(
        w.db.pool(),
        "acct:viewer",
        &initial_vector,
        &notified_vector
    )
    .await
    .unwrap());
    assert!(!crate::realtime::inbox_addressed_since(
        w.db.pool(),
        "acct:outsider",
        &initial_vector,
        &notified_vector
    )
    .await
    .unwrap());

    let list = json!({"action":"list_notification_candidates","limit":1});
    let first = call(&w, "acct:viewer", "manage_messages", list.clone())
        .await
        .unwrap();
    assert_eq!(first["candidates"].as_array().unwrap().len(), 1);
    let seq = first["scanned_through"].as_i64().unwrap();
    let second = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_notification_candidates","after_seq":seq,"limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(second["candidates"].as_array().unwrap().len(), 1);
    assert_ne!(
        first["candidates"][0]["reason"],
        second["candidates"][0]["reason"]
    );
    let head = second["head"].as_i64().unwrap();
    for who in ["acct:admin", "acct:outsider"] {
        let denied = call(&w, who, "manage_messages", list.clone())
            .await
            .unwrap();
        assert_eq!(denied["candidates"], json!([]));
        assert_eq!(denied["head"], 0);
    }
    let inbox = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    assert_eq!(inbox["heads"]["candidates"], head);
    assert_eq!(inbox["items"][0]["delivery"]["candidate_count"], 2);
    // Exact retries do not emit another candidate or move the frontier.
    call(&w, "acct:admin", "manage_messages", send)
        .await
        .unwrap();
    assert_eq!(
        kernel::notifications::head_on(&mut w.db.pool().acquire().await.unwrap(), &w.viewer)
            .await
            .unwrap(),
        head
    );
    let harvest =
        crate::awareness::harvest_host_notification_candidates(&w.db, "acct:viewer", true, 0, 1)
            .await
            .unwrap();
    assert_eq!(harvest.candidates.len(), 1);
    let cid = harvest.candidates[0].candidate_id.clone();
    assert!(crate::awareness::revalidate_host_notification_candidate(
        &w.db,
        &cid,
        "acct:outsider",
        true
    )
    .await
    .unwrap()
    .is_none());
    let pref = |action: &str, version: i64, key: &str| json!({"action":"set_preference","message_id":id,"preference":action,"expected_version":version,"idempotency_key":key,"reason":"Notification preference"});
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        pref("mute", 0, "mute"),
    )
    .await
    .unwrap();
    let muted =
        crate::awareness::harvest_host_notification_candidates(&w.db, "acct:viewer", true, 0, 500)
            .await
            .unwrap();
    assert!(muted.candidates.iter().all(|c| c.muted));
    assert!(
        !crate::awareness::revalidate_host_notification_candidate(&w.db, &cid, "acct:viewer", true)
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted
    );
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        pref("unmute", 1, "unmute"),
    )
    .await
    .unwrap();
    let until = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let mut snooze = pref("snooze", 2, "snooze");
    snooze["snoozed_until"] = json!(until);
    call(&w, "acct:viewer", "manage_messages", snooze)
        .await
        .unwrap();
    let due = crate::awareness::harvest_host_notification_candidates(
        &w.db,
        "acct:viewer",
        true,
        head,
        500,
    )
    .await
    .unwrap();
    assert_eq!(due.candidates.len(), 1);
    assert_eq!(due.candidates[0].reason, "snooze_due");
    let due_state = crate::awareness::revalidate_host_notification_candidate(
        &w.db,
        &due.candidates[0].candidate_id,
        "acct:viewer",
        true,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(due_state.not_before.as_deref(), Some(until.as_str()));
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        pref("clear_snooze", 3, "clear-snooze"),
    )
    .await
    .unwrap();
    let withdrawn = crate::awareness::harvest_host_notification_candidates(
        &w.db,
        "acct:viewer",
        true,
        due.scanned_through,
        500,
    )
    .await
    .unwrap();
    assert!(withdrawn.candidates.is_empty());
    assert!(withdrawn.scanned_through > due.scanned_through);
    // Read paths never reveal another recipient's IDs, notes, or preferences,
    // even though this Collection message itself is visible to the outsider.
    for who in ["acct:admin", "acct:outsider"] {
        let record = call(&w, who, "get_record", json!({"ids":[id]}))
            .await
            .unwrap()
            .to_string();
        assert!(!record.contains(&cid));
        assert!(!record.contains("source_frontier"));
        let found = call(&w, who, "search", json!({"query":cid})).await.unwrap();
        assert_eq!(found["hits"], json!([]));
        let events = call(
            &w,
            who,
            "query_sql",
            json!({"sql":"SELECT id,record_id,type,actor,run_key FROM content_events LIMIT 500"}),
        )
        .await
        .unwrap()
        .to_string();
        assert!(!events.contains(&cid));

        let sql = call(
            &w,
            who,
            "query_sql",
            json!({"sql":"SELECT * FROM notification_candidates"}),
        )
        .await;
        assert!(sql.is_err());
        assert!(call(
            &w,
            who,
            "query_sql",
            json!({"sql":"SELECT * FROM kernel_message_candidates"})
        )
        .await
        .is_err());
        assert!(kernel::history_as(
            &w.db,
            if who == "acct:admin" {
                &w.admin
            } else {
                &w.outsider
            },
            id
        )
        .await
        .unwrap()
        .iter()
        .all(|r| !serde_json::to_string(r).unwrap().contains(&cid)));
    }
    let mut channel = send_args(&w, "empty-channel");
    channel["addressed_to"] = json!([]);
    channel["expectation"] = json!("none");
    call(&w, "acct:admin", "manage_messages", channel)
        .await
        .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        crate::awareness::harvest_host_notification_candidates(
            &w.db,
            "acct:viewer",
            true,
            due.scanned_through,
            500
        )
        .await
        .unwrap(),
        withdrawn
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn sealed_messages_work_through_the_ordinary_mcp_surface_and_replay() {
    let w = world().await;
    let args = send_args(&w, "send-one");
    let sent = call(&w, "acct:admin", "manage_messages", args.clone())
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    assert_eq!(sent["id"], args["id"]);
    assert_eq!(sent["write_receipt"]["event"]["record_id"], sent["id"]);
    let rail = call(
        &w,
        "acct:admin",
        "manage_messages",
        json!({"action":"list_destinations"}),
    )
    .await
    .unwrap();
    assert_eq!(rail["destinations"][0]["collection_id"], w.origin);
    let rail = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_destinations"}),
    )
    .await
    .unwrap();
    assert_eq!(rail["destinations"], json!([]));

    assert_eq!(
        sent,
        call(&w, "acct:admin", "manage_messages", args.clone())
            .await
            .unwrap()
    );
    let retry_after_replay = args.clone();
    let mut different = args;
    different["body"] = json!("different");
    assert!(call(&w, "acct:admin", "manage_messages", different)
        .await
        .is_err());
    let context = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_context","origin":{"type":"collection","collection_id":w.origin}}),
    )
    .await
    .unwrap();
    assert_eq!(context["messages"][0]["id"], id);
    let exact = call(&w, "acct:viewer", "get_record", json!({"ids":[id],"children_limit":0,"links_limit":200,"include_comments":false,"include_citations":false,"include_suggestions":false,"include_history_summary":false})).await.unwrap();
    assert_eq!(
        exact["records"][0]["communication_origin"]["context_key"],
        format!("collection:{}", w.origin)
    );
    let awaiting = call(
        &w,
        "acct:viewer",
        "query_sql",
        json!({"sql":"SELECT message_id FROM messages_awaiting_reply ORDER BY message_id"}),
    )
    .await
    .unwrap();
    assert_eq!(awaiting["rows"][0]["message_id"], id);
    let attention = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"get_attention"}),
    )
    .await
    .unwrap();
    assert_eq!(attention["has_new_messages"], true);
    let reaction = json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"reaction","reason":"Seen"});
    let reacted = call(&w, "acct:viewer", "manage_messages", reaction.clone())
        .await
        .unwrap();
    assert_eq!(
        reacted,
        call(&w, "acct:viewer", "manage_messages", reaction)
            .await
            .unwrap()
    );
    let preference = json!({"action":"set_preference","message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":"read","reason":"Read"});
    assert_eq!(reacted["status"], "added");
    assert_eq!(reacted["emoji"], "👍");
    let marked = call(&w, "acct:viewer", "manage_messages", preference.clone())
        .await
        .unwrap();
    assert_eq!(
        marked,
        call(&w, "acct:viewer", "manage_messages", preference)
            .await
            .unwrap()
    );
    assert_eq!(marked["unread_override"], false);
    assert_eq!(marked["version"], 1);
    let state = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(state["messages"][0]["attention"]["unread"], false);
    assert_eq!(state["messages"][0]["reactions"][0]["viewer_reacted"], true);
    let author = call(
        &w,
        "acct:admin",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(author["messages"][0]["attention"]["version"], 0);
    let reply = json!({"action":"send","body":"Reply proof","addressed_to":["person:admin"],"origin":{"type":"collection","collection_id":w.origin},"expectation":"none","links":[{"target_id":id,"relationship":"reply_to"}],"idempotency_key":"reply","reason":"Reply"});
    call(&w, "acct:viewer", "manage_messages", reply)
        .await
        .unwrap();
    let state = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(
        state["messages"][0]["message_expectation_state"]["state"],
        "satisfied"
    );
    let inbox = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    crate::awareness::validate_messaging_surface_response(&inbox).unwrap();
    let awaiting = call(
        &w,
        "acct:viewer",
        "query_sql",
        json!({"sql":"SELECT message_id FROM messages_awaiting_reply ORDER BY message_id"}),
    )
    .await
    .unwrap();
    assert_eq!(awaiting["rows"], json!([]));
    let private = call(
        &w,
        "acct:viewer",
        "query_sql",
        json!({"sql":"SELECT message_id,unread FROM my_message_state ORDER BY message_id"}),
    )
    .await
    .unwrap();
    assert!(private["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|r| r["unread"] == 0));
    let attention = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"get_attention"}),
    )
    .await
    .unwrap();
    assert_eq!(attention["has_new_messages"], false);
    let conversation = call(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Conversation","kind":"thread","name":"W6 conversation","reason":"Proof"}),
    )
    .await
    .unwrap();
    let conversation_id = conversation["id"].as_str().unwrap();
    for action in ["classify", "unclassify", "classify"] {
        call(
            &w,
            "acct:admin",
            "manage_messages",
            json!({"action":action,"message_id":id,"conversation_id":conversation_id}),
        )
        .await
        .unwrap();
    }
    let classified = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_conversation","conversation_id":conversation_id}),
    )
    .await
    .unwrap();
    assert_eq!(classified["messages"][0]["id"], id);
    let links = kernel::generic_links::visible_link_rows_as(&w.db, &w.viewer, id)
        .await
        .unwrap();
    assert!(links
        .iter()
        .any(|link| link["relationship"] == "participates_in"
            && link["target_id"] == conversation_id));
    call(&w,"acct:viewer","manage_messages",json!({"action":"set_destination","collection_id":w.origin,"destination":"remove","expected_version":1,"idempotency_key":"remove-rail","reason":"Leave"})).await.unwrap();
    let rail = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_destinations","include_removed":true}),
    )
    .await
    .unwrap();
    assert_eq!(rail["destinations"][0]["present"], false);
    assert_eq!(rail["destinations"][0]["version"], 2);
    call(&w,"acct:viewer","manage_messages",json!({"action":"set_destination","collection_id":w.origin,"destination":"add","expected_version":2,"idempotency_key":"rejoin-rail","reason":"Rejoin"})).await.unwrap();
    let state = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        sent,
        call(&w, "acct:admin", "manage_messages", retry_after_replay)
            .await
            .unwrap()
    );
    assert_eq!(
        state,
        call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":"list_message_state","message_ids":[id]})
        )
        .await
        .unwrap()
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn sealed_audience_blocks_every_record_read_path_including_admin_and_derived_content() {
    let w = world().await;
    let mut private = send_args(&w, "privacy");
    private["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let sent = call(&w, "acct:admin", "manage_messages", private)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    // A missing audience projection must deny even its owner. Exercise the
    // SQL path with no other sealed Message to mask that fail-closed case.
    sqlx::query("DELETE FROM kernel_messages WHERE message_id=?")
        .bind(id)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let mut identity = w.db.pool().begin().await.unwrap();
    assert!(kernel::is_message_record(&mut identity, id).await.unwrap());
    identity.rollback().await.unwrap();
    let unsealed = call(
        &w,
        "acct:admin",
        "query_sql",
        json!({"sql":"SELECT id FROM records WHERE type='Message'"}),
    )
    .await
    .unwrap();
    assert_eq!(unsealed["rows"], json!([]));
    assert!(kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .is_none());
    kernel::replay_all_projections(&w.db).await.unwrap();
    // Offboarding retains authorship even if a damaged carrier loses its type.
    let mut identity = w.db.write_pool().begin().await.unwrap();
    sqlx::query("DELETE FROM kernel_record_fields WHERE record_id=? AND name='v1_type'")
        .bind(id)
        .execute(&mut *identity)
        .await
        .unwrap();
    assert!(kernel::is_message_record(&mut identity, id).await.unwrap());
    assert!(!kernel::is_message_record(&mut identity, "missing-message")
        .await
        .unwrap());
    identity.rollback().await.unwrap();
    let attachment = call(
        &w,
        "acct:admin",
        "attach_text",
        json!({"record_id":id,"text":"W6 sealed attachment needle"}),
    )
    .await
    .unwrap();
    let attachment_id = attachment["attachment_id"].as_str().unwrap();
    let comment=call(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"W6 sealed comment needle","links":[{"target_id":id,"relationship":"part_of"}],"reason":"Proof"})).await.unwrap();
    let comment_id = comment["id"].as_str().unwrap();
    // Overlong/cyclic bearer paths deny instead of stopping before a hidden
    // Message and accidentally reverting to a public document's home grant.
    let mut bearer = id.to_owned();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for _ in 0..9 {
        let derived = call(&w, "acct:admin", "create_record", json!({"type":"Document","kind":"legacy-proof","name":"Derived proof","reason":"Derived visibility proof"})).await.unwrap();
        let next = derived["id"].as_str().unwrap().to_owned();
        kernel::generic_links::import_generic_link_as(
            &w.db,
            &host,
            &kernel::generic_links::GenericLink {
                link_id: uuid::Uuid::new_v4().to_string(),
                source_id: next.clone(),
                target_id: bearer,
                relationship: "part_of".into(),
                note: None,
                created_at: "2026-01-01T00:00:00Z".into(),
                actor: None,
            },
        )
        .await
        .unwrap();
        bearer = next;
    }
    assert!(kernel::read_record_as(&w.db, &w.outsider, &bearer)
        .await
        .unwrap()
        .is_none());
    // Root administration cannot cross a Direct message's private policy boundary.
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[
            (&w.admin, "manage"),
            (&w.viewer, "edit"),
            (&w.outsider, "manage"),
        ],
    )
    .await
    .unwrap();
    kernel::generic_links::import_generic_link_as(
        &w.db,
        &host,
        &kernel::generic_links::GenericLink {
            link_id: "private-note-link".into(),
            source_id: id.into(),
            target_id: "person:viewer".into(),
            relationship: "derived_from".into(),
            note: Some("private link note".into()),
            created_at: "2026-01-01T00:00:00Z".into(),
            actor: None,
        },
    )
    .await
    .unwrap();
    let public_person = call(
        &w,
        "acct:outsider",
        "get_record",
        json!({"ids":["person:viewer"],"children_limit":0,"links_limit":200}),
    )
    .await
    .unwrap();
    assert!(!public_person.to_string().contains(id));
    assert!(!public_person.to_string().contains("private link note"));
    assert!(
        kernel::generic_links::visible_link_rows_as(&w.db, &w.outsider, "person:viewer")
            .await
            .unwrap()
            .is_empty()
    );
    for target in [id, attachment_id, comment_id] {
        assert!(kernel::read_record_as(&w.db, &w.outsider, target)
            .await
            .unwrap()
            .is_none());
        assert!(kernel::history_as(&w.db, &w.outsider, target)
            .await
            .unwrap()
            .is_empty());
        let got = call(&w, "acct:outsider", "get_record", json!({"ids":[target]}))
            .await
            .unwrap();
        assert!(!got.to_string().contains("W6 sealed"));
    }
    assert!(call(
        &w,
        "acct:outsider",
        "read_attachment",
        json!({"attachment_id":attachment_id})
    )
    .await
    .is_err());
    assert!(call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]})
    )
    .await
    .is_err());
    let search = call(&w, "acct:outsider", "search", json!({"query":"needle"}))
        .await
        .unwrap();
    assert_eq!(search["total"], 0);
    let sql=call(&w,"acct:outsider","query_sql",json!({"sql":"SELECT id,body FROM records WHERE type IN ('Message','Annotation','Document') ORDER BY id"})).await.unwrap();
    assert!(!sql.to_string().contains("W6 sealed"));
    let list = kernel::list_records_as(&w.db, &w.outsider).await.unwrap();
    assert!(!list
        .iter()
        .any(|r| [id, attachment_id, comment_id].contains(&r.id.as_str())));
    let inbox = call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    assert_eq!(inbox["items"], json!([]));
    for relation in ["my_message_state", "messages_awaiting_reply"] {
        let result = call(
            &w,
            "acct:outsider",
            "query_sql",
            json!({"sql":format!("SELECT message_id FROM {relation} ORDER BY message_id")}),
        )
        .await
        .unwrap();
        assert_eq!(result["rows"], json!([]));
    }
    // A legacy reply may address someone who cannot see its parent. Keep the
    // visible utterance, but never disclose that parent's id from raw state.
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    let def = &package.definitions[0];
    kernel::import_record_as(
        &w.db,
        &host,
        "legacy-visible-reply",
        KERNEL_ROOT_ID,
        Some(&w.outsider),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: def.family.clone(),
                    version: def.version,
                    digest: def.digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Message",
                    "text",
                    Some("Visible reply"),
                    None,
                    None,
                ),
            }),
            body: Some("Reply bytes".into()),
            message: Some(kernel::MessageState {
                author: Some(w.outsider.clone()),
                audience: BTreeMap::from([(w.outsider.clone(), "manage".into())]),
                origin: json!({"type":"collection","collection_id":w.origin}),
                reply_to: Some(id.into()),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let context = call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_context","origin":{"type":"collection","collection_id":w.origin}}),
    )
    .await
    .unwrap();
    assert_eq!(context["messages"][0]["reply_to_ids"], json!([]));
    assert!(!context.to_string().contains(id));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn frozen_v1_rules_reconcile_live_action_and_decision_evidence() {
    let w = world().await;
    let package = crate::v2_standard::v1_compat::package();
    let def = &package.definitions[0];
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let rules = kernel::MessageRules {
        source_origin: Some("fixture-rules".into()),
        schemas: vec![
            json!({"id":"frozen-work","layer":"pack","data":{"shapes":{"WorkItem":{"facets":{"lifecycle":{"vocab":"voc:work-state"}}}}},"applies_to_collection_id":null,"created_at":"2026-01-01T00:00:00Z"}),
        ],
        positive: BTreeMap::from([("voc:work-state".into(), BTreeSet::from(["done".into()]))]),
        decision_kinds: BTreeSet::from(["decision".into()]),
    };
    kernel::import_record_as(
        &w.db,
        &host,
        "frozen-rules-source",
        KERNEL_ROOT_ID,
        Some(&w.admin),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: def.family.clone(),
                    version: def.version,
                    digest: def.digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Message",
                    "text",
                    Some("Rules fixture"),
                    None,
                    None,
                ),
            }),
            message: Some(kernel::MessageState {
                author: Some(w.admin.clone()),
                audience: BTreeMap::from([(w.admin.clone(), "manage".into())]),
                rules: Some(rules),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    for expectation in ["action", "decision"] {
        let mut request = send_args(&w, expectation);
        request["expectation"] = json!(expectation);
        let sent = call(&w, "acct:admin", "manage_messages", request)
            .await
            .unwrap();
        let id = sent["id"].as_str().unwrap();
        let evidence=call(&w,"acct:viewer","create_record",json!({"type":if expectation=="action" {"WorkItem"} else {"Resolution"},"kind":if expectation=="action" {"task"} else {"decision"},"lifecycle":"open","name":"Evidence","links":[{"target_id":id,"relationship":"derived_from"}],"reason":"Governed evidence proof"})).await.unwrap();
        let evidence_id = evidence["id"].as_str().unwrap();
        let state = call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":"list_message_state","message_ids":[id]}),
        )
        .await
        .unwrap();
        assert_eq!(
            state["messages"][0]["message_expectation_state"]["state"],
            if expectation == "action" {
                "open"
            } else {
                "satisfied"
            }
        );
        if expectation == "action" {
            call(
                &w,
                "acct:viewer",
                "update_record",
                json!({"id":evidence_id,"lifecycle":"done","reason":"Complete work"}),
            )
            .await
            .unwrap();
            let state = call(
                &w,
                "acct:viewer",
                "manage_messages",
                json!({"action":"list_message_state","message_ids":[id]}),
            )
            .await
            .unwrap();
            assert_eq!(
                state["messages"][0]["message_expectation_state"]["state"],
                "satisfied"
            );
            call(
                &w,
                "acct:viewer",
                "update_record",
                json!({"id":evidence_id,"lifecycle":"open","reason":"Reopen work"}),
            )
            .await
            .unwrap();
            let state = call(
                &w,
                "acct:viewer",
                "manage_messages",
                json!({"action":"list_message_state","message_ids":[id]}),
            )
            .await
            .unwrap();
            assert_eq!(
                state["messages"][0]["message_expectation_state"]["state"],
                "open"
            );
        }
        let state = call(
            &w,
            "acct:outsider",
            "manage_messages",
            json!({"action":"list_message_state","message_ids":[id]}),
        )
        .await;
        assert!(state.is_ok());
    }
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn collection_policy_and_all_direct_participants_govern_visibility() {
    let w = world().await;
    let mut channel = send_args(&w, "channel-empty");
    channel["addressed_to"] = json!([]);
    channel["expectation"] = json!("none");
    let sent = call(&w, "acct:admin", "manage_messages", channel)
        .await
        .unwrap();
    let channel_id = sent["id"].as_str().unwrap();
    for principal in [&w.viewer, &w.outsider] {
        assert!(kernel::read_record_as(&w.db, principal, channel_id)
            .await
            .unwrap()
            .is_some());
    }
    let mut direct = send_args(&w, "direct-three");
    direct["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer","person:outsider"]});
    let sent = call(&w, "acct:admin", "manage_messages", direct)
        .await
        .unwrap();
    let direct_id = sent["id"].as_str().unwrap();
    assert!(kernel::read_record_as(&w.db, &w.outsider, direct_id)
        .await
        .unwrap()
        .is_some());
    // v1 derives the generic expectation for any viewer; addressing alone
    // determines their obligation and inclusion in awaiting-reply selections.
    let state = call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[direct_id]}),
    )
    .await
    .unwrap();
    assert_eq!(
        state["messages"][0]["message_expectation_state"]["state"],
        "open"
    );
    let awaiting = call(
        &w,
        "acct:outsider",
        "query_sql",
        json!({"sql":"SELECT message_id FROM messages_awaiting_reply"}),
    )
    .await
    .unwrap();
    assert_eq!(awaiting["rows"], json!([]));
    let inbox = call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    let direct_row = inbox["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == direct_id)
        .unwrap();
    assert_eq!(direct_row["obligation"]["state"], "none");
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    assert!(kernel::read_record_as(&w.db, &w.outsider, channel_id)
        .await
        .unwrap()
        .is_none());
    assert!(kernel::read_record_as(&w.db, &w.outsider, direct_id)
        .await
        .unwrap()
        .is_some());
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert!(kernel::read_record_as(&w.db, &w.outsider, channel_id)
        .await
        .unwrap()
        .is_none());
    assert!(kernel::read_record_as(&w.db, &w.outsider, direct_id)
        .await
        .unwrap()
        .is_some());
    call(&w,"acct:outsider","manage_messages",json!({"action":"add_reaction","message_id":direct_id,"emoji":"👍","idempotency_key":"before-removal","reason":"Previously admitted reaction"})).await.unwrap();
    // Catalogue removal overrides retained Direct participant grants everywhere.
    let membership = unsafe {
        kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
            "acct:admin".into(),
            BTreeSet::from(["acct:admin".into(), "acct:viewer".into()]),
        )
    };
    kernel::hosted_identity::reconcile_hosted_caller(&w.db, |_| async { Ok(membership) })
        .await
        .unwrap();
    assert!(kernel::read_record_as(&w.db, &w.outsider, direct_id)
        .await
        .unwrap()
        .is_none());
    assert!(kernel::history_as(&w.db, &w.outsider, direct_id)
        .await
        .unwrap()
        .is_empty());
    assert!(
        kernel::generic_links::visible_link_rows_as(&w.db, &w.outsider, "person:viewer")
            .await
            .unwrap()
            .is_empty()
    );
    assert!(call(
        &w,
        "acct:outsider",
        "query_sql",
        json!({"sql":"SELECT id FROM records WHERE type='Message'"})
    )
    .await
    .is_err());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert!(kernel::read_record_as(&w.db, &w.outsider, direct_id)
        .await
        .unwrap()
        .is_none());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn persona_mentions_and_private_command_receipts_survive_replay() {
    let w = world().await;
    let register = json!({"action":"register_persona","name":"Proof persona","reason":"Persona proof","idempotency_key":"persona"});
    let persona = call(&w, "acct:admin", "manage_participants", register.clone())
        .await
        .unwrap();
    let persona_id = persona["persona_id"].as_str().unwrap();
    let mut args = send_args(&w, "persona-message");
    args["body"] = json!("é @Admin origin");
    args["addressed_to"] = json!(["person:admin"]);
    args["speaker"] = json!({"persona_id":persona_id});
    args["mentions"] = json!([
        {"mention_id":"principal-mention","target_kind":"principal","target_id":"person:admin","span_start":3,"span_end":9,"authored_label":"@Admin"},
        {"mention_id":"record-mention","target_kind":"record","target_id":w.origin,"span_start":10,"span_end":16,"authored_label":"origin"}
    ]);
    let mut invalid = args.clone();
    invalid["mentions"][0]["span_start"] = json!(1);
    assert!(call(&w, "acct:admin", "manage_messages", invalid)
        .await
        .is_err());
    let mut invalid = args.clone();
    invalid["addressed_to"] = json!(["person:viewer"]);
    assert!(call(&w, "acct:admin", "manage_messages", invalid)
        .await
        .is_err());
    for speaker in [
        Value::Null,
        json!({"persona_id":persona_id,"extra":true}),
        json!({"persona_id":"missing"}),
    ] {
        let mut invalid = args.clone();
        invalid["speaker"] = speaker;
        assert!(call(&w, "acct:admin", "manage_messages", invalid)
            .await
            .is_err());
    }
    let sent = call(&w, "acct:admin", "manage_messages", args.clone())
        .await
        .unwrap();
    assert_eq!(sent["speaker_claim_status"], "recorded");
    assert_eq!(sent["speaker"]["assurance"], "client_asserted");
    let id = sent["id"].as_str().unwrap();
    let record = call(
        &w,
        "acct:admin",
        "get_record",
        json!({"ids":[id],"children_limit":0}),
    )
    .await
    .unwrap();
    assert_eq!(record["records"][0]["mentions_count"], 2);
    assert_eq!(record["records"][0]["speaker"]["id"], persona_id);
    let private = call(
        &w,
        "acct:admin",
        "query_sql",
        json!({"sql":"SELECT mentioned FROM my_message_state"}),
    )
    .await
    .unwrap();
    assert_eq!(private["rows"][0]["mentioned"], 1);
    // Persona replies never impersonate the addressed human's evidence.
    call(&w,"acct:admin","manage_messages",json!({"action":"send","body":"Persona follow-up","addressed_to":["person:admin"],"speaker":{"persona_id":persona_id},"origin":{"type":"collection","collection_id":w.origin},"expectation":"none","links":[{"target_id":id,"relationship":"reply_to"}],"idempotency_key":"persona-followup","reason":"Persona is not human evidence"})).await.unwrap();
    let state = call(
        &w,
        "acct:admin",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(
        state["messages"][0]["message_expectation_state"]["state"],
        "open"
    );
    // v1 routes a Collection reply to a persona utterance without requiring
    // the human to explicitly address their own account again.
    call(&w,"acct:admin","manage_messages",json!({"action":"send","body":"Persona reply","addressed_to":[],"origin":{"type":"collection","collection_id":w.origin},"expectation":"none","links":[{"target_id":id,"relationship":"reply_to"}],"idempotency_key":"persona-reply","reason":"Reply to persona"})).await.unwrap();
    let state = call(
        &w,
        "acct:admin",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(
        state["messages"][0]["message_expectation_state"]["state"],
        "satisfied"
    );

    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        sent,
        call(&w, "acct:admin", "manage_messages", args.clone())
            .await
            .unwrap()
    );
    assert_eq!(
        persona,
        call(&w, "acct:admin", "manage_participants", register)
            .await
            .unwrap()
    );
    call(
        &w,
        "acct:admin",
        "manage_participants",
        json!({"action":"retire_persona","persona_id":persona_id,"reason":"Retire proof"}),
    )
    .await
    .unwrap();
    assert!(call(&w, "acct:admin", "manage_messages", args)
        .await
        .is_err());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn awareness_noops_append_nothing_and_consumed_nonces_replay() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "human-message"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let human_call = |nonce: &str| {
        Caller::authenticated("acct:viewer").with_verified_human_interaction(
            crate::awareness::VerifiedHumanInteraction {
                nonce: nonce.into(),
                executor_ref: "proof-host".into(),
            },
        )
    };
    let request = |stage: &str, version: i64, key: &str| json!({"action":"mutate_human_awareness","message_ids":[id],"expected_versions":{id:version},"stage":stage,"idempotency_key":key,"reason":"Human proof"});
    let registry = super::super::tests::registry();
    let args = request("presented", 0, "human-surfaced");
    let first = registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            human_call("nonce-one"),
            "manage_messages",
            args.clone(),
        )
        .await
        .unwrap();
    assert_eq!(first["changed"], true);
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let noop = registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            human_call("nonce-two"),
            "manage_messages",
            request("presented", 1, "human-noop"),
        )
        .await
        .unwrap();
    assert_eq!(noop["changed"], false);
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(before, after);
    // Simulate the previous probe's non-event receipt/nonce projections.
    sqlx::query("INSERT INTO kernel_message_receipts VALUES(?,?,?,?)")
        .bind(&w.viewer)
        .bind("legacy-probe")
        .bind("legacy-intent")
        .bind(first.to_string())
        .execute(w.db.write_pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_message_interactions VALUES(?,?,?)")
        .bind(&w.viewer)
        .bind("legacy-nonce")
        .bind("legacy-probe")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    let upgraded: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_message_interactions WHERE principal_id=? AND nonce='legacy-nonce' AND operation_key='legacy-probe')").bind(&w.viewer).fetch_one(w.db.pool()).await.unwrap();
    assert!(upgraded);
    let upgraded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type='kernel.message_command_committed.v1' AND json_extract(payload,'$.operation_key')='legacy-probe'").fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(upgraded, 1);
    kernel::replay_all_projections(&w.db).await.unwrap();
    let upgraded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE type='kernel.message_command_committed.v1' AND json_extract(payload,'$.operation_key')='legacy-probe'").fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(upgraded, 1);
    assert_eq!(
        first,
        registry
            .call_engine(
                EngineHandle::KernelV2(w.db.clone()),
                human_call("nonce-one"),
                "manage_messages",
                args
            )
            .await
            .unwrap()
    );
    assert!(registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            human_call("nonce-one"),
            "manage_messages",
            request("opened", 1, "human-reused-nonce")
        )
        .await
        .is_err());
    let advanced = registry
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            human_call("nonce-two"),
            "manage_messages",
            request("opened", 1, "human-opened"),
        )
        .await
        .unwrap();
    assert_eq!(advanced["changed"], true);
}

/// Consent and offboarding fences are pinned at admission, even when both
/// evaluator calls consistently return the same newly revoked authority.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn app_subscription_closes_on_epoch_consent_or_evaluator_failure() {
    use crate::need_subscriptions::{
        GateSnapshot, NeedClosedReason, NeedSinkFrame, SurfaceBinding,
    };
    use crate::realtime::{v2::*, RealtimeHub};
    use futures::future::BoxFuture;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    #[derive(Debug)]
    struct Evaluator {
        gate: Mutex<AppDataGate>,
        fail: AtomicBool,
    }
    impl AppDataNeeds for Evaluator {
        fn evaluate<'a>(
            &'a self,
            _db: &'a Db,
            _caller: &'a Caller,
            _request: &'a AppDataRequest,
        ) -> BoxFuture<'a, Result<AppDataEvaluation>> {
            Box::pin(async move {
                if self.fail.load(Ordering::SeqCst) {
                    return Err(Error::engine("fixture evaluator error"));
                }
                Ok(AppDataEvaluation {
                    result: json!({}),
                    gate: self.gate.lock().unwrap().clone(),
                    time_dependent: false,
                })
            })
        }
        fn revalidate<'a>(
            &'a self,
            _db: &'a Db,
            _caller: &'a Caller,
            _request: &'a AppDataRequest,
        ) -> BoxFuture<'a, Result<AppDataGate>> {
            Box::pin(async move {
                if self.fail.load(Ordering::SeqCst) {
                    return Err(Error::engine("fixture evaluator error"));
                }
                Ok(self.gate.lock().unwrap().clone())
            })
        }
    }
    let w = world().await;
    let (_, hub) = RealtimeHub::attach(w.db.clone(), None).await.unwrap();
    let caller = Caller::authenticated("acct:viewer");
    for failure in ["epoch", "consent", "evaluator", "generation"] {
        let evaluator = Arc::new(Evaluator {
            gate: Mutex::new(AppDataGate {
                principal: w.viewer.clone(),
                consent_status: "active".into(),
                executable: true,
                revocation_epoch: 1,
                install_generation: 1,
                surface: GateSnapshot::test_snapshot(),
            }),
            fail: AtomicBool::new(false),
        });
        hub.set_app_data_needs(evaluator.clone());
        let request = AppDataRequest {
            package: "fixture.app".into(),
            expected_install_event_id: "event-1".into(),
            need: None,
            params: json!({}),
        };
        let (token, id, mut receiver) = {
            let mut registry = hub.need_registry().lock().unwrap();
            let token = registry.register_connection("acct:viewer", hub.database_identity(), true);
            let (sender, receiver) = tokio::sync::mpsc::channel(16);
            registry.register_sink(&token, sender);
            let id = registry
                .subscribe_pending(
                    &token,
                    "acct:viewer",
                    hub.database_identity(),
                    SurfaceBinding::alpha_tab("fixture.app", "event-1"),
                    "snapshot",
                    "params",
                )
                .unwrap();
            (token, id, receiver)
        };
        hub.admit_app_data_subscription(&caller, &token, &id, &request)
            .await
            .unwrap();
        hub.check_app_data_subscription(&caller, &token, &id)
            .await
            .unwrap();
        match failure {
            "epoch" => evaluator.gate.lock().unwrap().revocation_epoch += 1,
            "consent" => {
                let mut gate = evaluator.gate.lock().unwrap();
                gate.consent_status = "revoked".into();
                gate.executable = false;
            }
            "generation" => evaluator.gate.lock().unwrap().install_generation += 1,
            _ => evaluator.fail.store(true, Ordering::SeqCst),
        }
        assert!(
            hub.check_app_data_subscription(&caller, &token, &id)
                .await
                .is_err(),
            "{failure}"
        );
        assert!(hub
            .need_registry()
            .lock()
            .unwrap()
            .subscription_state(&token, &id)
            .is_none());
        assert!(
            matches!(receiver.recv().await, Some(NeedSinkFrame::Closed(frame)) if frame.reason == NeedClosedReason::AccessLost)
        );
        hub.need_registry()
            .lock()
            .unwrap()
            .remove_connection(&token);
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn whats_changed_baseline_bounds_hidden_scan_and_resumes() {
    let w = world().await;
    // Immutable unrelated events are withheld by ordinary history. The budget
    // must advance without disclosing their IDs or pretending the scan ended.
    let head: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    for n in 0..1100 {
        sqlx::query("INSERT INTO content_events(id,record_id,type,payload,created_at,causal_envelope_version,causal_status) VALUES(?,?,'fixture.hidden.v1','{}','2026-01-01T00:00:00Z',1,'legacy_unknown')")
            .bind(format!("hidden-event-{n}")).bind("hidden-subject").execute(&mut *tx).await.unwrap();
    }
    tx.commit().await.unwrap();
    let first = call(
        &w,
        "acct:viewer",
        "whats_changed",
        json!({"after_local_seq":head}),
    )
    .await
    .unwrap();
    assert_eq!(first["changes"], json!([]));
    assert_eq!(first["has_more"], true);
    assert_eq!(
        first["scanned_through_local_seq"].as_i64().unwrap(),
        head + 1024
    );
    assert!(!first.to_string().contains("hidden-subject"));
    let second = call(
        &w,
        "acct:viewer",
        "whats_changed",
        first["next_request"].clone(),
    )
    .await
    .unwrap();
    assert_eq!(second["has_more"], false);
    assert_eq!(second["changes"], json!([]));
}

#[cfg(all(unix, feature = "v2-kernel-probe"))]
#[tokio::test]
async fn vault_messages_use_the_production_audience_gate() {
    let w = world().await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[
            (&w.admin, "manage"),
            (&w.viewer, "view"),
            (&w.outsider, "view"),
        ],
    )
    .await
    .unwrap();
    let public = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "vault-channel"),
    )
    .await
    .unwrap();
    let mut private = send_args(&w, "vault-direct");
    private["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let private = call(&w, "acct:admin", "manage_messages", private)
        .await
        .unwrap();
    let viewer = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:viewer", true),
    )
    .await
    .unwrap();
    assert!(viewer.records.contains_key(public["id"].as_str().unwrap()));
    assert!(viewer.records.contains_key(private["id"].as_str().unwrap()));
    let directory = tempfile::tempdir().unwrap();
    let mut publisher = crate::markdown_vault::Publisher::open(directory.path()).unwrap();
    assert!(publisher.cycle(&viewer).unwrap().is_empty());
    let outsider = crate::query::sql::projection_snapshot(
        &w.db,
        crate::query::QueryPrincipal::authenticated("acct:outsider", true),
    )
    .await
    .unwrap();
    assert!(!outsider
        .records
        .contains_key(private["id"].as_str().unwrap()));
    assert!(!outsider
        .links
        .iter()
        .any(|l| Some(l.source_id.as_str()) == private["id"].as_str()
            || Some(l.target_id.as_str()) == private["id"].as_str()));
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn browser_message_query_rows_keep_body_origin_and_visibility_with_order() {
    let w = world().await;
    let mut send = send_args(&w, "browser-ordered-feed");
    send["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let sent = call(&w, "acct:admin", "manage_messages", send)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    for ordered in [false, true] {
        let mut args =
            json!({"steps":[{"step":"filter","types":["Message"],"ids":[id]}],"limit":10});
        if ordered {
            args["order"] = json!("last_activity_desc");
        }
        let out = call(&w, "acct:viewer", "query_record", args.clone())
            .await
            .unwrap();
        assert_eq!(out["records"][0]["id"], id);
        assert!(out["records"][0]["body"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        assert_eq!(out["records"][0]["communication_origin"]["type"], "direct");
        assert!(out["records"][0]["lifecycle_interpretation"].is_object());
        let hidden = call(&w, "acct:outsider", "query_record", args)
            .await
            .unwrap();
        assert_eq!(hidden["records"], json!([]));
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_delete_message_withdraws_candidates_atomically_and_replays() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "delete-candidates"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert!(
        kernel::notifications::count_on(&mut conn, &w.viewer, id)
            .await
            .unwrap()
            > 0
    );
    drop(conn);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(call(
        &w,
        "acct:viewer",
        "delete_record",
        json!({"id":id,"reason":"Recipient Edit is insufficient"})
    )
    .await
    .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(
        call(
            &w,
            "acct:admin",
            "delete_record",
            json!({"id":id,"reason":"Withdraw this Message"})
        )
        .await
        .unwrap()["deleted"],
        true
    );
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert_eq!(
        kernel::notifications::count_on(&mut conn, &w.viewer, id)
            .await
            .unwrap(),
        0
    );
    drop(conn);
    let status:String=sqlx::query_scalar("SELECT json_extract(state,'$.status') FROM kernel_message_candidates WHERE message_id=? LIMIT 1").bind(id).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(status, "withdrawn");
    let after = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(after, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}
