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

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_scoped_currency_message_and_derived_sources_keep_audience_gate() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    for (index, person) in ["person:viewer", "person:outsider"].iter().enumerate() {
        let mut args = send_args(&w, &format!("currency-message-{index}"));
        args["origin"] = json!({"type":"direct","participant_ids":["person:admin",person]});
        args["addressed_to"] = json!([person]);
        let message = call(&w, "acct:admin", "manage_messages", args)
            .await
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let comment = call(&w,"acct:admin","create_record",json!({"type":"Annotation","kind":"comment","body":"Currency bearer","links":[{"target_id":message,"relationship":"part_of"}],"reason":"Currency audience parity"})).await.unwrap()["id"].as_str().unwrap().to_owned();
        // Imported generic links exercise the existing currency representation
        // without relaxing sealed Message mutation rules or adding a new kind
        // of imported-link dependency to the reader.
        for (kind, source) in [("message", message), ("comment", comment)] {
            kernel::generic_links::import_generic_link_as(
                &w.db,
                &host,
                &kernel::GenericLink {
                    link_id: format!("currency-{kind}-{index}"),
                    source_id: source,
                    target_id: w.origin.clone(),
                    relationship: "supersedes".into(),
                    note: None,
                    created_at: "2026-11-09T00:00:00Z".into(),
                    actor: None,
                },
            )
            .await
            .unwrap();
        }
    }
    let args = json!({"sql":"SELECT id,home_id,successor_count,is_current FROM records WHERE id=?1","parameters":[{"type":"text","value":w.origin}]});
    for replay in [false, true] {
        if replay {
            kernel::replay_all_projections(&w.db).await.unwrap();
        }
        for (credential, expected) in [("acct:admin", 4), ("acct:viewer", 2), ("acct:outsider", 2)]
        {
            let (narrow, stats) =
                super::sql::measured(call(&w, credential, "query_sql", args.clone())).await;
            let full = super::sql::with_full_record_scope_staging(call(
                &w,
                credential,
                "query_sql",
                args.clone(),
            ))
            .await
            .unwrap();
            let narrow = narrow.unwrap();
            assert_eq!(
                narrow["rows"], full["rows"],
                "{credential}, replay={replay}; {stats:?}"
            );
            assert_eq!(
                narrow["rows"][0]["successor_count"], expected,
                "{credential}, replay={replay}"
            );
            assert_eq!(stats.staged_currency_records, expected, "{stats:?}");
        }
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn workbench_direct_bindings_are_verified_visible_and_read_only() {
    let w = world().await;
    let read = |id: &str| {
        call(
            &w,
            "acct:viewer",
            "manage_bindings",
            json!({"action":"list","record_id":id}),
        )
    };
    let out = read("person:admin").await.unwrap();
    assert_eq!(out["bindings"], json!([]));
    assert_eq!(
        out["kernel_identity"],
        json!({"principal_id":w.admin,"person_id":"person:admin"})
    );
    let unbound = read(&w.origin).await.unwrap();
    assert_eq!(unbound["bindings"], json!([]));
    assert!(unbound["kernel_identity"].is_null());
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "workbench-owner-proof"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let message = || call(&w, "acct:viewer", "get_record", json!({"ids":[id]}));
    let listed = || {
        call(
            &w,
            "acct:viewer",
            "query_record",
            json!({"steps":[{"step":"filter","types":["Message"],"ids":[id]}],"limit":1}),
        )
    };
    let context = || {
        call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":"list_context","origin":{"type":"collection","collection_id":w.origin},"limit":200}),
        )
    };
    assert_eq!(
        message().await.unwrap()["records"][0]["owner_id"],
        "person:admin"
    );
    let row = listed().await.unwrap();
    assert_eq!(row["records"][0]["owner_id"], "person:admin");
    assert_eq!(
        row["records"][0]["communication_origin"]["collection_id"],
        w.origin
    );
    assert_eq!(
        context().await.unwrap()["messages"][0]["owner_id"],
        "person:admin"
    );
    assert!(call(&w,"acct:viewer","manage_bindings",json!({"action":"add","record_id":"person:admin","binding":{"system":"native-principal","identifier":w.viewer},"canonical":true,"reason":"Must not replace verified identity"})).await.is_err());
    let private = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, "person:admin", &private)
        .await
        .unwrap();
    let hidden = read("person:admin").await.unwrap_err().to_string();
    assert_eq!(hidden, read("missing").await.unwrap_err().to_string());
    assert!(message().await.unwrap()["records"][0]["owner_id"].is_null());
    assert!(listed().await.unwrap()["records"][0]["owner_id"].is_null());
    assert!(context().await.unwrap()["messages"][0]["owner_id"].is_null());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn workbench_public_binding_cannot_create_native_direct_authority() {
    let w = world().await;
    let created = call(
        &w,
        "acct:admin",
        "create_record",
        json!({
            "type":"Entity","kind":"person","name":"Unbound contact",
            "home_id":KERNEL_ROOT_ID,"reason":"Verify separate native messaging identity",
        }),
    )
    .await
    .unwrap();
    let id = created["id"].as_str().unwrap();
    call(&w, "acct:admin", "manage_bindings", json!({
        "action":"add","record_id":id,"binding":{"system":"native-principal","identifier":"native/Forged"},
        "canonical":true,"reason":"A public claim must not create native authority",
    })).await.unwrap();
    let listed = call(
        &w,
        "acct:admin",
        "manage_bindings",
        json!({"action":"list","record_id":id}),
    )
    .await
    .unwrap();
    assert!(listed.get("kernel_identity").is_none());
    assert!(listed["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|b| b["identifier"] == "native/Forged"));
    let error = call(&w, "acct:admin", "manage_messages", json!({
        "action":"list_context","origin":{"type":"direct","participant_ids":["person:admin",id]},"limit":200,
    })).await.unwrap_err();
    assert!(
        error.to_string().contains("no verified messaging identity"),
        "{error}"
    );
    w.db.close().await;
}

/// Execute the shipping Messages page, not an independently copied query.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn frozen_slack_logical_headers_follow_public_reactions_only() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "frozen-slack-send"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let headers = |who: &'static str| {
        call(
            &w,
            who,
            "query_sql",
            json!({
                "sql":"SELECT record_id,type,actor FROM content_events WHERE type IN ('record.created','message.reaction.added.v1','message.reaction.removed.v1') AND record_id=?1 ORDER BY local_seq",
                "parameters":[{"type":"text","value":id}]
            }),
        )
    };
    let birth = headers("acct:viewer").await.unwrap();
    assert_eq!(
        birth["rows"],
        json!([{"record_id":id,"type":"record.created","actor":w.admin}])
    );
    call(&w,"acct:admin","manage_messages",json!({"action":"set_preference","message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":"frozen-slack-private","reason":"Private sender state"})).await.unwrap();
    assert_eq!(headers("acct:viewer").await.unwrap()["rows"], birth["rows"]);
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"frozen-slack-react","reason":"Public reaction"})).await.unwrap();
    let added = headers("acct:viewer").await.unwrap();
    assert_eq!(added["rows"].as_array().unwrap().len(), 2);
    assert_eq!(added["rows"][1]["type"], "message.reaction.added.v1");
    call(&w,"acct:viewer","manage_messages",json!({"action":"set_preference","message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":"frozen-slack-viewer-private","reason":"Private recipient state"})).await.unwrap();
    assert_eq!(headers("acct:viewer").await.unwrap()["rows"], added["rows"]);
    call(&w,"acct:admin","manage_messages",json!({"action":"remove_reaction","message_id":id,"emoji":"👍","idempotency_key":"frozen-slack-unreact","reason":"Public reaction removal"})).await.unwrap();
    let removed = headers("acct:viewer").await.unwrap();
    assert_eq!(removed["rows"].as_array().unwrap().len(), 3);
    assert_eq!(removed["rows"][2]["type"], "message.reaction.removed.v1");
    let mut private = send_args(&w, "frozen-slack-hidden");
    private["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let private = call(&w, "acct:admin", "manage_messages", private)
        .await
        .unwrap();
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":private["id"],"emoji":"👀","idempotency_key":"frozen-slack-hidden-react","reason":"Private direct context"})).await.unwrap();
    let hidden = call(
        &w,
        "acct:outsider",
        "query_sql",
        json!({
            "sql":"SELECT id FROM content_events WHERE record_id=?1",
            "parameters":[{"type":"text","value":private["id"]}]
        }),
    )
    .await
    .unwrap();
    assert_eq!(hidden["rows"], json!([]));
    // A root-directory viewer may see native principal identities even when
    // a Person is hidden. Keep only explicit Message/Collection access here.
    let visible_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage"), (&w.viewer, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    for record in [id, w.origin.as_str()] {
        kernel::rehome_record_as(&w.db, &w.admin, record, &visible_home)
            .await
            .unwrap();
    }
    kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    assert!(kernel::read_record_as(&w.db, &w.viewer, "person:admin")
        .await
        .unwrap()
        .is_none());
    let redacted = headers("acct:viewer").await.unwrap();
    assert_eq!(redacted["rows"].as_array().unwrap().len(), 3);
    assert!(redacted["rows"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["actor"].is_null()));
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        headers("acct:viewer").await.unwrap()["rows"],
        redacted["rows"]
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn messages_feed_reads_native_creation_and_reaction_state_without_private_cross_talk() {
    let w = world().await;
    let page = |who: &'static str| {
        call(
            &w,
            who,
            "query_sql",
            json!({
                "sql":include_str!("messages_feed.sql"),
                "parameters":[{"type":"integer","value":"9007199254740991"},{"type":"text","value":"~"}]
            }),
        )
    };
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "feed-send"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let initial = page("acct:viewer").await.unwrap();
    assert_eq!(initial["rows"].as_array().unwrap().len(), 1, "{initial}");
    assert_eq!(initial["rows"][0]["actor"], w.admin);
    assert_eq!(initial["rows"][0]["actor_person_id"], "person:admin");
    assert!(initial["rows"][0]["created_at_ms"].as_i64().unwrap() > 0);
    assert!(initial["rows"][0]["reaction_revision"].is_null());
    let viewer = call(&w,"acct:viewer","query_sql",json!({"sql":"SELECT current_principal() AS account,b.record_id AS person_id,r.name FROM bindings b JOIN records r ON r.id=b.record_id WHERE b.system='account' AND b.identifier=current_principal() ORDER BY b.record_id LIMIT 2"})).await.unwrap();
    assert_eq!(
        viewer["rows"],
        json!([{"account":w.viewer,"person_id":"person:viewer","name":"person:viewer"}])
    );
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"feed-react","reason":"Reaction in another client"})).await.unwrap();
    let reacted = page("acct:viewer").await.unwrap();
    assert_ne!(
        reacted["rows"][0]["reaction_revision"],
        initial["rows"][0]["reaction_revision"]
    );
    let exact = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(exact["messages"][0]["reactions"][0]["count"], 1);
    call(&w,"acct:admin","manage_messages",json!({"action":"set_preference","message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":"feed-private","reason":"Private preference"})).await.unwrap();
    assert_eq!(
        page("acct:viewer").await.unwrap()["rows"],
        reacted["rows"],
        "another account's private state cannot alter this page or reaction identities"
    );
    call(&w,"acct:admin","manage_messages",json!({"action":"remove_reaction","message_id":id,"emoji":"👍","idempotency_key":"feed-unreact","reason":"Change reaction"})).await.unwrap();
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👀","idempotency_key":"feed-react-again","reason":"Change reaction"})).await.unwrap();
    assert_ne!(
        page("acct:viewer").await.unwrap()["rows"][0]["reaction_revision"],
        reacted["rows"][0]["reaction_revision"],
        "equal counts with different emojis must wake loaded pages"
    );
    let mut direct = send_args(&w, "feed-hidden");
    direct["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let direct = call(&w, "acct:admin", "manage_messages", direct)
        .await
        .unwrap();
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":direct["id"],"emoji":"❤️","idempotency_key":"feed-hidden-reaction","reason":"Private context"})).await.unwrap();
    let outsider = page("acct:outsider").await.unwrap();
    assert_eq!(outsider["rows"].as_array().unwrap().len(), 1);
    let reactions=call(&w,"acct:outsider","query_sql",json!({"sql":"SELECT message_id,emoji,viewer FROM message_reactions ORDER BY message_id,emoji"})).await.unwrap();
    assert_eq!(
        reactions["rows"],
        json!([{"message_id":id,"emoji":"👀","viewer":0}])
    );
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        page("acct:outsider").await.unwrap()["rows"],
        outsider["rows"]
    );
    let private = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    for person in ["person:admin", "person:viewer"] {
        kernel::rehome_record_as(&w.db, &w.admin, person, &private)
            .await
            .unwrap();
    }
    let query = || {
        call(
            &w,
            "acct:outsider",
            "query_sql",
            json!({"sql":"SELECT * FROM message_reactions ORDER BY reaction_id"}),
        )
    };
    let hidden = query().await.unwrap();
    assert!(hidden["rows"][0]["actor_record_id"].is_null());
    assert!(hidden["rows"][0]["actor_name"].is_null());
    call(&w,"acct:admin","manage_messages",json!({"action":"remove_reaction","message_id":id,"emoji":"👀","idempotency_key":"feed-private-swap-remove","reason":"Reaction"})).await.unwrap();
    call(&w,"acct:viewer","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👀","idempotency_key":"feed-private-swap-add","reason":"Reaction"})).await.unwrap();
    assert_eq!(
        query().await.unwrap()["rows"],
        hidden["rows"],
        "opaque keys must not identify which withheld account reacted"
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn messages_feed_mentions_resolve_only_against_current_visible_bodies_and_rivals() {
    let w = world().await;
    let me = kernel::create_principal(
        &w.db,
        "account",
        "Mention reader",
        "acct:mention-reader",
        &w.admin,
    )
    .await
    .unwrap();
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[
            (&w.admin, "manage"),
            (&w.viewer, "edit"),
            (&w.outsider, "view"),
            (&me, "view"),
        ],
    )
    .await
    .unwrap();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    let person = "01234567-0000-4000-8000-000000000001";
    let definition = |typ: &str, kind: &str| kernel::ImportDefinition {
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
            Some("Mention target"),
            None,
            None,
        ),
    };
    kernel::import_record_as(
        &w.db,
        &host,
        person,
        KERNEL_ROOT_ID,
        Some(&me),
        &kernel::ImportRecordState {
            message_principal: Some(me.clone()),
            definition: Some(definition("Entity", "person")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let mut args = send_args(&w, "feed-reference");
    args["body"] = json!("See n8v.to/0123456");
    let sent = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    let read = || {
        call(
            &w,
            "acct:mention-reader",
            "query_sql",
            json!({"sql":"SELECT source_id,via,own_source,seen FROM my_mentions ORDER BY source_id,via"}),
        )
    };
    let expected = json!([{"source_id":sent["id"],"via":"reference","own_source":0,"seen":null}]);
    assert_eq!(read().await.unwrap()["rows"], expected);
    let private = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    let rival = "0123456f-0000-4000-8000-000000000002";
    kernel::import_record_as(
        &w.db,
        &host,
        rival,
        &private,
        Some(&w.admin),
        &kernel::ImportRecordState {
            definition: Some(definition("Document", "note")),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        read().await.unwrap()["rows"],
        expected,
        "a hidden rival cannot suppress a visible reference"
    );
    kernel::rehome_record_as(&w.db, &w.admin, rival, KERNEL_ROOT_ID)
        .await
        .unwrap();
    assert_eq!(
        read().await.unwrap()["rows"],
        json!([]),
        "a visible ambiguous prefix is not a mention"
    );
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
    assert_eq!(inbox["capabilities"]["saved_session_sharing"], false);
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
    world_with_person_ids(["person:admin", "person:viewer", "person:outsider"]).await
}
async fn world_with_person_ids(person_ids: [&str; 3]) -> World {
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
        (person_ids[0], "Entity", "person", Some(admin.clone())),
        (person_ids[1], "Entity", "person", Some(viewer.clone())),
        (person_ids[2], "Entity", "person", Some(outsider.clone())),
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

fn channel_mention(w: &World, key: &str, label: &str, target: &str) -> Value {
    let mut args = send_args(w, key);
    args["addressed_to"] = json!([]);
    args["expectation"] = json!("none");
    args["body"] = json!(format!("{label} owns the launch date."));
    args["mentions"] = json!([{"mention_id":"m","target_kind":"principal","target_id":target,"span_start":0,"span_end":label.len(),"authored_label":label}]);
    args
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn channel_mention_alerts_a_viewer_without_addressing_or_narrowing() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        channel_mention(&w, "channel-mention", "@Viewer", "person:viewer"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    // Visibility is the Collection's: a non-mentioned member still reads it.
    for principal in [&w.viewer, &w.outsider] {
        assert!(kernel::read_record_as(&w.db, principal, id)
            .await
            .unwrap()
            .is_some());
    }
    // Only the mentioned person is alerted, and only by the mention.
    let harvest =
        crate::awareness::harvest_host_notification_candidates(&w.db, "acct:viewer", true, 0, 500)
            .await
            .unwrap();
    assert_eq!(harvest.candidates.len(), 1);
    assert_eq!(harvest.candidates[0].reason, "principal_mention");
    assert!(crate::awareness::harvest_host_notification_candidates(
        &w.db,
        "acct:outsider",
        true,
        0,
        500
    )
    .await
    .unwrap()
    .candidates
    .is_empty());
    // The mention is no addressee and puts no obligation on the viewer.
    let state = kernel::messaging::on(&mut w.db.write_pool().acquire().await.unwrap(), id)
        .await
        .unwrap()
        .unwrap();
    assert!(state.addressed_to.is_empty());
    let inbox = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    let row = inbox["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == id)
        .unwrap();
    assert_eq!(row["obligation"]["state"], "none");
    assert_eq!(row["mention"]["principal"], true);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

/// v2 has no member/guest footing: a principal is admitted or it reads nothing.
/// The analogue of the v1 guest is a mentioned person whose access to the
/// Collection is withdrawn after the send. Their candidate stays stored but no
/// viewer-relative surface may reveal it, and delivery must refuse it.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn mentioned_person_who_loses_the_collection_is_never_told_about_the_post() {
    let w = world().await;
    let mut args = channel_mention(&w, "revoked-mention", "@Outsider", "person:outsider");
    args["body"] = json!("@Outsider and @Viewer own the zebra launch.");
    args["mentions"] = json!([
        {"mention_id":"o","target_kind":"principal","target_id":"person:outsider","span_start":0,"span_end":9,"authored_label":"@Outsider"},
        {"mention_id":"v","target_kind":"principal","target_id":"person:viewer","span_start":14,"span_end":21,"authored_label":"@Viewer"}
    ]);
    let sent = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let candidate_of = |account: &'static str| {
        let db = w.db.clone();
        async move {
            crate::awareness::harvest_host_notification_candidates(&db, account, true, 0, 500)
                .await
                .unwrap()
                .candidates
        }
    };
    // Both are really alerted while they can see the channel.
    let viewer_candidates = candidate_of("acct:viewer").await;
    let outsider_candidates = candidate_of("acct:outsider").await;
    assert_eq!(viewer_candidates.len(), 1);
    assert_eq!(outsider_candidates.len(), 1);
    let outsider_candidate = outsider_candidates[0].candidate_id.clone();

    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();

    // Member control: the viewer still sees and is told everything.
    assert_eq!(candidate_of("acct:viewer").await.len(), 1);
    assert!(
        crate::awareness::revalidate_host_notification_candidate(
            &w.db,
            &viewer_candidates[0].candidate_id,
            "acct:viewer",
            true
        )
        .await
        .unwrap()
        .unwrap()
        .effective_viewable_unmuted
    );
    let listed = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_notification_candidates"}),
    )
    .await
    .unwrap();
    assert_eq!(listed["candidates"].as_array().unwrap().len(), 1);
    let inbox = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    assert!(inbox["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == id));

    // The outsider learns nothing, and delivery refuses the stored candidate.
    assert!(candidate_of("acct:outsider").await.is_empty());
    assert!(
        !crate::awareness::revalidate_host_notification_candidate(
            &w.db,
            &outsider_candidate,
            "acct:outsider",
            true
        )
        .await
        .unwrap()
        .unwrap()
        .effective_viewable_unmuted
    );
    let listed = call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_notification_candidates"}),
    )
    .await
    .unwrap();
    assert!(listed["candidates"].as_array().unwrap().is_empty());
    let inbox = call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    assert!(inbox["items"].as_array().unwrap().is_empty(), "{inbox}");
    let attention = call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"get_attention"}),
    )
    .await
    .unwrap();
    assert_eq!(attention["has_new_messages"], false, "{attention}");
    let found = call(&w, "acct:outsider", "search", json!({"query":"zebra"}))
        .await
        .unwrap();
    assert!(found["hits"].as_array().unwrap().is_empty(), "{found}");
    assert!(kernel::read_record_as(&w.db, &w.outsider, id)
        .await
        .unwrap()
        .is_none());
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[tokio::test]
async fn channel_mention_of_a_person_who_cannot_see_the_collection_is_refused() {
    let w = world().await;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.viewer, "edit")],
    )
    .await
    .unwrap();
    let error = call(
        &w,
        "acct:admin",
        "manage_messages",
        channel_mention(&w, "channel-mention-hidden", "@Outsider", "person:outsider"),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("must be able to see the Collection"),
        "{error}"
    );
    let messages: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_messages")
        .fetch_one(w.db.write_pool())
        .await
        .unwrap();
    assert_eq!(messages, 0);
    assert!(kernel::read_record_as(&w.db, &w.outsider, "origin")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn direct_send_still_requires_a_principal_mention_to_be_addressed() {
    let w = world().await;
    let mut args = channel_mention(&w, "direct-mention", "@Viewer", "person:viewer");
    args["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer","person:outsider"]});
    args["addressed_to"] = json!(["person:outsider"]);
    let error = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("must already be addressed"), "{error}");
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
async fn import_work_completion_rules(w: &World) {
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
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn frozen_v1_rules_reconcile_live_action_and_decision_evidence() {
    let w = world().await;
    import_work_completion_rules(&w).await;
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

/// Ordinary MCP credentials can record completed work without claiming either
/// a human interaction or a server-verified agent identity (record 8af970b).
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn direct_action_completion_uses_recipient_work_without_awareness_attestation() {
    let w = world().await;
    import_work_completion_rules(&w).await;
    let origin = json!({"type":"direct","participant_ids":["person:admin","person:viewer","person:outsider"]});
    let mut request = send_args(&w, "delegated-action-request");
    request["origin"] = origin.clone();
    request["addressed_to"] = json!(["person:viewer", "person:outsider"]);
    request["expectation"] = json!("action");
    let sent = call(&w, "acct:admin", "manage_messages", request)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let state = |who: &'static str| {
        call(
            &w,
            who,
            "manage_messages",
            json!({"action":"list_message_state","message_ids":[id]}),
        )
    };
    let needs_me = |who: &'static str| {
        call(
            &w,
            who,
            "manage_messages",
            json!({"action":"list_inbox","view":"needs_me"}),
        )
    };
    let before = state("acct:viewer").await.unwrap();
    assert_eq!(
        before["messages"][0]["message_expectation_state"]["state"],
        "open"
    );
    assert_eq!(
        needs_me("acct:viewer").await.unwrap()["items"][0]["message_id"],
        id
    );

    // These are real authority boundaries, not alternative completion paths.
    for (args, refusal) in [
        (
            json!({"action":"set_routing","message_id":id,"obligation_state":"satisfied","executor_route":"closed","expected_version":0,"idempotency_key":"unattested-route","reason":"Person reported completion"}),
            "routing requires attested principal choice",
        ),
        (
            json!({"action":"set_agent_disposition","message_id":id,"state":"resolved","expected_version":0,"evidence":[],"idempotency_key":"unattested-agent","reason":"Person reported completion"}),
            "agent disposition requires server-verified executor",
        ),
        (
            json!({"action":"mutate_human_awareness","message_ids":[id],"stage":"acknowledged","expected_versions":{id:0},"idempotency_key":"unattested-awareness","reason":"Person reported completion"}),
            "human awareness requires a server-verified interaction",
        ),
    ] {
        let error = call(&w, "acct:viewer", "manage_messages", args)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(refusal), "{error}");
        assert!(error.contains("recipient-authored WorkItem"), "{error}");
        assert!(error.contains("messaging guide"), "{error}");
    }
    assert_eq!(before, state("acct:viewer").await.unwrap());

    // A reply that says "done" does not, by itself, complete action work.
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({
            "action":"send","body":"The recipient says this is done.","origin":origin,
            "addressed_to":["person:admin"],"expectation":"none",
            "links":[{"target_id":id,"relationship":"reply_to"}],
            "idempotency_key":"delegated-action-reply","reason":"Record the recipient's report"
        }),
    )
    .await
    .unwrap();
    assert_eq!(
        state("acct:viewer").await.unwrap()["messages"][0]["message_expectation_state"]["state"],
        "open"
    );

    for private in [false, true] {
        let mut work = json!({
            "type":"WorkItem","kind":"task","name":"Requested action completed",
            "body":"The recipient confirmed completion; this records their report.",
            "lifecycle":"done","links":[{"target_id":id,"relationship":"derived_from"}],
            "reason":"Record the recipient's confirmed completion"
        });
        if private {
            work["access_policy"] = json!("account_only");
        }
        let evidence = call(&w, "acct:viewer", "create_record", work)
            .await
            .unwrap();
        let evidence_id = evidence["id"].as_str().unwrap();
        for replay in [false, true] {
            if replay {
                kernel::replay_all_projections(&w.db).await.unwrap();
            }
            // Public evidence still needs the recipient's authorship; private
            // evidence must stay unreadable to the other addressed participant.
            assert_eq!(
                kernel::read_record_as(&w.db, &w.outsider, evidence_id)
                    .await
                    .unwrap()
                    .is_none(),
                private
            );
            let completed = state("acct:viewer").await.unwrap();
            assert_eq!(
                completed["messages"][0]["message_expectation_state"]["state"],
                "satisfied"
            );
            assert_eq!(
                completed["messages"][0]["message_expectation_state"]["evidence"],
                json!({"kind":"completed_work_item","record_id":evidence_id})
            );
            assert_eq!(
                completed["messages"][0]["human"],
                before["messages"][0]["human"]
            );
            assert_eq!(
                completed["messages"][0]["attention"],
                before["messages"][0]["attention"]
            );
            assert!(needs_me("acct:viewer").await.unwrap()["items"]
                .as_array()
                .unwrap()
                .is_empty());
            assert_eq!(
                state("acct:outsider").await.unwrap()["messages"][0]["message_expectation_state"]
                    ["state"],
                "open"
            );
            assert_eq!(
                needs_me("acct:outsider").await.unwrap()["items"][0]["message_id"],
                id
            );
        }
        // The person can correct their report; satisfaction follows the live work.
        call(
            &w,
            "acct:viewer",
            "update_record",
            json!({"id":evidence_id,"lifecycle":"open","reason":"Correct the reported completion"}),
        )
        .await
        .unwrap();
        assert_eq!(
            state("acct:viewer").await.unwrap()["messages"][0]["message_expectation_state"]
                ["state"],
            "open"
        );
        assert_eq!(
            needs_me("acct:viewer").await.unwrap()["items"][0]["message_id"],
            id
        );
    }
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
async fn record_reads_render_message_speaker() {
    let w = world().await;
    let persona = call(&w, "acct:admin", "manage_participants", json!({"action":"register_persona","name":"Render persona","reason":"Read proof","idempotency_key":"render-persona"})).await.unwrap();
    let mut args = send_args(&w, "render-speaker");
    args["speaker"] = json!({"persona_id":persona["persona_id"]});
    let sent = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    let record = call(&w, "acct:admin", "get_record", json!({"ids":[sent["id"]]}))
        .await
        .unwrap();
    let rendered = call(&w, "acct:admin", "render_record", json!({"id":sent["id"]}))
        .await
        .unwrap();
    assert_eq!(rendered["speaker"], record["records"][0]["speaker"]);
    assert!(rendered["markdown"]
        .as_str()
        .unwrap()
        .contains("\nSpeaker: Render persona (client_asserted)\n"));
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
    // In a direct context a mention must still be an addressee; a Collection
    // origin may mention an unaddressed person who can see it.
    let mut invalid = args.clone();
    invalid["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
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
                authorization_epoch: "fixture".into(),
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

/// Both exact frozen Slack versions share this public SQL, including `.v1`
/// reaction event names. Add reaction is inert in those bundles on both engines.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn frozen_slack_query_reaction_counts_match_v1_versioned_headers() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "slack-reaction-count-send"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let query = include_str!("../../../tests/fixtures/kernel_v2_frozen_slack_dms.sql");
    let count = |who: &'static str| call(&w, who, "query_sql", json!({"sql":query}));
    let row_count = |result: &Value| {
        result["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap()["reactions"]
            .clone()
    };
    assert_eq!(row_count(&count("acct:viewer").await.unwrap()), 0);
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"slack-reaction-count-add","reason":"Shared reaction"})).await.unwrap();
    assert_eq!(row_count(&count("acct:admin").await.unwrap()), 1);
    assert_eq!(row_count(&count("acct:viewer").await.unwrap()), 1);
    // Existing accepted reactions survive projection rebuild, not just a live poll.
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(row_count(&count("acct:viewer").await.unwrap()), 1);
    call(&w,"acct:admin","manage_messages",json!({"action":"set_preference","message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":"slack-reaction-count-private","reason":"Private preference"})).await.unwrap();
    assert_eq!(row_count(&count("acct:viewer").await.unwrap()), 1);
    call(&w,"acct:admin","manage_messages",json!({"action":"remove_reaction","message_id":id,"emoji":"👍","idempotency_key":"slack-reaction-count-remove","reason":"Remove shared reaction"})).await.unwrap();
    assert_eq!(row_count(&count("acct:viewer").await.unwrap()), 0);
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

/// The reasons the viewer holds an effective candidate for on one Message.
#[cfg(feature = "v2-kernel-probe")]
async fn effective_viewer_reasons(w: &World, id: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT json_extract(state,'$.reason') FROM kernel_message_candidates WHERE principal_id=? AND message_id=? AND json_extract(state,'$.status')='effective' ORDER BY 1")
        .bind(&w.viewer)
        .bind(id)
        .fetch_all(w.db.pool())
        .await
        .unwrap()
}

/// v2 parity with v1's clearing model for the cases the projector can see:
/// an acknowledgement closes the obligation but leaves the mention, and
/// archiving withdraws every kind. Reply and no-longer-relevant closure are not
/// ported (see the follow-up note in the C2 task).
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn acknowledging_and_archiving_withdraw_candidates_like_v1() {
    let w = world().await;
    let mut ack = send_args(&w, "withdraw-ack");
    ack["expectation"] = json!("ack");
    ack["body"] = json!("@Viewer please ack");
    ack["mentions"] = json!([{"mention_id":"m1","target_kind":"principal","target_id":"person:viewer","span_start":0,"span_end":7,"authored_label":"@Viewer"}]);
    let sent = call(&w, "acct:admin", "manage_messages", ack)
        .await
        .unwrap();
    let ack_id = sent["id"].as_str().unwrap().to_owned();
    assert_eq!(
        effective_viewer_reasons(&w, &ack_id).await,
        vec!["human_obligation", "principal_mention"]
    );
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"satisfy_acknowledgement_expectation_with_reaction","message_id":ack_id,"idempotency_key":"withdraw-ack-1","reason":"Acknowledge"}),
    )
    .await
    .unwrap();
    assert_eq!(
        effective_viewer_reasons(&w, &ack_id).await,
        vec!["principal_mention"]
    );

    let pref = |action: &str, version: i64, key: &str| json!({"action":"set_preference","message_id":ack_id,"preference":action,"expected_version":version,"idempotency_key":key,"reason":"Notification preference"});
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        pref("archive", 0, "withdraw-archive"),
    )
    .await
    .unwrap();
    assert!(effective_viewer_reasons(&w, &ack_id).await.is_empty());
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        pref("restore", 1, "withdraw-restore"),
    )
    .await
    .unwrap();
    assert!(
        effective_viewer_reasons(&w, &ack_id).await.is_empty(),
        "restoring proposes nothing back"
    );

    // Archiving again, after a snooze proposed a reminder, withdraws that too.
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        pref("archive", 2, "withdraw-archive-2"),
    )
    .await
    .unwrap();
    let until = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    let mut snooze = pref("snooze", 3, "withdraw-snooze");
    snooze["snoozed_until"] = json!(until);
    call(&w, "acct:viewer", "manage_messages", snooze)
        .await
        .unwrap();
    assert_eq!(
        effective_viewer_reasons(&w, &ack_id).await,
        vec!["snooze_due"]
    );
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        pref("archive", 4, "withdraw-archive-3"),
    )
    .await
    .unwrap();
    assert!(effective_viewer_reasons(&w, &ack_id).await.is_empty());

    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

/// An acknowledgement closes the acknowledger's routing as v1's does, so an
/// obligation reopened after an earlier acknowledgement is withdrawn again by a
/// fresh one, with or without the thumbs-up having been removed in between.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn a_fresh_acknowledgement_closes_a_reopened_obligation() {
    let w = world().await;
    let mut ask = send_args(&w, "reopen-ack-req");
    ask["expectation"] = json!("ack");
    let sent = call(&w, "acct:admin", "manage_messages", ask)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap().to_owned();
    assert_eq!(
        effective_viewer_reasons(&w, &id).await,
        vec!["human_obligation"]
    );

    let ack = |key: &str| json!({"action":"satisfy_acknowledgement_expectation_with_reaction","message_id":id,"idempotency_key":key,"reason":"Acknowledge"});
    let first = call(&w, "acct:viewer", "manage_messages", ack("reopen-ack-1"))
        .await
        .unwrap();
    assert_eq!(first["changed"], true);
    assert!(effective_viewer_reasons(&w, &id).await.is_empty());

    let registry = super::super::tests::registry();
    let route = |version: i64, key: &str, nonce: &str| {
        let registry = &registry;
        let (db, id) = (w.db.clone(), id.clone());
        let key = key.to_owned();
        let nonce = nonce.to_owned();
        async move {
            registry
                .call_engine(
                    EngineHandle::KernelV2(db),
                    Caller::authenticated("acct:viewer").with_verified_human_interaction(
                        crate::awareness::VerifiedHumanInteraction {
                            nonce,
                            executor_ref: "proof-host".into(),
                        },
                    ),
                    "manage_messages",
                    json!({"action":"set_routing","message_id":id,"obligation_state":"open","executor_route":"human","expected_version":version,"idempotency_key":key,"reason":"Reopen"}),
                )
                .await
                .unwrap()
        }
    };
    // Reopen: a fresh candidate, although the old acknowledgement still stands.
    route(1, "reopen-route-1", "reopen-nonce-1").await;
    assert_eq!(
        effective_viewer_reasons(&w, &id).await,
        vec!["human_obligation"]
    );

    // A fresh acknowledgement under a new key closes the routing again.
    let second = call(&w, "acct:viewer", "manage_messages", ack("reopen-ack-2"))
        .await
        .unwrap();
    assert_eq!(second["changed"], true);
    assert!(effective_viewer_reasons(&w, &id).await.is_empty());
    let events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_message_candidate_events WHERE principal_id=?",
    )
    .bind(&w.viewer)
    .fetch_one(w.db.pool())
    .await
    .unwrap();

    // An exact retry replays the receipt; a fresh key with nothing left to
    // close changes nothing. Neither appends a candidate event.
    let retry = call(&w, "acct:viewer", "manage_messages", ack("reopen-ack-2"))
        .await
        .unwrap();
    assert_eq!(
        retry["changed"], true,
        "the retry returns the original receipt"
    );
    let nothing = call(&w, "acct:viewer", "manage_messages", ack("reopen-ack-3"))
        .await
        .unwrap();
    assert_eq!(nothing["changed"], false);
    let after: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_message_candidate_events WHERE principal_id=?",
    )
    .bind(&w.viewer)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(after, events);

    // Variant: the thumbs-up was removed before the fresh acknowledgement.
    route(3, "reopen-route-2", "reopen-nonce-2").await;
    assert_eq!(
        effective_viewer_reasons(&w, &id).await,
        vec!["human_obligation"]
    );
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"remove_reaction","message_id":id,"emoji":"👍","idempotency_key":"reopen-unreact","reason":"Remove"}),
    )
    .await
    .unwrap();
    let third = call(&w, "acct:viewer", "manage_messages", ack("reopen-ack-4"))
        .await
        .unwrap();
    assert_eq!(third["changed"], true);
    assert!(effective_viewer_reasons(&w, &id).await.is_empty());
    let delivered =
        crate::awareness::harvest_host_notification_candidates(&w.db, "acct:viewer", true, 0, 500)
            .await
            .unwrap();
    assert!(
        delivered.candidates.is_empty(),
        "nothing effective is left to deliver"
    );

    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn message_policy_list_refuses_instead_of_describing_the_home_policy() {
    let w = world().await;
    let mut args = send_args(&w, "policy-audience");
    args["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let sent = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let error = call(
        &w,
        "acct:admin",
        "manage_record_policy",
        json!({"action":"list","record_id":id}),
    )
    .await
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("Message access uses its sealed audience"));
    let error = call(
        &w,
        "acct:outsider",
        "manage_record_policy",
        json!({"action":"list","record_id":id}),
    )
    .await
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        Error::engine("manage_record_policy: record does not exist").to_string()
    );
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn message_policy_listing_refuses_derived_comment_and_attachment_home_policies() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "policy-derived"),
    )
    .await
    .unwrap();
    let message = sent["id"].as_str().unwrap();
    let attachment = call(
        &w,
        "acct:admin",
        "attach_text",
        json!({"record_id":message,"text":"sealed attachment"}),
    )
    .await
    .unwrap();
    let comment = call(&w, "acct:admin", "create_record", json!({"type":"Annotation","kind":"comment","body":"sealed comment","links":[{"target_id":message,"relationship":"part_of"}],"reason":"policy regression"})).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for id in [
        message,
        attachment["attachment_id"].as_str().unwrap(),
        comment["id"].as_str().unwrap(),
    ] {
        let error = call(
            &w,
            "acct:admin",
            "manage_record_policy",
            json!({"action":"list","record_id":id}),
        )
        .await
        .unwrap_err();
        assert_eq!(error.to_string(), Error::engine("manage_record_policy: Message access uses its sealed audience; a home policy listing does not describe Message access and isn't available on v2 yet").to_string());
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn bounded_message_get_and_discovery_match_full_staging_and_old_filter() {
    let w = world().await;
    let mut message_ids = Vec::new();
    for direct in [false, true] {
        let mut args = send_args(
            &w,
            if direct {
                "parity-direct"
            } else {
                "parity-channel"
            },
        );
        args["body"] = json!("parityneedle");
        if direct {
            args["origin"] =
                json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
        }
        let answer = call(&w, "acct:admin", "manage_messages", args)
            .await
            .unwrap();
        message_ids.push(answer["id"].as_str().unwrap().to_owned());
    }
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let pin = kernel::read_record_as(&w.db, &w.admin, &w.origin)
        .await
        .unwrap()
        .unwrap()
        .pin
        .unwrap();
    let private = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[]), &w.admin)
        .await
        .unwrap();
    let mut ids = message_ids.clone();
    for (id, typ, kind, home, owner) in [
        (
            "parity-document",
            "Document",
            "note",
            KERNEL_ROOT_ID,
            w.admin.as_str(),
        ),
        (
            "parity-private",
            "Document",
            "note",
            private.as_str(),
            w.admin.as_str(),
        ),
        (
            "parity-owner",
            "Document",
            "note",
            private.as_str(),
            w.viewer.as_str(),
        ),
        (
            "parity-derived",
            "Annotation",
            "comment",
            private.as_str(),
            w.admin.as_str(),
        ),
    ] {
        kernel::import_record_as(
            &w.db,
            &host,
            id,
            home,
            Some(owner),
            &kernel::ImportRecordState {
                body: Some("parityneedle".into()),
                definition: Some(kernel::ImportDefinition {
                    pin: pin.clone(),
                    primary_type: "V1".into(),
                    kind: crate::v2_standard::v1_compat::KIND.into(),
                    fields: crate::v2_standard::v1_compat::compat_fields(
                        typ,
                        kind,
                        Some("parityneedle"),
                        None,
                        None,
                    ),
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        ids.push(id.to_owned());
    }
    kernel::generic_links::import_generic_link_as(
        &w.db,
        &host,
        &kernel::GenericLink {
            link_id: "parity-bearer-link".into(),
            source_id: "parity-derived".into(),
            target_id: "parity-document".into(),
            relationship: "part_of".into(),
            note: None,
            created_at: "2026-10-21T00:00:00Z".into(),
            actor: None,
        },
    )
    .await
    .unwrap();
    let reads = [
        ("records", "id"),
        ("records", "type"),
        ("records", "kind"),
        ("records", "name"),
        ("records", "archived"),
        ("records", "created_at"),
        ("records", "home_id"),
        ("links", "source_id"),
        ("links", "target_id"),
        ("links", "relationship"),
    ];
    for (credential, actor) in [
        ("acct:admin", &w.admin),
        ("acct:viewer", &w.viewer),
        ("acct:outsider", &w.outsider),
    ] {
        // The ordinary-record fast path must match the original recursive
        // audience reader for every record, including private Messages and
        // their derived bearers, independently of the final record gate.
        let mut snapshot = w.db.pool().begin().await.unwrap();
        let homes = kernel::visible_home_anchors_as(&mut snapshot, actor)
            .await
            .unwrap();
        let homes: Vec<_> = homes
            .homes
            .iter()
            .filter(|h| h.policy_valid)
            .map(|h| json!({"id":h.home_id,"view":h.policy_view}))
            .collect();
        let guard = kernel::messaging::sql_guard("r", "?1", "SELECT json_extract(value,'$.id') AS id,json_extract(value,'$.view') AS view FROM json_each(?2)", false);
        let results: Vec<(String, bool)> =
            sqlx::query_as(&format!("SELECT r.id,({guard}) FROM kernel_records r"))
                .bind(actor)
                .bind(serde_json::to_string(&homes).unwrap())
                .fetch_all(&mut *snapshot)
                .await
                .unwrap();
        for (id, allowed) in results {
            assert_eq!(
                allowed,
                kernel::messaging::audience_allows(&mut snapshot, actor, &id)
                    .await
                    .unwrap(),
                "audience fast path {credential}/{id}"
            );
        }
        snapshot.rollback().await.unwrap();
        let groups = kernel::search_v2::distinct_groups(&w.db).await.unwrap();
        for (types, kinds) in [
            (vec!["Message".to_owned()], Vec::new()),
            (
                vec![
                    "Document".to_owned(),
                    "Annotation".to_owned(),
                    "Message".to_owned(),
                ],
                Vec::new(),
            ),
            (vec!["Annotation".to_owned()], vec!["comment".to_owned()]),
        ] {
            for offset in [0, 1, usize::MAX] {
                let counters = kernel::search_v2::S7aCounters::default();
                let scan = kernel::search_v2::FORCE_GROUP_SCAN
                    .scope(
                        true,
                        kernel::search_v2::bounded_query_as(
                            &w.db,
                            actor,
                            &groups,
                            None,
                            Some(&types),
                            Some(&kinds),
                            None,
                            2,
                            offset,
                            &counters,
                        ),
                    )
                    .await
                    .unwrap();
                let counters = kernel::search_v2::S7aCounters::default();
                let counted = kernel::search_v2::bounded_query_as(
                    &w.db,
                    actor,
                    &groups,
                    None,
                    Some(&types),
                    Some(&kinds),
                    None,
                    2,
                    offset,
                    &counters,
                )
                .await
                .unwrap();
                assert_eq!(counted.total, scan.total, "counted total {credential}");
                let shape = |page: kernel::search_v2::BoundedQueryPage| {
                    page.records.into_iter().map(|r|json!({"id":r.id,"home":r.home_id,"owner":r.owner_id,"type":r.primary_type,"kind":r.kind,"fields":r.fields,"revision":r.revision,"pin":r.pin,"metadata":r.metadata})).collect::<Vec<_>>()
                };
                assert_eq!(
                    shape(counted),
                    shape(scan),
                    "counted window {credential}/{offset}"
                );
            }
        }
        let args = json!({"ids":ids,"include_comments":true});
        let expected = kernel::read_cache::scope_request(super::super::sql::with_read_session(
            &w.db,
            actor,
            &reads,
            super::super::get_record_in_session(&w.db, actor, args.clone()),
        ))
        .await
        .unwrap();
        let actual = call(&w, credential, "get_record", args).await.unwrap();
        assert_eq!(
            actual["records"], expected["records"],
            "bounded/full {credential}"
        );
        let expected = kernel::search_v2::pre_staging_visible_ids(&w.db, actor, &ids)
            .await
            .unwrap();
        let listing = call(
            &w,
            credential,
            "query_record",
            json!({"steps":[{"step":"filter","ids":ids}],"limit":100}),
        )
        .await
        .unwrap();
        let actual: BTreeSet<String> = listing["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            actual,
            expected.iter().cloned().collect(),
            "old query filter {credential}"
        );
        let hits = call(
            &w,
            credential,
            "search",
            json!({"query":"parityneedle","limit":100}),
        )
        .await
        .unwrap();
        let actual: BTreeSet<String> = hits["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            actual,
            expected.into_iter().collect(),
            "old search filter {credential}"
        );
    }
    w.db.close().await;
}

/// Message edit is v1-only for now: v2 refuses it by name and writes
/// nothing, rather than failing as an unknown action or half-applying.
/// Delete is implemented below (`kernel_v2_message_delete_*`).
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn message_edit_is_unsupported_on_v2_and_writes_nothing() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "edit-send"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let state = call(
        &w,
        "acct:admin",
        "manage_messages",
        json!({"action":"list_message_state","message_ids":[id]}),
    )
    .await
    .unwrap();
    assert_eq!(
        state["capabilities"],
        json!({"edit":false,"delete":true,"reactions":true,"saved_session_sharing":false})
    );
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let error = call(
        &w,
        "acct:admin",
        "manage_messages",
        json!({"action":"edit","message_id":id,"body":"changed","idempotency_key":"e","reason":"fixture"}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("unsupported"), "{error}");
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

fn delete_args(id: &str, key: &str, reason: &str) -> Value {
    json!({"action":"delete","message_id":id,"idempotency_key":key,"reason":reason})
}

/// Send one channel Message in the world origin from `who` to one person.
async fn send_from(w: &World, who: &str, key: &str, addressed: &str) -> String {
    let mut args = send_args(w, key);
    args["addressed_to"] = json!([addressed]);
    call(w, who, "manage_messages", args).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

async fn context_ids(w: &World, who: &str) -> Vec<String> {
    let context = call(
        w,
        who,
        "manage_messages",
        json!({"action":"list_context","origin":{"type":"collection","collection_id":w.origin},"limit":200}),
    )
    .await
    .unwrap();
    context["messages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["id"].as_str().unwrap().to_owned())
        .collect()
}

async fn deletion_event_count(w: &World, id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events WHERE record_id=? AND type='kernel.record_deleted.v1'",
    )
    .bind(id)
    .fetch_one(w.db.pool())
    .await
    .unwrap()
}

/// v1 parity (messaging_delete_tests.rs): the author's delete tombstones
/// the Message, hides it from every reader, withdraws its notification
/// candidates and keeps the stored state for history/replay.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_author_tombstones_hides_and_withdraws() {
    let w = world().await;
    let id = send_from(&w, "acct:admin", "del-author-send", "person:viewer").await;
    assert!(context_ids(&w, "acct:viewer").await.contains(&id));
    let inbox = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    assert!(inbox.to_string().contains(&id), "{inbox}");
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert!(
        kernel::notifications::count_on(&mut conn, &w.viewer, &id)
            .await
            .unwrap()
            > 0
    );
    drop(conn);

    // Give the Message a reply, a reaction and two classifications, so the
    // replay check below covers a deleted parent with live dependents.
    // v2 has no deleted-parent stub: the parent drops out of every list
    // and the reply stays.
    let mut reply_args = send_args(&w, "del-author-reply");
    reply_args["addressed_to"] = json!(["person:admin"]);
    reply_args["links"] = json!([{"target_id":id,"relationship":"reply_to"}]);
    let reply = call(&w, "acct:viewer", "manage_messages", reply_args)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"del-author-react","reason":"fixture"}),
    )
    .await
    .unwrap();
    let mut conversations = Vec::new();
    for name in ["del thread a", "del thread b"] {
        let conversation = call(
            &w,
            "acct:admin",
            "create_record",
            json!({"type":"Conversation","kind":"thread","name":name,"reason":"fixture"}),
        )
        .await
        .unwrap();
        conversations.push(conversation["id"].as_str().unwrap().to_owned());
    }
    for (message, conversation) in [
        (&id, &conversations[0]),
        (&reply, &conversations[0]),
        (&id, &conversations[1]),
    ] {
        call(
            &w,
            "acct:admin",
            "manage_messages",
            json!({"action":"classify","message_id":message,"conversation_id":conversation}),
        )
        .await
        .unwrap();
    }

    let receipt = call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&id, "del-author", "Taking it back."),
    )
    .await
    .unwrap();
    assert_eq!(receipt["status"], "deleted");
    assert_eq!(receipt["message_id"], id.as_str());
    assert!(receipt["deleted_at"].is_string(), "{receipt}");
    assert_eq!(deletion_event_count(&w, &id).await, 1);
    let tombstone_at: Option<String> =
        sqlx::query_scalar("SELECT deleted_at FROM kernel_import_tombstones WHERE record_id=?")
            .bind(&id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(tombstone_at.as_deref(), receipt["deleted_at"].as_str());

    for who in ["acct:admin", "acct:viewer"] {
        assert!(!context_ids(&w, who).await.contains(&id), "{who}");
        let error = call(
            &w,
            who,
            "manage_messages",
            json!({"action":"list_message_state","message_ids":[id]}),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("missing or hidden"), "{error}");
    }
    // The reply survives in the channel, and each Conversation drops only
    // the deleted parent.
    assert!(context_ids(&w, "acct:viewer").await.contains(&reply));
    for (conversation, keeps_reply) in [(&conversations[0], true), (&conversations[1], false)] {
        let listed = call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":"list_conversation","conversation_id":conversation}),
        )
        .await
        .unwrap();
        let ids: Vec<String> = listed["messages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["id"].as_str().unwrap().to_owned())
            .collect();
        assert!(!ids.contains(&id), "{listed}");
        assert_eq!(ids.contains(&reply), keeps_reply, "{listed}");
    }
    let inbox = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse"}),
    )
    .await
    .unwrap();
    assert!(!inbox.to_string().contains(&id), "{inbox}");

    // Notification candidates are withdrawn, not left effective.
    let mut conn = w.db.pool().acquire().await.unwrap();
    assert_eq!(
        kernel::notifications::count_on(&mut conn, &w.viewer, &id)
            .await
            .unwrap(),
        0
    );
    drop(conn);
    let status: String = sqlx::query_scalar(
        "SELECT json_extract(state,'$.status') FROM kernel_message_candidates WHERE message_id=? LIMIT 1",
    )
    .bind(&id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(status, "withdrawn");

    // A reaction on the deleted Message is refused as missing.
    let error = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"del-react","reason":"fixture"}),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("missing or hidden"), "{error}");

    // The Message state is not erased, and projections replay identically.
    let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_messages WHERE message_id=?")
        .bind(&id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(kept, 1);
    let after = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(after, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

/// The viewer authors in the origin channel; admin holds Manage there
/// (Manage on the root home the collection and its Messages live in), so
/// admin may moderate. The deletion is attributed to the moderator with
/// the reason kept, and a keyed retry replays without a second event.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_channel_manager_moderates_and_retry_replays() {
    let w = world().await;
    let id = send_from(&w, "acct:viewer", "del-mgr-send", "person:admin").await;
    let receipt = call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&id, "del-mgr", "Moderation: spam."),
    )
    .await
    .unwrap();
    assert_eq!(receipt["status"], "deleted");
    assert_eq!(receipt["message_id"], id.as_str());
    let (actor, payload): (Option<String>, String) = sqlx::query_as(
        "SELECT actor,payload FROM content_events WHERE record_id=? AND type='kernel.record_deleted.v1'",
    )
    .bind(&id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(actor.as_deref(), Some(w.admin.as_str()));
    assert!(payload.contains("Moderation: spam."), "{payload}");
    assert!(!context_ids(&w, "acct:viewer").await.contains(&id));

    let replay = call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&id, "del-mgr", "Moderation: spam."),
    )
    .await
    .unwrap();
    assert_eq!(replay["status"], receipt["status"]);
    assert_eq!(replay["message_id"], receipt["message_id"]);
    assert_eq!(replay["deleted_at"], receipt["deleted_at"]);
    assert_eq!(deletion_event_count(&w, &id).await, 1);
    w.db.close().await;
}

/// Edit on the channel (viewer) and View only (outsider) are not Manage:
/// neither may delete admin's Message. A persona-voiced Message follows
/// the same rule; its owner is its sender and may delete it.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_edit_and_view_members_are_refused() {
    let w = world().await;
    let id = send_from(&w, "acct:admin", "del-members-send", "person:viewer").await;
    for (who, key) in [
        ("acct:viewer", "del-viewer"),
        ("acct:outsider", "del-outsider"),
    ] {
        let error = call(
            &w,
            who,
            "manage_messages",
            delete_args(&id, key, "Not mine to remove."),
        )
        .await
        .unwrap_err();
        // No-event first: these callers are refused before anything is
        // written. In this fixture the executor gate and kernel admission
        // agree (neither holds Manage anywhere relevant); the moved-channel
        // test below isolates the channel check on its own.
        assert_eq!(deletion_event_count(&w, &id).await, 0, "{who}");
        assert!(
            error
                .to_string()
                .contains("only the author or someone who manages this channel can delete"),
            "{who}: {error}"
        );
    }
    assert_eq!(deletion_event_count(&w, &id).await, 0);
    assert!(context_ids(&w, "acct:viewer").await.contains(&id));

    let persona = call(
        &w,
        "acct:admin",
        "manage_participants",
        json!({"action":"register_persona","name":"Chief","reason":"fixture","idempotency_key":"del-persona"}),
    )
    .await
    .unwrap();
    let mut spoken = send_args(&w, "del-persona-send");
    spoken["speaker"] = json!({"persona_id":persona["persona_id"]});
    let spoken = call(&w, "acct:admin", "manage_messages", spoken)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let error = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&spoken, "del-persona-viewer", "Not mine to remove."),
    )
    .await
    .unwrap_err();
    assert_eq!(deletion_event_count(&w, &spoken).await, 0);
    assert!(error.to_string().contains("only the author"), "{error}");
    assert!(error.to_string().contains("sent as a persona"), "{error}");
    call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&spoken, "del-persona-owner", "Taking it back."),
    )
    .await
    .unwrap();
    w.db.close().await;
}

/// Filing a channel Message into a Conversation the filer manages (the
/// viewer owns the Conversation they create) confers no delete authority:
/// only the origin channel counts, never classification.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_classified_conversation_manager_gets_no_delete() {
    let w = world().await;
    let id = send_from(&w, "acct:admin", "del-filed-send", "person:viewer").await;
    let conversation = call(
        &w,
        "acct:viewer",
        "create_record",
        json!({"type":"Conversation","kind":"thread","name":"viewer's filing thread","reason":"fixture"}),
    )
    .await
    .unwrap();
    let conversation_id = conversation["id"].as_str().unwrap();
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"classify","message_id":id,"conversation_id":conversation_id}),
    )
    .await
    .unwrap();
    let listed = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_conversation","conversation_id":conversation_id}),
    )
    .await
    .unwrap();
    assert!(listed.to_string().contains(&id), "{listed}");
    let error = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&id, "del-filed", "Filed it, so mine."),
    )
    .await
    .unwrap_err();
    assert_eq!(deletion_event_count(&w, &id).await, 0);
    assert!(
        error
            .to_string()
            .contains("only the author or someone who manages this channel can delete"),
        "{error}"
    );
    assert!(context_ids(&w, "acct:viewer").await.contains(&id));
    w.db.close().await;
}

/// A Collection owner holds Manage on the channel through the owner floor
/// alone, with only Edit on the Message itself. Like v1, that channel
/// Manage is enough to moderate: kernel admission for a Message tombstone
/// accepts Manage on the Message's origin Collection as an alternative to
/// Manage on the Message. The tombstone is attributed to the creator with
/// the reason kept, exactly one event is written, and projections replay
/// identically. Generic `delete_record` does not gain the channel route:
/// it stays Manage-on-the-record for every type, Messages included, so
/// the creator is still refused there and moderation goes through
/// `manage_messages.delete` only. The same channel route covers an
/// author who manages the channel without Manage on their own Message,
/// and never a channel manager who cannot see the Message — the gate
/// and kernel admission both refuse that case.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_collection_owner_without_message_manage_moderates() {
    let w = world().await;
    // The viewer creates (and so owns) the channel; admin posts there.
    let channel = call(
        &w,
        "acct:viewer",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"viewer's channel","reason":"fixture"}),
    )
    .await
    .unwrap();
    let channel_id = channel["id"].as_str().unwrap().to_owned();
    let mut send = send_args(&w, "del-owner-send");
    send["origin"] = json!({"type":"collection","collection_id":channel_id});
    let id = call(&w, "acct:admin", "manage_messages", send)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    // Pin the premise and the generic-delete choice together: the creator
    // has no Manage on the Message, so generic delete_record refuses and
    // writes nothing, even though moderated delete below succeeds.
    let error = call(
        &w,
        "acct:viewer",
        "delete_record",
        json!({"id":id,"reason":"Generic delete has no channel route"}),
    )
    .await
    .unwrap_err();
    assert_eq!(deletion_event_count(&w, &id).await, 0);
    assert!(error.to_string().contains("missing or hidden"), "{error}");
    let receipt = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&id, "del-owner", "My channel, my call."),
    )
    .await
    .unwrap();
    assert_eq!(receipt["status"], "deleted");
    assert_eq!(receipt["message_id"], id.as_str());
    assert_eq!(deletion_event_count(&w, &id).await, 1);
    let (actor, payload): (Option<String>, String) = sqlx::query_as(
        "SELECT actor,payload FROM content_events WHERE record_id=? AND type='kernel.record_deleted.v1'",
    )
    .bind(&id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(actor.as_deref(), Some(w.viewer.as_str()));
    assert!(payload.contains("My channel, my call."), "{payload}");
    // The Message is gone from the channel for moderator and author alike.
    for who in ["acct:viewer", "acct:admin"] {
        let context = call(
            &w,
            who,
            "manage_messages",
            json!({"action":"list_context","origin":{"type":"collection","collection_id":channel_id},"limit":200}),
        )
        .await
        .unwrap();
        assert!(!context.to_string().contains(&id), "{who}: {context}");
    }
    // The creator-moderator tombstone replays identically: projection
    // replay does not re-evaluate today's channel authority.
    let after = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(after, kernel::dump_all_kernel_tables(&w.db).await.unwrap());

    // The channel arm also covers the author, as on v1: an author who
    // lacks Manage on their own Message but manages its channel may
    // delete it. Native sends cannot produce that state (the author is
    // the record owner, and the owner floor grants Manage), so simulate
    // an imported Message whose record owner is not its author by
    // moving ownership to the outsider. The Message and its channel
    // live in a home where admin holds only Edit, so after the move
    // admin has Edit — not Manage — on the Message, while still owning
    // (and so managing) the channel Collection. No replay comparison
    // follows: replay would restore the created owner this simulates
    // away.
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "manage"), (&w.admin, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    let own_channel = call(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"author's own channel","home_id":home,"reason":"fixture"}),
    )
    .await
    .unwrap();
    let own_channel_id = own_channel["id"].as_str().unwrap().to_owned();
    let mut own_send = send_args(&w, "del-owner-author-send");
    own_send["origin"] = json!({"type":"collection","collection_id":own_channel_id});
    let own = call(&w, "acct:admin", "manage_messages", own_send)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    sqlx::query("UPDATE kernel_records SET owner_id=? WHERE id=?")
        .bind(&w.outsider)
        .bind(&own)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // Pin the premise: with no Manage on the Message, generic
    // delete_record refuses the author and writes nothing.
    let error = call(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id":own,"reason":"Generic delete has no channel route"}),
    )
    .await
    .unwrap_err();
    assert_eq!(deletion_event_count(&w, &own).await, 0);
    assert!(error.to_string().contains("missing or hidden"), "{error}");
    let receipt = call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&own, "del-owner-author", "My post, my channel."),
    )
    .await
    .unwrap();
    assert_eq!(receipt["status"], "deleted");
    assert_eq!(receipt["message_id"], own.as_str());
    assert_eq!(deletion_event_count(&w, &own).await, 1);
    let actor: Option<String> = sqlx::query_scalar(
        "SELECT actor FROM content_events WHERE record_id=? AND type='kernel.record_deleted.v1'",
    )
    .bind(&own)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(actor.as_deref(), Some(w.admin.as_str()));

    // Defence in depth: channel Manage without View on the Message is
    // not enough, at the gate or in kernel admission itself. The
    // viewer owns this channel, but the Message has been rehomed into
    // a home only admin can see.
    let hidden_channel = call(
        &w,
        "acct:viewer",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"unseen channel posts","reason":"fixture"}),
    )
    .await
    .unwrap();
    let hidden_channel_id = hidden_channel["id"].as_str().unwrap().to_owned();
    let mut hidden_send = send_args(&w, "del-owner-hidden-send");
    hidden_send["origin"] = json!({"type":"collection","collection_id":hidden_channel_id});
    let hidden = call(&w, "acct:admin", "manage_messages", hidden_send)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let private_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &hidden, &private_home)
        .await
        .unwrap();
    let error = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&hidden, "del-owner-hidden", "My channel, sight unseen."),
    )
    .await
    .unwrap_err();
    assert_eq!(deletion_event_count(&w, &hidden).await, 0);
    assert!(error.to_string().contains("missing or hidden"), "{error}");
    // Bypassing the executor gate does not help: appends run kernel
    // admission, which requires View on the Message for the channel
    // route. Nothing is committed either way.
    let head: i64 =
        sqlx::query_scalar("SELECT MAX(seq) FROM main.content_events WHERE record_id=?")
            .bind(&hidden)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    let mut tx = crate::db::begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = crate::act::ActAllocation::new();
    let error = crate::store::append_in(
        &w.db,
        &mut tx,
        crate::store::AppendSpec {
            record_id: hidden.clone(),
            event_type: kernel::deletion::EVENT.into(),
            payload: serde_json::to_value(kernel::deletion::Deleted {
                reason: "Direct tombstone bypass".into(),
                previous_seq: head,
            })
            .unwrap(),
            actor: Some(w.viewer.clone()),
        },
        &mut acts,
    )
    .await
    .unwrap_err();
    drop(tx);
    assert_eq!(deletion_event_count(&w, &hidden).await, 0);
    assert!(error.to_string().contains("missing or hidden"), "{error}");
    w.db.close().await;
}

/// The moderator's Manage comes from a policy grant on the channel's own
/// home, not from the root: the viewer holds only Edit on the root home
/// but Manage in this home, where the Collection and admin's Message
/// live, and may delete admin's Message there.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_moderator_manages_through_the_channel_home_grant() {
    let w = world().await;
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "manage"), (&w.admin, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    let channel = call(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"granted channel","home_id":home,"reason":"fixture"}),
    )
    .await
    .unwrap();
    let channel_id = channel["id"].as_str().unwrap().to_owned();
    let mut send = send_args(&w, "del-grant-send");
    send["origin"] = json!({"type":"collection","collection_id":channel_id});
    let id = call(&w, "acct:admin", "manage_messages", send)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let receipt = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&id, "del-grant", "Moderation: off-topic."),
    )
    .await
    .unwrap();
    assert_eq!(receipt["status"], "deleted");
    assert_eq!(receipt["message_id"], id.as_str());
    assert_eq!(deletion_event_count(&w, &id).await, 1);
    let (actor, payload): (Option<String>, String) = sqlx::query_as(
        "SELECT actor,payload FROM content_events WHERE record_id=? AND type='kernel.record_deleted.v1'",
    )
    .bind(&id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(actor.as_deref(), Some(w.viewer.as_str()));
    assert!(payload.contains("Moderation: off-topic."), "{payload}");
    w.db.close().await;
}

/// The one case only the channel check can refuse: the viewer keeps
/// Manage on the Message (through the home it was sent in) but the
/// channel Collection has since moved to the root, where the viewer
/// holds only Edit. Kernel admission would admit this delete, so the
/// refusal proves the executor's Manage-on-origin-channel check on its
/// own. This matches v1: someone who no longer manages a channel loses
/// moderation over its older Messages.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_moved_channel_leaves_only_the_channel_check_to_refuse() {
    let w = world().await;
    let home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "manage"), (&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    let channel = call(
        &w,
        "acct:admin",
        "create_record",
        json!({"type":"Collection","kind":"folder","name":"movable channel","home_id":home,"reason":"fixture"}),
    )
    .await
    .unwrap();
    let channel_id = channel["id"].as_str().unwrap().to_owned();
    let mut send = send_args(&w, "del-moved-send");
    send["origin"] = json!({"type":"collection","collection_id":channel_id});
    let id = call(&w, "acct:admin", "manage_messages", send)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    kernel::rehome_record_as(&w.db, &w.admin, &channel_id, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let error = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&id, "del-moved", "I managed this channel once."),
    )
    .await
    .unwrap_err();
    assert_eq!(deletion_event_count(&w, &id).await, 0);
    assert!(
        error
            .to_string()
            .contains("only the author or someone who manages this channel can delete a Message"),
        "{error}"
    );
    let context = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_context","origin":{"type":"collection","collection_id":channel_id},"limit":200}),
    )
    .await
    .unwrap();
    assert!(context.to_string().contains(&id), "{context}");
    // Pin that admission was not the refusal: the viewer really does hold
    // Manage on the Message itself, proven by the generic record delete
    // succeeding where the moderated delete was refused.
    call(
        &w,
        "acct:viewer",
        "delete_record",
        json!({"id":id,"reason":"Prove Message Manage"}),
    )
    .await
    .unwrap();
    w.db.close().await;
}

/// A direct Message has no channel, so delete stays author-only and the
/// refusal does not mention one; the author's delete then works.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_direct_message_is_author_only() {
    let w = world().await;
    let mut dm = send_args(&w, "del-dm-send");
    dm["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let id = call(&w, "acct:admin", "manage_messages", dm).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let error = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&id, "del-dm-viewer", "Not mine to remove."),
    )
    .await
    .unwrap_err();
    assert_eq!(deletion_event_count(&w, &id).await, 0);
    let refusal = error.to_string();
    assert!(
        refusal.contains("only the author can delete a Message"),
        "{refusal}"
    );
    assert!(!refusal.contains("channel"), "{refusal}");

    call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&id, "del-dm-author", "Taking it back."),
    )
    .await
    .unwrap();
    let context = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_context","origin":{"type":"direct","participant_ids":["person:admin","person:viewer"]},"limit":200}),
    )
    .await
    .unwrap();
    assert!(!context.to_string().contains(&id), "{context}");
    w.db.close().await;
}

/// Keyed replay (in the channel-manager test) aside: a fresh key on an
/// already-deleted Message is named as such to its author and reads as
/// missing to anyone else; a key cannot be reused for a different
/// Message; a caller who cannot see the Message gets the same refusal
/// as for a missing id; blank reason and key are refused.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_message_delete_second_delete_and_non_viewer_refusals() {
    let w = world().await;
    let id = send_from(&w, "acct:admin", "del-again-send", "person:viewer").await;
    let other = send_from(&w, "acct:admin", "del-again-other", "person:viewer").await;
    call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&id, "del-again", "Taking it back."),
    )
    .await
    .unwrap();
    let error = call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&id, "del-again-fresh", "Taking it back."),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("already deleted"), "{error}");
    let error = call(
        &w,
        "acct:viewer",
        "manage_messages",
        delete_args(&id, "del-again-viewer", "Not mine to remove."),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("missing or hidden"), "{error}");
    assert_eq!(deletion_event_count(&w, &id).await, 1);

    let error = call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&other, "del-again", "Taking it back."),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("idempotency_key"), "{error}");
    assert!(context_ids(&w, "acct:viewer").await.contains(&other));

    // The outsider cannot see a direct Message between admin and viewer:
    // its delete refusal is indistinguishable from a missing id's.
    let mut dm = send_args(&w, "del-hidden-send");
    dm["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let dm = call(&w, "acct:admin", "manage_messages", dm).await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let hidden = call(
        &w,
        "acct:outsider",
        "manage_messages",
        delete_args(&dm, "del-hidden", "Not mine to remove."),
    )
    .await
    .unwrap_err()
    .to_string();
    let missing = call(
        &w,
        "acct:outsider",
        "manage_messages",
        delete_args("missing-message", "del-missing", "Not mine to remove."),
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(deletion_event_count(&w, &dm).await, 0);
    assert_eq!(hidden, missing);

    let mut blank = delete_args(&other, "del-blank-reason", "Taking it back.");
    blank["reason"] = json!("  ");
    assert!(call(&w, "acct:admin", "manage_messages", blank)
        .await
        .is_err());
    assert!(call(
        &w,
        "acct:admin",
        "manage_messages",
        delete_args(&other, "  ", "Taking it back.")
    )
    .await
    .is_err());
    assert!(context_ids(&w, "acct:viewer").await.contains(&other));
    w.db.close().await;
}

fn arrival_args(arrival: &str, key: &str) -> Value {
    json!({"action":"set_notification_preference","arrival":arrival,
        "idempotency_key":key,"reason":"Private arrival choice"})
}
// Registry run_context is transport metadata, not the durable feature receipt.
// Keep exact equality for every receipt field while comparing retries.
fn arrival_receipt(mut value: Value) -> Value {
    value.as_object_mut().unwrap().remove("run_context");
    value
}
async fn arrivals(w: &World, account: &str) -> Value {
    call(
        w,
        account,
        "manage_messages",
        json!({"action":"list_notification_candidates"}),
    )
    .await
    .unwrap()["candidates"]
        .clone()
}
async fn quiet_send(
    w: &World,
    account: &str,
    key: &str,
    direct: bool,
    parent: Option<&str>,
) -> Value {
    let mut args = send_args(w, key);
    args["addressed_to"] = json!([]);
    args["expectation"] = json!("none");
    if direct {
        args["origin"] =
            json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    }
    if let Some(parent) = parent {
        args["links"] = json!([{"relationship":"reply_to","target_id":parent}]);
    }
    call(w, account, "manage_messages", args).await.unwrap()
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_arrival_preference_is_private_retry_safe_atomic_and_replayed() {
    let w = world().await;
    let get = || {
        call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":"get_notification_preference"}),
        )
    };
    assert_eq!(get().await.unwrap()["arrival"], "all");
    let noop = arrival_args("all", "initial-no-op");
    assert_eq!(
        call(&w, "acct:viewer", "manage_messages", noop.clone())
            .await
            .unwrap()["changed"],
        false
    );
    let vector = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    let set = arrival_args("off", "private-first");
    let first = arrival_receipt(
        call(&w, "acct:viewer", "manage_messages", set.clone())
            .await
            .unwrap(),
    );
    assert_eq!(
        first,
        json!({"arrival":"off","changed":true,"idempotent":false})
    );
    let updated = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    assert!(
        crate::realtime::inbox_addressed_since(w.db.pool(), "acct:viewer", &vector, &updated)
            .await
            .unwrap()
    );
    assert!(
        !crate::realtime::inbox_addressed_since(w.db.pool(), "acct:admin", &vector, &updated)
            .await
            .unwrap()
    );
    let event:String=sqlx::query_scalar("SELECT id FROM content_events WHERE type='kernel.notification_preference_set.v1' ORDER BY seq DESC LIMIT 1").fetch_one(w.db.pool()).await.unwrap();
    for who in ["acct:viewer", "acct:admin", "acct:outsider"] {
        assert!(
            call(&w, who, "get_event_context", json!({"event_id":event}))
                .await
                .unwrap_err()
                .to_string()
                .contains("does not exist")
        );
        assert_eq!(
            call(&w, who, "search", json!({"query":"Private arrival choice"}))
                .await
                .unwrap()["total"],
            0
        );
    }
    for who in ["acct:admin", "acct:outsider"] {
        assert_eq!(
            call(
                &w,
                who,
                "manage_messages",
                json!({"action":"get_notification_preference"})
            )
            .await
            .unwrap()["arrival"],
            "all"
        );
        let history = kernel::history_as(
            &w.db,
            if who == "acct:admin" {
                &w.admin
            } else {
                &w.outsider
            },
            &w.viewer,
        )
        .await
        .unwrap();
        assert!(!serde_json::to_string(&history)
            .unwrap()
            .contains("notification_preference_set"));
        for field in ["principal_id", "account_id", "subject"] {
            let mut args = json!({"action":"get_notification_preference"});
            args[field] = json!(w.viewer);
            let error = call(&w, who, "manage_messages", args)
                .await
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("subject is the authenticated account"),
                "{who}/{field}: {error}"
            );
        }
        let sql=call(&w,who,"query_sql",json!({"sql":"SELECT id FROM content_events WHERE type='kernel.notification_preference_set.v1'"})).await.unwrap();
        assert_eq!(sql["rows"], json!([]));
        assert!(call(
            &w,
            who,
            "query_sql",
            json!({"sql":"SELECT * FROM kernel_notification_preferences"})
        )
        .await
        .is_err());
        let changes = call(
            &w,
            who,
            "whats_changed",
            json!({"after_local_seq":vector.content}),
        )
        .await
        .unwrap();
        assert!(!changes.to_string().contains("notification_preference_set"));
    }
    // Exact retry after a newer choice must not apply the old setting again.
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        arrival_args("dms_and_mentions", "private-second"),
    )
    .await
    .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert_eq!(
        arrival_receipt(
            call(&w, "acct:viewer", "manage_messages", set.clone())
                .await
                .unwrap()
        ),
        first
    );
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(get().await.unwrap()["arrival"], "dms_and_mentions");
    assert_eq!(
        call(&w, "acct:viewer", "manage_messages", noop)
            .await
            .unwrap()["changed"],
        false
    );
    assert_eq!(get().await.unwrap()["arrival"], "dms_and_mentions");

    assert!(call(
        &w,
        "acct:viewer",
        "manage_messages",
        arrival_args("all", "private-first")
    )
    .await
    .is_err());
    for value in ["mentions_only", "invalid"] {
        assert!(call(
            &w,
            "acct:viewer",
            "manage_messages",
            arrival_args(value, "invalid")
        )
        .await
        .is_err());
    }
    // A failure saving the durable command receipt rolls back the setting too.
    sqlx::query("CREATE TRIGGER reject_preference_receipt BEFORE INSERT ON content_events WHEN NEW.type='kernel.message_command_committed.v1' BEGIN SELECT RAISE(ABORT,'receipt failure'); END").execute(w.db.write_pool()).await.unwrap();
    assert!(call(
        &w,
        "acct:viewer",
        "manage_messages",
        arrival_args("all", "failed-receipt")
    )
    .await
    .is_err());
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    sqlx::query("DROP TRIGGER reject_preference_receipt")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    // Two simultaneous identical operations commit one preference and receipt.
    let args = arrival_args("all", "concurrent");
    let (a, b) = tokio::join!(
        call(&w, "acct:viewer", "manage_messages", args.clone()),
        call(&w, "acct:viewer", "manage_messages", args)
    );
    assert_eq!(arrival_receipt(a.unwrap()), arrival_receipt(b.unwrap()));
    let dump = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(dump, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(get().await.unwrap()["arrival"], "all");
    assert_eq!(
        arrival_receipt(
            call(&w, "acct:viewer", "manage_messages", set)
                .await
                .unwrap()
        ),
        first
    );
    assert_eq!(get().await.unwrap()["arrival"], "all");
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_arrival_creation_uses_event_time_and_delivery_uses_current_preference() {
    let w = world().await;
    let first = quiet_send(&w, "acct:admin", "first-dm", true, None).await;
    let initial = arrivals(&w, "acct:viewer").await;
    assert_eq!(initial.as_array().unwrap().len(), 1);
    assert_eq!(initial[0]["message_id"], first["id"]);
    assert_eq!(initial[0]["reason"], "routine_arrival");
    let cid = initial[0]["candidate_id"].as_str().unwrap();
    assert!(arrivals(&w, "acct:admin")
        .await
        .as_array()
        .unwrap()
        .is_empty());
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        arrival_args("off", "off"),
    )
    .await
    .unwrap();
    let second = quiet_send(&w, "acct:admin", "off-dm", true, None).await;
    assert!(arrivals(&w, "acct:viewer")
        .await
        .as_array()
        .unwrap()
        .is_empty());
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
    assert!(
        !crate::awareness::revalidate_host_notification_candidate(&w.db, cid, "acct:viewer", true)
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted
    );
    // Neither off nor dms_and_mentions suppresses explicit mentions/obligations.
    let explicit = call(
        &w,
        "acct:admin",
        "manage_messages",
        channel_mention(&w, "off-mention", "@Viewer", "person:viewer"),
    )
    .await
    .unwrap();
    let mut obligation_args = send_args(&w, "off-obligation");
    obligation_args["origin"] =
        json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let obligation = call(&w, "acct:admin", "manage_messages", obligation_args)
        .await
        .unwrap();
    let current = arrivals(&w, "acct:viewer").await;
    assert!(current
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["message_id"] == explicit["id"] && v["reason"] == "principal_mention"));
    assert!(current
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["message_id"] == obligation["id"] && v["reason"] == "human_obligation"));
    assert_eq!(
        current
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["message_id"] == obligation["id"])
            .count(),
        1
    );
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        arrival_args("dms_and_mentions", "dm-only"),
    )
    .await
    .unwrap();
    quiet_send(&w, "acct:admin", "dm-reply", true, first["id"].as_str()).await;
    // Viewer authors a channel root. Its admin reply should be withheld.
    let root = quiet_send(&w, "acct:viewer", "channel-root", false, None).await;
    let withheld = quiet_send(
        &w,
        "acct:admin",
        "channel-reply-off",
        false,
        root["id"].as_str(),
    )
    .await;
    let current = arrivals(&w, "acct:viewer").await;
    assert!(!current
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["message_id"] == withheld["id"] || v["message_id"] == second["id"]));
    assert!(
        crate::awareness::revalidate_host_notification_candidate(&w.db, cid, "acct:viewer", true)
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted
    );
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        arrival_args("all", "all"),
    )
    .await
    .unwrap();
    let reply = quiet_send(
        &w,
        "acct:admin",
        "channel-reply-all",
        false,
        root["id"].as_str(),
    )
    .await;
    let current = arrivals(&w, "acct:viewer").await;
    assert!(current
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["message_id"] == reply["id"] && v["reason"] == "routine_arrival"));
    // Final all must not cause a replay to create candidates withheld earlier.
    let dump = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(dump, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(current, arrivals(&w, "acct:viewer").await);
    let home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(first["id"].as_str().unwrap())
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, &home, &[(&w.admin, "manage")])
        .await
        .unwrap();
    assert!(
        !crate::awareness::revalidate_host_notification_candidate(&w.db, cid, "acct:viewer", true)
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted
    );
    assert!(!arrivals(&w, "acct:viewer")
        .await
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["candidate_id"] == cid));
}

/// A later roster must neither remove an earlier eligible arrival nor admit
/// an arrival that was withheld while the recipient was not a member.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_arrival_creation_uses_event_time_hosted_membership() {
    let w = world().await;
    for (members, key) in [
        (vec!["acct:admin", "acct:viewer"], "before-removal"),
        (vec!["acct:admin"], "during-removal"),
    ] {
        let membership = unsafe {
            kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
                "acct:admin".into(),
                members.into_iter().map(str::to_owned).collect(),
            )
        };
        kernel::hosted_identity::reconcile_hosted_caller(&w.db, |_| async { Ok(membership) })
            .await
            .unwrap();
        quiet_send(&w, "acct:admin", key, true, None).await;
    }
    let membership = unsafe {
        kernel::hosted_identity::VerifiedHostedMembership::from_accounts_unchecked(
            "acct:admin".into(),
            BTreeSet::from(["acct:admin".into(), "acct:viewer".into()]),
        )
    };
    kernel::hosted_identity::reconcile_hosted_caller(&w.db, |_| async { Ok(membership) })
        .await
        .unwrap();
    let current = arrivals(&w, "acct:viewer").await;
    assert_eq!(current.as_array().unwrap().len(), 1);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(current, arrivals(&w, "acct:viewer").await);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_arrival_conversation_mute_applies_to_threads_and_exact_direct_sets() {
    let w = world().await;
    let root = quiet_send(&w, "acct:viewer", "mute-root", false, None).await;
    let dm = quiet_send(&w, "acct:admin", "mute-dm", true, None).await;
    let reply = quiet_send(&w, "acct:admin", "mute-reply", false, root["id"].as_str()).await;
    let initial = arrivals(&w, "acct:viewer").await;
    for (id, key) in [
        (root["id"].as_str().unwrap(), "mute-root-choice"),
        (dm["id"].as_str().unwrap(), "mute-dm-choice"),
    ] {
        call(&w,"acct:viewer","manage_messages",json!({"action":"set_preference","message_id":id,"preference":"mute","expected_version":0,"idempotency_key":key,"reason":"Mute this conversation"})).await.unwrap();
    }
    for candidate in initial.as_array().unwrap() {
        assert!(
            !crate::awareness::revalidate_host_notification_candidate(
                &w.db,
                candidate["candidate_id"].as_str().unwrap(),
                "acct:viewer",
                true
            )
            .await
            .unwrap()
            .unwrap()
            .effective_viewable_unmuted
        );
    }
    assert!(arrivals(&w, "acct:viewer")
        .await
        .as_array()
        .unwrap()
        .is_empty());
    quiet_send(
        &w,
        "acct:admin",
        "muted-deep-reply",
        false,
        reply["id"].as_str(),
    )
    .await;
    quiet_send(&w, "acct:admin", "muted-sibling-dm", true, None).await;
    assert!(arrivals(&w, "acct:viewer")
        .await
        .as_array()
        .unwrap()
        .is_empty());
    // A different participant set is not the muted DM conversation.
    let mut different = send_args(&w, "other-set");
    different["addressed_to"] = json!([]);
    different["expectation"] = json!("none");
    different["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer","person:outsider"]});
    let other = call(&w, "acct:admin", "manage_messages", different)
        .await
        .unwrap();
    assert_eq!(
        arrivals(&w, "acct:viewer").await[0]["message_id"],
        other["id"]
    );
    let dump = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(dump, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_arrival_preference_requires_explicit_preparation_for_old_v2_files() {
    let w = world().await;
    call(
        &w,
        "acct:viewer",
        "manage_messages",
        arrival_args("off", "before-projection-loss"),
    )
    .await
    .unwrap();
    sqlx::query("DROP TABLE kernel_notification_preferences")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(kernel::verify_v2_ready(&w.db)
        .await
        .unwrap_err()
        .to_string()
        .contains("kernel_notification_preferences"));
    // Ordinary opening/readiness is not DDL or implicit trust in v1 control history.
    kernel::prepare_v2_database(&w.db).await.unwrap();
    kernel::verify_v2_ready(&w.db).await.unwrap();
    assert_eq!(
        call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":"get_notification_preference"})
        )
        .await
        .unwrap()["arrival"],
        "off"
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_arrival_generic_append_import_and_forged_projection_are_refused() {
    use crate::{
        act::ActAllocation,
        db::begin_write,
        store::{append_in, AppendSpec},
    };
    let w = world().await;
    let spec = || AppendSpec {
        record_id: w.viewer.clone(),
        actor: Some(w.viewer.clone()),
        event_type: kernel::notifications::PREFERENCE_EVENT.into(),
        payload: json!({"arrival":"off"}),
    };
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    assert!(crate::store::append(&w.db, spec())
        .await
        .unwrap_err()
        .to_string()
        .contains("cannot be appended"));
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    assert!(append_in(&w.db, &mut tx, spec(), &mut ActAllocation::new())
        .await
        .unwrap_err()
        .to_string()
        .contains("sealed kernel commit port"));
    assert!(crate::store::append_migration_on(
        &mut tx,
        uuid::Uuid::new_v4().to_string(),
        spec(),
        "2026-10-24T00:00:00Z"
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("cannot be imported"));
    tx.rollback().await.unwrap();
    let forged = crate::events::EventRow {
        local_seq: -1,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: w.viewer.clone(),
        event_type: kernel::notifications::PREFERENCE_EVENT.into(),
        payload: Some(json!({"arrival":"off"}).to_string()),
        actor: Some(w.viewer.clone()),
        created_at: "2026-10-24T00:00:00Z".into(),
        run_key: None,
        parent_key: None,
        intent: None,
        act: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
    };
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    assert!(crate::projector::project(&mut tx, &forged)
        .await
        .unwrap_err()
        .to_string()
        .contains("kernel-issued logged event"));
    tx.rollback().await.unwrap();
    for payload in [
        json!({"arrival":"mentions_only"}),
        json!({"arrival":"off","subject":w.admin}),
    ] {
        let mut tx = begin_write(w.db.write_pool()).await.unwrap();
        let mut bad = spec();
        bad.payload = payload;
        assert!(crate::store::append_kernel_notification_preference_in(
            &w.db,
            &mut tx,
            bad,
            &mut ActAllocation::new()
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
    }
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut bad = spec();
    bad.record_id = w.admin.clone();
    assert!(crate::store::append_kernel_notification_preference_in(
        &w.db,
        &mut tx,
        bad,
        &mut ActAllocation::new()
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

async fn imported_thread_message(
    w: &World,
    id: &str,
    author: &str,
    parent: Option<&str>,
    delivered: bool,
) {
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
        id,
        KERNEL_ROOT_ID,
        Some(author),
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
                    Some(id),
                    None,
                    None,
                ),
            }),
            message: Some(kernel::MessageState {
                author: Some(author.into()),
                audience: std::collections::BTreeMap::from([(author.into(), "manage".into())]),
                origin: json!({"type":"collection","collection_id":w.origin}),
                reply_to: parent.map(str::to_owned),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    if delivered {
        kernel::import_event_as(
            &w.db,
            &host,
            id,
            &kernel::LegacyEvent {
                source: Some(
                    json!({"stream":"content_events","subjects":[id],"metadata":{"record_id":id}}),
                ),
                id: format!("delivery-{id}"),
                event_type: "message.send_evaluated.v1".into(),
                payload: json!({"delivered":true}),
                created_at: "2026-10-24T00:00:00Z".into(),
                actor: None,
                run_key: None,
            },
        )
        .await
        .unwrap();
    }
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn notification_arrival_threads_are_cycle_safe_unbounded_and_do_not_cross_drafts() {
    let w = world().await;
    // A frozen imported cycle longer than common recursive depth limits.
    for n in 0..70 {
        let id = format!("old-thread-{n}");
        let parent = format!("old-thread-{}", (n + 1) % 70);
        imported_thread_message(
            &w,
            &id,
            if n == 0 { &w.viewer } else { &w.admin },
            Some(&parent),
            true,
        )
        .await;
    }
    let reply = quiet_send(
        &w,
        "acct:admin",
        "long-cycle-reply",
        false,
        Some("old-thread-35"),
    )
    .await;
    assert_eq!(
        arrivals(&w, "acct:viewer").await[0]["message_id"],
        reply["id"]
    );
    // An audience is insufficient delivery evidence. The draft's viewer author
    // and its edge into the delivered cycle must not widen routine recipients.
    imported_thread_message(&w, "draft-bridge", &w.viewer, Some("old-thread-0"), false).await;
    let draft_reply =
        quiet_send(&w, "acct:admin", "draft-reply", false, Some("draft-bridge")).await;
    assert!(!arrivals(&w, "acct:viewer")
        .await
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["message_id"] == draft_reply["id"]));
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
}

/// A public reaction is derived from adjacent full states, but private states
/// between reactions must neither emit headers nor duplicate another window.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn bounded_global_history_matches_reaction_headers_across_private_windows() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "history-window-send"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    call(&w, "acct:admin", "manage_messages", json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"window-react","reason":"Public reaction"})).await.unwrap();
    for n in 0..270 {
        call(&w, "acct:admin", "manage_messages", json!({"action":"set_preference","message_id":id,"preference":if n%2==0 {"mute"} else {"unmute"},"expected_version":n,"idempotency_key":format!("window-private-{n}"),"reason":"Private state is not public history"})).await.unwrap();
    }
    call(&w, "acct:admin", "manage_messages", json!({"action":"remove_reaction","message_id":id,"emoji":"👍","idempotency_key":"window-unreact","reason":"Public reaction removal"})).await.unwrap();
    let scan = call(&w, "acct:admin", "scan", json!({"scope":id}))
        .await
        .unwrap();
    let latest=call(&w,"acct:admin","query_sql",json!({"sql":"SELECT created_at FROM content_events WHERE record_id=?1 AND type='message.reaction.removed.v1' ORDER BY local_seq DESC LIMIT 1","parameters":[{"type":"text","value":id}]})).await.unwrap();
    assert_eq!(scan["axes"]["authored_by"]["count"], 1);
    assert_eq!(
        scan["axes"]["authored_by"]["samples"][0]["authored_at"],
        latest["rows"][0]["created_at"]
    );
    let reads = &[
        ("content_events", "local_seq"),
        ("content_events", "record_id"),
        ("content_events", "type"),
        ("content_events", "run_key"),
        ("content_events", "parent_key"),
    ];
    for actor in [&w.viewer, &w.admin] {
        for order in ["oldest_first", "newest_first"] {
            let args = json!({"limit":100,"order":order,"detail":"metadata"});
            let query = json!({"sql":"SELECT local_seq,type FROM content_events WHERE type LIKE 'message.reaction.%' ORDER BY local_seq"});
            let expected = kernel::read_cache::scope_request(sql::with_read_session(
                &w.db,
                actor,
                reads,
                async {
                    let headers = sql::query_sql(&w.db, actor, query.clone()).await?;
                    let history =
                        read_surface::history_in_session(&w.db, actor, args.clone()).await?;
                    Ok((headers, history))
                },
            ))
            .await
            .unwrap();
            let actual = kernel::read_cache::scope_request(sql::with_history_read_session(
                &w.db,
                actor,
                reads,
                sql::HistoryWindow {
                    after: None,
                    newest: order == "newest_first",
                    limit: 100,
                },
                async {
                    let headers = sql::query_sql(&w.db, actor, query.clone()).await?;
                    let history =
                        read_surface::history_in_session(&w.db, actor, args.clone()).await?;
                    Ok((headers, history))
                },
            ))
            .await
            .unwrap();
            assert_eq!(actual, expected, "reaction headers and history {order}");
            assert_eq!(
                actual.0["rows"].as_array().unwrap().len(),
                2,
                "both public transitions must remain in the SQL headers"
            );
        }
    }
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn write_request_read_caches_follow_message_audience_events() {
    let w = world().await;
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let package = crate::v2_standard::v1_compat::package();
    let definition = &package.definitions[0];
    let mut state = kernel::ImportRecordState {
        definition: Some(kernel::ImportDefinition {
            pin: crate::meta::definition_artifact::RevisionIdentity {
                family: definition.family.clone(),
                version: definition.version,
                digest: definition.digest.clone(),
            },
            primary_type: "V1".into(),
            kind: crate::v2_standard::v1_compat::KIND.into(),
            fields: crate::v2_standard::v1_compat::compat_fields(
                "Message",
                "text",
                Some("Audience cache proof"),
                None,
                None,
            ),
        }),
        message: Some(kernel::MessageState {
            author: Some(w.admin.clone()),
            audience: std::collections::BTreeMap::from([
                (w.admin.clone(), "manage".into()),
                (w.viewer.clone(), "view".into()),
            ]),
            origin: json!({"type":"collection","collection_id":w.origin}),
            ..Default::default()
        }),
        ..Default::default()
    };
    let id = "audience-cache-message";
    kernel::import_record_as(&w.db, &host, id, KERNEL_ROOT_ID, Some(&w.admin), &state)
        .await
        .unwrap();
    kernel::read_cache::scope_request(async {
        let namespaces = [
            "home_visibility",
            "lifecycle",
            "ancestor_descriptors",
            "disclosed_accounts",
        ];
        let mut snapshot = w.db.write_pool().begin().await.unwrap();
        let mut before = Vec::new();
        for namespace in namespaces {
            let key = kernel::read_cache::key_on(&mut snapshot, &w.viewer, namespace)
                .await
                .unwrap();
            kernel::read_cache::put(key.clone(), std::sync::Arc::new(17usize));
            before.push(key);
        }
        assert!(kernel::read_record_on(&mut snapshot, &w.viewer, id)
            .await
            .unwrap()
            .is_some());
        snapshot.rollback().await.unwrap();
        state.message.as_mut().unwrap().audience.remove(&w.viewer);
        kernel::hq::resume_record_with_blob_as(
            &w.db,
            &host,
            id,
            KERNEL_ROOT_ID,
            Some(&w.admin),
            &state,
            None,
        )
        .await
        .unwrap();
        let mut snapshot = w.db.write_pool().begin().await.unwrap();
        for (namespace, old) in namespaces.into_iter().zip(before) {
            let key = kernel::read_cache::key_on(&mut snapshot, &w.viewer, namespace)
                .await
                .unwrap();
            assert!(key != old, "{namespace}");
            assert!(kernel::read_cache::get::<usize>(&key).is_none());
        }
        // W7's v1-parity model treats audience as addressing data, not an
        // ACL. The write still advances the shared cache key; current home
        // policy continues to grant View independently of that data.
        let message = kernel::messaging::on(&mut snapshot, id)
            .await
            .unwrap()
            .unwrap();
        assert!(!message.audience.contains_key(&w.viewer));
        assert!(kernel::read_record_on(&mut snapshot, &w.viewer, id)
            .await
            .unwrap()
            .is_some());
        snapshot.rollback().await.unwrap();
    })
    .await;
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_workspace_snapshot_message_read_state_is_control_reactions_are_content() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "snapshot-send"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let opened = call(
        &w,
        "acct:viewer",
        "get_workspace_snapshot",
        json!({"action":"open"}),
    )
    .await
    .unwrap();
    call(&w,"acct:admin","manage_messages",json!({"action":"set_preference","message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":"snapshot-read","reason":"Private state"})).await.unwrap();
    let quiet = call(
        &w,
        "acct:viewer",
        "get_workspace_snapshot",
        json!({"action":"catch_up","snapshot_token":opened["snapshot_token"]}),
    )
    .await
    .unwrap();
    assert!(quiet["snapshot_token"].is_string(), "{quiet}");
    assert!(quiet["content_events"]
        .as_array()
        .unwrap()
        .iter()
        .all(|e| e["seq"].as_i64().unwrap() <= opened["content_seq"].as_i64().unwrap()));
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"snapshot-react","reason":"Public reaction"})).await.unwrap();
    let changed = call(
        &w,
        "acct:viewer",
        "get_workspace_snapshot",
        json!({"action":"catch_up","snapshot_token":quiet["snapshot_token"]}),
    )
    .await
    .unwrap();
    assert!(changed["snapshot_token"].is_string(), "{changed}");
    let new: Vec<_> = changed["content_events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["seq"].as_i64().unwrap() > quiet["content_seq"].as_i64().unwrap())
        .collect();
    assert_eq!(new.len(), 1);
    assert_eq!(new[0]["record_id"], id);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn direct_context_response_returns_verified_principals_on_empty_and_paged_reads() {
    let w = world().await;
    let origin = json!({"type":"direct","participant_ids":["person:viewer","person:admin"]});
    let principals =
        crate::events::normalize_direct_origin_principals(vec![w.admin.clone(), w.viewer.clone()]);
    let expected =
        serde_json::to_value(crate::events::MessageOriginDeclaredPayload::Direct { principals })
            .unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let empty = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_context","origin":origin,"limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(empty["origin"], expected);
    assert_eq!(empty["messages"], json!([]));
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let mut sent_ids = BTreeSet::new();
    for key in ["direct-origin-one", "direct-origin-two"] {
        let mut args = send_args(&w, key);
        args["origin"] = origin.clone();
        let sent = call(&w, "acct:admin", "manage_messages", args)
            .await
            .unwrap();
        sent_ids.insert(sent["id"].as_str().unwrap().to_owned());
    }
    let first = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_context","origin":origin,"limit":1}),
    )
    .await
    .unwrap();
    assert_eq!(first["origin"], expected);
    assert_eq!(first["has_more"], true);
    let second = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_context","origin":origin,"limit":1,"cursor":first["next_cursor"]}),
    )
    .await
    .unwrap();
    assert_eq!(second["origin"], expected);
    assert_eq!(second["has_more"], false);
    assert_eq!(
        BTreeSet::from([
            first["messages"][0]["id"].as_str().unwrap().to_owned(),
            second["messages"][0]["id"].as_str().unwrap().to_owned()
        ]),
        sent_ids
    );
    assert!(call(
        &w,
        "acct:outsider",
        "manage_messages",
        json!({"action":"list_context","origin":origin,"limit":1,"cursor":first["next_cursor"]})
    )
    .await
    .is_err());
    let outsider=call(&w,"acct:outsider","manage_messages",json!({"action":"list_context","origin":{"type":"direct","participant_ids":["person:admin","person:outsider"]},"limit":1})).await.unwrap();
    assert_eq!(outsider["messages"], json!([]));
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn direct_context_response_shape_matches_v1_resolved_origin_contract() {
    use crate::identity::hosted::{
        reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
        HostedMembershipSource,
    };
    let source = crate::create_database(":memory:").await.unwrap();
    let mut accounts = Vec::new();
    let mut people = Vec::new();
    for label in ["direct-a", "direct-b"] {
        let public_principal = format!("native/{label}");
        let account = reconcile_hosted_identity(
            &source,
            &format!("{label}@example.test"),
            &format!("catalog-{label}"),
            &HostedMembershipArrival::new(
                HostedMembershipRole::Member,
                HostedMembershipSource::Direct,
                "2026-10-21T00:00:00Z".into(),
            )
            .unwrap(),
            Some(&public_principal),
        )
        .await
        .unwrap();
        let person:String=sqlx::query_scalar("SELECT record_id FROM bindings WHERE system='account' AND identifier=? AND is_canonical=1").bind(&account).fetch_one(source.pool()).await.unwrap();
        accounts.push(account);
        people.push(person);
    }
    let v1=super::super::tests::registry().call(source.clone(),Caller::authenticated(&accounts[0]),"manage_messages",json!({"action":"list_context","origin":{"type":"direct","participant_ids":people},"limit":1})).await.unwrap();
    let w = world().await;
    let v2=call(&w,"acct:viewer","manage_messages",json!({"action":"list_context","origin":{"type":"direct","participant_ids":["person:viewer","person:admin"]},"limit":1})).await.unwrap();
    for answer in [&v1, &v2] {
        let parsed: crate::events::MessageOriginDeclaredPayload =
            serde_json::from_value(answer["origin"].clone()).unwrap();
        let crate::events::MessageOriginDeclaredPayload::Direct { principals } = parsed else {
            panic!("direct context")
        };
        assert_eq!(principals.len(), 2);
        assert!(principals[0] < principals[1]);
        assert!(answer["origin"].get("participant_ids").is_none());
        assert_eq!(answer["messages"], json!([]));
        assert_eq!(answer["has_more"], false);
        assert!(answer["next_cursor"].is_null());
    }
    assert_eq!(
        v1["origin"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<BTreeSet<_>>(),
        v2["origin"].as_object().unwrap().keys().collect()
    );
    source.close().await;
    w.db.close().await;
}

/// The identity fields of a `list_inbox` page, with message ids replaced by
/// bodies (they differ per database). Person ids, names and conversation keys
/// are compared exactly: both routes must agree on them.
#[cfg(feature = "v2-kernel-probe")]
fn identity_view(page: &Value) -> Vec<Value> {
    let items = page["items"].as_array().unwrap();
    let body_of = |id: &Value| {
        items
            .iter()
            .find(|i| i["message_id"] == *id)
            .map(|i| i["body"].clone())
            .unwrap_or(Value::Null)
    };
    let mut rows: Vec<Value> = items
        .iter()
        .map(|i| {
            json!({
                "body": i["body"],
                "sender": i["sender"],
                "participants": i["participants"],
                "participant_count": i["participant_count"],
                "reply_to_body": if i["reply_to_id"].is_null() { Value::Null } else { body_of(&i["reply_to_id"]) },
                // A collection key embeds that collection's own record id, which
                // this fixture creates differently per database; direct keys
                // are compared exactly.
                "body_truncated": i.get("body_truncated").cloned().unwrap_or(Value::Null),
                "conversation": if i["conversation"]["type"] == "collection"
                    && i["conversation"].get("key").is_some()
                    && i["conversation"]["key"] != "collection:native:root"
                {
                    json!({"type":"collection","key":"collection:<id>"})
                } else {
                    i["conversation"].clone()
                },
            })
        })
        .collect();
    rows.sort_by_key(|r| r["body"].as_str().unwrap_or_default().to_owned());
    rows
}

#[cfg(feature = "v2-kernel-probe")]
const PARITY_ADMIN: &str = "a0000000-0000-4000-8000-0000000000a1";
#[cfg(feature = "v2-kernel-probe")]
const PARITY_VIEWER: &str = "a0000000-0000-4000-8000-0000000000a2";
#[cfg(feature = "v2-kernel-probe")]
const PARITY_THIRD: &str = "a0000000-0000-4000-8000-0000000000a3";
#[cfg(feature = "v2-kernel-probe")]
const PARITY_HIDDEN: &str = "a0000000-0000-4000-8000-0000000000a4";

/// Run one fixture through kernel v2 and hosted and return both viewers'
/// browse pages. A group DM of four (admin sends, viewer is the reader, one
/// member is private to the admin), a channel post and a reply to it. When
/// `viewer_loses_root` is true the viewer is then dropped from the workspace
/// root, so they can no longer read any Person, their own included.
#[cfg(feature = "v2-kernel-probe")]
async fn parity_pages(viewer_loses_root: bool, scoped: bool) -> (Value, Value) {
    use crate::mcp::tools::messaging::inbox_identity_tests as hosted;
    use crate::mcp::tools::participants::tests::registry as hosted_registry;

    // ---- Kernel v2
    let w = world_with_person_ids([PARITY_ADMIN, PARITY_VIEWER, PARITY_THIRD]).await;
    let hidden_principal =
        kernel::create_principal(&w.db, "account", "Hidden", "acct:hidden", &w.admin)
            .await
            .unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let private_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(w.admin.as_str(), "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::import_record_as(
        &w.db,
        &host,
        PARITY_HIDDEN,
        &private_home,
        Some(&w.admin),
        &kernel::ImportRecordState {
            message_principal: Some(hidden_principal),
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: package.definitions[0].family.clone(),
                    version: package.definitions[0].version,
                    digest: package.definitions[0].digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Entity",
                    "person",
                    Some(PARITY_HIDDEN),
                    None,
                    None,
                ),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let everyone = json!([PARITY_ADMIN, PARITY_VIEWER, PARITY_THIRD, PARITY_HIDDEN]);
    let mut group = send_args(&w, "parity-group");
    group["body"] = json!("group");
    group["addressed_to"] = json!([PARITY_VIEWER]);
    group["origin"] = json!({"type":"direct","participant_ids":everyone});
    call(&w, "acct:admin", "manage_messages", group)
        .await
        .unwrap();
    let mut root = send_args(&w, "parity-root");
    root["body"] = json!("root");
    root["addressed_to"] = json!([]);
    root["expectation"] = json!("none");
    let root_id = call(&w, "acct:admin", "manage_messages", root)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut reply = send_args(&w, "parity-reply");
    reply["body"] = json!("reply");
    reply["addressed_to"] = json!([]);
    reply["expectation"] = json!("none");
    reply["links"] = json!([{"target_id":root_id,"relationship":"reply_to"}]);
    call(&w, "acct:viewer", "manage_messages", reply)
        .await
        .unwrap();
    let mut root_post = send_args(&w, "parity-rootpost");
    root_post["body"] = json!("rootpost");
    root_post["addressed_to"] = json!([]);
    root_post["expectation"] = json!("none");
    root_post["origin"] = json!({"type":"collection","collection_id":"native:root"});
    call(&w, "acct:admin", "manage_messages", root_post)
        .await
        .unwrap();
    let long_body = "é".repeat(400);
    if scoped {
        let mut long = send_args(&w, "parity-long");
        long["body"] = json!(long_body);
        long["addressed_to"] = json!([PARITY_VIEWER]);
        long["origin"] = json!({"type":"direct","participant_ids":[PARITY_ADMIN, PARITY_VIEWER]});
        call(&w, "acct:admin", "manage_messages", long)
            .await
            .unwrap();
        // Legacy messages (no declared origin) from the admin: one to the
        // viewer, one to the viewer and the private member.
        let import_message = |id: &'static str,
                              body: &'static str,
                              author: String,
                              addressed_to: Vec<String>,
                              origin: Value| {
            let (w, host, definition) = (&w, &host, &package.definitions[0]);
            async move {
                let mut audience = std::collections::BTreeMap::new();
                audience.insert(w.admin.clone(), "manage".to_string());
                audience.insert(w.viewer.clone(), "view".to_string());
                kernel::import_record_as(
                    &w.db,
                    host,
                    id,
                    KERNEL_ROOT_ID,
                    Some(&w.admin),
                    &kernel::ImportRecordState {
                        definition: Some(kernel::ImportDefinition {
                            pin: crate::meta::definition_artifact::RevisionIdentity {
                                family: definition.family.clone(),
                                version: definition.version,
                                digest: definition.digest.clone(),
                            },
                            primary_type: "V1".into(),
                            kind: crate::v2_standard::v1_compat::KIND.into(),
                            fields: crate::v2_standard::v1_compat::compat_fields(
                                "Message",
                                "text",
                                Some(id),
                                None,
                                None,
                            ),
                        }),
                        body: Some(body.into()),
                        message: Some(kernel::MessageState {
                            author: Some(author),
                            audience,
                            addressed_to,
                            home_id: Some("native:unfiled".into()),
                            origin,
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            }
        };
        import_message(
            "parity-legacy",
            "legacy hello",
            w.admin.clone(),
            vec![PARITY_VIEWER.into()],
            Value::Null,
        )
        .await;
        import_message(
            "parity-legacy-hidden",
            "legacy hidden",
            w.admin.clone(),
            vec![PARITY_VIEWER.into(), PARITY_HIDDEN.into()],
            Value::Null,
        )
        .await;
        // A legacy message the viewer sent to the admin: in scope for the sender.
        import_message(
            "parity-legacy-sent",
            "legacy sent",
            w.viewer.clone(),
            vec![PARITY_ADMIN.into()],
            Value::Null,
        )
        .await;
        // Collection-origin messages filed in Unfiled with no addressee: the
        // viewer's own is a note to self, the admin's is not the viewer's.
        let collection = json!({"type":"collection","collection_id":"native:unfiled"});
        import_message(
            "parity-note",
            "my note",
            w.viewer.clone(),
            vec![],
            collection.clone(),
        )
        .await;
        import_message(
            "parity-admin-note",
            "admin note",
            w.admin.clone(),
            vec![],
            collection,
        )
        .await;
    }
    if viewer_loses_root {
        kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
            .await
            .unwrap();
    }
    let mut list_args = json!({"action":"list_inbox","view":"browse","limit":200});
    if scoped {
        list_args["scope"] = json!("direct");
    }
    let kernel_page = call(&w, "acct:viewer", "manage_messages", list_args.clone())
        .await
        .unwrap();

    // ---- Hosted
    let db = crate::create_database(":memory:").await.unwrap();
    for (id, account) in [
        (PARITY_ADMIN, "padmin"),
        (PARITY_VIEWER, "pviewer"),
        (PARITY_THIRD, "pthird"),
        (PARITY_HIDDEN, "phidden"),
    ] {
        hosted::add_named_person(&db, id, account, id).await;
    }
    use crate::authorization::{AllowEntry, Capability};
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        crate::schema::ROOT_RECORD_ID,
        vec![
            AllowEntry::account("padmin", Capability::Manage),
            AllowEntry::account("pviewer", Capability::Edit),
            AllowEntry::account("pthird", Capability::View),
        ],
    )
    .await
    .unwrap();
    let shared = hosted_registry()
        .call(db.clone(), Caller::authenticated("padmin"), "create_record",
            json!({"type":"Collection","kind":"folder","name":"Shared","home_id":crate::schema::ROOT_RECORD_ID,"reason":"fixture"}))
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    hosted::call(&db, "padmin", json!({"action":"send","body":"group",
        "origin":{"type":"direct","participant_ids":everyone},
        "addressed_to":[PARITY_VIEWER],"expectation":"reply","idempotency_key":"group","reason":"fixture"}))
        .await
        .unwrap();
    let post = |from: &'static str, body: &'static str, reply: Option<String>| {
        let db = db.clone();
        let shared = shared.clone();
        async move {
            let mut args = json!({"action":"send","body":body,"origin":{"type":"collection","collection_id":shared},
                "addressed_to":[],"expectation":"none","idempotency_key":body,"reason":"fixture"});
            if let Some(target) = reply {
                args["links"] = json!([{"target_id":target,"relationship":"reply_to"}]);
            }
            hosted::call(&db, from, args).await.unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
    };
    hosted::call(
        &db,
        "padmin",
        json!({"action":"send","body":"rootpost",
        "origin":{"type":"collection","collection_id":crate::schema::ROOT_RECORD_ID},
        "addressed_to":[],"expectation":"none","idempotency_key":"rootpost","reason":"fixture"}),
    )
    .await
    .unwrap();
    let hosted_root = post("padmin", "root", None).await;
    post("pviewer", "reply", Some(hosted_root)).await;
    // The fourth member is private to the admin, as in the kernel fixture.
    crate::authorization::replace_explicit_policy(
        &db,
        "local",
        PARITY_HIDDEN,
        vec![AllowEntry::account("padmin", Capability::Manage)],
    )
    .await
    .unwrap();
    if viewer_loses_root {
        crate::authorization::replace_explicit_policy(
            &db,
            "local",
            crate::schema::ROOT_RECORD_ID,
            vec![AllowEntry::account("padmin", Capability::Manage)],
        )
        .await
        .unwrap();
    }
    if scoped {
        hosted::call(&db, "padmin", json!({"action":"send","body":long_body,
            "origin":{"type":"direct","participant_ids":[PARITY_ADMIN, PARITY_VIEWER]},
            "addressed_to":[PARITY_VIEWER],"expectation":"none","idempotency_key":"long","reason":"fixture"}))
            .await
            .unwrap();
        crate::mcp::tools::messaging::inbox_scope_tests::legacy_message(
            &db,
            "padmin",
            "legacy hello",
            &[PARITY_VIEWER],
        )
        .await;
        crate::mcp::tools::messaging::inbox_scope_tests::legacy_message(
            &db,
            "padmin",
            "legacy hidden",
            &[PARITY_VIEWER, PARITY_HIDDEN],
        )
        .await;
        // The viewer's own legacy message; its owner has drifted off the
        // sender, which must not drop it from the sender's scope.
        crate::mcp::tools::messaging::inbox_scope_tests::legacy_message(
            &db,
            "pviewer",
            "legacy sent",
            &[PARITY_ADMIN],
        )
        .await;
        sqlx::query("UPDATE records SET owner_id=? WHERE body='legacy sent'")
            .bind(PARITY_ADMIN)
            .execute(db.write_pool())
            .await
            .unwrap();
        for (from, body) in [("pviewer", "my note"), ("padmin", "admin note")] {
            hosted::call(
                &db,
                from,
                json!({"action":"send","body":body,
                "origin":{"type":"collection","collection_id":"native:unfiled"},
                "addressed_to":[],"expectation":"none","idempotency_key":body,"reason":"fixture"}),
            )
            .await
            .unwrap();
        }
    }
    let mut hosted_args = list_args;
    let hosted_page = hosted::call(&db, "pviewer", hosted_args.take())
        .await
        .unwrap();
    (kernel_page, hosted_page)
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn hosted_and_kernel_v2_inbox_identity_fields_are_identical_including_the_conversation_key() {
    let (kernel_page, hosted_page) = parity_pages(false, false).await;
    assert_eq!(kernel_page["schema"], "native.message-inbox.v3");
    // Kernel items no longer carry the raw origin fields that list every
    // participant, hidden ones included.
    for item in kernel_page["items"].as_array().unwrap() {
        assert!(
            item.get("origin").is_none() && item.get("communication_origin").is_none(),
            "{item}"
        );
    }
    assert!(!kernel_page.to_string().contains(PARITY_HIDDEN));
    let (kernel_view, hosted_view) = (identity_view(&kernel_page), identity_view(&hosted_page));
    // Guard against a vacuous pass.
    let group = hosted_view.iter().find(|r| r["body"] == "group").unwrap();
    assert_eq!(
        group["participant_count"], 3,
        "hidden member not counted: {group}"
    );
    assert_eq!(group["participants"][0]["viewer"], true);
    assert_eq!(group["participants"].as_array().unwrap().len(), 3);
    assert_eq!(group["conversation"], json!({"type": "direct"}));
    assert!(!group.to_string().contains(PARITY_HIDDEN));
    assert_eq!(
        hosted_view.iter().find(|r| r["body"] == "reply").unwrap()["reply_to_body"],
        "root"
    );
    // A message filed in the workspace root keeps its key on both routes.
    let rootpost = hosted_view
        .iter()
        .find(|r| r["body"] == "rootpost")
        .unwrap();
    assert_eq!(
        rootpost["conversation"],
        json!({"type": "collection", "key": "collection:native:root"})
    );
    assert_eq!(kernel_view, hosted_view);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn hosted_and_kernel_v2_agree_when_the_viewers_own_person_is_unreadable() {
    let (kernel_page, hosted_page) = parity_pages(true, false).await;
    let (kernel_view, hosted_view) = (identity_view(&kernel_page), identity_view(&hosted_page));
    let group = hosted_view.iter().find(|r| r["body"] == "group").unwrap();
    // Only the viewer's own slot survives, named null; the sender is the opaque hidden object.
    assert_eq!(group["participant_count"], 1, "{group}");
    assert_eq!(group["participants"][0]["person_id"], PARITY_VIEWER);
    assert_eq!(group["participants"][0]["name"], Value::Null);
    assert_eq!(group["sender"]["state"], "hidden");
    // With the workspace root gone the viewer cannot see the Collection, so
    // the collection key is withheld on both routes.
    let reply = hosted_view.iter().find(|r| r["body"] == "reply").unwrap();
    assert_eq!(reply["conversation"], json!({"type": "collection"}));
    assert_eq!(kernel_view, hosted_view);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_reply_to_id_is_null_when_the_target_is_hidden_from_the_viewer() {
    let w = world().await;
    let package = crate::v2_standard::v1_compat::package();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let private_home = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(w.admin.as_str(), "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::import_record_as(
        &w.db,
        &host,
        "priv",
        &private_home,
        Some(&w.admin),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: package.definitions[0].family.clone(),
                    version: package.definitions[0].version,
                    digest: package.definitions[0].digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Collection",
                    "folder",
                    Some("priv"),
                    None,
                    None,
                ),
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    // Public writes keep a reply in its target's origin, so a hidden target is
    // unreachable by sending; exercise the read rule on a state that points at a
    // record only the admin can read.
    let mut post = send_args(&w, "visible-post");
    post["addressed_to"] = json!([]);
    post["expectation"] = json!("none");
    let id = call(&w, "acct:admin", "manage_messages", post)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let mut state = crate::kernel::messaging::on(&mut tx, &id)
        .await
        .unwrap()
        .unwrap();
    state.reply_to = Some("priv".into());
    let as_viewer = inbox_identity_one(&mut tx, &w.viewer, Some("person:viewer"), &state)
        .await
        .unwrap();
    assert_eq!(as_viewer["reply_to_id"], Value::Null);
    assert!(!Value::Object(as_viewer).to_string().contains("priv"));
    let as_admin = inbox_identity_one(&mut tx, &w.admin, Some("person:admin"), &state)
        .await
        .unwrap();
    assert_eq!(as_admin["reply_to_id"], "priv");
    // A Collection the viewer cannot read yields no key; a readable one does.
    state.origin = json!({"type":"collection","collection_id":"priv"});
    let hidden_key = inbox_identity_one(&mut tx, &w.viewer, Some("person:viewer"), &state)
        .await
        .unwrap();
    assert_eq!(hidden_key["conversation"], json!({"type":"collection"}));
    let shown_key = inbox_identity_one(&mut tx, &w.admin, Some("person:admin"), &state)
        .await
        .unwrap();
    assert_eq!(
        shown_key["conversation"],
        json!({"type":"collection","key":"collection:priv"})
    );
    tx.rollback().await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_self_needs_the_unfiled_origin_and_the_viewers_own_authorship() {
    let w = world().await;
    let mut post = send_args(&w, "self-probe");
    post["addressed_to"] = json!([]);
    post["expectation"] = json!("none");
    let id = call(&w, "acct:viewer", "manage_messages", post)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let mut state = crate::kernel::messaging::on(&mut tx, &id)
        .await
        .unwrap()
        .unwrap();
    state.home_id = Some("native:unfiled".into());
    // A channel post filed into Unfiled is not a note to self.
    let as_channel = inbox_identity_one(&mut tx, &w.viewer, Some("person:viewer"), &state)
        .await
        .unwrap();
    assert_eq!(as_channel["conversation"]["type"], "collection");
    // Authored in the Unfiled origin by the viewer: a note to self.
    state.origin = json!({"type":"collection","collection_id":"native:unfiled"});
    let own = inbox_identity_one(&mut tx, &w.viewer, Some("person:viewer"), &state)
        .await
        .unwrap();
    assert_eq!(own["conversation"], json!({"type":"self"}));
    assert_eq!(own["participant_count"], 1);
    // The same state is not the admin's note to self, or anyone else's.
    let as_admin = inbox_identity_one(&mut tx, &w.admin, Some("person:admin"), &state)
        .await
        .unwrap();
    assert_ne!(as_admin["conversation"]["type"], "self");
    // Authored by another principal: not the viewer's, even in the same origin.
    state.author = Some(w.admin.clone());
    let other = inbox_identity_one(&mut tx, &w.viewer, Some("person:viewer"), &state)
        .await
        .unwrap();
    assert_ne!(other["conversation"]["type"], "self");
    tx.rollback().await.unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_inbox_sender_carries_speaker_kind_and_assurance() {
    let w = world().await;
    let persona = call(
        &w,
        "acct:admin",
        "manage_participants",
        json!({"action":"register_persona","name":"Proof persona","reason":"Persona proof","idempotency_key":"persona-inbox"}),
    )
    .await
    .unwrap();
    let mut args = send_args(&w, "persona-inbox-message");
    args["addressed_to"] = json!([]);
    args["expectation"] = json!("none");
    args["speaker"] = json!({"persona_id": persona["persona_id"]});
    let id = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let page = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":50}),
    )
    .await
    .unwrap();
    let row = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["message_id"] == id.as_str())
        .unwrap();
    assert_eq!(
        row["sender"]["speaker"],
        json!({"kind":"persona","assurance":"client_asserted"}),
        "{row}"
    );
    assert_eq!(row["sender"]["person_id"], "person:admin");
}

/// One state through the page-level identity pass.
#[cfg(feature = "v2-kernel-probe")]
async fn inbox_identity_one(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    actor: &str,
    viewer_person: Option<&str>,
    state: &kernel::MessageState,
) -> Result<serde_json::Map<String, Value>> {
    Ok(
        inbox_identity_page(tx, actor, viewer_person, std::slice::from_ref(state))
            .await?
            .remove(0),
    )
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn frozen_slack_direct_filing_matches_v1_without_exposing_policy_homes() {
    let w = world().await;
    let mut args = send_args(&w, "slack-direct-filing");
    args["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let sent = call(&w, "acct:admin", "manage_messages", args.clone())
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let policy_home: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
        .bind(id)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_ne!(
        policy_home, "native:unfiled",
        "Direct authority needs its separate private home"
    );
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for who in ["acct:admin", "acct:viewer"] {
        let record = call(&w, who, "get_record", json!({"ids":[id]}))
            .await
            .unwrap();
        assert_eq!(
            record["records"][0]["home_id"], "native:unfiled",
            "{record:#}"
        );
        let records = call(
            &w,
            who,
            "query_record",
            json!({"steps":[{"step":"filter","ids":[id]}]}),
        )
        .await
        .unwrap();
        assert_eq!(
            records["records"][0]["home_id"], "native:unfiled",
            "{records:#}"
        );
        let rows = call(
            &w,
            who,
            "query_sql",
            json!({"sql":include_str!("../../../tests/fixtures/kernel_v2_frozen_slack_dms.sql")}),
        )
        .await
        .unwrap();
        let row = rows["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == id)
            .unwrap();
        assert_eq!(
            row["home_id"], "native:unfiled",
            "the exact frozen ingestion backstop rejects other non-null homes"
        );
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let hidden = call(&w, "acct:outsider", "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    let hidden = call(
        &w,
        "acct:outsider",
        "query_sql",
        json!({"sql":include_str!("../../../tests/fixtures/kernel_v2_frozen_slack_dms.sql")}),
    )
    .await
    .unwrap();
    assert_eq!(hidden["rows"], json!([]));
    call(&w, "acct:viewer", "manage_messages", json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"slack-direct-filing-reaction","reason":"Frozen Direct read parity"})).await.unwrap();
    let rows = call(
        &w,
        "acct:admin",
        "query_sql",
        json!({"sql":include_str!("../../../tests/fixtures/kernel_v2_frozen_slack_dms.sql")}),
    )
    .await
    .unwrap();
    assert_eq!(rows["rows"][0]["reactions"], 1);

    // A hidden explicitly requested filing target stays withheld even though
    // the participant may read the Direct itself. The public unfiled sentinel
    // is the only special case in the visibility check.
    let private = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    args["id"] = json!(uuid::Uuid::new_v4().to_string());
    args["idempotency_key"] = json!("slack-direct-hidden-filing");
    args["home_id"] = json!(private);
    let second = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    let second = second["id"].as_str().unwrap();
    let record = call(&w, "acct:viewer", "get_record", json!({"ids":[second]}))
        .await
        .unwrap();
    assert_eq!(record["records"][0]["status"], "found");
    assert!(record["records"][0]["home_id"].is_null());
    let rows = call(&w, "acct:viewer", "query_sql", json!({"sql":"SELECT id,home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":second}]})).await.unwrap();
    assert!(rows["rows"][0]["home_id"].is_null());

    // Explicit current placement wins over the original Direct filing state.
    let moved = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage"), (&w.viewer, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, id, &moved)
        .await
        .unwrap();
    let record = call(&w, "acct:viewer", "get_record", json!({"ids":[id]}))
        .await
        .unwrap();
    assert_eq!(record["records"][0]["home_id"], moved);
    let rows = call(&w, "acct:viewer", "query_sql", json!({"sql":"SELECT id,home_id FROM records WHERE id=?1","parameters":[{"type":"text","value":id}]})).await.unwrap();
    assert_eq!(rows["rows"][0]["home_id"], moved);
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn realtime_grant_fence_ignores_content_but_revalidates_authority() {
    let w = world().await;
    let predicate = kernel::notifications::REALTIME_AUTHORITY_INDEX
        .split_once(" WHERE ")
        .unwrap()
        .1;
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(&format!(
        "EXPLAIN QUERY PLAN SELECT MAX(seq + 0) FROM content_events WHERE {predicate}"
    ))
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert!(
        plan.iter()
            .any(|row| row.3.contains("idx_kernel_realtime_authority")),
        "{plan:?}"
    );
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "grant-fence-send"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let before = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    call(&w, "acct:admin", "manage_messages", json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"grant-fence-react","reason":"Public reaction leaves the frame mounted"})).await.unwrap();
    call(&w, "acct:viewer", "manage_messages", json!({"action":"set_preference","message_id":id,"preference":"mark_read","expected_version":0,"idempotency_key":"grant-fence-read","reason":"Private read state is not a grant"})).await.unwrap();
    // Agent boot creates a principal. Principal creation grants no authority.
    kernel::create_principal(&w.db, "agent", "Reader", "agent:grant-fence", &w.admin)
        .await
        .unwrap();
    let ordinary = call(&w,"acct:admin","create_record",json!({"type":"Document","kind":"legacy-proof","name":"Ordinary birth","reason":"No policy changed"})).await.unwrap();
    call(
        &w,
        "acct:admin",
        "update_record",
        json!({"id":ordinary["id"],"body_set":"Ordinary body","if_body_digest":crate::mcp::tools::lifecycle::body_digest(None),"reason":"No policy changed"}),
    )
    .await
    .unwrap();
    let edited = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    assert!(edited.content > before.content);
    assert!(edited.awareness > before.awareness);
    assert_eq!(edited.authorization, before.authorization);
    kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let revoked = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    assert!(revoked.authorization > edited.authorization);
    assert!(kernel::read_record_as(&w.db, &w.viewer, id)
        .await
        .unwrap()
        .is_none());
    let private = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    let own_policy = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    assert!(own_policy.authorization > revoked.authorization);
    kernel::rehome_record_as(&w.db, &w.admin, id, &private)
        .await
        .unwrap();
    let moved = crate::realtime::inbox_invalidation_vector(&w.db)
        .await
        .unwrap();
    assert!(moved.authorization > own_policy.authorization);
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        crate::realtime::inbox_invalidation_vector(&w.db)
            .await
            .unwrap()
            .authorization,
        moved.authorization
    );
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn hosted_and_kernel_v2_scope_direct_return_the_same_messages_and_identity() {
    let (kernel_page, hosted_page) = parity_pages(false, true).await;
    assert_eq!(kernel_page["scope"], "direct");
    assert_eq!(hosted_page["scope"], "direct");
    assert_eq!(kernel_page["truncated"], false);
    assert_eq!(hosted_page["truncated"], false);
    assert_eq!(kernel_page["candidate_cap"], hosted_page["candidate_cap"]);
    let (kernel_view, hosted_view) = (identity_view(&kernel_page), identity_view(&hosted_page));
    let bodies: Vec<_> = hosted_view
        .iter()
        .map(|r| r["body"].as_str().unwrap().len())
        .collect();
    // group, the 400-char DM (cut to 360), three legacy messages (one the
    // viewer sent) and the viewer's note to self; no channel posts, and not
    // the admin's unaddressed note.
    assert_eq!(hosted_view.len(), 6, "{bodies:?}");
    assert!(hosted_view.iter().all(|r| r["body"] != "root"
        && r["body"] != "reply"
        && r["body"] != "rootpost"
        && r["body"] != "admin note"));
    let note = hosted_view.iter().find(|r| r["body"] == "my note").unwrap();
    assert_eq!(note["conversation"], json!({"type": "self"}));
    assert_eq!(note["participant_count"], 1);
    assert_eq!(note["participants"][0]["person_id"], PARITY_VIEWER);
    assert_eq!(note["participants"][0]["viewer"], true);
    // A legacy message lists its sender and addressees, the viewer first; the
    // private member is omitted and not counted.
    for body in ["legacy hello", "legacy hidden"] {
        let row = hosted_view.iter().find(|r| r["body"] == body).unwrap();
        assert_eq!(row["participant_count"], 2, "{row}");
        assert_eq!(row["participants"][0]["person_id"], PARITY_VIEWER);
        assert_eq!(row["participants"][1]["person_id"], PARITY_ADMIN);
        assert!(!row.to_string().contains(PARITY_HIDDEN));
    }
    let long = hosted_view
        .iter()
        .find(|r| r["body_truncated"] == true)
        .unwrap();
    assert_eq!(long["body"].as_str().unwrap().chars().count(), 360);
    let legacy = hosted_view
        .iter()
        .find(|r| r["body"] == "legacy hello")
        .unwrap();
    assert_eq!(legacy["conversation"], json!({"type": "legacy"}));
    assert_eq!(kernel_view, hosted_view);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_scope_direct_validates_pages_discloses_truncation_and_binds_the_cursor() {
    let w = world().await;
    for n in 0..5 {
        let mut dm = send_args(&w, &format!("scope-dm-{n}"));
        dm["body"] = json!(format!("dm {n}"));
        dm["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
        call(&w, "acct:admin", "manage_messages", dm).await.unwrap();
    }
    let mut channel = send_args(&w, "scope-channel");
    channel["addressed_to"] = json!([]);
    channel["expectation"] = json!("none");
    call(&w, "acct:admin", "manage_messages", channel)
        .await
        .unwrap();
    let list = |extra: Value| {
        let mut args = json!({"action":"list_inbox","view":"browse","scope":"direct","limit":2});
        for (k, v) in extra.as_object().into_iter().flatten() {
            args[k] = v.clone();
        }
        call(&w, "acct:viewer", "manage_messages", args)
    };
    let bodies = |page: &Value| -> Vec<String> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["body"].as_str().unwrap().to_owned())
            .collect()
    };
    let first = list(json!({})).await.unwrap();
    assert_eq!(bodies(&first), vec!["dm 4", "dm 3"]);
    let snapshot = first["snapshot"].as_str().unwrap().to_owned();
    let second = list(json!({"snapshot": snapshot, "after": first["next_after"]}))
        .await
        .unwrap();
    assert_eq!(bodies(&second), vec!["dm 2", "dm 1"]);
    let third = list(json!({"snapshot": snapshot, "after": second["next_after"]}))
        .await
        .unwrap();
    assert_eq!(bodies(&third), vec!["dm 0"]);
    assert_eq!(third["next_after"], Value::Null);
    // The cursor is bound to the scope.
    let unscoped = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","limit":2,"snapshot":snapshot,"after":2}),
    )
    .await;
    assert!(unscoped.is_err());
    // Truncation is disclosed and keeps the newest.
    crate::mcp::tools::messaging::DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(Some(3)));
    let cut = list(json!({"limit":10})).await.unwrap();
    crate::mcp::tools::messaging::DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(None));
    assert_eq!(cut["truncated"], true);
    assert_eq!(bodies(&cut), vec!["dm 4", "dm 3", "dm 2"]);
    // Validation.
    for args in [
        json!({"scope":"channels"}),
        json!({"preview_chars":0}),
        json!({"preview_chars":1001}),
    ] {
        assert!(list(args).await.is_err());
    }
    // A principal with no Person fails closed, never an empty list.
    kernel::create_principal(&w.db, "account", "Stranger", "acct:stranger", &w.admin)
        .await
        .unwrap();
    let err = call(
        &w,
        "acct:stranger",
        "manage_messages",
        json!({"action":"list_inbox","view":"browse","scope":"direct"}),
    )
    .await;
    assert!(err
        .unwrap_err()
        .to_string()
        .contains("current member identity"),);
}

/// Import a legacy Message (no declared origin) from the admin, addressed to
/// the viewer, in Unfiled. `viewer_can_read` controls the audience map.
#[cfg(feature = "v2-kernel-probe")]
async fn import_legacy_to_viewer(w: &World, id: &str, viewer_can_read: bool) {
    // An unreadable message is filed in a home only the admin can read.
    let home = if viewer_can_read {
        KERNEL_ROOT_ID.to_owned()
    } else {
        kernel::create_home(
            &w.db,
            KERNEL_ROOT_ID,
            Some(&[(w.admin.as_str(), "manage")]),
            &w.admin,
        )
        .await
        .unwrap()
    };
    let package = crate::v2_standard::v1_compat::package();
    let host = kernel::resolve_principal_by_binding(&w.db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let definition = &package.definitions[0];
    let mut audience = std::collections::BTreeMap::from([(w.admin.clone(), "manage".to_string())]);
    if viewer_can_read {
        audience.insert(w.viewer.clone(), "view".into());
    }
    kernel::import_record_as(
        &w.db,
        &host,
        id,
        &home,
        Some(&w.admin),
        &kernel::ImportRecordState {
            definition: Some(kernel::ImportDefinition {
                pin: crate::meta::definition_artifact::RevisionIdentity {
                    family: definition.family.clone(),
                    version: definition.version,
                    digest: definition.digest.clone(),
                },
                primary_type: "V1".into(),
                kind: crate::v2_standard::v1_compat::KIND.into(),
                fields: crate::v2_standard::v1_compat::compat_fields(
                    "Message",
                    "text",
                    Some(id),
                    None,
                    None,
                ),
            }),
            body: Some(format!("legacy {id}")),
            message: Some(kernel::MessageState {
                author: Some(w.admin.clone()),
                audience,
                addressed_to: vec!["person:viewer".into()],
                home_id: Some("native:unfiled".into()),
                origin: Value::Null,
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await
    .unwrap();
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn kernel_v2_unreadable_and_deleted_dms_do_not_use_the_cap_or_set_truncated() {
    let w = world().await;
    let mut ids = Vec::new();
    for n in 0..2 {
        let mut dm = send_args(&w, &format!("cap-old-{n}"));
        dm["body"] = json!(format!("old {n}"));
        dm["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
        ids.push(
            call(&w, "acct:admin", "manage_messages", dm).await.unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    // Newer candidates the viewer cannot read.
    for n in 0..5 {
        import_legacy_to_viewer(&w, &format!("unreadable-{n}"), false).await;
    }
    // A newer deleted DM.
    let mut gone = send_args(&w, "cap-gone");
    gone["body"] = json!("gone");
    gone["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let gone_id = call(&w, "acct:admin", "manage_messages", gone)
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    call(
        &w,
        "acct:admin",
        "delete_record",
        json!({"id": gone_id, "reason": "fixture"}),
    )
    .await
    .unwrap();
    let list = |cap: usize| {
        let w = &w;
        async move {
            crate::mcp::tools::messaging::DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(Some(cap)));
            let page = call(
                w,
                "acct:viewer",
                "manage_messages",
                json!({"action":"list_inbox","view":"browse","scope":"direct","limit":50}),
            )
            .await
            .unwrap();
            crate::mcp::tools::messaging::DIRECT_SCOPE_CAP_OVERRIDE.with(|c| c.set(None));
            page
        }
    };
    let page = list(3).await;
    assert_eq!(page["truncated"], false, "{page}");
    let got: Vec<&str> = page["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["message_id"].as_str().unwrap())
        .collect();
    assert_eq!(got.len(), 2, "{got:?}");
    for id in &ids {
        assert!(got.contains(&id.as_str()));
    }
    // Readable messages beyond the cap still disclose truncation.
    for n in 0..3 {
        import_legacy_to_viewer(&w, &format!("readable-{n}"), true).await;
    }
    let page = list(3).await;
    assert_eq!(page["truncated"], true);
    assert_eq!(page["items"].as_array().unwrap().len(), 3);
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn hosted_and_kernel_v2_rehydrate_a_scoped_needs_me_page_between_pages() {
    use crate::mcp::tools::messaging::inbox_identity_tests as hosted;
    use crate::mcp::tools::participants::tests::{fixture, ALICE, BOB};

    // Kernel v2: two obligations for the viewer; flag the older between pages.
    let w = world().await;
    let mut kernel_ids = Vec::new();
    for n in 0..2 {
        let mut dm = send_args(&w, &format!("rehydrate-{n}"));
        dm["body"] = json!(format!("ask {n}"));
        dm["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
        kernel_ids.push(
            call(&w, "acct:admin", "manage_messages", dm).await.unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    let k_page = |extra: Value| {
        let w = &w;
        async move {
            let mut args =
                json!({"action":"list_inbox","view":"needs_me","scope":"direct","limit":1});
            for (k, v) in extra.as_object().into_iter().flatten() {
                args[k] = v.clone();
            }
            call(w, "acct:viewer", "manage_messages", args)
                .await
                .unwrap()
        }
    };
    let k1 = k_page(json!({})).await;
    let k_snapshot = k1["snapshot"].as_str().unwrap().to_owned();
    call(&w, "acct:viewer", "manage_messages", json!({"action":"set_preference","message_id":kernel_ids[0],
        "preference":"flag_attention","expected_version":0,"idempotency_key":"flag-k","reason":"fixture"})).await.unwrap();
    let k2 = k_page(json!({"snapshot":k_snapshot,"after":k1["next_after"]})).await;

    // Hosted: the same flow.
    let db = crate::create_database(":memory:").await.unwrap();
    fixture(&db).await;
    let mut hosted_ids = Vec::new();
    for n in 0..2 {
        let id = hosted::send_direct(
            &db,
            "alice",
            &[ALICE, BOB],
            &[BOB],
            &format!("rehydrate-{n}"),
            "reply",
        )
        .await;
        hosted_ids.push(id);
    }
    let h_page = |extra: Value| {
        let db = db.clone();
        async move {
            let mut args =
                json!({"action":"list_inbox","view":"needs_me","scope":"direct","limit":1});
            for (k, v) in extra.as_object().into_iter().flatten() {
                args[k] = v.clone();
            }
            hosted::call(&db, "bob", args).await.unwrap()
        }
    };
    let h1 = h_page(json!({})).await;
    let h_snapshot = h1["snapshot"].as_str().unwrap().to_owned();
    hosted::call(&db, "bob", json!({"action":"set_preference","message_id":hosted_ids[0],
        "preference":"flag_attention","expected_version":0,"idempotency_key":"flag-h","reason":"fixture"})).await.unwrap();
    let h2 = h_page(json!({"snapshot":h_snapshot,"after":h1["next_after"]})).await;

    for (page, label) in [(&k2, "kernel"), (&h2, "hosted")] {
        let item = &page["items"][0];
        assert_eq!(
            item["attention"]["flagged"], true,
            "{label}: page two shows the change made between pages: {item}"
        );
    }
    assert_eq!(
        k2["items"][0]["body"]
            .as_str()
            .map(|b| b.replace("hello ", "ask ")),
        h2["items"][0]["body"]
            .as_str()
            .map(|b| b.replace("hello ", "ask "))
            .map(|b| b.replace("rehydrate-", "")),
        "same message on both routes"
    );
}

#[tokio::test]
async fn relevance_marks_match_v1_recipient_sender_third_party_and_undo_semantics() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "relevance-message"),
    )
    .await
    .unwrap();
    let id = sent["id"].as_str().unwrap();
    let mark = |who: &'static str, action: &str, key: &str| {
        call(
            &w,
            who,
            "manage_messages",
            json!({"action":action,"message_id":id,"idempotency_key":key,"reason":"Relevance parity"}),
        )
    };
    let state = || {
        call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":"list_message_state","message_ids":[id]}),
        )
    };
    let third = mark(
        "acct:outsider",
        "mark_no_longer_relevant",
        "third-party-mark",
    )
    .await
    .unwrap();
    assert_eq!(third["changed"], true);
    assert_eq!(
        state().await.unwrap()["messages"][0]["message_expectation_state"]["state"],
        "open"
    );
    let marked = mark("acct:viewer", "mark_no_longer_relevant", "recipient-mark")
        .await
        .unwrap();
    let evidence = marked["evidence_record_id"].as_str().unwrap();
    assert_eq!(
        mark("acct:viewer", "mark_no_longer_relevant", "recipient-mark")
            .await
            .unwrap(),
        marked
    );
    let own = state().await.unwrap();
    assert_eq!(
        own["messages"][0]["message_expectation_state"]["evidence"]["by"],
        "recipient"
    );
    let mut snapshot = w.db.write_pool().begin().await.unwrap();
    let links = kernel::messaging::own_relevance_marks_on(&mut snapshot, &w.viewer, id)
        .await
        .unwrap();
    snapshot.rollback().await.unwrap();
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
    assert!(
        kernel::generic_links::remove_generic_link_as(&w.db, &w.viewer, evidence, &links[0].1)
            .await
            .is_err(),
        "ordinary generic-link APIs still require bearer Edit"
    );
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[
            (&w.admin, "manage"),
            (&w.viewer, "edit"),
            (&w.outsider, "view"),
        ],
    )
    .await
    .unwrap();
    // An editor can reassert this link, but that must not impersonate the
    // recipient's own relevance decision. Re-mark restores their assertion.
    for note in ["not-a-mark", "no_longer_relevant"] {
        kernel::generic_links::add_generic_link_as(
            &w.db,
            &w.admin,
            evidence,
            id,
            "resolves",
            Some(note.into()),
        )
        .await
        .unwrap();
    }
    assert_eq!(
        state().await.unwrap()["messages"][0]["message_expectation_state"]["state"],
        "open"
    );
    let mark_again = mark("acct:viewer", "mark_no_longer_relevant", "recipient-again")
        .await
        .unwrap();
    assert_eq!(mark_again["changed"], false);
    assert_eq!(mark_again["evidence_record_id"], evidence);
    assert_eq!(
        state().await.unwrap()["messages"][0]["message_expectation_state"]["state"],
        "satisfied"
    );
    let candidate = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({"action":"list_notification_candidates","after_seq":0,"limit":50}),
    )
    .await
    .unwrap();
    assert!(candidate.to_string().contains("withdrawn"), "{candidate}");
    let unmarked = mark("acct:viewer", "unmark_no_longer_relevant", "recipient-undo")
        .await
        .unwrap();
    assert_eq!(unmarked["changed"], true);
    assert_eq!(
        mark("acct:viewer", "unmark_no_longer_relevant", "recipient-undo")
            .await
            .unwrap(),
        unmarked
    );
    assert_eq!(
        state().await.unwrap()["messages"][0]["message_expectation_state"]["state"],
        "open"
    );
    assert!(
        kernel::read_record_as(&w.db, &w.viewer, evidence)
            .await
            .unwrap()
            .is_some(),
        "undo preserves evidence history"
    );
    assert_eq!(
        mark("acct:viewer", "unmark_no_longer_relevant", "recipient-noop")
            .await
            .unwrap()["changed"],
        false
    );
    mark("acct:admin", "mark_no_longer_relevant", "sender-withdraw")
        .await
        .unwrap();
    assert_eq!(
        state().await.unwrap()["messages"][0]["message_expectation_state"]["evidence"]["by"],
        "sender"
    );
    mark("acct:admin", "unmark_no_longer_relevant", "sender-undo")
        .await
        .unwrap();
    let mut reply = send_args(&w, "real-reply");
    reply["addressed_to"] = json!(["person:admin"]);
    reply["expectation"] = json!("none");
    reply["links"] = json!([{"target_id":id,"relationship":"reply_to"}]);
    call(&w, "acct:viewer", "manage_messages", reply)
        .await
        .unwrap();
    mark("acct:viewer", "mark_no_longer_relevant", "mark-with-reply")
        .await
        .unwrap();
    assert_eq!(
        state().await.unwrap()["messages"][0]["message_expectation_state"]["evidence"]["kind"],
        "reply",
        "real evidence wins over marks"
    );
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    w.db.close().await;
}

#[tokio::test]
async fn relevance_direct_evidence_follows_bearer_visibility_and_archive_remark_keeps_history() {
    let w = world().await;
    let mut args = send_args(&w, "private-relevance");
    args["origin"] = json!({"type":"direct","participant_ids":["person:admin","person:viewer"]});
    let sent = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    let id = sent["id"].as_str().unwrap();
    let request = json!({"action":"mark_no_longer_relevant","message_id":id,"note":"Private recipient note","idempotency_key":"direct-mark","reason":"Local readable Message"});
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    for action in [
        "list_message_state",
        "mark_no_longer_relevant",
        "unmark_no_longer_relevant",
    ] {
        let mut bad = request.clone();
        bad["action"] = json!(action);
        if action == "list_message_state" {
            bad = json!({"action":action,"message_ids":[id]});
        }
        assert!(call(&w, "acct:outsider", "manage_messages", bad)
            .await
            .is_err());
    }
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());
    let marked = call(&w, "acct:viewer", "manage_messages", request)
        .await
        .unwrap();
    let evidence = marked["evidence_record_id"].as_str().unwrap();
    assert!(kernel::read_record_as(&w.db, &w.outsider, evidence)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        kernel::read_record_as(&w.db, &w.admin, evidence)
            .await
            .unwrap()
            .unwrap()
            .body
            .as_deref(),
        Some("Private recipient note")
    );
    kernel::set_archived_as(
        &w.db,
        &w.admin,
        evidence,
        true,
        kernel::read_record_as(&w.db, &w.viewer, evidence)
            .await
            .unwrap()
            .unwrap()
            .revision,
    )
    .await
    .unwrap();
    let new_mark=call(&w,"acct:viewer","manage_messages",json!({"action":"mark_no_longer_relevant","message_id":id,"note":"New note","idempotency_key":"re-mark","reason":"Re-mark archived evidence"})).await.unwrap();
    assert_ne!(new_mark["evidence_record_id"], evidence);
    kernel::set_archived_as(
        &w.db,
        &w.admin,
        evidence,
        false,
        kernel::read_record_as(&w.db, &w.viewer, evidence)
            .await
            .unwrap()
            .unwrap()
            .revision,
    )
    .await
    .unwrap();
    call(&w,"acct:viewer","manage_messages",json!({"action":"unmark_no_longer_relevant","message_id":id,"idempotency_key":"all-marks","reason":"Remove all own live links"})).await.unwrap();
    let mut tx = w.db.write_pool().begin().await.unwrap();
    assert!(
        kernel::messaging::own_relevance_marks_on(&mut tx, &w.viewer, id)
            .await
            .unwrap()
            .is_empty()
    );
    tx.rollback().await.unwrap();
    // v1 Annotations follow the live bearer. An explicit Message grant also
    // admits its evidence; a revoke hides both. The copied storage ACL is not
    // independent authority (authorization.rs:1292).
    let home = kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
        .home_id;
    kernel::replace_home_policy(
        &w.db,
        &w.admin,
        &home,
        &[
            (&w.admin, "manage"),
            (&w.viewer, "view"),
            (&w.outsider, "view"),
        ],
    )
    .await
    .unwrap();
    assert!(kernel::read_record_as(&w.db, &w.outsider, id)
        .await
        .unwrap()
        .is_some());
    assert!(kernel::read_record_as(&w.db, &w.outsider, evidence)
        .await
        .unwrap()
        .is_some());
    w.db.close().await;
}

#[tokio::test]
async fn relevance_candidate_withdrawal_honors_routing_and_existing_reply_evidence() {
    let w = world().await;
    let registry = super::super::tests::registry();
    let routed = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "explicit-route-message"),
    )
    .await
    .unwrap();
    let routed_id = routed["id"].as_str().unwrap();
    let human = Caller::authenticated("acct:viewer").with_verified_human_interaction(
        crate::awareness::VerifiedHumanInteraction {
            nonce: "route-before-relevance".into(),
            executor_ref: "synthetic-host".into(),
        },
    );
    registry.call_engine(EngineHandle::KernelV2(w.db.clone()),human,"manage_messages",json!({"action":"set_routing","message_id":routed_id,"obligation_state":"open","executor_route":"human","expected_version":0,"idempotency_key":"route-before-relevance","reason":"Explicit open route"})).await.unwrap();
    call(&w,"acct:viewer","manage_messages",json!({"action":"mark_no_longer_relevant","message_id":routed_id,"idempotency_key":"mark-explicit-route","reason":"Mark with route override"})).await.unwrap();
    let effective:Vec<String>=sqlx::query_scalar("SELECT message_id FROM kernel_message_candidates WHERE principal_id=? AND json_extract(state,'$.reason')='human_obligation' AND json_extract(state,'$.status')='effective'").bind(&w.viewer).fetch_all(w.db.pool()).await.unwrap();
    assert!(
        effective.iter().any(|id| id == routed_id),
        "v1 explicit open routing overrides derived closure"
    );
    let ordinary = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "existing-reply-message"),
    )
    .await
    .unwrap();
    let id = ordinary["id"].as_str().unwrap();
    let mut reply = send_args(&w, "existing-reply");
    reply["addressed_to"] = json!(["person:admin"]);
    reply["expectation"] = json!("none");
    reply["links"] = json!([{"target_id":id,"relationship":"reply_to"}]);
    call(&w, "acct:viewer", "manage_messages", reply)
        .await
        .unwrap();
    call(&w,"acct:outsider","manage_messages",json!({"action":"mark_no_longer_relevant","message_id":id,"idempotency_key":"third-party-after-reply","reason":"Full existing closure evidence"})).await.unwrap();
    let effective:Vec<String>=sqlx::query_scalar("SELECT message_id FROM kernel_message_candidates WHERE principal_id=? AND json_extract(state,'$.reason')='human_obligation' AND json_extract(state,'$.status')='effective'").bind(&w.viewer).fetch_all(w.db.pool()).await.unwrap();
    assert!(
        !effective.iter().any(|message| message == id),
        "v1 withdraws already-closed obligations even when the new mark is third-party"
    );
    w.db.close().await;
}

#[tokio::test]
async fn relevance_raw_events_require_the_annotations_own_message_bearer() {
    let w = world().await;
    let first = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "own-bearer"),
    )
    .await
    .unwrap();
    let second = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "other-bearer"),
    )
    .await
    .unwrap();
    let first_id = first["id"].as_str().unwrap();
    let second_id = second["id"].as_str().unwrap();
    let marked = call(
        &w,
        "acct:viewer",
        "manage_messages",
        json!({
            "action":"mark_no_longer_relevant", "message_id":first_id,
            "idempotency_key":"own-mark", "reason":"Own Message bearer"
        }),
    )
    .await
    .unwrap();
    let evidence = marked["evidence_record_id"].as_str().unwrap();
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
    let forged_link = uuid::Uuid::new_v4().to_string();
    let payload = json!({"link_id":forged_link,"source_id":evidence,
        "target_id":second_id,"relationship":"resolves","note":"no_longer_relevant"});
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = ActAllocation::new();
    assert!(
        append(
            &w.db,
            &mut tx,
            &mut acts,
            &w.viewer,
            evidence,
            "kernel.generic_link_added.v1",
            payload.clone()
        )
        .await
        .is_err(),
        "owning the Annotation and viewing another Message must not admit re-pointing"
    );
    tx.rollback().await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());

    // An editor may have added a mismatched historical link. Its owner cannot
    // use the View-only undo exemption for that other Message either.
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = ActAllocation::new();
    append(
        &w.db,
        &mut tx,
        &mut acts,
        &w.admin,
        evidence,
        "kernel.generic_link_added.v1",
        payload,
    )
    .await
    .unwrap();
    w.db.commit_kernel_content(tx).await.unwrap();
    let before = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    let mut tx = begin_write(w.db.write_pool()).await.unwrap();
    let mut acts = ActAllocation::new();
    assert!(append(
        &w.db,
        &mut tx,
        &mut acts,
        &w.viewer,
        evidence,
        "kernel.generic_link_removed.v1",
        json!({"link_id":forged_link})
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert_eq!(before, kernel::dump_all_kernel_tables(&w.db).await.unwrap());

    // Reaffirming and undoing the actual bearer still work with only View.
    for (action, key) in [
        ("mark_no_longer_relevant", "reaffirm-own"),
        ("unmark_no_longer_relevant", "undo-own"),
    ] {
        call(
            &w,
            "acct:viewer",
            "manage_messages",
            json!({"action":action,
            "message_id":first_id,"idempotency_key":key,"reason":"Own bearer only"}),
        )
        .await
        .unwrap();
    }
    let before_replay = kernel::dump_all_kernel_tables(&w.db).await.unwrap();
    kernel::replay_all_projections(&w.db).await.unwrap();
    assert_eq!(
        before_replay,
        kernel::dump_all_kernel_tables(&w.db).await.unwrap()
    );
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn record_reads_scan_reaction_after_import_baseline() {
    let w = world().await;
    let id = uuid::Uuid::new_v4().to_string();
    import_legacy_to_viewer(&w, &id, true).await;
    let before = call(&w, "acct:admin", "scan", json!({"scope":id}))
        .await
        .unwrap();
    assert_eq!(before["axes"]["authored_by"]["count"], 0);
    call(&w,"acct:admin","manage_messages",json!({"action":"add_reaction","message_id":id,"emoji":"👍","idempotency_key":"scan-imported-react","reason":"Exercise reaction attribution from an imported predecessor"})).await.unwrap();
    let after = call(&w, "acct:admin", "scan", json!({"scope":id}))
        .await
        .unwrap();
    assert_eq!(after["axes"]["authored_by"]["count"], 1, "{after}");
    assert_eq!(after["axes"]["authored_by"]["samples"][0]["id"], id);
    w.db.close().await;
}

#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn record_reads_scan_actor_person_visibility_and_hidden_agent_class() {
    let w = world().await;
    let id = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "scan-person"),
    )
    .await
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let private = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, "person:admin", &private)
        .await
        .unwrap();
    // Root View also discloses native principals: use an explicit message
    // home and remove that independent grant before testing the Person gate.
    let visible = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.viewer, "view"), (&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &id, &visible)
        .await
        .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, &w.origin, &visible)
        .await
        .unwrap();
    kernel::replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let scan = || call(&w, "acct:viewer", "scan", json!({"scope":id}));
    let hidden = scan().await.unwrap();
    assert_eq!(
        hidden["census"]["provenance"]["buckets"],
        json!([{"key":"unknown","count":1}])
    );
    kernel::rehome_record_as(&w.db, &w.admin, "person:admin", &visible)
        .await
        .unwrap();
    let disclosed = scan().await.unwrap();
    assert_eq!(
        disclosed["census"]["provenance"]["buckets"],
        json!([{"key":"other_account","count":1}])
    );
    kernel::rehome_record_as(&w.db, &w.admin, "person:admin", &private)
        .await
        .unwrap();
    let agent_id = crate::store::with_event_annotations(
        crate::store::EventAnnotations {
            run_key: Some("undisclosed-agent-run".into()),
            ..Default::default()
        },
        kernel::create_record_as(&w.db, &w.admin, &visible),
    )
    .await
    .unwrap();
    let stored_run: String = sqlx::query_scalar("SELECT e.run_key FROM kernel_records r JOIN content_events e ON e.seq=r.created_seq WHERE r.id=?")
        .bind(&agent_id).fetch_one(w.db.write_pool()).await.unwrap();
    assert_eq!(stored_run, "undisclosed-agent-run");
    let agent = call(&w, "acct:viewer", "scan", json!({"scope":agent_id}))
        .await
        .unwrap();
    assert_eq!(
        agent["census"]["provenance"]["buckets"],
        json!([{"key":"agent","count":1}])
    );
    for text in [
        agent.to_string(),
        crate::mcp::render::render("scan", &agent).unwrap(),
    ] {
        for secret in [
            &w.admin,
            "acct:admin",
            "person:admin",
            "undisclosed-agent-run",
        ] {
            assert!(!text.contains(secret), "{text}");
        }
        assert!(text.contains("other_account counts only actors"));
    }
    w.db.close().await;
}

/// Read-only projection benchmark: bulk-loads the same indexed record,
/// retained-header, message-state and link shapes as the producer fixtures.
/// Setup is excluded; the timed call includes visibility, all axes, admission,
/// reaction derivation and sample enrichment. No scope or type filter.
/// Run: RUST_MIN_STACK=67108864 cargo test -p native-ce --lib --features v2-kernel-probe record_reads_scan_hq_size_timing -- --ignored --nocapture
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
#[ignore = "opt-in HQ-size read deadline measurement"]
async fn record_reads_scan_hq_size_timing() {
    use tracing_subscriber::prelude::*;
    // Opt in to per-statement timings when phase intervals are too coarse to
    // assess cooperative-budget overruns. Fixture data only; default stays terse.
    let statements = std::env::var_os("NATIVE_MEASURE_SQL_STATEMENTS").is_some();
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_test_writer()
                .with_filter(tracing_subscriber::filter::filter_fn(move |m| {
                    m.target() == "native_ce::read_staging"
                        || (statements && m.target() == "sqlx::query")
                })),
        )
        .try_init();
    let w = world().await;
    let template = "hq-template";
    import_legacy_to_viewer(&w, template, true).await;
    let private = kernel::create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    kernel::rehome_record_as(&w.db, &w.admin, "person:outsider", &private)
        .await
        .unwrap();
    let baseline = call(&w, "acct:viewer", "scan", json!({})).await.unwrap()["corpus_size"]
        .as_i64()
        .unwrap();
    let owner_before = call(&w, "acct:admin", "scan", json!({})).await.unwrap();
    let owner_baseline = owner_before["corpus_size"].as_i64().unwrap();
    let owner_authored = owner_before["axes"]["authored_by"]["count"]
        .as_i64()
        .unwrap();
    let n = 16_500 - baseline;
    let mut tx = w.db.write_pool().begin().await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<?1) INSERT INTO kernel_records(id,home_id,owner_id,primary_type,kind,accession,pin_family,pin_version,pin_digest,interpreter,created_seq,created_at) SELECT printf('hq:%05d',x),r.home_id,r.owner_id,r.primary_type,r.kind,printf('hq-accession:%05d',x),r.pin_family,r.pin_version,r.pin_digest,r.interpreter,r.created_seq,r.created_at FROM n CROSS JOIN kernel_records r WHERE r.id=?2")
        .bind(n).bind(template).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields SELECT r.id,f.name,CASE WHEN f.name='title' THEN json_quote(r.id) WHEN f.name='v1_type' AND r.id<='hq:00360' THEN '\"Collection\"' WHEN f.name='v1_kind' AND r.id<='hq:00360' THEN '\"folder\"' WHEN f.name='v1_type' AND r.id<=printf('hq:%05d',?1-2000) THEN '\"Document\"' WHEN f.name='v1_kind' AND r.id<=printf('hq:%05d',?1-2000) THEN '\"note\"' ELSE f.value_json END,f.created_seq FROM kernel_records r CROSS JOIN kernel_record_fields f WHERE r.id LIKE 'hq:%' AND f.record_id=?2")
        .bind(n).bind(template).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'birth:'||r.id,r.id,CASE WHEN r.id>='hq:09001' AND r.id<=printf('hq:%05d',?1-2000) THEN 'kernel.record_created.v1' ELSE 'kernel.import_state.v1' END,json_object('state',json_object('message',json(m.state))),?2,'2026-11-08T00:00:00Z',1,'legacy_unknown' FROM kernel_records r CROSS JOIN kernel_messages m WHERE r.id LIKE 'hq:%' AND m.message_id=?3")
        .bind(n).bind(&w.admin).bind(template).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE kernel_records AS r SET created_seq=(SELECT seq FROM content_events e WHERE e.id='birth:'||r.id) WHERE r.id LIKE 'hq:%'").execute(&mut *tx).await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<360) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'home:'||x,printf('hq-home:%03d',x),'kernel.import_home.v1',json_object('source_record_id',printf('hq:%05d',x)),?1,'2020-01-01T00:00:00Z',1,'legacy_unknown' FROM n")
        .bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_roots SELECT record_id,CASE WHEN CAST(substr(id,6) AS INTEGER)%6=1 THEN ?1 ELSE printf('hq-home:%03d',CAST(substr(id,6) AS INTEGER)-1) END,?2,seq,created_at FROM content_events WHERE id LIKE 'home:%'")
        .bind(KERNEL_ROOT_ID).bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_policies SELECT root_id,created_at FROM kernel_roots WHERE root_id LIKE 'hq-home:%' AND CAST(substr(root_id,9) AS INTEGER)%6=1; INSERT INTO kernel_policy_entries SELECT root_id,'account',?1,'allow','view' FROM kernel_roots WHERE root_id LIKE 'hq-home:%' AND CAST(substr(root_id,9) AS INTEGER)%6=1")
        .bind(&w.viewer).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE kernel_records SET home_id=CASE WHEN id<='hq:00360' THEN CASE WHEN CAST(substr(id,4) AS INTEGER)%6=1 THEN ?1 ELSE printf('hq-home:%03d',CAST(substr(id,4) AS INTEGER)-1) END ELSE printf('hq-home:%03d',(CAST(substr(id,4) AS INTEGER)-1)%360+1) END WHERE id LIKE 'hq:%'")
        .bind(KERNEL_ROOT_ID).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_fields(record_id,name,value_json,created_seq) SELECT id,'lifecycle','\"active\"',created_seq FROM kernel_records WHERE id BETWEEN 'hq:00361' AND 'hq:03960'")
        .execute(&mut *tx).await.unwrap();
    // Two recorded moves per non-folder record, ending at current placement.
    sqlx::query("WITH moves(k) AS (VALUES(1),(2)) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'move:'||r.id||':'||k,r.id,'kernel.record_rehomed.v1',json_object('new_home_id',CASE WHEN k=2 THEN r.home_id ELSE printf('hq-home:%03d',(CAST(substr(r.id,4) AS INTEGER)+71)%360+1) END,'logical_home_id',CASE WHEN k=2 THEN printf('hq:%05d',(CAST(substr(r.id,4) AS INTEGER)-1)%360+1) ELSE printf('hq:%05d',(CAST(substr(r.id,4) AS INTEGER)+71)%360+1) END),?1,'2026-11-08T01:30:00Z',1,'legacy_unknown' FROM moves CROSS JOIN kernel_records r WHERE r.id>'hq:00360' AND r.id LIKE 'hq:%' ORDER BY k,r.id")
        .bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_messages SELECT r.id,m.state,r.created_seq FROM kernel_records r CROSS JOIN kernel_messages m WHERE r.id>printf('hq:%05d',?1-2000) AND r.id LIKE 'hq:%' AND m.message_id=?2")
        .bind(n).bind(template).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'legacy:'||id,id,'kernel.legacy_recorded.v1','{}',?1,'2020-01-01T00:00:00Z',1,'legacy_unknown' FROM kernel_records WHERE id BETWEEN 'hq:00001' AND 'hq:09000'")
        .bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.created','v1:acct:admin',NULL,NULL,'2020-01-01T00:00:00Z','content_events' FROM content_events WHERE id LIKE 'legacy:hq:%'; INSERT INTO kernel_legacy_history SELECT seq,'record.created',json_array(record_id),NULL,0,0,0,2 FROM content_events WHERE id LIKE 'legacy:hq:%'; INSERT INTO kernel_legacy_subjects SELECT record_id,seq FROM content_events WHERE id LIKE 'legacy:hq:%'; INSERT OR REPLACE INTO kernel_legacy_sql_progress VALUES(1,(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1'),1,1)").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'reaction:'||message_id,message_id,'kernel.message_state.v1',json_set(state,'$.reactions',json_object(?1,json_array('👍'))),?1,'2026-11-08T01:00:00Z',1,'legacy_unknown' FROM kernel_messages WHERE message_id LIKE 'hq:%'")
        .bind(&w.viewer).execute(&mut *tx).await.unwrap();
    sqlx::query("UPDATE kernel_messages AS m SET state=(SELECT payload FROM content_events e WHERE e.id='reaction:'||m.message_id),event_seq=(SELECT seq FROM content_events e WHERE e.id='reaction:'||m.message_id) WHERE message_id LIKE 'hq:%'").execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'hq-link:'||id,id,'kernel.generic_link_imported.v1',json_object('link_id','link:'||id),?1,'2026-11-08T00:00:00Z',1,'legacy_unknown' FROM kernel_records WHERE id BETWEEN 'hq:00002' AND 'hq:04001'")
        .bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_generic_links SELECT 'link:'||record_id,record_id,printf('hq:%05d',CAST(substr(record_id,4) AS INTEGER)+178),'related_to',NULL,created_at,actor,1,seq,1 FROM content_events WHERE id LIKE 'hq-link:%'")
        .execute(&mut *tx).await.unwrap();
    // Twenty-four retained owner edits, one member edit, birth and two
    // rehomes model about 28 events per record. Excluded retained envelopes
    // carry synthetic bulk to catch accidental event-row hydration.
    sqlx::query("WITH RECURSIVE edits(k) AS (VALUES(1) UNION ALL SELECT k+1 FROM edits WHERE k<25) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'hq-authored:'||r.id||':'||k,r.id,'kernel.legacy_recorded.v1',json_object('padding',printf('%02048d',0)),?1,CASE WHEN k=25 THEN '2026-11-08T03:00:00Z' ELSE '2026-11-08T02:00:00Z' END,1,'legacy_unknown' FROM edits CROSS JOIN kernel_records r WHERE r.id LIKE 'hq:%' ORDER BY k,r.id")
        .bind(&w.admin).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,id,record_id,'record.updated',CASE WHEN id LIKE '%:25' THEN 'v1:acct:viewer' ELSE 'v1:acct:admin' END,NULL,NULL,created_at,'content_events' FROM content_events WHERE id LIKE 'hq-authored:%'; INSERT INTO kernel_legacy_history SELECT seq,'record.updated',json_array(record_id),NULL,0,0,0,2 FROM content_events WHERE id LIKE 'hq-authored:%'; INSERT INTO kernel_legacy_subjects SELECT record_id,seq FROM content_events WHERE id LIKE 'hq-authored:%'; INSERT OR REPLACE INTO kernel_legacy_sql_progress VALUES(1,(SELECT max(seq) FROM content_events WHERE type='kernel.legacy_recorded.v1'),1,1)")
        .execute(&mut *tx).await.unwrap();
    sqlx::query("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096) INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) SELECT 'hq-hidden-chain:'||x,'hq:00001','kernel.link_removed.v1',json_object('target_id','person:outsider'),?1,'2026-11-08T02:00:00Z',1,'legacy_unknown' FROM n")
        .bind(&w.viewer).execute(&mut *tx).await.unwrap();
    sqlx::query("INSERT INTO kernel_record_metadata SELECT r.id,'enduring',NULL,'2026-11-08T03:00:00Z',coalesce(m.event_seq,r.created_seq) FROM kernel_records r LEFT JOIN kernel_messages m ON m.message_id=r.id WHERE r.id LIKE 'hq:%'")
        .execute(&mut *tx).await.unwrap();
    tx.commit().await.unwrap();
    let dimensions: (i64,i64,i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM kernel_roots WHERE root_id LIKE 'hq-home:%'),(SELECT count(*) FROM kernel_record_fields WHERE name='lifecycle' AND value_json='\"active\"'),(SELECT count(*) FROM content_events WHERE id LIKE 'move:hq:%'),(SELECT count(*) FROM kernel_legacy_sql_events WHERE source_id LIKE 'hq-authored:%' AND actor='v1:acct:admin'),(SELECT count(DISTINCT source_id) FROM kernel_generic_links WHERE link_id LIKE 'link:hq:%'),(SELECT count(DISTINCT target_id) FROM kernel_generic_links WHERE link_id LIKE 'link:hq:%')")
        .fetch_one(w.db.write_pool()).await.unwrap();
    assert_eq!(dimensions, (360, 3600, 2 * (n - 360), 24 * n, 4000, 4000));
    let depth: i64 = sqlx::query_scalar("WITH RECURSIVE homes(id,depth) AS (SELECT root_id,1 FROM kernel_roots WHERE root_id LIKE 'hq-home:%' AND parent_id=?1 UNION ALL SELECT h.root_id,p.depth+1 FROM kernel_roots h JOIN homes p ON h.parent_id=p.id) SELECT max(depth) FROM homes")
        .bind(KERNEL_ROOT_ID).fetch_one(w.db.write_pool()).await.unwrap();
    assert_eq!(depth, 6);
    let mut failures = Vec::new();
    for (label, credential, expected_size, expected_authored, authored_at) in [
        (
            "owner",
            "acct:admin",
            n + owner_baseline,
            n + owner_authored,
            "2026-11-08T02:00:00Z",
        ),
        (
            "member",
            "acct:viewer",
            n + baseline,
            n,
            "2026-11-08T03:00:00Z",
        ),
    ] {
        eprintln!("HQ-shaped scan begin caller={label}: {expected_size} visible, 360 folder homes in 60 six-level branches, 32272 rehomes, 3600 lifecycles, 4000 distributed links, 24 retained owner edits + 2 rehomes and 1 member edit per non-folder record, 4096 newer hidden edits; debug_assertions={}",cfg!(debug_assertions));
        let started = std::time::Instant::now();
        let result = call(&w, credential, "scan", json!({"high_degree_min":1})).await;
        eprintln!(
            "HQ-shaped scan end caller={label}: elapsed={:?}, result={}",
            started.elapsed(),
            if result.is_ok() { "ok" } else { "error" }
        );
        match result {
            Ok(out) => {
                assert_eq!(out["corpus_size"], expected_size);
                assert_eq!(out["axes"]["authored_by"]["count"], expected_authored);
                assert_eq!(
                    out["axes"]["authored_by"]["samples"][0]["authored_at"],
                    authored_at
                );
                assert_eq!(out["axes"]["high_degree"]["count"], 4178);
                assert_eq!(out["axes"]["high_degree"]["samples"][0]["degree"], 2);
                assert!(out["census"]["by_lifecycle"]["buckets"]
                    .as_array()
                    .unwrap()
                    .contains(&json!({"key":"active","count":3600})));
            }
            Err(error) => {
                eprintln!("HQ-shaped scan caller={label}: {error}");
                failures.push(label);
            }
        }
    }
    w.db.close().await;
    assert!(
        failures.is_empty(),
        "HQ-shaped scan exceeded the unchanged deadline: {failures:?}"
    );
}

#[tokio::test]
async fn explicit_root_filing_preserves_root_origin_message() {
    let w = world().await;
    let mut args = send_args(&w, "root-filing-message-proof");
    args["origin"] = json!({"type":"collection","collection_id":"native:root"});
    args["home_id"] = json!("native:root");
    let sent = call(&w, "acct:admin", "manage_messages", args)
        .await
        .unwrap();
    assert!(sent.get("redirected_home").is_none());
    let row = kernel::read_record_as(&w.db, &w.admin, sent["id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.home_id, KERNEL_ROOT_ID);
}

/// Extended query_record anchor narrowing (Native 3a3eabb), owed Message
/// placement fixture: a direct Message's logical home is its direct home
/// (LOGICAL_DIRECT_HOME_SQL), not its physical root. P1 admits every
/// Message as a candidate; containment plus narrowed/full byte-identity for
/// participants and a non-participant, on each home a Message lands in.
#[cfg(feature = "v2-kernel-probe")]
#[tokio::test]
async fn extended_query_record_message_placements_lie_within_anchor_candidates() {
    let w = world().await;
    let mut sent = Vec::new();
    for (key, origin) in [
        ("anchor-collection", None),
        (
            "anchor-direct-viewer",
            Some(["person:admin", "person:viewer"]),
        ),
        (
            "anchor-direct-outsider",
            Some(["person:admin", "person:outsider"]),
        ),
    ] {
        let mut args = send_args(&w, key);
        if let Some(participants) = origin {
            args["origin"] = json!({"type":"direct","participant_ids":participants});
            args["addressed_to"] = json!([participants[1]]);
        }
        sent.push(
            call(&w, "acct:admin", "manage_messages", args)
                .await
                .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
    }
    // Every home a Message is placed in, as admin sees it.
    let mut homes = BTreeSet::from([
        w.origin.clone(),
        KERNEL_ROOT_ID.to_owned(),
        "native:root".to_owned(),
    ]);
    let mut direct_differs = false;
    for id in &sent {
        let got = call(
            &w,
            "acct:admin",
            "query_record",
            json!({"steps":[{"step":"filter","ids":[id]}],"order":"name_asc"}),
        )
        .await
        .unwrap();
        let home = got["records"][0]["home_id"].as_str().unwrap().to_owned();
        let physical: String = sqlx::query_scalar("SELECT home_id FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        direct_differs |= home != physical;
        homes.insert(home);
        homes.insert(physical);
    }
    assert!(
        direct_differs,
        "fixture must place a Message away from its physical root"
    );
    let mut checked = 0;
    for home in &homes {
        for order in ["updated_desc", "last_activity_desc", "name_asc"] {
            let args =
                json!({"steps":[{"step":"filter","home_id":home}],"order":order,"limit":500});
            let plan = super::read_surface::recognize_args(&args)
                .unwrap_or_else(|| panic!("not recognised: {args}"));
            let mut conn = w.db.pool().acquire().await.unwrap();
            let candidates = super::read_surface::direct_candidates_on(&mut conn, &plan)
                .await
                .unwrap();
            drop(conn);
            for credential in ["acct:admin", "acct:viewer", "acct:outsider"] {
                for (limit, offset) in [(500, 0), (2, 1), (1, 0), (3, 1000)] {
                    let mut variant = args.clone();
                    variant["limit"] = json!(limit);
                    variant["offset"] = json!(offset);
                    let full = super::read_surface::FORCE_FULL_STAGING
                        .scope(true, call(&w, credential, "query_record", variant.clone()))
                        .await;
                    let narrowed = call(&w, credential, "query_record", variant.clone()).await;
                    match (&full, &narrowed) {
                        (Ok(a), Ok(b)) => assert_eq!(
                            serde_json::to_string(a).unwrap(),
                            serde_json::to_string(b).unwrap(),
                            "{credential} {variant}: narrowed output differs"
                        ),
                        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
                        _ => {
                            panic!("{credential} {variant}: full {full:?} vs narrowed {narrowed:?}")
                        }
                    }
                }
                let Ok(result) = call(&w, credential, "query_record", args.clone()).await else {
                    continue;
                };
                for r in result["records"].as_array().unwrap() {
                    let id = r["id"].as_str().unwrap();
                    assert!(
                        candidates.contains(id),
                        "{credential} {args}: {id} outside candidates"
                    );
                }
                checked += 1;
            }
        }
    }
    assert!(checked >= 30, "oracle exercised {checked} calls");
}

#[tokio::test]
async fn kernel_v2_batch_guard_only_supports_immutable_messages() {
    let w = world().await;
    let sent = call(
        &w,
        "acct:admin",
        "manage_messages",
        send_args(&w, "batch-message-guard"),
    )
    .await
    .unwrap();
    let record = call(&w, "acct:admin", "get_record", json!({"ids":[sent["id"]]}))
        .await
        .unwrap();
    let updated = &record["records"][0]["updated_at"];
    assert!(updated.is_string(), "{record}");
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let result = call(&w,"acct:admin","batch_write",json!({"reason":"assert message unchanged","items":[{"op":"update","id":sent["id"],"if_unmodified_since":updated}]})).await.unwrap();
    assert_eq!(result["changed"], 0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
            .fetch_one(w.db.pool())
            .await
            .unwrap(),
        before
    );
    w.db.close().await;
}
