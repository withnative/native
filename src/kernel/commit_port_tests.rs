use super::*;
use crate::v2_standard::{
    self,
    relates_to::{self as provider, Command, Source},
};
use serde_json::json;

fn engine_error<T: std::fmt::Debug>(result: Result<T>, expected: &str) {
    match result.unwrap_err() {
        Error::Engine(message) => assert_eq!(message, expected),
        error => panic!("expected Engine({expected}), got {error:?}"),
    }
}
fn conflict<T: std::fmt::Debug>(result: Result<T>, expected: &str) {
    match result.unwrap_err() {
        Error::Conflict(message) => assert_eq!(message, expected),
        error => panic!("expected Conflict({expected}), got {error:?}"),
    }
}

struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
    note: String,
    bare: String,
}
impl World {
    async fn fresh() -> Self {
        Self::fresh_with_binding("acct:admin").await
    }
    async fn fresh_with_binding(binding: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("port.db").display()),
            "account",
            "Admin",
            if binding == relates_to_port::HOST_TRANSFORM_BINDING {
                "acct:fixture-admin"
            } else {
                binding
            },
        )
        .await
        .unwrap();
        let admin = if binding == relates_to_port::HOST_TRANSFORM_BINDING {
            let host = resolve_principal_by_binding(&db, binding)
                .await
                .unwrap()
                .unwrap()
                .0;
            replace_home_policy(
                &db,
                &admin,
                KERNEL_ROOT_ID,
                &[(&admin, "manage"), (&host, "manage")],
            )
            .await
            .unwrap();
            host
        } else {
            admin
        };
        for manifest in [provider::package(), v2_standard::document3_package()] {
            let id = install_package_as(&db, &admin, &manifest).await.unwrap();
            adopt_package_at(
                &db,
                &admin,
                KERNEL_ROOT_ID,
                &manifest,
                Some(&id),
                &manifest.declared_reads,
            )
            .await
            .unwrap();
        }
        let note = create_json_as(
            &db,
            &admin,
            v2_standard::DOCUMENT_FAMILY,
            "note",
            "{}",
            KERNEL_ROOT_ID,
        )
        .await
        .unwrap();
        let bare = create_record_as(&db, &admin, KERNEL_ROOT_ID).await.unwrap();
        Self {
            _dir: dir,
            db,
            admin,
            note,
            bare,
        }
    }
    async fn prepare(&self, key: &str) -> ProviderRequest {
        prepare_provider_as(
            &self.db,
            &self.admin,
            &self.note,
            &self.bare,
            key,
            Command::Assert { sources: vec![] },
        )
        .await
        .unwrap()
    }
    async fn count(&self) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(self.db.pool())
            .await
            .unwrap()
    }
    async fn replay(&self) {
        let before = dump_all_kernel_tables(&self.db).await.unwrap();
        replay_all_projections(&self.db).await.unwrap();
        assert_eq!(before, dump_all_kernel_tables(&self.db).await.unwrap());
    }
    async fn disable(&self) {
        let p = provider::package();
        adopt_package_at(&self.db, &self.admin, KERNEL_ROOT_ID, &p, None, &[])
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn reversal_retry_and_sequential_prepares_keep_one_relation() {
    let w = World::fresh().await;
    let r = w.prepare("first").await;
    let reverse = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.bare,
        &w.note,
        "reverse",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    assert_eq!(r.aggregate_id, reverse.aggregate_id);
    let receipt = commit_provider_as(&w.db, &w.admin, &r).await.unwrap();
    let count = w.count().await;
    assert_eq!(
        receipt,
        commit_provider_as(&w.db, &w.admin, &r).await.unwrap()
    );
    assert_eq!(r, w.prepare("first").await);
    assert_eq!(count, w.count().await);
    conflict(
        commit_provider_as(&w.db, &w.admin, &reverse).await,
        "provider aggregate head moved",
    );
    assert_eq!(count, w.count().await);
    let reverse = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.bare,
        &w.note,
        "reverse",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let reverse_receipt = commit_provider_as(&w.db, &w.admin, &reverse).await.unwrap();
    assert_eq!(receipt.aggregate_id, reverse_receipt.aggregate_id);
    let a = relations_as(&w.db, &w.admin, &w.note).await.unwrap();
    assert_eq!(a, relations_as(&w.db, &w.admin, &w.bare).await.unwrap());
    assert_eq!(a.len(), 1);
    assert_eq!(
        links_from_as(&w.db, &w.admin, &w.bare).await.unwrap(),
        vec![(w.note.clone(), "relates_to.v1".into())]
    );
    w.replay().await;
}

#[tokio::test]
async fn synthetic_d9_two_directions_preserve_two_sources_and_host_transform_attribution() {
    let w = World::fresh_with_binding(relates_to_port::HOST_TRANSFORM_BINDING).await;
    let sources = vec![
        Source {
            source_id: "fixture.legacy.forward".into(),
            from: w.note.clone(),
            to: w.bare.clone(),
            claimed_author: Some("fixture.author.a".into()),
            claimed_timestamp: Some("2001-01-01T00:00:00Z".into()),
            note: Some("forward note".into()),
        },
        Source {
            source_id: "fixture.legacy.reverse".into(),
            from: w.bare.clone(),
            to: w.note.clone(),
            claimed_author: Some("fixture.author.b".into()),
            claimed_timestamp: Some("2002-02-02T00:00:00Z".into()),
            note: Some("reverse note".into()),
        },
    ];
    let r = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.note,
        &w.bare,
        "fixture.d9.transform",
        Command::Assert {
            sources: sources.clone(),
        },
    )
    .await
    .unwrap();
    let receipt = commit_provider_as(&w.db, &w.admin, &r).await.unwrap();
    let relations = relations_as(&w.db, &w.admin, &w.bare).await.unwrap();
    assert_eq!(relations.len(), 1);
    let state: provider::State = serde_json::from_value(relations[0]["state"].clone()).unwrap();
    assert_eq!(state.assertions[0].sources, sources);
    let (actor, time): (String, String) =
        sqlx::query_as("SELECT actor,created_at FROM content_events WHERE seq=?")
            .bind(receipt.event_seq)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(actor, w.admin);
    assert_ne!(
        time,
        state.assertions[0].sources[0]
            .claimed_timestamp
            .as_deref()
            .unwrap()
    );
    assert_eq!(
        state.assertions[0].asserted_by.as_deref(),
        Some(w.admin.as_str())
    );
    assert_eq!(state.assertions[0].asserted_at, time);
    assert_eq!(state.assertions[0].asserted_seq, receipt.event_seq);
    w.replay().await;
}

#[tokio::test]
async fn stale_anchor_binding_aggregate_and_selection_are_event_free() {
    let w = World::fresh().await;
    let r = w.prepare("stale").await;
    revise_json_as_expected(
        &w.db,
        &w.admin,
        &w.note,
        r#"{"body":"new"}"#,
        Some(r.anchor.head),
    )
    .await
    .unwrap();
    let count = w.count().await;
    conflict(
        commit_provider_as(&w.db, &w.admin, &r).await,
        "provider endpoint or binding head moved",
    );
    assert_eq!(count, w.count().await);
    let r = w.prepare("binding").await;
    rebind_record_as(
        &w.db,
        &w.admin,
        &w.bare,
        v2_standard::DOCUMENT_FAMILY,
        "note",
        &serde_json::Map::new(),
    )
    .await
    .unwrap();
    let count = w.count().await;
    conflict(
        commit_provider_as(&w.db, &w.admin, &r).await,
        "provider endpoint or binding head moved",
    );
    assert_eq!(count, w.count().await);
    let r = w.prepare("selection").await;
    w.disable().await;
    let p = provider::package();
    adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &p,
        Some(&p.identity().unwrap()),
        &p.declared_reads,
    )
    .await
    .unwrap();
    let count = w.count().await;
    conflict(
        commit_provider_as(&w.db, &w.admin, &r).await,
        "provider selection head moved",
    );
    assert_eq!(count, w.count().await);
    w.replay().await;
}

#[tokio::test]
async fn disable_blocks_new_assertions_and_retractions_but_retains_replay_and_receipts() {
    let w = World::fresh().await;
    let r = w.prepare("first").await;
    let receipt = commit_provider_as(&w.db, &w.admin, &r).await.unwrap();
    w.disable().await;
    let count = w.count().await;
    engine_error(
        prepare_provider_as(
            &w.db,
            &w.admin,
            &w.bare,
            &w.note,
            "new",
            Command::Assert { sources: vec![] },
        )
        .await,
        "package is disabled in this scope",
    );
    engine_error(
        prepare_provider_as(
            &w.db,
            &w.admin,
            &w.note,
            &w.bare,
            "retract",
            Command::Retract {
                assertion_id: receipt.assertion_id.clone(),
            },
        )
        .await,
        "package is disabled in this scope",
    );
    assert_eq!(
        receipt,
        commit_provider_as(&w.db, &w.admin, &r).await.unwrap()
    );
    assert_eq!(count, w.count().await);
    let describe = describe_record_links_as(&w.db, &w.admin, &w.note)
        .await
        .unwrap();
    assert_eq!(describe["governed_relationships"]["available"], false);
    w.replay().await;
    assert_eq!(
        relations_as(&w.db, &w.admin, &w.bare).await.unwrap().len(),
        1
    );
}

#[tokio::test]
async fn retraction_is_attributed_symmetric_and_preserves_sources() {
    let w = World::fresh_with_binding(relates_to_port::HOST_TRANSFORM_BINDING).await;
    let sources = vec![Source {
        source_id: "fixture.retract-source".into(),
        from: w.note.clone(),
        to: w.bare.clone(),
        claimed_author: Some("fixture.source-author".into()),
        claimed_timestamp: Some("2003-01-01T00:00:00Z".into()),
        note: Some("Retained legacy note".into()),
    }];
    let original = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.note,
        &w.bare,
        "assert",
        Command::Assert {
            sources: sources.clone(),
        },
    )
    .await
    .unwrap();
    let receipt = commit_provider_as(&w.db, &w.admin, &original)
        .await
        .unwrap();
    let r = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.bare,
        &w.note,
        "retract",
        Command::Retract {
            assertion_id: receipt.assertion_id.clone(),
        },
    )
    .await
    .unwrap();
    let retracted = commit_provider_as(&w.db, &w.admin, &r).await.unwrap();
    for id in [&w.note, &w.bare] {
        assert!(links_from_as(&w.db, &w.admin, id).await.unwrap().is_empty());
        let relations = relations_as(&w.db, &w.admin, id).await.unwrap();
        let a = &relations[0]["state"]["assertions"][0];
        assert_eq!(a["retracted"], true);
        assert_eq!(a["sources"], serde_json::to_value(&sources).unwrap());
        assert_eq!(a["asserted_by"], w.admin);
        assert_eq!(a["asserted_seq"], receipt.event_seq);
        assert_eq!(a["retracted_by"], w.admin);
        assert_eq!(a["retracted_seq"], retracted.event_seq);
        let (actor, time): (String, String) =
            sqlx::query_as("SELECT actor,created_at FROM content_events WHERE seq=?")
                .bind(retracted.event_seq)
                .fetch_one(w.db.pool())
                .await
                .unwrap();
        assert_eq!(a["retracted_by"], actor);
        assert_eq!(a["retracted_at"], time);
    }
    w.replay().await;
}

#[tokio::test]
async fn either_anchor_requires_opt_in_edit_and_both_views() {
    let w = World::fresh().await;
    let editor = create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    let home = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage"), (&editor, "view")]),
        &w.admin,
    )
    .await
    .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.bare, &home)
        .await
        .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let r = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "either",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &editor, &r).await.unwrap();
    engine_error(
        prepare_provider_as(
            &w.db,
            &editor,
            &w.bare,
            &w.note,
            "no-edit",
            Command::Assert { sources: vec![] },
        )
        .await,
        HIDDEN_OR_MISSING,
    );
    // A bound non-opted-in record can receive a relationship, but cannot anchor it.
    let outcome = v2_standard::outcome_package();
    let id = install_package_as(&w.db, &w.admin, &outcome).await.unwrap();
    adopt_package_at(&w.db, &w.admin, KERNEL_ROOT_ID, &outcome, Some(&id), &[])
        .await
        .unwrap();
    let impact = create_as(
        &w.db,
        &w.admin,
        v2_standard::OUTCOME_FAMILY,
        "impact",
        &serde_json::from_value(
            json!({"claim":"Impact","method":"declared","effective_at":"2026-10-11"}),
        )
        .unwrap(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let count = w.count().await;
    assert!(prepare_provider_as(
        &w.db,
        &w.admin,
        &impact,
        &w.note,
        "wrong-anchor",
        Command::Assert { sources: vec![] }
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("anchor does not declare"));
    assert_eq!(count, w.count().await);
    let r = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.note,
        &impact,
        "incoming",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &w.admin, &r).await.unwrap();
    w.replay().await;
}

#[tokio::test]
async fn visibility_races_hide_reverse_reads_retries_and_raw_projection() {
    let w = World::fresh().await;
    let editor = create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let r = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "visible",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let pending = prepare_provider_as(
        &w.db,
        &editor,
        &w.bare,
        &w.note,
        "pending",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &editor, &r).await.unwrap();
    let hidden = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.bare, &hidden)
        .await
        .unwrap();
    let count = w.count().await;
    for request in [&r, &pending] {
        assert_eq!(
            commit_provider_as(&w.db, &editor, request)
                .await
                .unwrap_err()
                .to_string(),
            Error::engine(HIDDEN_OR_MISSING).to_string()
        );
    }
    let hidden_err = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "hidden",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap_err()
    .to_string();
    let missing_err = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        "fixture.missing",
        "missing",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(hidden_err, missing_err);
    assert!(relations_as(&w.db, &editor, &w.note)
        .await
        .unwrap()
        .is_empty());
    assert!(relations_as(&w.db, &editor, &w.bare)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(count, w.count().await);
    w.replay().await;
}

#[tokio::test]
async fn raw_events_and_forged_outcomes_cannot_bypass_port() {
    use crate::store::{append, AppendSpec};
    let w = World::fresh().await;
    let r = w.prepare("raw").await;
    let count = w.count().await;
    for payload in [
        json!({"source_id":w.bare,"target_id":w.note,"relationship":"relates_to"}),
        json!({"source_id":w.note,"target_id":w.bare,"relationship":"relates_to"}),
    ] {
        assert!(append(
            &w.db,
            AppendSpec {
                record_id: payload["source_id"].as_str().unwrap().into(),
                event_type: "kernel.link_added.v1".into(),
                payload,
                actor: Some(w.admin.clone())
            }
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("governed provider"));
    }
    engine_error(
        link_as(&w.db, &w.admin, &w.bare, "relates_to", &w.note).await,
        "relates_to requires the governed provider commit port",
    );
    let mut forged = r.clone();
    forged.request_digest = "fixture.forged".into();
    engine_error(
        commit_provider_as(&w.db, &w.admin, &forged).await,
        "provider request checksum mismatch",
    );
    let mut forged = r.clone();
    forged.pins.reducer = "fixture.forged".into();
    engine_error(
        commit_provider_as(&w.db, &w.admin, &forged).await,
        "live admission requires current provider interpretation pins",
    );
    let mut forged = r.clone();
    forged.principal_id = "fixture.forged".into();
    engine_error(
        commit_provider_as(&w.db, &w.admin, &forged).await,
        HIDDEN_OR_MISSING,
    );
    engine_error(append(
        &w.db,
        AppendSpec {
            record_id: w.note.clone(),
            event_type: commit_port::PROVIDER_OUTCOME_EVENT.into(),
            payload: serde_json::to_value(&r).unwrap(),
            actor: Some("fixture.forged".into())
        }
    )
    .await,"provider outcomes are kernel commit-port-owned and cannot be appended through the public event seam");
    let payload = json!({"request":r,"assertion_id":uuid::Uuid::new_v4().to_string()});
    let forged_actor = crate::events::EventRow {
        local_seq: -1,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: r.aggregate_id.clone(),
        event_type: commit_port::PROVIDER_OUTCOME_EVENT.into(),
        payload: Some(payload.to_string()),
        actor: Some("fixture.forged".into()),
        created_at: "2026-10-11T00:00:00Z".into(),
        run_key: None,
        parent_key: None,
        intent: None,
        act: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
    };
    let mut tx = w.db.write_pool().begin().await.unwrap();
    engine_error(
        admit_provider_event(&mut tx, &forged_actor).await,
        "provider actor or aggregate mismatch",
    );
    tx.rollback().await.unwrap();
    assert_eq!(count, w.count().await);
}

#[tokio::test]
async fn fresh_generic_reader_uses_describe_contract_only() {
    let w = World::fresh().await;
    let described = describe_world_as(&w.db, &w.admin).await.unwrap();
    let contract = &described["governed_relationships"];
    assert!(contract["harness"]["prepare"]
        .as_str()
        .unwrap()
        .contains("relation-prepare"));
    let note = describe_record_links_as(&w.db, &w.admin, &w.note)
        .await
        .unwrap();
    assert_eq!(note["record"]["binding"]["interpreter"], "native.defn/5");
    assert_eq!(
        described["directed_links"]["interpreter"],
        "native.defn/4 and later"
    );
    assert_eq!(note["governed_relationships"]["can_assert"], true);
    assert_eq!(
        note["links"][0]["declaration"]["relationship_ref"],
        contract["relationship_ref"]
    );
    let command: Command = serde_json::from_value(contract["api"]["assert"].clone()).unwrap();
    let request = prepare_provider_as(&w.db, &w.admin, &w.note, &w.bare, "from-describe", command)
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(&request.pins).unwrap(),
        contract["pins"]
    );
    commit_provider_as(&w.db, &w.admin, &request).await.unwrap();
    let read = relations_as(&w.db, &w.admin, &w.bare).await.unwrap();
    let mut retract = contract["api"]["retract"].clone();
    retract["Retract"]["assertion_id"] = read[0]["state"]["assertions"][0]["id"].clone();
    let request = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.bare,
        &w.note,
        "retract-from-describe",
        serde_json::from_value(retract).unwrap(),
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &w.admin, &request).await.unwrap();
    w.replay().await;
}

#[tokio::test]
async fn edit_policy_race_and_hidden_retry_refuse_without_events() {
    let w = World::fresh().await;
    let editor = create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let r = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "edit-race",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "view")],
    )
    .await
    .unwrap();
    let count = w.count().await;
    engine_error(
        commit_provider_as(&w.db, &editor, &r).await,
        HIDDEN_OR_MISSING,
    );
    assert_eq!(count, w.count().await);
    assert!(relations_as(&w.db, &editor, &w.note)
        .await
        .unwrap()
        .is_empty());
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let retry = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "hidden-retry",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &editor, &retry).await.unwrap();
    replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    let count = w.count().await;
    engine_error(
        commit_provider_as(&w.db, &editor, &retry).await,
        HIDDEN_OR_MISSING,
    );
    engine_error(
        prepare_provider_as(
            &w.db,
            &editor,
            &w.note,
            &w.bare,
            "hidden-retry",
            Command::Assert { sources: vec![] },
        )
        .await,
        HIDDEN_OR_MISSING,
    );
    assert_eq!(count, w.count().await);
    w.replay().await;
}

#[test]
fn relationship_declaration_and_command_grammar_are_closed() {
    let base: serde_json::Value =
        serde_json::from_str(include_str!("../v2_standard/document3.defn.json")).unwrap();
    for (key, value, expected) in [
        ("predicate",json!("relates_to"),"$.kinds[0].links[0].relationship_ref: predicate and relationship_ref are mutually exclusive"),
        ("relationship_ref",json!({"namespace":"fixture","package":"relation","version":1,"relationship":"x","actor":"forged"}),"$.kinds[0].links[0].relationship_ref: invalid relationship_ref"),
        ("relationship_ref",json!({"namespace":"fixture","package":"relation","version":0,"relationship":"x"}),"$.kinds[0].links[0].relationship_ref: relationship_ref version must be positive"),
    ] {
        let mut doc=base.clone(); doc["kinds"][0]["links"][0][key]=value;
        engine_error(crate::meta::definition_artifact::validate_kernel_definition_bytes(&doc.to_string()),expected);
    }
    assert_eq!(
        serde_json::from_value::<Command>(json!({"Assert":{"sources":[],"actor":"forged"}}))
            .unwrap_err()
            .to_string(),
        "unknown field `actor`, expected `sources`"
    );
}

#[tokio::test]
async fn fold_failure_rolls_back_event_state_and_receipt_together() {
    let w = World::fresh().await;
    let r = w.prepare("fold-failure").await;
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    sqlx::query("CREATE TRIGGER fixture_fail_receipt BEFORE INSERT ON kernel_provider_receipts BEGIN SELECT RAISE(ABORT, 'fixture fold failure'); END").execute(w.db.write_pool()).await.unwrap();
    match commit_provider_as(&w.db, &w.admin, &r).await.unwrap_err() {
        Error::Sqlx(sqlx::Error::Database(error)) => {
            assert_eq!(error.message(), "fixture fold failure")
        }
        error => panic!("expected receipt trigger failure, got {error:?}"),
    }
    assert_eq!(count, w.count().await);
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    sqlx::query("DROP TRIGGER fixture_fail_receipt")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    commit_provider_as(&w.db, &w.admin, &r).await.unwrap();
    w.replay().await;
}

#[tokio::test]
async fn prepared_directed_event_cannot_bypass_new_selection_and_old_event_still_replays() {
    use crate::store::{append, AppendSpec};
    let w = World::fresh().await;
    w.disable().await;
    let doc = json!({"family":"fixture.directed","version":1,"interpreter":"native.defn/4","primary_type":"Fixture","kinds":[{"token":"record","maturity":"current","description":"Directed bypass fixture.","fields":[],"identity":{"mode":"record"},"links":[{"predicate":"relates_to","target":{"any_record":true},"direction":"out","cardinality":"many"}]}]});
    let pin = install_definition_as(
        &w.db,
        &w.admin,
        "fixture.directed",
        1,
        doc.to_string().as_bytes(),
    )
    .await
    .unwrap();
    adopt_definition_as(&w.db, &w.admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let record = create_as(
        &w.db,
        &w.admin,
        "fixture.directed",
        "record",
        &serde_json::Map::new(),
        KERNEL_ROOT_ID,
    )
    .await
    .unwrap();
    let old = prepare_link4_as(
        &w.db,
        &w.admin,
        &record,
        "relates_to",
        &w.bare,
        "old-directed",
    )
    .await
    .unwrap();
    link4_as(&w.db, &w.admin, &old).await.unwrap();
    let other = create_record_as(&w.db, &w.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let pending = prepare_link4_as(
        &w.db,
        &w.admin,
        &record,
        "relates_to",
        &other,
        "pending-directed",
    )
    .await
    .unwrap();
    let p = provider::package();
    adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &p,
        Some(&p.identity().unwrap()),
        &p.declared_reads,
    )
    .await
    .unwrap();
    let count = w.count().await;
    assert!(link4_as(&w.db, &w.admin, &pending)
        .await
        .unwrap_err()
        .to_string()
        .contains("governed provider"));
    assert!(append(
        &w.db,
        AppendSpec {
            record_id: record.clone(),
            event_type: "kernel.link_added.v2".into(),
            payload: serde_json::to_value(&pending).unwrap(),
            actor: Some(w.admin.clone())
        }
    )
    .await
    .unwrap_err()
    .to_string()
    .contains("governed provider"));
    assert_eq!(count, w.count().await);
    w.replay().await;
    assert_eq!(
        links_from_as(&w.db, &w.admin, &record).await.unwrap(),
        vec![(w.bare.clone(), "relates_to".into())]
    );
}

#[tokio::test]
async fn restored_permissions_do_not_hide_an_authority_frontier_race() {
    let w = World::fresh().await;
    let editor = create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let r = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "authority-aba",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    engine_error(
        commit_provider_as(&w.db, &editor, &r).await,
        HIDDEN_OR_MISSING,
    );
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let count = w.count().await;
    conflict(
        commit_provider_as(&w.db, &editor, &r).await,
        "provider authority frontier moved",
    );
    assert_eq!(count, w.count().await);
    let fresh = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "fresh-authority",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &editor, &fresh).await.unwrap();
    w.replay().await;
}

/// Design fixture 51, relationship half: a relation prepared before a sealed
/// home creation cannot commit across it, exactly as for `home_created.v1`.
#[tokio::test]
async fn sealed_home_creation_moves_the_provider_authority_frontier() {
    let w = World::fresh().await;
    let (_, _, cfg) = super::slots_home_for_tests::designate(&w.db, &w.admin).await;
    let r = w.prepare("before-home").await;
    let event = super::slots_home_for_tests::provision_for(&w.db, &cfg, &w.admin)
        .await
        .unwrap();
    let fresh = w.prepare("after-home").await;
    assert_eq!(fresh.authority_head, event.local_seq);
    assert!(r.authority_head < fresh.authority_head);
    let count = w.count().await;
    conflict(
        commit_provider_as(&w.db, &w.admin, &r).await,
        "provider authority frontier moved",
    );
    assert_eq!(count, w.count().await);
    commit_provider_as(&w.db, &w.admin, &fresh).await.unwrap();
    w.replay().await;
}

#[test]
fn foreign_package_cannot_advertise_the_compiled_relationship_service() {
    let mut manifest = provider::package();
    manifest.namespace = "fixture.foreign".into();
    assert!(manifest
        .validate()
        .unwrap_err()
        .to_string()
        .contains("exact compiled first-party"));
}

#[tokio::test]
async fn retry_receipt_needs_current_visibility_but_no_new_write_authority() {
    let w = World::fresh().await;
    let editor = create_principal(&w.db, "account", "Editor", "acct:editor", &w.admin)
        .await
        .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "edit")],
    )
    .await
    .unwrap();
    let r = prepare_provider_as(
        &w.db,
        &editor,
        &w.note,
        &w.bare,
        "receipt",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let receipt = commit_provider_as(&w.db, &editor, &r).await.unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&editor, "view")],
    )
    .await
    .unwrap();
    let count = w.count().await;
    assert_eq!(
        receipt,
        commit_provider_as(&w.db, &editor, &r).await.unwrap()
    );
    assert_eq!(
        r,
        prepare_provider_as(
            &w.db,
            &editor,
            &w.note,
            &w.bare,
            "receipt",
            r.command.clone()
        )
        .await
        .unwrap()
    );
    engine_error(
        prepare_provider_as(
            &w.db,
            &editor,
            &w.note,
            &w.bare,
            "new-write",
            r.command.clone(),
        )
        .await,
        HIDDEN_OR_MISSING,
    );
    assert_eq!(count, w.count().await);
    w.replay().await;
}

#[tokio::test]
async fn hidden_relation_does_not_move_visible_endpoint_or_conflict_other_pair() {
    let w = World::fresh().await;
    let reader = create_principal(&w.db, "account", "Reader", "acct:reader", &w.admin)
        .await
        .unwrap();
    let visible = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage"), (&reader, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    let hidden = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.note, &visible)
        .await
        .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.bare, &visible)
        .await
        .unwrap();
    let c = create_record_as(&w.db, &w.admin, &hidden).await.unwrap();
    let pending = prepare_provider_as(
        &w.db,
        &reader,
        &w.note,
        &w.bare,
        "visible-pair",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let before = describe_record_links_as(&w.db, &reader, &w.bare)
        .await
        .unwrap();
    let hidden_request = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.bare,
        &c,
        "hidden-pair",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let hidden_receipt = commit_provider_as(&w.db, &w.admin, &hidden_request)
        .await
        .unwrap();
    let stream: String = sqlx::query_scalar("SELECT record_id FROM content_events WHERE seq=?")
        .bind(hidden_receipt.event_seq)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert_eq!(stream, hidden_request.aggregate_id);
    assert_ne!(stream, w.bare);
    let after = describe_record_links_as(&w.db, &reader, &w.bare)
        .await
        .unwrap();
    assert_eq!(before["record"], after["record"]);
    assert!(relations_as(&w.db, &reader, &w.bare)
        .await
        .unwrap()
        .is_empty());
    let again = prepare_provider_as(
        &w.db,
        &reader,
        &w.note,
        &w.bare,
        "visible-pair",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    assert_eq!(pending, again);
    commit_provider_as(&w.db, &reader, &pending).await.unwrap();
    w.replay().await;
}

#[tokio::test]
async fn only_aggregate_head_moves_and_specific_conflict_is_event_free() {
    let w = World::fresh().await;
    commit_provider_as(&w.db, &w.admin, &w.prepare("seed").await)
        .await
        .unwrap();
    let request = w.prepare("aggregate-only").await;
    let endpoints = describe_record_links_as(&w.db, &w.admin, &w.note)
        .await
        .unwrap()["record"]
        .clone();
    sqlx::query("UPDATE kernel_provider_state SET head=head+1 WHERE id=?")
        .bind(&request.aggregate_id)
        .execute(w.db.write_pool())
        .await
        .unwrap();
    let count = w.count().await;
    conflict(
        commit_provider_as(&w.db, &w.admin, &request).await,
        "provider aggregate head moved",
    );
    assert_eq!(count, w.count().await);
    assert_eq!(
        endpoints,
        describe_record_links_as(&w.db, &w.admin, &w.note)
            .await
            .unwrap()["record"]
    );
}

#[tokio::test]
async fn non_root_reader_gets_redacted_authors_and_no_folded_prepare_or_retry() {
    let w = World::fresh_with_binding(relates_to_port::HOST_TRANSFORM_BINDING).await;
    let reader = create_principal(&w.db, "account", "Reader", "acct:reader", &w.admin)
        .await
        .unwrap();
    let home = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage"), (&reader, "edit")]),
        &w.admin,
    )
    .await
    .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.note, &home)
        .await
        .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.bare, &home)
        .await
        .unwrap();
    let source = Source {
        source_id: "fixture.legacy-source".into(),
        from: w.note.clone(),
        to: w.bare.clone(),
        claimed_author: Some("fixture.private-author".into()),
        claimed_timestamp: Some("2001-01-01T00:00:00Z".into()),
        note: Some("legacy note".into()),
    };
    let imported = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.note,
        &w.bare,
        "host-transform",
        Command::Assert {
            sources: vec![source],
        },
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &w.admin, &imported)
        .await
        .unwrap();
    let read = relations_as(&w.db, &reader, &w.bare).await.unwrap();
    let assertion = &read[0]["state"]["assertions"][0];
    assert!(assertion["asserted_by"].is_null());
    assert!(assertion["sources"][0]["claimed_author"].is_null());
    assert!(assertion["asserted_seq"].as_i64().unwrap() > 0);
    let request = prepare_provider_as(
        &w.db,
        &reader,
        &w.note,
        &w.bare,
        "reader",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let json = serde_json::to_value(&request).unwrap();
    assert!(json.get("outcome").is_none());
    assert!(!json.to_string().contains("fixture.private-author"));
    assert!(!json.to_string().contains("asserted_by"));
    let receipt = commit_provider_as(&w.db, &reader, &request).await.unwrap();
    assert_eq!(
        uuid::Uuid::parse_str(&receipt.assertion_id)
            .unwrap()
            .get_version_num(),
        4
    );
    let retried = prepare_provider_as(
        &w.db,
        &reader,
        &w.note,
        &w.bare,
        "reader",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    assert_eq!(request, retried);
    assert_eq!(
        receipt,
        commit_provider_as(&w.db, &reader, &retried).await.unwrap()
    );
    let stored: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE seq=?")
        .bind(receipt.event_seq)
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    assert!(!stored.contains("outcome"));
    assert!(!stored.contains("fixture.private-author"));
    w.replay().await;
}

#[tokio::test]
async fn retraction_requires_own_assertion_or_manage_on_eligible_anchor() {
    let w = World::fresh().await;
    let one = create_principal(&w.db, "account", "One", "acct:one", &w.admin)
        .await
        .unwrap();
    let two = create_principal(&w.db, "account", "Two", "acct:two", &w.admin)
        .await
        .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&one, "edit"), (&two, "edit")],
    )
    .await
    .unwrap();
    let request = prepare_provider_as(
        &w.db,
        &one,
        &w.note,
        &w.bare,
        "one",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let receipt = commit_provider_as(&w.db, &one, &request).await.unwrap();
    let command = Command::Retract {
        assertion_id: receipt.assertion_id.clone(),
    };
    let count = w.count().await;
    engine_error(
        prepare_provider_as(&w.db, &two, &w.bare, &w.note, "foreign", command.clone()).await,
        "retraction requires assertion ownership or Manage on the eligible anchor",
    );
    assert_eq!(count, w.count().await);
    let own = prepare_provider_as(&w.db, &one, &w.bare, &w.note, "own", command.clone())
        .await
        .unwrap();
    commit_provider_as(&w.db, &one, &own).await.unwrap();
    let next = prepare_provider_as(
        &w.db,
        &one,
        &w.note,
        &w.bare,
        "next",
        Command::Assert { sources: vec![] },
    )
    .await
    .unwrap();
    let next = commit_provider_as(&w.db, &one, &next).await.unwrap();
    let manage = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.bare,
        &w.note,
        "manage",
        Command::Retract {
            assertion_id: next.assertion_id,
        },
    )
    .await
    .unwrap();
    commit_provider_as(&w.db, &w.admin, &manage).await.unwrap();
    w.replay().await;
}

#[tokio::test]
async fn claimed_author_requires_transform_and_provenance_has_closed_bounds() {
    let w = World::fresh().await;
    let source = Source {
        source_id: "fixture.source".into(),
        from: w.note.clone(),
        to: w.bare.clone(),
        claimed_author: Some(w.admin.clone()),
        claimed_timestamp: Some("2001-01-01T00:00:00Z".into()),
        note: None,
    };
    engine_error(
        prepare_provider_as(
            &w.db,
            &w.admin,
            &w.note,
            &w.bare,
            "forged-author",
            Command::Assert {
                sources: vec![source.clone()],
            },
        )
        .await,
        "claimed provenance authors require the designated host transform principal",
    );
    for invalid in 0..4 {
        let mut source = source.clone();
        source.claimed_author = None;
        match invalid {
            0 => source.source_id = "x".repeat(257),
            1 => source.note = Some("x".repeat(4097)),
            2 => source.claimed_timestamp = Some("not a timestamp".into()),
            _ => source.claimed_timestamp = Some("x".repeat(65)),
        };
        engine_error(
            prepare_provider_as(
                &w.db,
                &w.admin,
                &w.note,
                &w.bare,
                &format!("invalid-{invalid}"),
                Command::Assert {
                    sources: vec![source],
                },
            )
            .await,
            "invalid relationship provenance",
        );
    }
    w.replay().await;
}

#[tokio::test]
async fn recorded_v1_pins_replay_through_retained_catalogue_after_current_advances() {
    use crate::v2_standard::relates_to_v1 as old;
    let w = World::fresh().await;
    let request = w.prepare("fixture.retained-v1").await;
    assert_ne!(request.pins, old::pins());
    let (left, right) = old::pair(&w.note, &w.bare).unwrap();
    let assertion = format!(
        "assertion:{}",
        crate::meta::definition_artifact::digest_artifact_bytes(
            &serde_json::to_vec(&(
                "assertion",
                &[
                    provider::RELATIONSHIP,
                    w.admin.as_str(),
                    "fixture.retained-v1"
                ]
            ))
            .unwrap()
        )
    );
    let folded = old::prepare(
        &old::Command::Assert { sources: vec![] },
        left,
        right,
        &assertion,
        None,
    )
    .unwrap();
    let mut payload = serde_json::to_value(request).unwrap();
    let object = payload.as_object_mut().unwrap();
    object.remove("request_digest");
    object.remove("policy_head");
    object.insert("pins".into(), serde_json::to_value(old::pins()).unwrap());
    object.insert("assertion_id".into(), json!(assertion));
    object.insert("outcome".into(), serde_json::to_value(folded).unwrap());
    let mut tx = w.db.write_pool().begin().await.unwrap();
    // Historical fixture only: an original /1 kernel-issued envelope, not new admission.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown')").bind(uuid::Uuid::new_v4().to_string()).bind(&w.note).bind(commit_port::PROVIDER_OUTCOME_EVENT).bind(payload.to_string()).bind(&w.admin).bind("2026-10-11T00:00:00.000Z").execute(&mut *tx).await.unwrap();
    let events = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap();
    let event = events.last().unwrap();
    project_provider_outcome(&mut tx, event, true)
        .await
        .unwrap();
    record_metadata::touch_event(&mut tx, event).await.unwrap();
    tx.commit().await.unwrap();
    w.replay().await;
    assert_eq!(
        relations_as(&w.db, &w.admin, &w.note).await.unwrap().len(),
        1
    );
    let retract = prepare_provider_as(
        &w.db,
        &w.admin,
        &w.note,
        &w.bare,
        "fixture.retained-v1.retract",
        Command::Retract {
            assertion_id: assertion.clone(),
        },
    )
    .await
    .unwrap();
    let receipt = commit_provider_as(&w.db, &w.admin, &retract).await.unwrap();
    assert_eq!(receipt.assertion_id, assertion);
    w.disable().await;
    w.replay().await;
    let relations = relations_as(&w.db, &w.admin, &w.note).await.unwrap();
    assert_eq!(relations[0]["state"]["assertions"][0]["retracted"], true);
    assert_eq!(
        relations[0]["state"]["assertions"][0]["retracted_seq"],
        receipt.event_seq
    );
    let mut unknown = old::pins();
    unknown.reducer = "fixture.unknown".into();
    engine_error(
        provider::interpreter(&unknown).map(|_| ()),
        "unknown retained provider interpretation pins",
    );
}

#[tokio::test]
async fn directed_reservation_checks_target_and_propagates_integrity_and_storage_errors() {
    let w = World::fresh().await;
    let home = create_home(
        &w.db,
        KERNEL_ROOT_ID,
        Some(&[(&w.admin, "manage")]),
        &w.admin,
    )
    .await
    .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.bare, &home)
        .await
        .unwrap();
    let package = provider::package();
    adopt_package_at(&w.db, &w.admin, &home, &package, None, &[])
        .await
        .unwrap();
    engine_error(
        link_as(&w.db, &w.admin, &w.bare, "relates_to", &w.note).await,
        "relates_to requires the governed provider commit port",
    );
    sqlx::query("UPDATE kernel_package_selections SET event_seq=event_seq+1 WHERE scope_home=? AND namespace=?").bind(KERNEL_ROOT_ID).bind(provider::NAMESPACE).execute(w.db.write_pool()).await.unwrap();
    engine_error(
        link_as(&w.db, &w.admin, &w.bare, "relates_to", &w.note).await,
        "package selection projection disagrees with its authorizing log event",
    );
    let mut tx = w.db.write_pool().begin().await.unwrap();
    sqlx::query("DROP TABLE kernel_package_selections")
        .execute(&mut *tx)
        .await
        .unwrap();
    match links_v2::refuse_governed_directed(&mut tx, &w.bare, &w.note, "relates_to")
        .await
        .unwrap_err()
    {
        Error::Sqlx(sqlx::Error::Database(error)) => {
            assert_eq!(error.message(), "no such table: kernel_package_selections")
        }
        error => panic!("expected missing selection table, got {error:?}"),
    }
}

#[tokio::test]
async fn domain_projector_and_import_routes_cannot_mint_provider_outcomes() {
    use crate::domain_transaction::{EventCursorPort, ProjectorIntent, ProjectorPort};
    use crate::events::{CausalAdmission, CausalEnvelopeV1, CausalFrontierV1, EventRow};
    use crate::portable_sql::ExecutionControl;
    struct NoAppend;
    impl EventCursorPort for NoAppend {
        fn append_event<'a>(
            &'a mut self,
            _: &'a mut EventRow,
            _: &'a CausalAdmission,
            _: &'a ExecutionControl,
        ) -> futures::future::BoxFuture<'a, Result<i64>> {
            Box::pin(async { panic!("generic provider append reached physical storage") })
        }
    }
    impl ProjectorPort for NoAppend {
        fn apply_projector<'a>(
            &'a mut self,
            _: &'a ProjectorIntent,
            _: &'a EventRow,
            _: &'a ExecutionControl,
        ) -> futures::future::BoxFuture<'a, Result<()>> {
            Box::pin(async { panic!("generic provider import reached projection") })
        }
    }
    let w = World::fresh().await;
    let request = w.prepare("seam").await;
    let mut event = EventRow {
        local_seq: -1,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: request.aggregate_id.clone(),
        event_type: commit_port::PROVIDER_OUTCOME_EVENT.into(),
        payload: Some(
            json!({"request":request,"assertion_id":uuid::Uuid::new_v4().to_string()}).to_string(),
        ),
        actor: Some(w.admin.clone()),
        created_at: "2026-10-11T00:00:00Z".into(),
        run_key: None,
        parent_key: None,
        intent: None,
        act: None,
        causal_envelope: CausalEnvelopeV1::legacy_unknown(),
    };
    let count = w.count().await;
    engine_error(
        crate::domain_transaction::append_and_project(
            &mut NoAppend,
            &mut event,
            &ExecutionControl::default(),
        )
        .await,
        "provider outcomes require the sealed kernel commit port",
    );
    let causal = CausalAdmission::GovernedImport(CausalEnvelopeV1::import_incomplete(
        CausalFrontierV1::empty(),
    ));
    engine_error(
        crate::domain_transaction::append_and_project_governed_import(
            &mut NoAppend,
            &mut event,
            &causal,
            &ExecutionControl::default(),
        )
        .await,
        "provider outcomes require the sealed kernel commit port",
    );
    engine_error(
        crate::store::exercise_provider_projector_port(&w.db, &event).await,
        "provider projection requires the kernel-issued logged outcome",
    );
    let mut tx = w.db.write_pool().begin().await.unwrap();
    engine_error(
        crate::store::append_migration_on(
            &mut tx,
            uuid::Uuid::new_v4().to_string(),
            crate::store::AppendSpec {
                record_id: event.record_id,
                event_type: event.event_type,
                payload: serde_json::from_str(event.payload.as_deref().unwrap()).unwrap(),
                actor: event.actor,
            },
            "2026-10-11T00:00:00Z",
        )
        .await,
        "provider outcomes cannot be imported through the generic event seam",
    );
    tx.rollback().await.unwrap();
    assert_eq!(count, w.count().await);
    w.replay().await;
}

#[tokio::test]
async fn request_and_event_size_do_not_grow_with_prior_assertions() {
    let w = World::fresh().await;
    let mut sizes = Vec::new();
    for index in 0..8 {
        let request = w.prepare(&format!("size-{index}")).await;
        let request_json = serde_json::to_value(&request).unwrap();
        assert!(request_json.get("outcome").is_none());
        let receipt = commit_provider_as(&w.db, &w.admin, &request).await.unwrap();
        let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE seq=?")
            .bind(receipt.event_seq)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        assert!(!payload.contains("asserted_by"));
        sizes.push(payload.len());
    }
    assert!(sizes.iter().max().unwrap() - sizes.iter().min().unwrap() < 32);
    assert_eq!(
        relations_as(&w.db, &w.admin, &w.note).await.unwrap()[0]["state"]["assertions"]
            .as_array()
            .unwrap()
            .len(),
        8
    );
    w.replay().await;
}

#[tokio::test]
async fn host_bindings_are_reserved_and_transform_is_kernel_minted() {
    let w = World::fresh().await;
    let before = w.count().await;
    for binding in [
        relates_to_port::HOST_TRANSFORM_BINDING,
        "host:claims:transform",
    ] {
        engine_error(
            create_principal(&w.db, "agent", "Caller forged host", binding, &w.admin).await,
            "host: auth bindings are reserved for kernel-owned principals",
        );
    }
    for event_type in [KERNEL_PRINCIPAL_CREATED_EVENT, HOST_TRANSFORM_CREATED_EVENT] {
        engine_error(crate::store::append(&w.db,crate::store::AppendSpec{record_id:uuid::Uuid::new_v4().to_string(),event_type:event_type.into(),payload:json!({"kind":"agent","display_label":"Forged","auth_binding":relates_to_port::HOST_TRANSFORM_BINDING}),actor:Some(KERNEL_GENESIS_ACTOR.into())}).await,
            "host: auth bindings are reserved for kernel-owned principals");
    }
    engine_error(
        create_v2_database(
            &format!(
                "sqlite://{}",
                w._dir.path().join("forged-genesis.db").display()
            ),
            "account",
            "Forged",
            relates_to_port::HOST_TRANSFORM_BINDING,
        )
        .await,
        "host: auth bindings are reserved for kernel-owned principals",
    );
    let forged = crate::events::EventRow {
        local_seq: -1,
        id: uuid::Uuid::new_v4().to_string(),
        record_id: uuid::Uuid::new_v4().to_string(),
        event_type: KERNEL_PRINCIPAL_CREATED_EVENT.into(),
        payload: Some(json!({"kind":"agent","display_label":"Forged", "auth_binding":relates_to_port::HOST_TRANSFORM_BINDING}).to_string()),
        actor: Some(w.admin.clone()),
        created_at: "2026-10-11T00:00:00Z".into(),
        run_key: None, parent_key: None, intent: None, act: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
    };
    let mut tx = w.db.write_pool().begin().await.unwrap();
    engine_error(
        project_kernel_principal_created(&mut tx, &forged).await,
        "host: auth bindings are reserved for kernel-owned principals",
    );
    tx.rollback().await.unwrap();
    assert_eq!(w.count().await, before);
    let host = resolve_principal_by_binding(&w.db, relates_to_port::HOST_TRANSFORM_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_ne!(host, w.admin);
    let (actor, event_type): (String, String) =
        sqlx::query_as("SELECT actor,type FROM content_events WHERE record_id=?")
            .bind(&host)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    assert_eq!(actor, KERNEL_GENESIS_ACTOR);
    assert_eq!(event_type, HOST_TRANSFORM_CREATED_EVENT);
    // Ordinary root administration still cannot claim source authorship.
    engine_error(
        prepare_provider_as(
            &w.db,
            &w.admin,
            &w.note,
            &w.bare,
            "forged-author",
            Command::Assert {
                sources: vec![Source {
                    source_id: "source".into(),
                    from: w.note.clone(),
                    to: w.bare.clone(),
                    claimed_author: Some("someone-else".into()),
                    claimed_timestamp: Some("2001-01-01T00:00:00Z".into()),
                    note: None,
                }],
            },
        )
        .await,
        "claimed provenance authors require the designated host transform principal",
    );
    w.replay().await;
}

#[tokio::test]
async fn ordinary_provenance_timestamp_is_optional_but_transform_author_requires_it() {
    let w = World::fresh().await;
    let command: Command = serde_json::from_value(
        json!({"Assert":{"sources":[{"source_id":"ordinary","from":w.note,"to":w.bare}]}}),
    )
    .unwrap();
    let request = prepare_provider_as(&w.db, &w.admin, &w.note, &w.bare, "ordinary", command)
        .await
        .unwrap();
    commit_provider_as(&w.db, &w.admin, &request).await.unwrap();
    let read = relations_as(&w.db, &w.admin, &w.note).await.unwrap();
    assert!(read[0]["state"]["assertions"][0]["sources"][0]["claimed_timestamp"].is_null());
    w.replay().await;
    let host = World::fresh_with_binding(relates_to_port::HOST_TRANSFORM_BINDING).await;
    engine_error(
        prepare_provider_as(
            &host.db,
            &host.admin,
            &host.note,
            &host.bare,
            "missing-time",
            Command::Assert {
                sources: vec![Source {
                    source_id: "legacy".into(),
                    from: host.note.clone(),
                    to: host.bare.clone(),
                    claimed_author: Some("claimed".into()),
                    claimed_timestamp: None,
                    note: None,
                }],
            },
        )
        .await,
        "invalid relationship provenance",
    );
}

fn golden_replay(bytes: &str) {
    use super::provider_catalogue::{self as catalogue, FoldInput, StoredState};
    let vector: serde_json::Value = serde_json::from_str(bytes).unwrap();
    let mut current: Option<StoredState> = None;
    for event in vector["events"].as_array().unwrap() {
        let entry = catalogue::recorded(&event["payload"]).unwrap();
        assert_eq!(
            entry.source_sha256,
            vector["source_sha256"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_value((entry.pins)()).unwrap(),
            vector["pins"]
        );
        let decoded = (entry.decode)(&event["payload"]).unwrap();
        let domain = provider::retained::relation_decoded(&decoded).unwrap();
        let request = provider::retained::host_request(&domain).unwrap();
        assert_eq!(request.principal_id, event["actor"].as_str().unwrap());
        if !domain.legacy {
            assert_eq!(
                request.request_digest,
                relates_to_port::request_checksum(&request).unwrap()
            );
        }

        let input = FoldInput {
            decoded: &decoded,
            principal: event["actor"].as_str().unwrap(),
            timestamp: event["created_at"].as_str().unwrap(),
            event_seq: event["seq"].as_i64().unwrap(),
        };
        let folded = (entry.fold)(&input, current.as_ref()).unwrap();
        assert_eq!(
            serde_json::to_string(&folded.state).unwrap(),
            event["state_bytes"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_string(&folded.attribution).unwrap(),
            event["attribution_bytes"].as_str().unwrap()
        );
        let stored = StoredState {
            pins: (entry.pins)(),
            state: folded.state,
            attribution: folded.attribution,
        };
        assert_eq!(
            serde_json::to_string(&stored.view().unwrap()).unwrap(),
            event["view_bytes"].as_str().unwrap()
        );
        current = Some(stored);
    }
}
#[test]
fn retained_v1_golden_event_log_locks_fold_and_state_codec() {
    golden_replay(include_str!("fixtures/relates_to_v1.golden.json"));
}
#[test]
fn retained_v2_golden_event_log_locks_fold_and_state_codec() {
    golden_replay(include_str!("fixtures/relates_to_v2.golden.json"));
}
#[test]
fn retained_v3_golden_event_log_locks_fold_and_state_codec() {
    golden_replay(include_str!("fixtures/relates_to_v3.golden.json"));
}
#[test]
fn retained_source_checksums_and_original_v1_pin_are_immutable() {
    let original = include_str!("../v2_standard/relates_to_v1.original.rs.txt");
    assert_eq!(
        crate::v2_standard::relates_to_v1::pins().provider,
        format!(
            "host.relates-to/1:{}",
            crate::meta::definition_artifact::digest_artifact_bytes(original.as_bytes())
        )
    );
    for entry in super::provider_catalogue::entries() {
        assert_eq!(
            crate::meta::definition_artifact::digest_artifact_bytes(entry.source.as_bytes()),
            entry.source_sha256
        );
        super::provider_catalogue::lookup(&(entry.pins)()).unwrap();
    }
}

#[tokio::test]
async fn recorded_v2_state_keeps_its_codec_until_current_v3_commits() {
    let w = World::fresh().await;
    let mut request = w.prepare("retained-v2").await;
    request.command = Command::Assert {
        sources: vec![Source {
            source_id: "retained-v2-source".into(),
            from: w.note.clone(),
            to: w.bare.clone(),
            claimed_author: None,
            claimed_timestamp: Some("2001-01-01T00:00:00Z".into()),
            note: Some("retained /2 provenance".into()),
        }],
    };
    request.pins = crate::v2_standard::relates_to_v2::pins();
    request.request_digest = relates_to_port::request_checksum(&request).unwrap();
    let payload = json!({"request":request,"assertion_id":"33333333-3333-4333-8333-333333333333"});
    let mut tx = w.db.write_pool().begin().await.unwrap();
    // Historical kernel-issued /2 fixture only, not new admission.
    sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown')").bind(uuid::Uuid::new_v4().to_string()).bind(&request.aggregate_id).bind(commit_port::PROVIDER_OUTCOME_EVENT).bind(payload.to_string()).bind(&w.admin).bind("2026-10-11T00:00:00Z").execute(&mut *tx).await.unwrap();
    let log = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap();
    project_provider_outcome(&mut tx, log.last().unwrap(), true)
        .await
        .unwrap();
    record_metadata::touch_event(&mut tx, log.last().unwrap())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let state: String =
        sqlx::query_scalar("SELECT state_json FROM kernel_provider_state WHERE id=?")
            .bind(&request.aggregate_id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    let state: super::provider_catalogue::StoredState = serde_json::from_str(&state).unwrap();
    assert_eq!(state.pins, crate::v2_standard::relates_to_v2::pins());
    assert_eq!(
        state.view().unwrap()["assertions"][0]["sources"][0]["claimed_timestamp"],
        "2001-01-01T00:00:00Z"
    );
    w.replay().await;
    let next = w.prepare("current-v3").await;
    commit_provider_as(&w.db, &w.admin, &next).await.unwrap();
    let state: String =
        sqlx::query_scalar("SELECT state_json FROM kernel_provider_state WHERE id=?")
            .bind(&request.aggregate_id)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    let state: super::provider_catalogue::StoredState = serde_json::from_str(&state).unwrap();
    assert_eq!(state.pins, provider::pins());
    assert_eq!(
        state.view().unwrap()["assertions"][0]["sources"][0]["note"],
        "retained /2 provenance"
    );
    assert_eq!(
        state.view().unwrap()["assertions"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    w.replay().await;
}

// Local catalogue only: this counter is not installed or admitted as a product provider.
mod neutral_fixture {
    use super::*;
    use crate::kernel::provider_catalogue::{
        self as catalogue, Decoded, Entry, FoldInput, Folded, ProjectionFacts, StoredState,
    };
    use serde::{Deserialize, Serialize};

    const SOURCE: &str = "test-only counter interpreter/1";
    fn package() -> crate::package_manifest::PackageManifest {
        let mut package = v2_standard::document_package();
        package.namespace = "fixture.catalogue".into();
        package.name = "counter".into();
        package.version = 1;
        let definition = &mut package.definitions[0];
        definition.family = "fixture.catalogue.counter".into();
        definition.artifact_bytes = definition
            .artifact_bytes
            .replace("native.standard.document", &definition.family);
        definition.digest = crate::meta::definition_artifact::digest_artifact_bytes(
            definition.artifact_bytes.as_bytes(),
        );
        package
    }
    fn pins() -> InterpretationPins {
        let package = package();
        let identity = package.identity().unwrap();
        let definition = &package.definitions[0];
        InterpretationPins {
            package: PackageSelection {
                namespace: identity.namespace,
                name: identity.name,
                version: identity.version,
                digest: identity.digest,
            },
            relationship: RevisionIdentity {
                family: definition.family.clone(),
                version: definition.version,
                digest: definition.digest.clone(),
            },
            provider: "fixture.counter/1".into(),
            decoder: "fixture.counter.payload/1".into(),
            reducer: "fixture.counter.fold/1".into(),
            payload_version: 1,
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Counter {
        count: i64,
    }
    fn decode(payload: &serde_json::Value) -> Result<Decoded> {
        let delta = payload["delta"]
            .as_i64()
            .ok_or_else(|| Error::engine("invalid counter delta"))?;
        Ok(Decoded {
            facts: ProjectionFacts {
                pins: serde_json::from_value(payload["pins"].clone())?,
                stream_id: "fixture.counter.stream".into(),
                aggregate_id: "fixture.counter.aggregate".into(),
                provider_key: "fixture.counter".into(),
                subjects: vec![
                    "subject-one".into(),
                    "subject-two".into(),
                    "subject-three".into(),
                ],
                principal: "fixture.counter.actor".into(),
                operation: "fixture.increment".into(),
                operation_key: payload["key"].as_str().unwrap().into(),
                receipt_id: format!("receipt:{}", payload["key"].as_str().unwrap()),
                receipt_request: json!({"delta":delta}),
            },
            domain: json!(delta),
        })
    }
    fn validate<'a>(
        _: &'a mut sqlx::SqliteConnection,
        _: &'a crate::events::EventRow,
        _: &'a Decoded,
        replay: bool,
    ) -> catalogue::ValidationFuture<'a> {
        Box::pin(async move {
            if !replay {
                return Err(Error::engine("fixture is replay-only"));
            }
            Ok(())
        })
    }
    fn fold(input: &FoldInput<'_>, previous: Option<&StoredState>) -> Result<Folded> {
        let count = previous
            .map(|s| serde_json::from_value::<Counter>(s.state.clone()))
            .transpose()?
            .map_or(0, |s| s.count);
        Ok(Folded {
            state: serde_json::to_value(Counter {
                count: count + input.decoded.domain.as_i64().unwrap(),
            })?,
            attribution: json!({"by":input.principal,"at":input.timestamp,"seq":input.event_seq}),
        })
    }
    fn codec(state: &StoredState) -> Result<serde_json::Value> {
        let counter: Counter = serde_json::from_value(state.state.clone())?;
        Ok(json!({"total":counter.count}))
    }
    fn fixture_admit<'a>(
        _: &'a mut sqlx::SqliteConnection,
        _: &'a EventRow,
    ) -> crate::kernel::provider_catalogue::ValidationFuture<'a> {
        Box::pin(async { Ok(()) })
    }
    fn entry() -> Entry {
        Entry {
            admit: fixture_admit,
            pins,
            package,
            source: SOURCE,
            source_sha256: "e5d9e89e7e281e3fde36b69aee73a3dc5d20a0a90e23b98cabf693dbca548362",
            validate_recorded: validate,
            decode,
            fold,
            state_codec: codec,
            link_read: None,
        }
    }
    fn other_pins() -> InterpretationPins {
        let mut pins = pins();
        pins.provider = "fixture.other/1".into();
        pins.decoder = "fixture.other.payload/1".into();
        pins.reducer = "fixture.other.fold/1".into();
        pins
    }
    fn other_decode(payload: &serde_json::Value) -> Result<Decoded> {
        let mut decoded = decode(payload)?;
        decoded.facts.provider_key = "fixture.other".into();
        Ok(decoded)
    }
    fn changed_subjects_decode(payload: &serde_json::Value) -> Result<Decoded> {
        let mut decoded = decode(payload)?;
        decoded.facts.subjects[0] = "replacement-subject".into();
        Ok(decoded)
    }
    fn must_not_fold(_: &FoldInput<'_>, _: Option<&StoredState>) -> Result<Folded> {
        panic!("aggregate identity refusal must precede folding")
    }
    #[derive(Debug, PartialEq, Eq)]
    struct ProjectionSnapshot {
        states: Vec<(String, String, String, String, i64)>,
        subjects: Vec<(String, String)>,
        receipts: Vec<(String, String, String, String, String, i64)>,
    }
    async fn snapshot(conn: &mut sqlx::SqliteConnection) -> ProjectionSnapshot {
        ProjectionSnapshot {
            states: sqlx::query_as("SELECT id,provider_key,subjects_json,state_json,head FROM kernel_provider_state ORDER BY id").fetch_all(&mut *conn).await.unwrap(),
            subjects: sqlx::query_as("SELECT subject_id,aggregate_id FROM kernel_provider_subjects ORDER BY subject_id,aggregate_id").fetch_all(&mut *conn).await.unwrap(),
            receipts: sqlx::query_as("SELECT principal_id,operation,operation_key,request_json,assertion_id,event_seq FROM kernel_provider_receipts ORDER BY principal_id,operation,operation_key").fetch_all(&mut *conn).await.unwrap(),
        }
    }
    async fn aggregate_refusal_is_atomic(mut refused: Entry, expected: &str) {
        let w = World::fresh().await;
        let mut tx = w.db.write_pool().begin().await.unwrap();
        let entries = [entry(), {
            refused.fold = must_not_fold;
            refused
        }];
        let mut original = None;
        for (index, key) in [(0, "initial"), (1, "refused")] {
            let payload = json!({"pins":(entries[index].pins)(),"delta":3,"key":key});
            assert!(catalogue::lookup(&(entries[index].pins)()).is_err());
            // Use a local catalogue with only this fixture interpreter. Both
            // outcomes satisfy the recorded pin and immutable log checks.
            let selected = catalogue::recorded_in(&payload, &entries[index..=index]).unwrap();
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown')")
                .bind(uuid::Uuid::new_v4().to_string()).bind("fixture.counter.stream").bind(commit_port::PROVIDER_OUTCOME_EVENT).bind(payload.to_string()).bind("fixture.counter.actor").bind("2026-10-11T00:00:00Z").execute(&mut *tx).await.unwrap();
            let events = crate::conformance::rebuild::read_all_events(&mut tx)
                .await
                .unwrap();
            let result = commit_port::project_with_entry(
                &mut tx,
                events.last().unwrap(),
                true,
                selected,
                &payload,
            )
            .await;
            if index == 0 {
                result.unwrap();
                original = Some(snapshot(&mut tx).await);
            } else {
                engine_error(result, expected);
                assert_eq!(snapshot(&mut tx).await, *original.as_ref().unwrap());
            }
        }
        // Committing the surrounding transaction proves refusal needs no
        // rollback to avoid partial state/head, subject-index or receipt writes.
        tx.commit().await.unwrap();
        let mut conn = w.db.write_pool().acquire().await.unwrap();
        assert_eq!(snapshot(&mut conn).await, original.unwrap());
    }
    #[tokio::test]
    async fn different_provider_cannot_overwrite_existing_aggregate() {
        let mut other = entry();
        other.pins = other_pins;
        other.decode = other_decode;
        aggregate_refusal_is_atomic(other, "provider aggregate identity mismatch").await;
    }
    #[tokio::test]
    async fn changed_subjects_cannot_mutate_existing_aggregate() {
        let mut changed = entry();
        changed.decode = changed_subjects_decode;
        aggregate_refusal_is_atomic(changed, "provider aggregate subjects mismatch").await;
    }
    #[tokio::test]
    async fn non_relation_recorded_decoder_fold_codec_and_shared_storage() {
        let w = World::fresh().await;
        let entries = [entry()];
        assert!(
            catalogue::lookup(&pins()).is_err(),
            "fixture must not enter supported catalogue"
        );
        catalogue::lookup_in(&pins(), &entries).unwrap();
        let mut damaged = entry();
        damaged.source = "changed source";
        engine_error(
            catalogue::lookup_in(&pins(), &[damaged]).map(|_| ()),
            "retained interpreter source checksum mismatch",
        );

        let mut tx = w.db.write_pool().begin().await.unwrap();
        for (key, delta) in [("first", 3), ("second", 5)] {
            let payload = json!({"pins":pins(),"delta":delta,"key":key});
            let entry = catalogue::recorded_in(&payload, &entries).unwrap();
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,?,?,?,?,1,'legacy_unknown')")
                .bind(uuid::Uuid::new_v4().to_string()).bind("fixture.counter.stream").bind(commit_port::PROVIDER_OUTCOME_EVENT).bind(payload.to_string()).bind("fixture.counter.actor").bind("2026-10-11T00:00:00Z").execute(&mut *tx).await.unwrap();
            let events = crate::conformance::rebuild::read_all_events(&mut tx)
                .await
                .unwrap();
            let event = events.last().unwrap();
            commit_port::project_with_entry(&mut tx, event, true, entry, &payload)
                .await
                .unwrap();
            let mut forged = event.clone();
            forged.actor = Some("forged".into());
            engine_error(
                commit_port::project_with_entry(&mut tx, &forged, true, entry, &payload).await,
                "provider projection requires the kernel-issued logged outcome",
            );
        }
        let raw: String = sqlx::query_scalar(
            "SELECT state_json FROM kernel_provider_state WHERE id='fixture.counter.aggregate'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        let state: StoredState = serde_json::from_str(&raw).unwrap();
        assert_eq!(state.pins, pins());
        assert_eq!(state.state, json!({"count":8}));
        assert_eq!(
            (entries[0].state_codec)(&state).unwrap(),
            json!({"total":8})
        );
        assert!(
            state.view().is_err(),
            "production reads cannot interpret the fixture"
        );
        let subjects: Vec<String> = sqlx::query_scalar("SELECT subject_id FROM kernel_provider_subjects WHERE aggregate_id='fixture.counter.aggregate' ORDER BY subject_id").fetch_all(&mut *tx).await.unwrap();
        assert_eq!(subjects, ["subject-one", "subject-three", "subject-two"]);
        let receipts: Vec<(String, String, String)> = sqlx::query_as("SELECT operation,assertion_id,request_json FROM kernel_provider_receipts WHERE principal_id='fixture.counter.actor' ORDER BY operation_key").fetch_all(&mut *tx).await.unwrap();
        assert_eq!(
            receipts,
            [
                (
                    "fixture.increment".into(),
                    "receipt:first".into(),
                    "{\"delta\":3}".into()
                ),
                (
                    "fixture.increment".into(),
                    "receipt:second".into(),
                    "{\"delta\":5}".into()
                )
            ]
        );
        let ambiguous = json!({"pins":pins(),"request":{"pins":pins()}});
        engine_error(
            catalogue::recorded_in(&ambiguous, &entries).map(|_| ()),
            "missing or ambiguous recorded provider pins",
        );
        let mut changed = pins();
        changed.reducer = "unknown".into();
        engine_error(
            catalogue::lookup_in(&changed, &entries).map(|_| ()),
            "unknown retained provider interpretation pins",
        );
        tx.rollback().await.unwrap();
    }
}

#[tokio::test]
async fn provider_link_read_projection_preparation_readiness_and_replay() {
    let w = World::fresh().await;
    let request = w.prepare("read-projection").await;
    commit_provider_as(&w.db, &w.admin, &request).await.unwrap();
    verify_v2_ready(&w.db).await.unwrap();
    let expected = projection_dump::dump(&w.db).await.unwrap();
    for table in [
        "kernel_provider_link_meta",
        "kernel_provider_link_heads",
        "kernel_provider_link_rows",
    ] {
        assert!(expected
            .tables
            .iter()
            .any(|t| t.name == table && t.rows > 0));
    }
    for index in [
        "idx_kernel_provider_link_identity",
        "idx_kernel_provider_state_heads",
        "idx_kernel_provider_link_coverage",
        "idx_kernel_event_birth",
        "idx_kernel_read_type",
        "idx_kernel_read_kind",
    ] {
        sqlx::query(&format!("DROP INDEX {index}"))
            .execute(w.db.write_pool())
            .await
            .unwrap();
        assert!(verify_v2_ready(&w.db).await.is_err(), "{index}");
        prepare_v2_database(&w.db).await.unwrap();
        assert_eq!(projection_dump::dump(&w.db).await.unwrap(), expected);
    }
    // These rows also feed the N1 delta digest; corrupting one must alter it.
    sqlx::query("UPDATE kernel_provider_link_heads SET head=head+1")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert_ne!(
        projection_dump::dump(&w.db).await.unwrap().sha256,
        expected.sha256
    );
    assert!(verify_v2_ready(&w.db).await.is_err());
    prepare_v2_database(&w.db).await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), expected);
    sqlx::query("DELETE FROM kernel_provider_link_rows WHERE ordinal=0")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(verify_v2_ready(&w.db).await.is_err());
    prepare_v2_database(&w.db).await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), expected);
    sqlx::query("DELETE FROM kernel_provider_link_heads")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(verify_v2_ready(&w.db).await.is_err());
    prepare_v2_database(&w.db).await.unwrap();
    sqlx::query("UPDATE kernel_provider_link_meta SET version=0")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(verify_v2_ready(&w.db).await.is_err());
    prepare_v2_database(&w.db).await.unwrap();
    sqlx::query("DROP TABLE kernel_provider_link_rows")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    assert!(verify_v2_ready(&w.db).await.is_err());
    prepare_v2_database(&w.db).await.unwrap();
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), expected);
    w.replay().await;
    assert_eq!(projection_dump::dump(&w.db).await.unwrap(), expected);
    w.db.close().await;
}
