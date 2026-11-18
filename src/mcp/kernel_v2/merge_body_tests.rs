//! KernelV2 `merge_body` (design section 7). Every test drives the real tool
//! through the registry on a v2 database; the flag is the thread-scoped test
//! override, so tests do not touch process state.
use super::*;
use crate::body_merge_flag::{scoped, BodyMergeConfig, ScopedConfig};
use crate::coedit::{
    live::{kernel_writes, OpenRequest},
    PeerKind,
};
use crate::events::KERNEL_ROOT_ID;
use crate::mcp::registry::ToolRegistry;

#[derive(Clone)]
struct World {
    db: Db,
    admin: String,
    home: String,
    admin_caller: Caller,
    viewer_caller: Caller,
}

async fn world() -> World {
    let (db, admin) = kernel::create_v2_database(":memory:", "account", "Admin", "acct:admin")
        .await
        .unwrap();
    kernel::prepare_v2_database(&db).await.unwrap();
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
    let host = kernel::resolve_principal_by_binding(&db, kernel::HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let manifest: Value = serde_json::from_str(crate::meta::kind::CORE_KIND_MANIFEST_JSON).unwrap();
    let mut rows = Vec::new();
    for typ in ["Document", "WorkItem"] {
        rows.push((
            "vocabularies",
            json!({"id":format!("voc:kind:{typ}"),"name":format!("kind:{typ}")}),
        ));
        for entry in manifest["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["type"] == typ)
        {
            rows.push(("vocabulary_values", json!({"id":entry["value_id"], "vocabulary_id":format!("voc:kind:{typ}"), "value":entry["token"], "status":"active", "gloss":null,"ordinal":0,"terminality":"open","metadata":entry["metadata"].to_string(),"alias_of":null})));
        }
    }
    let rows = rows
        .into_iter()
        .map(|(section, row)| kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: row["id"].as_str().unwrap().into(),
            origin: "merge-body-proof".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: "2026-10-28T00:00:00Z".into(),
            snapshot: json!({}),
        })
        .collect::<Vec<_>>();
    kernel::v1_state::import_state_batch_as(&db, &host, &rows)
        .await
        .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&viewer, "view")]), &admin)
        .await
        .unwrap();
    World {
        db,
        admin,
        home,
        admin_caller: Caller::authenticated("acct:admin"),
        viewer_caller: Caller::authenticated("acct:viewer"),
    }
}

async fn record_in(w: &World, home: &str, body: &str) -> String {
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"note","title":"Merge target"}).to_string(),
        home,
    )
    .await
    .unwrap();
    set_body(w, &id, body).await;
    id
}
async fn record(w: &World, body: &str) -> String {
    record_in(w, &w.home.clone(), body).await
}
/// An ordinary body write by someone else, through the same tool surface.
async fn set_body(w: &World, id: &str, body: &str) {
    let revision = kernel::read_record_as(&w.db, &w.admin, id)
        .await
        .unwrap()
        .unwrap()
        .revision;
    kernel::set_body_as(&w.db, &w.admin, id, body, revision)
        .await
        .unwrap();
}

fn registry() -> ToolRegistry {
    let mut tools = ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut tools).unwrap();
    crate::mcp::tools::register_surface_tools(&mut tools).unwrap();
    register_kernel_v2_tools(&mut tools).unwrap();
    tools
}
async fn call_as(w: &World, caller: &Caller, args: Value) -> Result<Value> {
    registry()
        .call_engine(
            EngineHandle::KernelV2(w.db.clone()),
            caller.clone(),
            "merge_body",
            args,
        )
        .await
}
async fn merge(w: &World, args: Value) -> Result<Value> {
    call_as(w, &w.admin_caller.clone(), args).await
}
fn intent(id: &str, base_version: &str, base: &str, mine: &str, key: &str) -> Value {
    json!({"record_id":id,"base_version":base_version,"base_text":base,"my_text":mine,
        "reason":"held edit","idempotency_key":key})
}
fn on() -> ScopedConfig {
    scoped(BodyMergeConfig {
        enabled: true,
        accounts: None,
    })
}

async fn head(w: &World, id: &str) -> i64 {
    sqlx::query_scalar("SELECT COALESCE(MAX(seq),0) FROM content_events WHERE record_id=?")
        .bind(id)
        .fetch_one(w.db.pool())
        .await
        .unwrap()
}
async fn version(w: &World, id: &str) -> String {
    format!("rec:{}", head(w, id).await)
}
async fn total_events(w: &World) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap()
}
async fn receipt_rows(w: &World) -> i64 {
    // Current preparation creates the ledger even when empty; older fixtures
    // may lack it. In either case a refusal must leave no keyed outcome.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='kernel_mcp_write_receipts')",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    if !exists {
        return 0;
    }
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_mcp_write_receipts WHERE operation='merge_body'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap()
}
// Assert the additional canonical recovery fact explicitly; global event
// counts below still detect every unexpected refusal, rollback or replay write.
async fn assert_carried_receipt(w: &World, key: &str, expected: &Value, output: Option<i64>) {
    let rows: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT seq,act,payload FROM content_events WHERE record_id='kernel:mcp-write-receipts' \
         AND type='kernel.mcp_write_receipt_recorded.v1' AND actor=? \
         AND json_extract(payload,'$.operation')='merge_body' \
         AND json_extract(payload,'$.operation_key')=?",
    )
    .bind(&w.admin)
    .bind(key)
    .fetch_all(w.db.pool())
    .await
    .unwrap();
    assert_eq!(rows.len(), 1, "one recovery fact per accepted key");
    let (seq, act, raw) = &rows[0];
    assert!(*act > 0);
    let fact: Value = serde_json::from_str(raw).unwrap();
    let stored: Value = serde_json::from_str(fact["receipt_json"].as_str().unwrap()).unwrap();
    let ledger: String = sqlx::query_scalar("SELECT receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='merge_body' AND operation_key=?")
        .bind(&w.admin).bind(key).fetch_one(w.db.pool()).await.unwrap();
    assert_eq!(
        fact["receipt_json"].as_str().unwrap(),
        ledger,
        "canonical carriage preserves the full stored response bytes"
    );
    let mut outward = stored;
    crate::mcp::counter_fence::withhold_receipt_acts("merge_body", &mut outward);
    let mut operation_receipt = expected.clone();
    // Registry run correlation is not part of the stored operation response.
    operation_receipt
        .as_object_mut()
        .unwrap()
        .remove("run_context");
    assert_eq!(
        outward, operation_receipt,
        "the full operation response preserves the existing caller counter fence"
    );
    if let Some(output) = output {
        let output_act: i64 = sqlx::query_scalar("SELECT act FROM content_events WHERE seq=?")
            .bind(output)
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        assert_eq!(
            *act, output_act,
            "body effect and receipt fact share one act"
        );
        assert!(*seq > output);
    }
}

async fn body_at(w: &World, id: &str, seq: i64) -> String {
    let mut conn = w.db.pool().acquire().await.unwrap();
    kernel::historical::body_at_on(&mut conn, &w.admin, id, seq)
        .await
        .unwrap()
        .unwrap()
}
fn seq_of(token: &Value) -> i64 {
    token
        .as_str()
        .unwrap()
        .strip_prefix("rec:")
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn the_tool_is_listed_with_a_v2_handler_and_is_a_keyed_mutation() {
    let tools = registry();
    let spec = tools.get("merge_body").expect("descriptor registered");
    assert_eq!(spec.name, "merge_body");
    assert!(spec.input_schema["properties"]["idempotency_key"].is_object());
    let args = intent("r", "rec:1", "a", "b", "k");
    assert_eq!(
        tools
            .registered_operation_access("merge_body", &args)
            .unwrap(),
        crate::mcp::OperationAccess::Mutation
    );
}

#[tokio::test]
async fn a_missing_key_and_an_unknown_argument_are_refused_by_name() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a").await;
    let base = version(&w, &id).await;
    let mut keyless = intent(&id, &base, "a", "b", "k");
    keyless.as_object_mut().unwrap().remove("idempotency_key");
    let error = merge(&w, keyless).await.unwrap_err();
    assert!(error.to_string().contains("idempotency_key"), "{error}");
    let mut extra = intent(&id, &base, "a", "b", "k");
    extra["sources"] = json!([]);
    let error = merge(&w, extra).await.unwrap_err();
    assert!(error.to_string().contains("sources"), "{error}");
    assert_eq!(receipt_rows(&w).await, 0);
}

#[tokio::test]
async fn flag_off_refuses_with_no_work_no_event_and_no_receipt() {
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    let before = total_events(&w).await;
    // Unset: off for everyone, and an authorised caller is the one refused.
    let refused = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "k1"))
        .await
        .unwrap();
    assert_eq!(refused["outcome"], "refused");
    assert_eq!(refused["reason"], "feature_not_enabled");
    assert_eq!(refused["error_code"], "BODY_MERGE_NOT_ENABLED");
    assert_eq!(refused["retryable"], true);
    assert_eq!(refused["applied"], false);
    assert_eq!(total_events(&w).await, before);
    assert_eq!(receipt_rows(&w).await, 0);
    // The refusal was never stored under the key: once the flag is on, the same
    // key evaluates afresh.
    let _on = on();
    let merged = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "k1"))
        .await
        .unwrap();
    assert_eq!(merged["outcome"], "merged");
    assert_eq!(merged["result"]["body"], "a\n\nB\n");
}

#[tokio::test]
async fn the_allowlist_limits_the_flag_and_an_empty_one_refuses_everyone() {
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    {
        let _other = scoped(BodyMergeConfig {
            enabled: true,
            accounts: Some(vec!["acct:somebody-else".into()]),
        });
        let refused = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "k"))
            .await
            .unwrap();
        assert_eq!(refused["reason"], "feature_not_enabled");
    }
    {
        let _none = scoped(BodyMergeConfig {
            enabled: true,
            accounts: Some(vec![]),
        });
        let refused = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "k"))
            .await
            .unwrap();
        assert_eq!(refused["reason"], "feature_not_enabled");
    }
    let listed = scoped(BodyMergeConfig {
        enabled: true,
        accounts: Some(vec!["acct:admin".into()]),
    });
    let merged = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "k"))
        .await
        .unwrap();
    assert_eq!(merged["outcome"], "merged");
    drop(listed);
    // A result already produced is returned after the account leaves the list.
    let _off = scoped(BodyMergeConfig::default());
    let replayed = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "k"))
        .await
        .unwrap();
    assert_eq!(replayed, merged);
}

#[tokio::test]
async fn a_clean_merge_appends_one_body_event_and_returns_its_exact_pairing() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    // Somebody else edits the other paragraph first.
    set_body(&w, &id, "A\n\nb\n").await;
    let events_before = total_events(&w).await;
    let receipt = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "clean"))
        .await
        .unwrap();
    assert_eq!(receipt["outcome"], "merged");
    assert_eq!(receipt["applied"], true);
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["merged_offline"], true);
    assert_eq!(receipt["base"]["verified"], true);
    assert_eq!(receipt["result"]["body"], "A\n\nB\n");
    assert_eq!(
        receipt["write_receipt"]["event"]["event_type"],
        "kernel.body_set.v1"
    );
    // One plain body_set plus its canonical private recovery fact.
    assert_eq!(total_events(&w).await, events_before + 2);
    let last: (String, i64) = sqlx::query_as(
        "SELECT type,seq FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&id)
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    assert_eq!(last.0, "kernel.body_set.v1");
    assert_carried_receipt(&w, "clean", &receipt, Some(last.1)).await;
    // The version is that event's, and the body folded at it is the body sent.
    assert_eq!(seq_of(&receipt["result"]["version"]), last.1);
    assert_eq!(version(&w, &id).await, receipt["result"]["version"]);
    let text = crate::mcp::render::render("merge_body", &receipt).unwrap();
    for field in ["version", "body_digest"] {
        let expected = receipt["result"][field].as_str().unwrap();
        assert!(
            text.split_whitespace().any(|part| part == expected),
            "merge_body omitted {field}:\n{text}"
        );
    }
    assert_eq!(body_at(&w, &id, last.1).await, "A\n\nB\n");
    assert_eq!(
        receipt["result"]["body_digest"],
        crate::mcp::tools::lifecycle::body_digest(Some("A\n\nB\n"))
    );
}

#[tokio::test]
async fn clash_only_and_unchanged_merges_write_nothing_and_replay_after_the_base_is_restored() {
    let _on = on();
    let w = world().await;
    // The abc / axc / ayc case.
    let id = record(&w, "abc").await;
    let base = version(&w, &id).await;
    set_body(&w, &id, "ayc").await;
    let before = total_events(&w).await;
    let clash_head = head(&w, &id).await;
    let clash = merge(&w, intent(&id, &base, "abc", "axc", "clash"))
        .await
        .unwrap();
    assert_eq!(clash["outcome"], "merged_with_clashes");
    assert_eq!(clash["applied_hunks"], 0);
    assert_eq!(clash["result"]["body"], "ayc");
    assert_eq!(clash["unmerged"][0]["id"], "u1");
    assert_eq!(clash["unmerged"][0]["theirs"], "y");
    assert!(clash.get("write_receipt").is_none(), "nothing was appended");
    assert_eq!(
        total_events(&w).await,
        before + 1,
        "only the private recovery fact is appended"
    );
    assert_eq!(head(&w, &id).await, clash_head, "clash has no body effect");
    assert_carried_receipt(&w, "clash", &clash, None).await;

    // Nothing to carry over: the person changed nothing.
    let unchanged_id = record(&w, "abc").await;
    let unchanged_base = version(&w, &unchanged_id).await;
    set_body(&w, &unchanged_id, "abcd").await;
    let before = total_events(&w).await;
    let unchanged_head = head(&w, &unchanged_id).await;
    let unchanged = merge(
        &w,
        intent(&unchanged_id, &unchanged_base, "abc", "abc", "unchanged"),
    )
    .await
    .unwrap();
    assert_eq!(unchanged["outcome"], "merged");
    assert_eq!(unchanged["changed"], false);
    assert_eq!(unchanged["result"]["body"], "abcd");
    assert_eq!(
        total_events(&w).await,
        before + 1,
        "only the private recovery fact is appended"
    );
    assert_eq!(
        head(&w, &unchanged_id).await,
        unchanged_head,
        "unchanged merge has no body effect"
    );
    assert!(unchanged.get("write_receipt").is_none());
    assert_carried_receipt(&w, "unchanged", &unchanged, None).await;
    assert_eq!(receipt_rows(&w).await, 2);

    // Another writer restores the base text. A replay that re-merged against
    // the current text would now find a clean merge and apply it on a replay.
    set_body(&w, &id, "abc").await;
    set_body(&w, &unchanged_id, "abc").await;
    let before = total_events(&w).await;
    let clash_again = merge(&w, intent(&id, &base, "abc", "axc", "clash"))
        .await
        .unwrap();
    assert_eq!(clash_again, clash);
    let unchanged_again = merge(
        &w,
        intent(&unchanged_id, &unchanged_base, "abc", "abc", "unchanged"),
    )
    .await
    .unwrap();
    assert_eq!(unchanged_again, unchanged);
    assert_eq!(total_events(&w).await, before, "a replay writes nothing");
}

#[tokio::test]
async fn a_committed_merge_replays_verbatim_even_after_later_writes() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    let first = merge(&w, intent(&id, &base, "a\n\nb\n", "A\n\nb\n", "once"))
        .await
        .unwrap();
    set_body(&w, &id, "totally different").await;
    let before = total_events(&w).await;
    let again = merge(&w, intent(&id, &base, "a\n\nb\n", "A\n\nb\n", "once"))
        .await
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(total_events(&w).await, before);
}

#[tokio::test]
async fn an_unverifiable_base_is_refused_and_nothing_is_written() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "one").await;
    let good = version(&w, &id).await;
    set_body(&w, &id, "two").await;
    let current = version(&w, &id).await;
    let other = record(&w, "other body").await;
    let other_version = version(&w, &other).await;
    let before = total_events(&w).await;

    let refuse = |label: &'static str, args: Value| {
        let w = w.clone();
        async move {
            let result = merge(&w, args).await.unwrap();
            assert_eq!(result["outcome"], "refused", "{label}: {result}");
            assert_eq!(result["reason"], "base_unverified", "{label}");
            assert_eq!(result["retryable"], false, "{label}");
        }
    };
    // Digest mismatch on a genuine token.
    refuse("wrong digest", intent(&id, &good, "not one", "x", "k1")).await;
    // A fabricated future seq whose folded text would equal the current body.
    let future = format!("rec:{}", seq_of(&json!(current)) + 100);
    refuse("future seq", intent(&id, &future, "two", "x", "k2")).await;
    // Another record's seq, with that record's text and with this record's.
    refuse(
        "foreign seq, foreign text",
        intent(&id, &other_version, "other body", "x", "k3"),
    )
    .await;
    refuse(
        "foreign seq, current text",
        intent(&id, &other_version, "two", "x", "k4"),
    )
    .await;
    // Not a token at all, and the kit's provisional shape.
    for (n, token) in ["", "rec:0", "7", "rec:-1", "local:3"]
        .into_iter()
        .enumerate()
    {
        refuse(
            "malformed",
            intent(&id, token, "one", "x", &format!("m{n}")),
        )
        .await;
    }
    assert_eq!(total_events(&w).await, before);
    assert_eq!(receipt_rows(&w).await, 0, "refusals are never stored");
    // A genuine token with the matching text is verified, and merges.
    let merged = merge(&w, intent(&id, &good, "one", "one!", "k5"))
        .await
        .unwrap();
    assert_ne!(merged["outcome"], "refused", "{merged}");
    assert_eq!(merged["base"]["verified"], true);
}

#[tokio::test]
async fn the_caller_needs_edit_and_a_hidden_or_unknown_record_reads_as_missing() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a").await;
    let base = version(&w, &id).await;
    let before = total_events(&w).await;
    // The viewer can see the record but not edit it.
    let denied = call_as(
        &w,
        &w.viewer_caller.clone(),
        intent(&id, &base, "a", "b", "v"),
    )
    .await
    .unwrap();
    assert_eq!(denied["reason"], "not_permitted");
    // A private record is invisible to the viewer, as a missing one is.
    let private_home = kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[]), &w.admin)
        .await
        .unwrap();
    let private = record_in(&w, &private_home, "secret").await;
    let private_base = version(&w, &private).await;
    let hidden = call_as(
        &w,
        &w.viewer_caller.clone(),
        intent(&private, &private_base, "secret", "x", "h"),
    )
    .await
    .unwrap();
    let before = before + 2; // the private record's own creation events
    let unknown = merge(
        &w,
        intent(
            "00000000-0000-4000-8000-00000000dead",
            "rec:1",
            "a",
            "b",
            "u",
        ),
    )
    .await
    .unwrap();
    assert_eq!(hidden["reason"], "record_missing");
    assert_eq!(unknown["reason"], "record_missing");
    assert_eq!(hidden["message"], unknown["message"]);
    assert_eq!(receipt_rows(&w).await, 0);
    assert!(total_events(&w).await <= before + 2);
    assert_eq!(head(&w, &id).await, seq_of(&json!(base)));
}

#[tokio::test]
async fn a_message_comment_or_artifact_is_not_a_text_body() {
    let _on = on();
    let w = world().await;
    let id = kernel::create_json_as(
        &w.db,
        &w.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &json!({"v1_type":"Document","v1_kind":"artifact","title":"Board"}).to_string(),
        &w.home,
    )
    .await
    .unwrap();
    let base = version(&w, &id).await;
    let refused = merge(&w, intent(&id, &base, "", "x", "art")).await.unwrap();
    assert_eq!(refused["reason"], "record_not_text");
    assert_eq!(receipt_rows(&w).await, 0);
}

#[tokio::test]
async fn an_open_live_session_refuses_home_busy_and_leaves_it_untouched() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    let (peer, _opened) = kernel_writes::open_for_test(
        &w.db,
        &w.admin_caller,
        OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    let before = total_events(&w).await;
    let live_before = kernel_writes::live_text_for_test(&w.db, &id);
    let busy = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "busy"))
        .await
        .unwrap();
    assert_eq!(busy["outcome"], "refused");
    assert_eq!(busy["reason"], "home_busy");
    assert_eq!(busy["retryable"], true);
    assert_eq!(busy["applied"], false);
    assert_eq!(
        total_events(&w).await,
        before,
        "nothing written, nothing flushed"
    );
    assert_eq!(kernel_writes::live_text_for_test(&w.db, &id), live_before);
    assert_eq!(receipt_rows(&w).await, 0, "home_busy is not stored");
    peer.leave().await;
}

#[tokio::test]
async fn a_stored_receipt_replays_while_a_session_is_open_without_flushing() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    let first = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "r"))
        .await
        .unwrap();
    let (peer, _opened) = kernel_writes::open_for_test(
        &w.db,
        &w.admin_caller,
        OpenRequest {
            record_id: id.clone(),
            mode: PeerKind::Edit,
            resume_peer: None,
        },
    )
    .await
    .unwrap();
    let before = total_events(&w).await;
    let again = merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "r"))
        .await
        .unwrap();
    assert_eq!(again, first);
    assert_eq!(total_events(&w).await, before);
    peer.leave().await;
}

#[tokio::test]
async fn oversize_inputs_and_an_oversize_outcome_are_refused_bad_intent() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "small").await;
    let base = version(&w, &id).await;
    let before = total_events(&w).await;
    let big = "x".repeat(1024 * 1024 + 1);
    for (label, args) in [
        ("base_text", intent(&id, &base, &big, "small", "o1")),
        ("my_text", intent(&id, &base, "small", &big, "o2")),
    ] {
        let refused = merge(&w, args).await.unwrap();
        assert_eq!(refused["reason"], "bad_intent", "{label}");
        assert_eq!(refused["applied"], false, "{label}");
    }
    assert_eq!(
        total_events(&w).await,
        before,
        "oversize inputs write nothing"
    );
    assert_eq!(receipt_rows(&w).await, 0);
    // Both inputs fit under the ceiling and the two edits are disjoint (one at
    // the start, one at the end), so the merge runs and its result is the one
    // thing over the ceiling: this reaches the outcome guard, not the input one.
    let near = "y".repeat(1024 * 1024 - 2);
    let grown = record(&w, &near).await;
    let grown_base = version(&w, &grown).await;
    let mine = format!("zz{near}");
    let theirs = format!("{near}ab");
    assert!(near.len() <= 1024 * 1024 && mine.len() <= 1024 * 1024);
    assert!(theirs.len() <= 1024 * 1024);
    set_body(&w, &grown, &theirs).await;
    let before = total_events(&w).await;
    let outcome = merge(&w, intent(&grown, &grown_base, &near, &mine, "o3"))
        .await
        .unwrap();
    assert_eq!(outcome["reason"], "bad_intent");
    assert_eq!(total_events(&w).await, before);
    assert_eq!(receipt_rows(&w).await, 0);
}

#[tokio::test]
async fn the_same_key_with_different_arguments_is_a_conflict() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    merge(&w, intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "dup"))
        .await
        .unwrap();
    let error = merge(&w, intent(&id, &base, "a\n\nb\n", "A\n\nb\n", "dup"))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("idempotency_key reused"),
        "{error}"
    );
}

#[tokio::test]
async fn two_principals_with_the_same_key_each_keep_their_own_result() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    // Give the viewer Edit by making them an owner of a second home's record.
    let editor = kernel::create_principal(&w.db, "account", "Second", "acct:second", &w.admin)
        .await
        .unwrap();
    let shared_home =
        kernel::create_home(&w.db, KERNEL_ROOT_ID, Some(&[(&editor, "edit")]), &w.admin)
            .await
            .unwrap();
    let shared = record_in(&w, &shared_home, "a\n\nb\n").await;
    let base_a = version(&w, &id).await;
    let base_b = version(&w, &shared).await;
    let second = Caller::authenticated("acct:second");
    let mine = merge(&w, intent(&id, &base_a, "a\n\nb\n", "a\n\nB\n", "same"))
        .await
        .unwrap();
    let theirs = call_as(
        &w,
        &second,
        intent(&shared, &base_b, "a\n\nb\n", "A\n\nb\n", "same"),
    )
    .await
    .unwrap();
    assert_eq!(mine["record_id"], id);
    assert_eq!(theirs["record_id"], shared);
    assert_eq!(theirs["result"]["body"], "A\n\nb\n");
    // Neither reads the other's row: each replays its own.
    assert_eq!(
        merge(&w, intent(&id, &base_a, "a\n\nb\n", "a\n\nB\n", "same"))
            .await
            .unwrap(),
        mine
    );
    assert_eq!(
        call_as(
            &w,
            &second,
            intent(&shared, &base_b, "a\n\nb\n", "A\n\nb\n", "same")
        )
        .await
        .unwrap(),
        theirs
    );
    assert_eq!(receipt_rows(&w).await, 2);
}

#[tokio::test]
async fn an_app_context_never_reads_or_writes_an_ordinary_callers_receipt() {
    // The real-install cross-caller proofs live in
    // `v1_import/tests/app_state/app_scope.rs` (merge_body app tests).
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    let args = intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "ctx");
    let ordinary = merge(&w, args.clone()).await.unwrap();
    let stored: String = sqlx::query_scalar(
        "SELECT request_json FROM kernel_mcp_write_receipts WHERE operation='merge_body'",
    )
    .fetch_one(w.db.pool())
    .await
    .unwrap();
    let stored: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored["schema"], "kernel.mcp.intent.v1");
    assert!(stored["app"].is_null(), "the ordinary identity is recorded");
    // The same key and arguments from an app context do not replay it.
    let claim = crate::mcp::app_attribution::AppAttribution::new(
        "example.merge-proof",
        "1.0.0",
        "missing-install",
    )
    .unwrap();
    let app = w.admin_caller.clone().with_host_asserted_app(claim);
    let before = total_events(&w).await;
    let from_app = call_as(&w, &app, args.clone()).await;
    assert!(from_app.is_err(), "{from_app:?}");
    assert_eq!(total_events(&w).await, before);
    assert_eq!(receipt_rows(&w).await, 1);
    assert_eq!(merge(&w, args).await.unwrap(), ordinary);
}

#[tokio::test]
async fn every_returned_pair_passes_a_later_base_check() {
    let _on = on();
    let w = world().await;
    // A merged-with-write, an unchanged and a clash-only receipt, each used as
    // the base of a following merge.
    let written = record(&w, "a\n\nb\n").await;
    let written_base = version(&w, &written).await;
    set_body(&w, &written, "A\n\nb\n").await;
    let r1 = merge(
        &w,
        intent(&written, &written_base, "a\n\nb\n", "a\n\nB\n", "p1"),
    )
    .await
    .unwrap();

    let unchanged = record(&w, "abc").await;
    let unchanged_base = version(&w, &unchanged).await;
    set_body(&w, &unchanged, "abcd").await;
    let r2 = merge(&w, intent(&unchanged, &unchanged_base, "abc", "abc", "p2"))
        .await
        .unwrap();

    let clashed = record(&w, "abc").await;
    let clashed_base = version(&w, &clashed).await;
    set_body(&w, &clashed, "ayc").await;
    let r3 = merge(&w, intent(&clashed, &clashed_base, "abc", "axc", "p3"))
        .await
        .unwrap();

    for (id, receipt) in [(&written, &r1), (&unchanged, &r2), (&clashed, &r3)] {
        let pair_version = receipt["result"]["version"].as_str().unwrap();
        let pair_body = receipt["result"]["body"].as_str().unwrap();
        // The pair is the real state at that version...
        assert_eq!(
            body_at(&w, id, seq_of(&receipt["result"]["version"])).await,
            pair_body
        );
        // ...so a later merge verifies it as a base, with no base_unverified.
        let next = merge(
            &w,
            intent(
                id,
                pair_version,
                pair_body,
                &format!("{pair_body}!"),
                &format!("next-{id}"),
            ),
        )
        .await
        .unwrap();
        assert_ne!(next["reason"], "base_unverified", "{next}");
        assert_eq!(next["base"]["verified"], true, "{next}");
        assert_eq!(next["result"]["body"], format!("{pair_body}!"));
    }
}

#[tokio::test]
async fn two_calls_with_one_key_merge_once_and_answer_identically() {
    let _on = on();
    let w = world().await;
    let id = record(&w, "a\n\nb\n").await;
    let base = version(&w, &id).await;
    let args = intent(&id, &base, "a\n\nb\n", "a\n\nB\n", "race");
    let before = total_events(&w).await;
    let (first, second) = tokio::join!(merge(&w, args.clone()), merge(&w, args));
    let (first, second) = (first.unwrap(), second.unwrap());
    assert_eq!(first, second);
    assert_eq!(
        total_events(&w).await,
        before + 2,
        "exactly one body version and one canonical recovery fact"
    );
    assert_eq!(receipt_rows(&w).await, 1);
    assert_carried_receipt(
        &w,
        "race",
        &first,
        Some(seq_of(&first["result"]["version"])),
    )
    .await;
}

#[tokio::test]
async fn a_large_receipt_keeps_its_full_body_and_replays_after_a_later_write() {
    let _on = on();
    let w = world().await;
    // About 300 KiB: above the old 256 KiB echo cap, well under the ceiling.
    let paragraph = "line of text\n\n".repeat(21_000);
    let base_text = format!("start\n\n{paragraph}end\n");
    assert!(base_text.len() > 256 * 1024 && base_text.len() < 1024 * 1024);
    let id = record(&w, &base_text).await;
    let base = version(&w, &id).await;
    let mine = base_text.replacen("end", "END", 1);
    let first = merge(&w, intent(&id, &base, &base_text, &mine, "big"))
        .await
        .unwrap();
    assert_eq!(first["outcome"], "merged");
    assert_eq!(first["result"]["body"], mine.as_str());
    assert!(first["result"].get("body_omitted").is_none());
    // Somebody else writes afterwards; the replay still carries the whole body.
    set_body(&w, &id, "something else entirely").await;
    let replayed = merge(&w, intent(&id, &base, &base_text, &mine, "big"))
        .await
        .unwrap();
    assert_eq!(replayed, first);
    // The (version, body) pair from the receipt is a valid later base.
    let pair_version = replayed["result"]["version"].as_str().unwrap();
    let pair_body = replayed["result"]["body"].as_str().unwrap();
    assert_eq!(
        body_at(&w, &id, seq_of(&replayed["result"]["version"])).await,
        pair_body
    );
    let next = merge(
        &w,
        intent(
            &id,
            pair_version,
            pair_body,
            &format!("{pair_body}!"),
            "after-big",
        ),
    )
    .await
    .unwrap();
    assert_ne!(next["reason"], "base_unverified", "{next}");
    assert_eq!(next["base"]["verified"], true, "{next}");
}
