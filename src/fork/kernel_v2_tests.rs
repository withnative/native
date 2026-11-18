//! Focused tests for the private KernelV2 working engine
//! (docs/node-v2-pending-engine.md, increment 1).
//!
//! Every test uses an isolated accepted fixture and the real v2 write/read
//! engine paths through [`ForkManager`]: note content, keyed append replayed
//! exactly once, private/base isolation, reconstruction from a durable
//! journal, and account mismatch. Assertions check expected domain behavior
//! (bodies, isolation, refusal), not implementation mirrors. No routing, no
//! flags, no deployment: the factory alone is the subject here.
use super::*;
use crate::events::KERNEL_ROOT_ID;
use std::time::Duration;

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    base: Db,
    admin: String,
    home: String,
    seed: String,
    task: String,
    manager: Arc<ForkManager>,
    key: ForkKey,
    caller: Caller,
}

struct Calls(Vec<PreparedCall>);
impl OrderedJournaledCalls for Calls {
    fn ordered_calls<'a>(
        &'a self,
        _: &'a ForkKey,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = crate::Result<Vec<PreparedCall>>> + Send + 'a>,
    > {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

async fn fixture() -> Fixture {
    fixture_with_shared_note(false).await
}

async fn fixture_with_shared_note(shared_note: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accepted.db");
    let (setup, admin) =
        crate::kernel::create_v2_database(path.to_str().unwrap(), "account", "Admin", "acct:admin")
            .await
            .unwrap();
    crate::kernel::prepare_v2_database(&setup).await.unwrap();
    let package = crate::v2_standard::v1_compat::package();
    let identity = package.identity().unwrap();
    crate::kernel::install_package_as(&setup, &admin, &package)
        .await
        .unwrap();
    crate::kernel::adopt_package_at(
        &setup,
        &admin,
        KERNEL_ROOT_ID,
        &package,
        Some(&identity),
        &package.declared_reads,
    )
    .await
    .unwrap();
    // Plain MCP note creates resolve through the document package.
    let documents = crate::v2_standard::document_package();
    let documents_identity = documents.identity().unwrap();
    crate::kernel::install_package_as(&setup, &admin, &documents)
        .await
        .unwrap();
    crate::kernel::adopt_package_at(
        &setup,
        &admin,
        KERNEL_ROOT_ID,
        &documents,
        Some(&documents_identity),
        &documents.declared_reads,
    )
    .await
    .unwrap();
    // Same kind vocabulary the ordinary v2 note path validates against.
    let host =
        crate::kernel::resolve_principal_by_binding(&setup, crate::kernel::HOST_IMPORT_BINDING)
            .await
            .unwrap()
            .unwrap()
            .0;
    let manifest: Value = serde_json::from_str(crate::meta::kind::CORE_KIND_MANIFEST_JSON).unwrap();
    let mut rows = Vec::new();
    for typ in ["Document", "WorkItem"] {
        rows.push((
            "vocabularies",
            serde_json::json!({"id":format!("voc:kind:{typ}"),"name":format!("kind:{typ}")}),
        ));
        for entry in manifest["kinds"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|row| row["type"] == typ)
        {
            rows.push((
                "vocabulary_values",
                serde_json::json!({"id":entry["value_id"], "vocabulary_id":format!("voc:kind:{typ}"), "value":entry["token"], "status":"active", "gloss":null,"ordinal":0,"terminality":"open","metadata":entry["metadata"].to_string(),"alias_of":null}),
            ));
        }
    }
    let rows = rows
        .into_iter()
        .map(|(section, row)| crate::kernel::v1_state::ImportedState {
            section: section.into(),
            source_id: row["id"].as_str().unwrap().into(),
            origin: "v2-pending-engine-proof".into(),
            value_json: Some(row.to_string()),
            account_principal: None,
            record_id: None,
            observed_at: "2026-10-28T00:00:00Z".into(),
            snapshot: serde_json::json!({}),
        })
        .collect::<Vec<_>>();
    crate::kernel::v1_state::import_state_batch_as(&setup, &host, &rows)
        .await
        .unwrap();
    let viewer =
        crate::kernel::create_principal(&setup, "account", "Viewer", "acct:viewer", &admin)
            .await
            .unwrap();

    let shared_entries = [(viewer.as_str(), "view")];
    let entries = shared_note.then_some(shared_entries.as_slice());
    let home = crate::kernel::create_home(&setup, KERNEL_ROOT_ID, entries, &admin)
        .await
        .unwrap();
    let seed = crate::kernel::create_json_as(
        &setup,
        &admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &serde_json::json!({"v1_type":"Document","v1_kind":"note","title":"Seed"}).to_string(),
        &home,
    )
    .await
    .unwrap();
    let revision = crate::kernel::read_record_as(&setup, &admin, &seed)
        .await
        .unwrap()
        .unwrap()
        .revision;
    crate::kernel::set_body_as(&setup, &admin, &seed, "accepted base", revision)
        .await
        .unwrap();
    // In the shared-note fixture the second record remains hidden from B.
    let task_home = if shared_note {
        crate::kernel::create_home(&setup, KERNEL_ROOT_ID, None, &admin)
            .await
            .unwrap()
    } else {
        home.clone()
    };
    // A non-note record the plain-note append scope must refuse.
    let task = crate::kernel::create_json_as(
        &setup,
        &admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &serde_json::json!({"v1_type":"WorkItem","v1_kind":"task","title":"Task seed"}).to_string(),
        &task_home,
    )
    .await
    .unwrap();
    setup.close().await;
    // Checkpoint the WAL into the main file so the read-only open sees a
    // plain database file.
    let standalone = sqlx::pool::PoolOptions::<sqlx::Sqlite>::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .journal_mode(sqlx::sqlite::SqliteJournalMode::Delete),
        )
        .await
        .unwrap();
    standalone.close().await;
    let base = crate::db::open_kernel_v2_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        base.open_mode(),
        crate::db::DatabaseOpenMode::StandbyReadOnly
    );
    let area = ForkArea::new(dir.path(), std::slice::from_ref(&path)).unwrap();
    let manager = ForkManager::new_kernel_v2(
        area,
        ForkLimits {
            copy_workers: 1,
            max_forks: 4,
            ..Default::default()
        },
    )
    .unwrap();
    let key = ForkManager::kernel_v2_key("acct:admin", "test-workspace");
    Fixture {
        _dir: dir,
        path,
        base,
        admin,
        home,
        seed,
        task,
        manager,
        key,
        caller: Caller::authenticated("acct:admin"),
    }
}

async fn ready(fixture: &Fixture) {
    fixture
        .manager
        .prepare(fixture.key.clone(), fixture.base.clone())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if fixture.manager.state(&fixture.key).await == ForkState::Ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

async fn dispatch_confirmed(
    fixture: &Fixture,
    operation: &str,
    arguments: Value,
) -> (PreparedCall, ForkOutcome) {
    let call = fixture
        .manager
        .prepare_call_kernel_v2(&fixture.key, &fixture.caller, operation, arguments)
        .await
        .unwrap();
    let outcome = fixture
        .manager
        .dispatch_kernel_v2(&fixture.key, &fixture.caller, &call)
        .await
        .unwrap();
    fixture
        .manager
        .confirm_journaled(&fixture.key, &outcome)
        .await
        .unwrap();
    (call, outcome)
}

async fn working_body(manager: &Arc<ForkManager>, admin: &str, key: &ForkKey, id: &str) -> String {
    let working = manager.test_working_db(key).await.unwrap();
    crate::kernel::read_record_as(&working, admin, id)
        .await
        .unwrap()
        .unwrap()
        .body
        .unwrap_or_default()
}

#[tokio::test(flavor = "current_thread")]
async fn private_create_is_readable_and_never_touches_accepted() {
    let fixture = fixture().await;
    ready(&fixture).await;
    let (_, outcome) = dispatch_confirmed(
        &fixture,
        "create_record",
        serde_json::json!({
            "type": "Document", "kind": "note",
            "body": "private hello", "reason": "engine proof",
            "idempotency_key": "private-create",
        }),
    )
    .await;
    // Domain touched IDs exclude internal kernel streams (notably the
    // event-backed keyed-receipt bookkeeping): a create touches exactly its
    // new note.
    assert_eq!(
        outcome.touched_record_ids.len(),
        1,
        "unexpected touched records: {:?}",
        outcome.touched_record_ids
    );
    let id = outcome.touched_record_ids[0].clone();
    assert_eq!(
        working_body(&fixture.manager, &fixture.admin, &fixture.key, &id).await,
        "private hello"
    );
    let (value, _, published) = fixture
        .manager
        .preview_read_kernel_v2(
            &fixture.key,
            &fixture.caller,
            "get_record",
            serde_json::json!({"ids": [id]}),
        )
        .await
        .unwrap();
    assert!(
        value.to_string().contains("private hello"),
        "private note missing from working-copy read: {value}"
    );
    assert!(
        !published.is_empty(),
        "confirmed write must publish its key"
    );
    assert!(
        crate::kernel::read_record_as(&fixture.base, &fixture.admin, &id)
            .await
            .unwrap()
            .is_none(),
        "private create leaked into the accepted base"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn keyed_append_applies_exactly_once() {
    let fixture = fixture().await;
    ready(&fixture).await;
    let args = serde_json::json!({
        "id": fixture.seed,
        "body_append": " +pending",
        "reason": "engine proof",
        "idempotency_key": "append-once",
    });
    let (call, _) = dispatch_confirmed(&fixture, "update_record", args).await;
    // Same key, same request: the event-backed receipt answers without a
    // second append.
    let replay = fixture
        .manager
        .dispatch_kernel_v2(&fixture.key, &fixture.caller, &call)
        .await
        .unwrap();
    fixture
        .manager
        .confirm_journaled(&fixture.key, &replay)
        .await
        .unwrap();
    assert_eq!(
        working_body(
            &fixture.manager,
            &fixture.admin,
            &fixture.key,
            &fixture.seed
        )
        .await,
        "accepted base +pending"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn private_append_leaves_accepted_body_untouched() {
    let fixture = fixture().await;
    ready(&fixture).await;
    dispatch_confirmed(
        &fixture,
        "update_record",
        serde_json::json!({
            "id": fixture.seed,
            "body_append": " +private",
            "reason": "engine proof",
            "idempotency_key": "append-private",
        }),
    )
    .await;
    assert_eq!(
        working_body(
            &fixture.manager,
            &fixture.admin,
            &fixture.key,
            &fixture.seed
        )
        .await,
        "accepted base +private"
    );
    let base_body = crate::kernel::read_record_as(&fixture.base, &fixture.admin, &fixture.seed)
        .await
        .unwrap()
        .unwrap()
        .body
        .unwrap_or_default();
    assert_eq!(base_body, "accepted base");
}

#[tokio::test(flavor = "current_thread")]
async fn append_target_scope_is_plain_notes() {
    let fixture = fixture().await;
    ready(&fixture).await;
    // Unknown targets are refused and leave the slot Ready.
    let missing = fixture
        .manager
        .prepare_call_kernel_v2(
            &fixture.key,
            &fixture.caller,
            "update_record",
            serde_json::json!({
                "id": "00000000-0000-4000-8000-000000000000",
                "body_append": " +lost",
                "reason": "engine proof",
                "idempotency_key": "append-missing",
            }),
        )
        .await
        .unwrap();
    let refused = fixture
        .manager
        .dispatch_kernel_v2(&fixture.key, &fixture.caller, &missing)
        .await
        .unwrap_err();
    // Missing and hidden share one uniform outcome.
    assert!(
        refused
            .to_string()
            .contains(crate::kernel::HIDDEN_OR_MISSING),
        "unexpected refusal: {refused}"
    );
    // Non-note records are refused: the factory scope is plain notes only.
    let wrong_kind = fixture
        .manager
        .prepare_call_kernel_v2(
            &fixture.key,
            &fixture.caller,
            "update_record",
            serde_json::json!({
                "id": fixture.task,
                "body_append": " +lost",
                "reason": "engine proof",
                "idempotency_key": "append-task",
            }),
        )
        .await
        .unwrap();
    let refused = fixture
        .manager
        .dispatch_kernel_v2(&fixture.key, &fixture.caller, &wrong_kind)
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("plain Document/note"),
        "unexpected refusal: {refused}"
    );
    assert_eq!(fixture.manager.state(&fixture.key).await, ForkState::Ready);
    assert_eq!(
        working_body(
            &fixture.manager,
            &fixture.admin,
            &fixture.key,
            &fixture.seed
        )
        .await,
        "accepted base"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hidden_target_is_indistinguishable_from_missing() {
    let fixture = fixture().await;
    ready(&fixture).await;
    // An admitted viewer with their own slot gets the very same outcome
    // for the admin's note (hidden from them) as for a missing id: the
    // refusal leaks neither existence, kind, nor who else can see it.
    let viewer = Caller::authenticated("acct:viewer");
    let viewer_key = ForkManager::kernel_v2_key("acct:viewer", "test-workspace");
    fixture
        .manager
        .prepare(viewer_key.clone(), fixture.base.clone())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if fixture.manager.state(&viewer_key).await == ForkState::Ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let hidden = fixture
        .manager
        .prepare_call_kernel_v2(
            &viewer_key,
            &viewer,
            "update_record",
            serde_json::json!({
                "id": fixture.seed,
                "body_append": " +snoop",
                "reason": "engine proof",
                "idempotency_key": "append-hidden",
            }),
        )
        .await
        .unwrap();
    let hidden_refused = fixture
        .manager
        .dispatch_kernel_v2(&viewer_key, &viewer, &hidden)
        .await
        .unwrap_err();
    let missing = fixture
        .manager
        .prepare_call_kernel_v2(
            &viewer_key,
            &viewer,
            "update_record",
            serde_json::json!({
                "id": "00000000-0000-4000-8000-000000000000",
                "body_append": " +snoop",
                "reason": "engine proof",
                "idempotency_key": "append-missing-viewer",
            }),
        )
        .await
        .unwrap();
    let missing_refused = fixture
        .manager
        .dispatch_kernel_v2(&viewer_key, &viewer, &missing)
        .await
        .unwrap_err();
    assert_eq!(
        hidden_refused.to_string(),
        missing_refused.to_string(),
        "hidden and missing targets must share one outcome"
    );
    assert!(hidden_refused
        .to_string()
        .contains(crate::kernel::HIDDEN_OR_MISSING));
}

#[tokio::test(flavor = "current_thread")]
async fn durable_reconstruction_reopens_journal_from_disk() {
    let fixture = fixture().await;
    ready(&fixture).await;
    let (append, _) = dispatch_confirmed(
        &fixture,
        "update_record",
        serde_json::json!({
            "id": fixture.seed,
            "body_append": " +pending",
            "reason": "engine proof",
            "idempotency_key": "append-rebuild",
        }),
    )
    .await;
    // The durable journal holds credential, operation and arguments — the
    // same arguments the node journal would retain across a restart.
    let journal_path = fixture._dir.path().join("pending-journal.json");
    std::fs::write(
        &journal_path,
        serde_json::to_vec(&serde_json::json!([{
            "credential": "acct:admin",
            "operation": append.operation(),
            "arguments": append.arguments(),
        }]))
        .unwrap(),
    )
    .unwrap();
    // Advance the accepted base in place: a newcomer note lands after the
    // working copy was prepared.
    let writer = crate::db::open_kernel_v2_in_place_writer(&fixture.path)
        .await
        .unwrap();
    let newcomer = crate::kernel::create_json_as(
        &writer,
        &fixture.admin,
        crate::v2_standard::v1_compat::FAMILY,
        "record",
        &serde_json::json!({"v1_type":"Document","v1_kind":"note","title":"Newcomer"}).to_string(),
        &fixture.home,
    )
    .await
    .unwrap();
    let revision = crate::kernel::read_record_as(&writer, &fixture.admin, &newcomer)
        .await
        .unwrap()
        .unwrap()
        .revision;
    crate::kernel::set_body_as(
        &writer,
        &fixture.admin,
        &newcomer,
        "accepted newcomer",
        revision,
    )
    .await
    .unwrap();
    writer.close().await;
    // Restart: drop the manager and the base entirely. Reopening cleans
    // stale fork files and adopts nothing from disk; reconstruction comes
    // only from the accepted base plus the durable journal.
    let Fixture {
        _dir,
        path,
        base,
        admin,
        home: _,
        seed,
        task: _,
        manager,
        key,
        caller: _,
    } = fixture;
    drop(manager);
    drop(base);
    let base = crate::db::open_kernel_v2_standby_read_only(path.to_str().unwrap())
        .await
        .unwrap();
    let area = ForkArea::new(_dir.path(), std::slice::from_ref(&path)).unwrap();
    let manager = ForkManager::new_kernel_v2(
        area,
        ForkLimits {
            copy_workers: 1,
            max_forks: 4,
            ..Default::default()
        },
    )
    .unwrap();
    manager.prepare(key.clone(), base.clone()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if manager.state(&key).await == ForkState::Ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let stored: Vec<Value> =
        serde_json::from_slice(&std::fs::read(&journal_path).unwrap()).unwrap();
    let mut calls = Vec::new();
    for item in stored {
        let caller = Caller::authenticated(item["credential"].as_str().unwrap());
        calls.push(
            manager
                .prepare_call_kernel_v2(
                    &key,
                    &caller,
                    item["operation"].as_str().unwrap(),
                    item["arguments"].clone(),
                )
                .await
                .unwrap(),
        );
    }
    // Rebuild copies once from the current base and replays only the
    // re-prepared durable calls.
    let touched = manager
        .rebuild_kernel_v2(&key, &Calls(calls))
        .await
        .unwrap();
    assert!(touched.contains(&seed));
    assert_eq!(
        working_body(&manager, &admin, &key, &seed).await,
        "accepted base +pending"
    );
    assert_eq!(
        working_body(&manager, &admin, &key, &newcomer).await,
        "accepted newcomer"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn account_mismatch_is_refused_before_dispatch() {
    let fixture = fixture().await;
    ready(&fixture).await;
    // Another valid account cannot address this engine's slot.
    let viewer = Caller::authenticated("acct:viewer");
    let refused = fixture
        .manager
        .prepare_call_kernel_v2(
            &fixture.key,
            &viewer,
            "create_record",
            serde_json::json!({
                "type": "Document", "kind": "note",
                "body": "viewer note", "reason": "engine proof",
                "idempotency_key": "viewer-create",
            }),
        )
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("binding mismatch"),
        "unexpected refusal: {refused}"
    );
    // An unknown credential resolves against the real v2 binding and fails.
    let ghost = Caller::authenticated("acct:ghost");
    let ghost_key = ForkManager::kernel_v2_key("acct:ghost", "test-workspace");
    fixture
        .manager
        .prepare(ghost_key.clone(), fixture.base.clone())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if fixture.manager.state(&ghost_key).await == ForkState::Ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let refused = fixture
        .manager
        .prepare_call_kernel_v2(
            &ghost_key,
            &ghost,
            "create_record",
            serde_json::json!({
                "type": "Document", "kind": "note",
                "body": "ghost note", "reason": "engine proof",
                "idempotency_key": "ghost-create",
            }),
        )
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("principal"),
        "unexpected refusal: {refused}"
    );
    // The refused attempts left no speculative content behind.
    assert!(fixture
        .manager
        .touched_record_ids(&fixture.key)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test(flavor = "current_thread")]
async fn v1_manager_refuses_kernel_v2_calls() {
    let fixture = fixture().await;
    let v1root = fixture._dir.path().join("v1-area");
    std::fs::create_dir(&v1root).unwrap();
    let area = ForkArea::new(&v1root, std::slice::from_ref(&fixture.path)).unwrap();
    let v1 = ForkManager::new(area, ForkLimits::default()).unwrap();
    let refused = v1
        .prepare_call_kernel_v2(
            &fixture.key,
            &fixture.caller,
            "create_record",
            serde_json::json!({
                "type": "Document", "kind": "note",
                "body": "v1 note", "reason": "engine proof",
                "idempotency_key": "v1-create",
            }),
        )
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("v1 fork manager"),
        "unexpected refusal: {refused}"
    );
}

#[test]
fn shape_gate_keeps_canonical_id_authority() {
    // Caller-supplied IDs never reach the kernel: ordinary v2 create mints them.
    let with_id = validate_shape_kernel_v2(
        "create_record",
        &serde_json::json!({"type":"Document","kind":"note","id":"some-id","body":"x"}),
        1024 * 1024,
    )
    .unwrap_err();
    assert!(with_id.to_string().contains("caller-supplied id"));
    // Only plain notes enter the private engine in this increment.
    let task = validate_shape_kernel_v2(
        "create_record",
        &serde_json::json!({"type":"WorkItem","kind":"task","body":"x"}),
        1024 * 1024,
    )
    .unwrap_err();
    assert!(task.to_string().contains("plain Document/note only"));
    // Appends require a single target and a body append.
    let no_target = validate_shape_kernel_v2(
        "update_record",
        &serde_json::json!({"body_append":"x"}),
        1024 * 1024,
    )
    .unwrap_err();
    assert!(no_target.to_string().contains("exactly one id"));
}

async fn working_owner_fixture(
    fixture: &Fixture,
    db: &Db,
    caller: &Caller,
    account_namespace: &str,
) -> (
    super::working_v2::WorkingPublication,
    super::working_v2::OwnerPinnedBase,
) {
    use super::working_v2::{OwnerPinnedBase, WorkingBinding, WorkingPublication};
    let genesis: String = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE type=? AND record_id=? AND actor=?",
    )
    .bind(crate::events::KERNEL_GENESIS_EVENT)
    .bind(crate::events::KERNEL_ROOT_ID)
    .bind(crate::events::KERNEL_GENESIS_ACTOR)
    .fetch_one(fixture.base.pool())
    .await
    .unwrap();
    let base_frontier = frontier(&fixture.base).await.unwrap();
    let binding = WorkingBinding {
        account_id: account_namespace.into(),
        database_id: "route".into(),
        origin_database_id: "origin".into(),
        history_lineage: format!("v2:origin:{genesis}"),
        resource_origin: "https://fixture.test".into(),
        install_id: None,
    };
    let owner = OwnerPinnedBase::from_verified_owner(
        fixture.base.clone(),
        binding.clone(),
        genesis,
        base_frontier,
        caller,
    )
    .await
    .unwrap();
    owner.check_native(db).await.unwrap();
    (
        WorkingPublication {
            binding,
            generation: Uuid::new_v4().to_string(),
            publication: 0,
            accepted_frontier: base_frontier,
            journal_revision: "a".repeat(64),
        },
        owner,
    )
}

// Support proof only: manager acknowledgement/replay tests are separate. This
// exercises the actual native Get hydration on a retained SQLite snapshot.
#[tokio::test(flavor = "current_thread")]
async fn working_manager_pinned_native_get_survives_writer_and_verified_close() {
    use super::working_v2::{BindingControl, VerifiedCloseReason};
    use crate::mcp::kernel_v2::PinnedWorkingRead;
    use serde_json::json;
    let fixture = fixture().await;
    ready(&fixture).await;
    let db = fixture.manager.test_working_db(&fixture.key).await.unwrap();
    let (publication, owner_binding) =
        working_owner_fixture(&fixture, &db, &fixture.caller, "portable-owner-account").await;
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    super::working_v2::initialize_publication_on(&mut tx, &publication)
        .await
        .unwrap();
    db.commit_kernel_content(tx).await.unwrap();
    let (control, guard) = BindingControl::new();
    let old = PinnedWorkingRead::pin(
        db.clone(),
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        guard.clone(),
        owner_binding.read_binding(),
    )
    .await
    .unwrap();
    let before = old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(before.publication, publication);
    assert!(before.value.to_string().contains("accepted base"));
    tokio::time::timeout(Duration::from_secs(5), dispatch_confirmed(&fixture, "update_record", json!({"id":fixture.seed,"body_append":" +first","reason":"snapshot proof","idempotency_key":"snapshot-first"}))).await.unwrap();
    // A second append must progress while the original native reader is pinned.
    tokio::time::timeout(Duration::from_secs(5), dispatch_confirmed(&fixture, "update_record", json!({"id":fixture.seed,"body_append":" +second","reason":"snapshot proof","idempotency_key":"snapshot-second"}))).await.unwrap();
    let retained = old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(retained.publication, publication);
    assert!(!retained.value.to_string().contains("+first"));
    let fresh = PinnedWorkingRead::pin(
        db,
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        guard,
        owner_binding.read_binding(),
    )
    .await
    .unwrap();
    let fresh_result = fresh
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert!(fresh_result.value.to_string().contains("+first +second"));
    assert!(
        fresh
            .get(fixture.caller.clone(), &fixture.task)
            .await
            .is_err(),
        "undeclared Get must be refused"
    );
    assert!(
        fresh
            .get(Caller::authenticated("acct:viewer"), &fixture.seed)
            .await
            .is_err(),
        "another principal must not borrow the pinned actor"
    );
    control.close(VerifiedCloseReason::Revocation);
    assert!(old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .is_err());
    assert!(fresh.get(fixture.caller, &fixture.seed).await.is_err());
}

// Original-lease proof, not a domain replay/acknowledgement proof. The probe
// table checks actual SQLite transaction settlement without another fold path.
#[tokio::test(flavor = "current_thread")]
async fn working_manager_original_wrapper_drop_and_bounded_panic_custody() {
    use super::working_v2::transaction::{
        retained_for_test, settle_retained_for_test, OwnedWorkingTransaction,
    };
    use super::working_v2::{BindingControl, WorkingState};
    use crate::mcp::kernel_v2::PinnedWorkingRead;
    use futures::FutureExt;
    struct Custody {
        _old: PinnedWorkingRead,
        _generation: Arc<ForkManager>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
    }
    impl Drop for Custody {
        fn drop(&mut self) {
            self.dropped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    let fixture = fixture().await;
    ready(&fixture).await;
    let db = fixture.manager.test_working_db(&fixture.key).await.unwrap();
    let (publication, owner_binding) =
        working_owner_fixture(&fixture, &db, &fixture.caller, "portable-owner-account").await;
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    super::working_v2::initialize_publication_on(&mut tx, &publication)
        .await
        .unwrap();
    sqlx::query("CREATE TABLE _working_lease_probe(value INTEGER)")
        .execute(&mut *tx)
        .await
        .unwrap();
    db.commit_kernel_content(tx).await.unwrap();
    let (_control, guard) = BindingControl::new();
    let old = PinnedWorkingRead::pin(
        db.clone(),
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        guard.clone(),
        owner_binding.read_binding(),
    )
    .await
    .unwrap();
    let state = Arc::new(std::sync::Mutex::new(WorkingState::Published));
    // Borrowed commit leaves Transaction.open true. A later real BEGIN must
    // survive the stale wrapper's queued Drop rollback; both values persist.
    for value in [1_i64, 2] {
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut owner = OwnedWorkingTransaction::begin(
            db.clone(),
            Custody {
                _old: old.clone(),
                _generation: fixture.manager.clone(),
                dropped,
            },
            publication.clone(),
            state.clone(),
        )
        .await
        .unwrap();
        sqlx::query("INSERT INTO _working_lease_probe(value) VALUES(?)")
            .bind(value)
            .execute(&mut **owner.parts().0)
            .await
            .unwrap();
        let committed = owner.commit().await.unwrap();
        let installed = PinnedWorkingRead::pin(
            db.clone(),
            fixture.caller.clone(),
            vec![fixture.seed.clone()],
            guard.clone(),
            owner_binding.read_binding(),
        )
        .await
        .unwrap();
        drop(committed.finish_installed(&installed).unwrap());
    }
    let values: Vec<i64> =
        sqlx::query_scalar("SELECT value FROM _working_lease_probe ORDER BY value")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(values, vec![1, 2]);
    let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut owner = OwnedWorkingTransaction::begin(
        db.clone(),
        Custody {
            _old: old.clone(),
            _generation: fixture.manager.clone(),
            dropped: dropped.clone(),
        },
        publication.clone(),
        state.clone(),
    )
    .await
    .unwrap();
    sqlx::query("INSERT INTO _working_lease_probe(value) VALUES(3)")
        .execute(&mut **owner.parts().0)
        .await
        .unwrap();
    let panic = std::panic::AssertUnwindSafe(async move {
        let _actual_owner = owner;
        panic!("owned writer fixture panic");
    })
    .catch_unwind()
    .await;
    assert!(panic.is_err());
    assert_eq!(*state.lock().unwrap(), WorkingState::Quarantined);
    assert_eq!(retained_for_test::<Custody>(), 1);
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "actual original custody cannot drop on panic"
    );
    assert!(old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap()
        .value
        .to_string()
        .contains("accepted base"));
    assert!(
        OwnedWorkingTransaction::begin(db.clone(), (), publication, state.clone())
            .await
            .is_err(),
        "new acknowledgements remain paused"
    );
    assert_eq!(retained_for_test::<Custody>(), 1);
    settle_retained_for_test::<Custody>().await;
    assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        *state.lock().unwrap(),
        WorkingState::Quarantined,
        "test disposal is not unquarantine"
    );
    let values: Vec<i64> =
        sqlx::query_scalar("SELECT value FROM _working_lease_probe ORDER BY value")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        values,
        vec![1, 2],
        "actual acknowledged fixture rollback undoes unfinished write"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn working_manager_pinned_owner_kind_and_native_base_are_bound() {
    use super::working_v2::BindingControl;
    use crate::mcp::kernel_v2::PinnedWorkingRead;
    let fixture = fixture_with_shared_note(true).await;
    let viewer = Caller::authenticated("acct:viewer");
    let viewer_principal = crate::mcp::kernel_v2::principal(&fixture.base, &viewer)
        .await
        .unwrap();
    assert_ne!(viewer_principal, fixture.admin);
    assert!(
        crate::kernel::read_record_as(&fixture.base, &viewer_principal, &fixture.seed)
            .await
            .unwrap()
            .is_some(),
        "B is genuinely authorized to view the shared accepted note"
    );
    assert!(
        crate::kernel::read_record_as(&fixture.base, &viewer_principal, &fixture.task)
            .await
            .unwrap()
            .is_none(),
        "the other record remains genuinely hidden from B"
    );
    ready(&fixture).await;
    let db = fixture.manager.test_working_db(&fixture.key).await.unwrap();
    let (publication, owner) =
        working_owner_fixture(&fixture, &db, &fixture.caller, "portable-A-account").await;
    let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
    super::working_v2::initialize_publication_on(&mut tx, &publication)
        .await
        .unwrap();
    db.commit_kernel_content(tx).await.unwrap();
    dispatch_confirmed(&fixture,"update_record",serde_json::json!({"id":fixture.seed,"body_append":" +A-private-pending","reason":"owner boundary proof","idempotency_key":"owner-bound-pending"})).await;
    let (_control, guard) = BindingControl::new();
    let a = PinnedWorkingRead::pin(
        db.clone(),
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        guard.clone(),
        owner.read_binding(),
    )
    .await
    .unwrap();
    assert!(a
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap()
        .value
        .to_string()
        .contains("+A-private-pending"));
    let denied = PinnedWorkingRead::pin(
        db.clone(),
        viewer.clone(),
        vec![fixture.seed.clone()],
        guard.clone(),
        owner.read_binding(),
    )
    .await
    .err()
    .expect("authorized B cannot pin A's pending publication");
    assert!(denied.to_string().contains("owner binding mismatch"));
    // Current W head legitimately advances, while its accepted-base anchor is
    // fixed. It cannot pass as a fresh exact accepted-base copy afterward.
    assert!(owner.check_native(&db).await.is_err());
    let wrong_kind = PinnedWorkingRead::pin(
        db.clone(),
        fixture.caller.clone(),
        vec![fixture.task.clone()],
        guard,
        owner.read_binding(),
    )
    .await
    .err()
    .expect("visible WorkItem is outside declared note scope");
    assert!(wrong_kind.to_string().contains("plain Document/note"));
    // B's own accepted-base capability does not grant A's namespace either.
    let b_handle = fixture.manager.copy(&fixture.base).await.unwrap();
    let b_db = b_handle.db.clone();
    let (b_publication, b_owner) =
        working_owner_fixture(&fixture, &b_db, &viewer, "portable-B-account").await;
    let (_b_control, b_guard) = BindingControl::new();
    assert!(PinnedWorkingRead::pin(
        db,
        viewer.clone(),
        vec![fixture.seed.clone()],
        b_guard.clone(),
        b_owner.read_binding()
    )
    .await
    .is_err());
    let mut tx = crate::db::begin_write(b_db.write_pool()).await.unwrap();
    super::working_v2::initialize_publication_on(&mut tx, &b_publication)
        .await
        .unwrap();
    b_db.commit_kernel_content(tx).await.unwrap();
    let hidden = PinnedWorkingRead::pin(
        b_db.clone(),
        viewer.clone(),
        vec![fixture.task.clone()],
        b_guard.clone(),
        b_owner.read_binding(),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    let missing = PinnedWorkingRead::pin(
        b_db,
        viewer,
        vec![Uuid::new_v4().to_string()],
        b_guard,
        b_owner.read_binding(),
    )
    .await
    .err()
    .unwrap()
    .to_string();
    assert_eq!(
        hidden, missing,
        "kind cannot be inspected before native visibility"
    );
    assert!(hidden.contains(crate::kernel::HIDDEN_OR_MISSING));
}

async fn append_manager_fixture(
    fixture: &Fixture,
    root: &std::path::Path,
) -> (
    super::working_v2::manager::WorkingManager,
    super::working_v2::manager::WorkingControl,
    super::working_v2::BindingControl,
) {
    use super::working_v2::{manager::WorkingManager, BindingControl};
    let (_, owner) = working_owner_fixture(
        fixture,
        &fixture.base,
        &fixture.caller,
        "portable-verified-account",
    )
    .await;
    let (binding, guard) = BindingControl::new();
    let area = ForkArea::new(root, std::slice::from_ref(&fixture.path)).unwrap();
    let (manager, control) = WorkingManager::open(
        owner,
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        (area, ForkLimits::default()),
        root,
        guard,
        "a".repeat(64),
    )
    .await
    .unwrap();
    (manager, control, binding)
}
fn manager_append(fixture: &Fixture, key: &str, body: &str) -> Value {
    serde_json::json!({"id":fixture.seed,"body_append":body,"reason":"private manager proof","idempotency_key":key})
}

/// Owner qualification only: actual replay and native read snapshots, without
/// journal admission, reconciliation, a node route or a pending ACK claim.
#[tokio::test(flavor = "current_thread")]
async fn working_pinned_actor_two_real_appends_keep_one_writer_and_old_native_get() {
    use super::working_v2::{transaction, BindingControl, WorkingState};
    use crate::mcp::kernel_v2::{writes::replay, PinnedWorkingRead};
    use futures::FutureExt;
    use sqlx::Connection;
    let fixture = Arc::new(fixture().await);
    let handle = fixture.manager.copy(&fixture.base).await.unwrap();
    let old_db_alias = handle.db.clone();
    let (mut publication, owner) = working_owner_fixture(
        &fixture,
        &handle.db,
        &fixture.caller,
        "pinned-writer-portable-account",
    )
    .await;
    let caller = fixture.caller.clone();
    let note = fixture.seed.clone();
    let actor = fixture.admin.clone();
    let (close, guard) = BindingControl::new();
    let binding = owner.read_binding();
    let (ready_send, ready) = tokio::sync::oneshot::channel();
    let (send, mut receive) = tokio::sync::mpsc::channel::<(
        replay::ReplayProposal,
        tokio::sync::oneshot::Sender<(PinnedWorkingRead, usize)>,
    )>(2);
    let state = Arc::new(std::sync::Mutex::new(WorkingState::Published));
    let retained_generation = fixture.clone();
    let writer = transaction::retain_writer_actor(
        Box::pin(async move {
            // All ownership is already in the static bounded slot before this
            // constructor (or any connection creation) is polled.
            let _retained_generation = retained_generation;
            let (reader, mut connection) = transaction::open_pinned_writer(&handle).await.unwrap();
            for pool in [reader.pool(), reader.write_pool(), reader.governed_pool()] {
                assert!(sqlx::query("CREATE TABLE forbidden_writer(v)")
                    .execute(pool)
                    .await
                    .is_err());
            }
            let mut tx = transaction::construct_pinned_transaction(&mut connection)
                .await
                .unwrap();
            let native_schema =
                crate::standby::kernel_v2::WorkingKernelSchema::from_fresh_native(&mut tx)
                    .await
                    .unwrap();
            super::working_v2::initialize_publication_on(&mut tx, &publication)
                .await
                .unwrap();
            sqlx::query(crate::kernel::working_undo_schema::WORKING_BASES_DDL)
                .execute(&mut *tx)
                .await
                .unwrap();
            assert!(matches!(
                reader.commit_owned_kernel_connection(&mut tx, None).await,
                crate::db::KernelCommitOutcome::Committed
            ));
            drop(tx); // Acknowledged depth zero BEFORE any subsequent BEGIN.
            let collector = crate::kernel::working_undo::with_handle(&mut connection, |raw| {
                crate::kernel::working_undo::Collector::install(
                    raw,
                    &crate::kernel::working_undo::test_keys(raw),
                    100_000,
                    16 * 1024 * 1024,
                )
                .map_err(|e| Error::engine(e.to_string()))
            })
            .await
            .unwrap();
            let physical = {
                let mut locked = connection.lock_handle().await.unwrap();
                locked.as_raw_handle().as_ptr() as usize
            };
            let old = PinnedWorkingRead::pin_owned(
                reader.clone(),
                caller.clone(),
                vec![note.clone()],
                guard.clone(),
                binding.clone(),
                _retained_generation.clone(),
            )
            .await
            .unwrap();
            ready_send
                .send((reader.clone(), old, physical))
                .unwrap_or_else(|_| panic!("reader receiver vanished"));
            let mut ordinal = 0;
            while let Some((proposal, reply)) = receive.recv().await {
                // The actual wrapper stays OUTSIDE the catch boundary. Only the
                // borrowed phase future can unwind; a fault test below parks it.
                let mut tx = transaction::construct_pinned_transaction(&mut connection)
                    .await
                    .unwrap();
                let phase = std::panic::AssertUnwindSafe(async {
                    crate::storage_profile::enforce_write_boundary_on(&mut tx).await?;
                    let resolved = crate::mcp::kernel_v2::principal_on(&mut tx, &caller).await?;
                    if resolved != actor {
                        return Err(Error::engine("actor changed"));
                    }
                    let tag = format!("owner-{ordinal}");
                    sqlx::query("SAVEPOINT owner_capture")
                        .execute(&mut *tx)
                        .await?;
                    crate::kernel::working_undo::with_handle(&mut tx, |raw| {
                        collector
                            .proposal(raw, &tag)
                            .map_err(|e| Error::engine(e.to_string()))
                    })
                    .await?;
                    let outcome = replay::replay_working_in_transaction(
                        &reader,
                        &mut tx,
                        &replay::ReplayCaller {
                            actor: resolved,
                            mint: Default::default(),
                        },
                        &proposal,
                        &replay::ReplaySavepoint::claim(),
                        (
                            None,
                            None,
                            replay::WorkingReplayOwner {
                                schema: &native_schema,
                                collector: &collector,
                            },
                        ),
                    )
                    .await?;
                    if !matches!(outcome, replay::ReplayOutcome::Applied { .. }) {
                        return Err(Error::engine("native replay refused"));
                    }
                    crate::kernel::working_undo::with_handle(&mut tx, |raw| {
                        collector
                            .finish_proposal(raw, &tag)
                            .map_err(|e| Error::engine(e.to_string()))
                    })
                    .await?;
                    sqlx::query("RELEASE owner_capture")
                        .execute(&mut *tx)
                        .await?;
                    publication.publication += 1;
                    sqlx::query("UPDATE _native_working_publication SET state=? WHERE singleton=1")
                        .bind(serde_json::to_string(&publication)?)
                        .execute(&mut *tx)
                        .await?;
                    Ok::<_, Error>(reader.commit_owned_kernel_connection(&mut tx, None).await)
                })
                .catch_unwind()
                .await;
                assert!(matches!(
                    phase,
                    Ok(Ok(crate::db::KernelCommitOutcome::Committed))
                ));
                drop(tx);
                let pinned = PinnedWorkingRead::pin_owned(
                    reader.clone(),
                    caller.clone(),
                    vec![note.clone()],
                    guard.clone(),
                    binding.clone(),
                    _retained_generation.clone(),
                )
                .await
                .unwrap();
                let actual = {
                    let mut locked = connection.lock_handle().await.unwrap();
                    locked.as_raw_handle().as_ptr() as usize
                };
                assert_eq!(actual, physical);
                // A dropped result receiver never owns or stops the actor.
                let _ = reply.send((pinned, actual));
                ordinal += 1;
            }
            assert_eq!(ordinal, 2);
            drop(collector);
            connection.close().await.unwrap();
        }),
        state,
    )
    .unwrap();
    let (reader, old, physical) = ready.await.unwrap();
    for pool in [
        old_db_alias.pool(),
        old_db_alias.write_pool(),
        old_db_alias.governed_pool(),
    ] {
        assert!(pool.is_closed());
        assert_eq!(pool.size(), 0);
        assert!(
            pool.acquire().await.is_err(),
            "old aliases cannot create another writer"
        );
    }
    let before = old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(before.publication.publication, 0);
    let mut latest = None;
    for (index, (key, body)) in [
        ("pinned-first", " +pinned-first"),
        ("pinned-second", " +pinned-second"),
    ]
    .into_iter()
    .enumerate()
    {
        let args = manager_append(&fixture, key, body);
        let proposal = replay::ReplayProposal::from_current_first_party(
            "update_record",
            args,
            Some(key.into()),
        )
        .unwrap();
        let (reply, result) = tokio::sync::oneshot::channel();
        send.send((proposal, reply))
            .await
            .unwrap_or_else(|_| panic!("actor ended"));
        if index == 0 {
            // Cancelling the first observer cannot abandon its native replay,
            // commit or pin. The second result must still include both edits.
            drop(result);
            continue;
        }
        let (pinned, current) = tokio::time::timeout(Duration::from_secs(10), result)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current, physical);
        latest = Some(pinned);
    }
    let fresh = latest
        .unwrap()
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(fresh.publication.publication, 2);
    let body = fresh.value.to_string();
    assert!(body.contains("+pinned-first +pinned-second"));
    assert_eq!(body.matches("+pinned-first").count(), 1);
    let prior = old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(prior.publication, before.publication);
    assert_eq!(
        prior.value, before.value,
        "old native snapshot stays coherent during both commits"
    );
    drop(send);
    writer.joined().await;
    close.close(super::working_v2::VerifiedCloseReason::AccountSwitch);
    reader.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn working_pinned_actor_faults_keep_actual_wrapper_and_pause_without_ack() {
    use super::working_v2::{transaction, BindingControl, WorkingState};
    use crate::mcp::kernel_v2::{writes::replay, PinnedWorkingRead};
    use futures::FutureExt;
    use sqlx::Connection;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    #[derive(Clone, Copy, PartialEq)]
    enum Fault {
        Panic,
        DriverCancel,
        CommitUncertain,
    }
    struct DropProbe(Arc<AtomicBool>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    for fault in [Fault::Panic, Fault::DriverCancel, Fault::CommitUncertain] {
        let fixture = Arc::new(fixture().await);
        let handle = fixture.manager.copy(&fixture.base).await.unwrap();
        let (publication, owner) =
            working_owner_fixture(&fixture, &handle.db, &fixture.caller, "fault-account").await;
        let proposal = replay::ReplayProposal::from_current_first_party(
            "update_record",
            manager_append(&fixture, "retained-owner-fault", " +retained-owner-fault"),
            Some("retained-owner-fault".into()),
        )
        .unwrap();
        let caller = fixture.caller.clone();
        let note = fixture.seed.clone();
        let binding = owner.read_binding();
        let (close, guard) = BindingControl::new();
        let state = Arc::new(std::sync::Mutex::new(WorkingState::Published));
        let actor_state = state.clone();
        let dropped = Arc::new(AtomicBool::new(false));
        let probe = DropProbe(dropped.clone());
        let starts = Arc::new(AtomicUsize::new(0));
        let actor_starts = starts.clone();
        let acks = Arc::new(AtomicUsize::new(0));
        let actor_acks = acks.clone();
        let phase_release = Arc::new(Semaphore::new(0));
        let release = phase_release.clone();
        let settlement = Arc::new(Semaphore::new(0));
        let settle = settlement.clone();
        let (ready_send, ready) = tokio::sync::oneshot::channel();
        let (entered_send, entered) = tokio::sync::oneshot::channel();
        let (parked_send, parked) = tokio::sync::oneshot::channel();
        let retained_generation = fixture.clone();
        let mut driver = transaction::retain_writer_actor(
            Box::pin(async move {
                let _probe = probe;
                let _retained_generation = retained_generation;
                let (reader, mut connection) =
                    transaction::open_pinned_writer(&handle).await.unwrap();
                let mut setup = transaction::construct_pinned_transaction(&mut connection)
                    .await
                    .unwrap();
                let native_schema =
                    crate::standby::kernel_v2::WorkingKernelSchema::from_fresh_native(&mut setup)
                        .await
                        .unwrap();
                super::working_v2::initialize_publication_on(&mut setup, &publication)
                    .await
                    .unwrap();
                sqlx::query(crate::kernel::working_undo_schema::WORKING_BASES_DDL)
                    .execute(&mut *setup)
                    .await
                    .unwrap();
                assert!(matches!(
                    reader
                        .commit_owned_kernel_connection(&mut setup, None)
                        .await,
                    crate::db::KernelCommitOutcome::Committed
                ));
                drop(setup);
                let collector = crate::kernel::working_undo::with_handle(&mut connection, |raw| {
                    crate::kernel::working_undo::Collector::install(
                        raw,
                        &crate::kernel::working_undo::test_keys(raw),
                        100_000,
                        16 * 1024 * 1024,
                    )
                    .map_err(|e| Error::engine(e.to_string()))
                })
                .await
                .unwrap();
                let old = PinnedWorkingRead::pin_owned(
                    reader.clone(),
                    caller.clone(),
                    vec![note],
                    guard.clone(),
                    binding,
                    _retained_generation.clone(),
                )
                .await
                .unwrap();
                ready_send
                    .send((reader.clone(), old))
                    .unwrap_or_else(|_| panic!("owner fixture receiver vanished"));
                actor_starts.fetch_add(1, Ordering::SeqCst);
                let mut tx = transaction::construct_pinned_transaction(&mut connection)
                    .await
                    .unwrap(); // REAL wrapper outside catch.
                let phase = std::panic::AssertUnwindSafe(async {
                    entered_send.send(()).ok();
                    release
                        .acquire()
                        .await
                        .map_err(|_| Error::engine("phase closed"))?
                        .forget();
                    if *actor_state.lock().unwrap() != WorkingState::Published {
                        return Err(Error::engine("driver cancelled; acknowledgements paused"));
                    }
                    crate::storage_profile::enforce_write_boundary_on(&mut tx).await?;
                    let principal = crate::mcp::kernel_v2::principal_on(&mut tx, &caller).await?;
                    crate::kernel::working_undo::with_handle(&mut tx, |raw| {
                        collector
                            .proposal(raw, "fault")
                            .map_err(|e| Error::engine(e.to_string()))
                    })
                    .await?;
                    let result = replay::replay_working_in_transaction(
                        &reader,
                        &mut tx,
                        &replay::ReplayCaller {
                            actor: principal,
                            mint: Default::default(),
                        },
                        &proposal,
                        &replay::ReplaySavepoint::claim(),
                        (
                            None,
                            None,
                            replay::WorkingReplayOwner {
                                schema: &native_schema,
                                collector: &collector,
                            },
                        ),
                    )
                    .await?;
                    if !matches!(result, replay::ReplayOutcome::Applied { .. }) {
                        return Err(Error::engine("replay refused"));
                    }
                    if fault == Fault::Panic {
                        panic!("borrowed native phase panic");
                    }
                    Ok::<_, Error>(reader.commit_owned_kernel_connection(&mut tx, None).await)
                })
                .catch_unwind()
                .await;
                if matches!(phase, Ok(Ok(crate::db::KernelCommitOutcome::Committed))) {
                    actor_acks.fetch_add(1, Ordering::SeqCst);
                }
                assert!(
                    !matches!(phase, Ok(Ok(crate::db::KernelCommitOutcome::Committed))),
                    "fault must not issue a successful publication"
                );
                if fault == Fault::CommitUncertain {
                    assert!(
                        matches!(phase, Ok(Ok(crate::db::KernelCommitOutcome::Uncertain(_)))),
                        "real classifier must report uncertainty"
                    );
                }
                *actor_state.lock().unwrap() = WorkingState::Quarantined;
                parked_send.send(()).ok();
                // Production parks forever here; only this explicit test permit
                // admits actual rollback+close, never a new BEGIN or publication.
                settle.acquire().await.unwrap().forget();
                assert_eq!(actor_acks.load(Ordering::SeqCst), 0);
                Db::rollback_owned_kernel_connection(&mut tx).await.unwrap();
                drop(tx);
                drop(collector);
                connection.close().await.unwrap();
            }),
            state.clone(),
        )
        .unwrap();
        let (reader, old) = ready.await.unwrap();
        let original = old
            .get(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap();
        entered.await.unwrap();
        let worker = if fault == Fault::CommitUncertain {
            Some(crate::coedit::live::kernel_writes::pause_commit_worker_for_test(&reader))
        } else {
            None
        };
        let gate = if fault == Fault::CommitUncertain {
            Some(crate::coedit::live::kernel_writes::test_gate(
                &reader,
                crate::coedit::live::kernel_writes::TestStage::BorrowedCommitPending,
                true,
            ))
        } else {
            None
        };
        if fault == Fault::DriverCancel {
            driver.abort_driver().await;
            assert!(
                driver.retained(),
                "cancelled driver cannot take the actor frame"
            );
            phase_release.add_permits(1);
            driver.resume_for_settlement();
        } else {
            phase_release.add_permits(1);
        }
        if let Some(worker) = &worker {
            worker.entered().await;
            let gate = gate.as_ref().unwrap();
            gate.entered.notified().await;
            gate.release.notify_one(); // classifier returns actual Uncertain.
        }
        parked.await.unwrap();
        driver.abort_driver().await;
        assert!(driver.retained());
        assert!(
            !dropped.load(Ordering::SeqCst),
            "wrapper/connection/collector owner still retained"
        );
        assert_eq!(*state.lock().unwrap(), WorkingState::Quarantined);
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert_eq!(acks.load(Ordering::SeqCst), 0);
        let after = old
            .get(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap();
        assert_eq!(after.publication, original.publication);
        assert_eq!(
            after.value, original.value,
            "unpublished outcomes preserve complete old native view"
        );
        assert!(transaction::retain_writer_actor(Box::pin(async {}), state.clone()).is_err());
        if let Some(worker) = &worker {
            worker.release();
        }
        settlement.add_permits(1);
        driver.resume_for_settlement();
        driver.joined().await;
        assert!(
            dropped.load(Ordering::SeqCst),
            "fixture disposal only after actual rollback+close"
        );
        assert_eq!(
            starts.load(Ordering::SeqCst),
            1,
            "settlement never starts another transaction"
        );
        close.close(super::working_v2::VerifiedCloseReason::AccountSwitch);
        reader.close().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn working_pinned_actor_driver_cancel_during_real_begin_keeps_constructor_frame() {
    use super::working_v2::{transaction, WorkingState};
    use sqlx::Connection;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    struct Probe(Arc<AtomicBool>);
    impl Drop for Probe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    struct Worker {
        fired: AtomicBool,
        entered: tokio::sync::Notify,
        released: std::sync::Mutex<bool>,
        release: std::sync::Condvar,
    }
    impl Worker {
        fn release(&self) {
            *self.released.lock().unwrap() = true;
            self.release.notify_all();
        }
    }
    struct ReleaseOnDrop(Arc<Worker>);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    // Even a driver cancelled before its FIRST poll must retain the inner
    // future and pause admission before any connection can be created.
    let pre_state = Arc::new(std::sync::Mutex::new(WorkingState::Published));
    let pre_dropped = Arc::new(AtomicBool::new(false));
    let pre_probe = Probe(pre_dropped.clone());
    let pre_polls = Arc::new(AtomicUsize::new(0));
    let polls = pre_polls.clone();
    let mut before_first_poll = transaction::retain_writer_actor(
        Box::pin(async move {
            let _probe = pre_probe;
            polls.fetch_add(1, Ordering::SeqCst);
        }),
        pre_state.clone(),
    )
    .unwrap();
    before_first_poll.abort_driver().await;
    assert!(before_first_poll.retained());
    assert!(!pre_dropped.load(Ordering::SeqCst));
    assert_eq!(pre_polls.load(Ordering::SeqCst), 0);
    assert_eq!(*pre_state.lock().unwrap(), WorkingState::Quarantined);
    before_first_poll.resume_for_settlement();
    before_first_poll.joined().await;
    assert!(pre_dropped.load(Ordering::SeqCst));
    let fixture = Arc::new(fixture().await);
    let handle = fixture.manager.copy(&fixture.base).await.unwrap();
    let state = Arc::new(std::sync::Mutex::new(WorkingState::Published));
    let worker = Arc::new(Worker {
        fired: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        released: std::sync::Mutex::new(false),
        release: std::sync::Condvar::new(),
    });
    let _release_on_failure = ReleaseOnDrop(worker.clone());
    let actor_worker = worker.clone();
    let dropped = Arc::new(AtomicBool::new(false));
    let probe = Probe(dropped.clone());
    let returned = Arc::new(AtomicUsize::new(0));
    let actor_returned = returned.clone();
    let (pending_send, pending) = tokio::sync::oneshot::channel();
    let retained_generation = fixture.clone();
    let mut driver = transaction::retain_writer_actor(
        Box::pin(async move {
            let _probe = probe;
            let _retained_generation = retained_generation;
            let (reader, mut connection) = transaction::open_pinned_writer(&handle).await.unwrap();
            // Only this real connection exists as a writer. Pause its BEGIN in
            // SQLite's worker; no second writer or invented Transaction is used.
            connection
                .lock_handle()
                .await
                .unwrap()
                .set_progress_handler(1, move || {
                    if !actor_worker.fired.swap(true, Ordering::SeqCst) {
                        actor_worker.entered.notify_one();
                        let mut released = actor_worker.released.lock().unwrap();
                        while !*released {
                            released = actor_worker.release.wait(released).unwrap();
                        }
                    }
                    true
                });
            let mut tx = {
                let begin = transaction::construct_pinned_transaction(&mut connection);
                tokio::pin!(begin);
                assert!(futures::poll!(begin.as_mut()).is_pending());
                pending_send.send(()).ok();
                // The slot retains BOTH the pending constructor and its connection.
                // We claim no actual wrapper ownership before this await returns.
                begin.await.unwrap()
            };
            actor_returned.fetch_add(1, Ordering::SeqCst);
            Db::rollback_owned_kernel_connection(&mut tx).await.unwrap();
            drop(tx);
            connection.close().await.unwrap();
            reader.close().await;
        }),
        state.clone(),
    )
    .unwrap();
    pending.await.unwrap();
    worker.entered.notified().await;
    driver.abort_driver().await;
    assert!(driver.retained());
    assert_eq!(returned.load(Ordering::SeqCst), 0);
    assert!(!dropped.load(Ordering::SeqCst));
    assert_eq!(*state.lock().unwrap(), WorkingState::Quarantined);
    worker.release();
    driver.resume_for_settlement();
    driver.joined().await;
    assert_eq!(returned.load(Ordering::SeqCst), 1);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        *state.lock().unwrap(),
        WorkingState::Quarantined,
        "constructor settlement does not restore admission"
    );
}

/// Direct private API proof, not installed node routing or hosted acceptance.
#[tokio::test(flavor = "current_thread")]
async fn working_append_ack_is_first_fresh_native_get_and_pinned_reads_progress() {
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (manager, _control, _binding) = append_manager_fixture(&fixture, root.path()).await;
    let client_two = Caller::authenticated("acct:admin")
        .with_oauth_client_id(Some("second-authorized-client".into()));
    let old = manager.pin(fixture.caller.clone()).await.unwrap();
    let before = old.get(client_two.clone(), &fixture.seed).await.unwrap();
    let args = manager_append(&fixture, "manager-first", " +first");
    let ingress_started = std::time::Instant::now();
    let first = tokio::time::timeout(
        Duration::from_secs(10),
        manager
            .append(fixture.caller.clone(), args.clone())
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    let ingress_to_ack = ingress_started.elapsed();
    let get_started = std::time::Instant::now();
    // No sleep, polling, fold or refresh between ACK and the FIRST fresh Get.
    let first_get = manager
        .pin(fixture.caller.clone())
        .await
        .unwrap()
        .get(client_two.clone(), &fixture.seed)
        .await
        .unwrap();
    eprintln!(
        "working_append_ingress_to_ack_us={} first_fresh_second_client_get_us={}",
        ingress_to_ack.as_micros(),
        get_started.elapsed().as_micros()
    );
    assert_eq!(first_get.publication, first.publication);
    assert!(first_get.value.to_string().contains("+first"));
    assert_eq!(first.publication.publication, 1);
    let retry = manager
        .append(client_two.clone(), args.clone())
        .unwrap()
        .await
        .unwrap();
    assert_eq!(retry.proposal_id, first.proposal_id);
    assert_eq!(retry.publication, first.publication);
    let conflict = manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "manager-first", " changed bytes"),
        )
        .unwrap()
        .await;
    assert!(conflict.unwrap_err().to_string().contains("reserved"));
    let second = tokio::time::timeout(
        Duration::from_secs(10),
        manager
            .append(
                client_two.clone(),
                manager_append(&fixture, "manager-second", " +second"),
            )
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(second.publication.publication, 2);
    let fresh = manager
        .pin(fixture.caller.clone())
        .await
        .unwrap()
        .get(client_two.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(fresh.publication, second.publication);
    assert!(fresh.value.to_string().contains("+first +second"));
    let retained = old.get(client_two, &fixture.seed).await.unwrap();
    assert_eq!(retained.publication, before.publication);
    assert_eq!(retained.value, before.value);
    assert_eq!(
        crate::kernel::read_record_as(&fixture.base, &fixture.admin, &fixture.seed)
            .await
            .unwrap()
            .unwrap()
            .body
            .unwrap(),
        "accepted base"
    );
    use std::os::unix::fs::MetadataExt;
    let working_path = manager.native_db().path().to_path_buf();
    let working_before = std::fs::metadata(&working_path).unwrap();
    let working_identity = (working_before.dev(), working_before.ino());
    let journal_directory = root.path().join("working-manager-journal").join("journal");
    let saved_originals = [&first.proposal_id, &second.proposal_id]
        .into_iter()
        .map(|id| {
            let path = journal_directory.join(format!("{id}.json"));
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect::<Vec<_>>();
    // Corruption is not an invitation to replay an already applied original.
    // Its provider receipt must not repair a missing local marker/counter.
    manager
        .remove_marker_for_test(first.proposal_id.clone())
        .await;
    let missing = manager
        .append(fixture.caller.clone(), args)
        .unwrap()
        .await
        .unwrap_err();
    assert!(missing
        .to_string()
        .contains("ordered prefix missing local applied marker"));
    manager.await_retained_for_test().await;
    assert_eq!(
        manager.state(),
        super::working_v2::WorkingState::Quarantined
    );
    assert_eq!(manager.retained_count(), 1, "actual owner remains parked");
    let working_after = std::fs::metadata(&working_path).unwrap();
    assert!(working_after.is_file());
    assert_eq!(
        (working_after.dev(), working_after.ino()),
        working_identity,
        "the same W remains owned after corruption refusal"
    );
    for (path, bytes) in saved_originals {
        assert_eq!(
            std::fs::read(path).unwrap(),
            bytes,
            "original bytes retained"
        );
    }
    let unchanged = manager.pin(fixture.caller.clone()).await.unwrap();
    assert_eq!(unchanged.publication(), &second.publication);
    let body = unchanged
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap()
        .value
        .to_string();
    assert_eq!(body.matches("+first").count(), 1);
    assert_eq!(manager.retained_journal_count(), 2);
    manager.settle_retained().await;
    manager.stop_for_test().await;
}

/// Actual actor retry, including durable transport doubt. Canonical outcomes,
/// missing markers and a longer original prefix still cannot grant this ACK.
#[tokio::test(flavor = "current_thread")]
async fn working_append_published_retry_retains_transport_uncertainty_and_strict_exclusions() {
    use super::working_v2::{manager::WorkingManager, BindingControl};
    use crate::node::working_v2::{FirstPartyIdentity, WorkingJournal};
    for exclusion in ["none", "canonical", "marker", "prefix"] {
        let fixture = fixture().await;
        let root = tempfile::tempdir().unwrap();
        let (_, owner) = working_owner_fixture(
            &fixture,
            &fixture.base,
            &fixture.caller,
            "portable-verified-account",
        )
        .await;
        let journal =
            WorkingJournal::fixture_installed(root.path(), owner.binding_for_test()).unwrap();
        let (_binding, guard) = BindingControl::new();
        let area = ForkArea::new(root.path(), std::slice::from_ref(&fixture.path)).unwrap();
        let (manager, _control) = WorkingManager::open_shared(
            owner,
            fixture.caller.clone(),
            vec![fixture.seed.clone()],
            (area, ForkLimits::default()),
            journal.clone(),
            guard,
            "a".repeat(64),
        )
        .await
        .unwrap();
        let args = manager_append(&fixture, "published-uncertain", " RETAINED_ONCE");
        let first = manager
            .append(fixture.caller.clone(), args.clone())
            .unwrap()
            .await
            .unwrap();
        journal
            .fixture_transport_uncertain(&first.proposal_id)
            .await;
        let view = journal.capture().await.unwrap();
        assert_eq!(view.view().proposals().len(), 1);
        assert!(view.view().outcome(&first.proposal_id).unwrap().uncertain());
        assert!(!view.view().requires_reconciliation());
        drop(view);
        match exclusion {
            "canonical" => {
                // Explicit test-only canonical outcome, not authority produced
                // by W. It still needs materialization before this retry.
                journal
                    .fixture_accepted_verdict(
                        &first.proposal_id,
                        serde_json::json!({"fixture_canonical_acceptance":true}),
                    )
                    .await;
            }
            "marker" => {
                manager
                    .remove_marker_for_test(first.proposal_id.clone())
                    .await
            }
            "prefix" => {
                let proposal =
                    crate::mcp::kernel_v2::writes::replay::ReplayProposal::from_original(
                        "update_record",
                        manager_append(&fixture, "unpublished-tail", " MUST_NOT_APPEAR"),
                        Some("unpublished-tail".into()),
                        &Default::default(),
                    )
                    .unwrap();
                journal
                    .persist_original(
                        fixture.admin.clone(),
                        &proposal,
                        FirstPartyIdentity::FirstParty,
                        "a".repeat(64),
                    )
                    .await
                    .unwrap();
            }
            _ => {}
        }
        let saved = journal.fixture_entry_bytes(&first.proposal_id);
        let db = manager.native_db();
        let events: i64 = sqlx::query_scalar("SELECT count(*) FROM main.content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let before = manager
            .read(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap();
        let retry = manager
            .append(fixture.caller.clone(), args.clone())
            .unwrap()
            .await;
        if exclusion == "none" {
            let retry = retry.unwrap();
            assert_eq!(retry.proposal_id, first.proposal_id);
            assert_eq!(retry.publication, first.publication);
            assert_eq!(manager.state(), super::working_v2::WorkingState::Published);
            assert_eq!(journal.retained_count_for_test(), 1);
            assert_eq!(journal.fixture_entry_bytes(&first.proposal_id), saved);
            let unchanged = manager
                .read(fixture.caller.clone(), &fixture.seed)
                .await
                .unwrap();
            assert_eq!(unchanged, before);
            assert_eq!(unchanged.1.to_string().matches("RETAINED_ONCE").count(), 1);
            // Changed original bytes are not an exact retry, even while the
            // original's existing local publication remains retrievable.
            assert!(manager
                .append(
                    fixture.caller.clone(),
                    manager_append(&fixture, "published-uncertain", " changed")
                )
                .unwrap()
                .await
                .is_err());
            assert_eq!(journal.fixture_entry_bytes(&first.proposal_id), saved);
            // A genuinely fresh write keeps the uncertainty pause boundary.
            assert!(manager
                .append(
                    fixture.caller.clone(),
                    manager_append(&fixture, "fresh-while-uncertain", " MUST_NOT_APPEAR")
                )
                .unwrap()
                .await
                .is_err());
        } else {
            assert!(retry.is_err(), "{exclusion} cannot retrieve a new ACK");
        }
        if exclusion == "marker" {
            manager.await_retained_for_test().await;
            assert_eq!(
                manager.state(),
                super::working_v2::WorkingState::Quarantined
            );
            assert_eq!(manager.retained_count(), 1, "actual owner remains parked");
        }
        assert_eq!(journal.fixture_entry_bytes(&first.proposal_id), saved);
        let after_events: i64 = sqlx::query_scalar("SELECT count(*) FROM main.content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(after_events, events, "retry/refusal never authors an event");
        assert_eq!(
            manager
                .read(fixture.caller.clone(), &fixture.seed)
                .await
                .unwrap(),
            before
        );
        assert!(
            journal
                .capture()
                .await
                .unwrap()
                .view()
                .outcome(&first.proposal_id)
                .unwrap()
                .uncertain(),
            "transport history is never cleared"
        );
        if exclusion == "marker" {
            // Test-only settlement follows the real parked-owner and retained
            // journal/events/old-view assertions; production stays parked.
            manager.settle_retained().await;
        }
        manager.stop_for_test().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn working_append_receiver_cancel_finishes_fsync_replay_commit_and_publication() {
    use super::working_v2::manager::{TestHook, TestPoint};
    for (index, point) in [
        TestPoint::Fsynced,
        TestPoint::Replayed,
        TestPoint::Committed,
    ]
    .into_iter()
    .enumerate()
    {
        let fixture = fixture().await;
        let root = tempfile::tempdir().unwrap();
        let (manager, _control, _binding) = append_manager_fixture(&fixture, root.path()).await;
        let hook = TestHook::new(point, false, false);
        manager.set_hook(hook.clone());
        let args = manager_append(
            &fixture,
            &format!("cancel-{index}"),
            " +survives cancellation",
        );
        let mut processed = manager.processed();
        let expected_processed = *processed.borrow() + 1;
        let task = tokio::spawn(
            manager
                .append(fixture.caller.clone(), args.clone())
                .unwrap(),
        );
        hook.entered.acquire().await.unwrap().forget();
        if point == TestPoint::Replayed {
            let read_started = std::time::Instant::now();
            let old = tokio::time::timeout(
                Duration::from_secs(5),
                manager.get(fixture.caller.clone(), &fixture.seed),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!old.to_string().contains("survives cancellation"));
            eprintln!(
                "working_append_old_get_with_writer_held_us={}",
                read_started.elapsed().as_micros()
            );
        }
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        hook.release.add_permits(1);
        processed
            .wait_for(|count| *count >= expected_processed)
            .await
            .unwrap();
        // The detached owner completed without its abandoned receiver.
        // FIFO barrier: an exact retry is processed after the abandoned job,
        // and must find its ordinary receipt and installed publication.
        let retry = tokio::time::timeout(
            Duration::from_secs(10),
            manager.append(fixture.caller.clone(), args).unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(retry.publication.publication, 1);
        let get = manager
            .pin(fixture.caller.clone())
            .await
            .unwrap()
            .get(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap();
        assert_eq!(get.publication, retry.publication);
        assert_eq!(
            get.value
                .to_string()
                .matches("survives cancellation")
                .count(),
            1
        );
        assert_eq!(manager.journal_view().await.proposals().len(), 1);
        manager.stop_for_test().await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn working_append_close_and_frontier_changes_retain_view_and_fence_ack() {
    use super::working_v2::{
        manager::{TestHook, TestPoint},
        VerifiedCloseReason, WorkingState,
    };
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (manager, control, binding) = append_manager_fixture(&fixture, root.path()).await;
    let ack = manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "before-frontier", " retained pending"),
        )
        .unwrap()
        .await
        .unwrap();
    let old = manager.pin(fixture.caller.clone()).await.unwrap();
    let native = manager.native_db();
    let head = frontier(&native).await.unwrap();
    control.requires_undo();
    assert_eq!(manager.state(), WorkingState::AwaitingQualifiedUndo);
    assert!(manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "paused", " must not run")
        )
        .is_err());
    assert_eq!(old.publication(), &ack.publication);
    assert!(manager
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap()
        .to_string()
        .contains("retained pending"));
    assert_eq!(
        frontier(&native).await.unwrap(),
        head,
        "no fold or full-copy rebuild"
    );
    binding.close(VerifiedCloseReason::Revocation);
    assert!(old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .is_err());
    assert!(manager.pin(fixture.caller.clone()).await.is_err());
    manager.stop_for_test().await;
    // Close after commit is armed must fence ACK, never cancel its owner.
    let root2 = tempfile::tempdir().unwrap();
    let (manager, _control, binding) = append_manager_fixture(&fixture, root2.path()).await;
    let hook = TestHook::new(TestPoint::Committed, false, false);
    manager.set_hook(hook.clone());
    let task = tokio::spawn(
        manager
            .append(
                fixture.caller.clone(),
                manager_append(&fixture, "closed-after-commit", " committed private"),
            )
            .unwrap(),
    );
    hook.entered.acquire().await.unwrap().forget();
    let committed_head = frontier(&manager.native_db()).await.unwrap();
    binding.close(VerifiedCloseReason::SignOut);
    hook.release.add_permits(1);
    assert!(task.await.unwrap().is_err());
    assert_eq!(
        frontier(&manager.native_db()).await.unwrap(),
        committed_head
    );
    assert_eq!(manager.retained_journal_count(), 1);
    manager.settle_retained().await;
    manager.stop_for_test().await;
}

#[tokio::test(flavor = "current_thread")]
async fn working_append_failures_retain_old_snapshot_and_bounded_original_owner() {
    use super::working_v2::{
        manager::{TestHook, TestPoint},
        WorkingState,
    };
    for (point, panic) in [
        (TestPoint::Fsynced, false),
        (TestPoint::Replayed, true),
        (TestPoint::Committed, false),
    ] {
        let fixture = fixture().await;
        let root = tempfile::tempdir().unwrap();
        let (manager, _control, _binding) = append_manager_fixture(&fixture, root.path()).await;
        let old = manager.pin(fixture.caller.clone()).await.unwrap();
        let before = old
            .get(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap();
        let retained_before = manager.retained_count();
        let hook = TestHook::new(point, !panic, panic);
        manager.set_hook(hook.clone());
        let task = tokio::spawn(
            manager
                .append(
                    fixture.caller.clone(),
                    manager_append(&fixture, "boundary-failure", " unpublished effect"),
                )
                .unwrap(),
        );
        hook.entered.acquire().await.unwrap().forget();
        hook.release.add_permits(1);
        assert!(task.await.unwrap().is_err());
        assert_eq!(manager.state(), WorkingState::Quarantined);
        let fresh = manager
            .pin(fixture.caller.clone())
            .await
            .unwrap()
            .get(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap();
        assert_eq!(fresh.publication, before.publication);
        assert_eq!(fresh.value, before.value);
        assert_eq!(manager.retained_journal_count(), 1);
        assert!(manager
            .append(
                fixture.caller.clone(),
                manager_append(&fixture, "later", " must not run")
            )
            .is_err());
        if point != TestPoint::Fsynced {
            assert_eq!(manager.retained_count(), retained_before + 1);
            // Test-only acknowledged disposal of the ORIGINAL lease. This
            // does not restore permission to ACK or invent a recovery result.
            manager.settle_retained().await;
        }
        manager.stop_for_test().await;
    }
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (manager, _control, _binding) = append_manager_fixture(&fixture, root.path()).await;
    manager.fail_fsync_for_test();
    let before = manager.pin(fixture.caller.clone()).await.unwrap();
    assert!(manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "failed-sync", " never acknowledged")
        )
        .unwrap()
        .await
        .is_err());
    assert_eq!(manager.retained_journal_count(), 0);
    assert_eq!(manager.state(), WorkingState::Quarantined);
    assert_eq!(
        manager
            .pin(fixture.caller.clone())
            .await
            .unwrap()
            .publication(),
        before.publication()
    );
    manager.stop_for_test().await;
}

#[tokio::test(flavor = "current_thread")]
async fn working_append_startup_reconstructs_retained_original_before_first_view() {
    use super::working_v2::{
        manager::{TestHook, TestPoint, WorkingManager},
        BindingControl,
    };
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (manager, control, binding) = append_manager_fixture(&fixture, root.path()).await;
    let old = manager.pin(fixture.caller.clone()).await.unwrap();
    let hook = TestHook::new(TestPoint::Fsynced, true, false);
    manager.set_hook(hook.clone());
    let task = tokio::spawn(
        manager
            .append(
                fixture.caller.clone(),
                manager_append(&fixture, "restart-original", " durable before crash"),
            )
            .unwrap(),
    );
    hook.entered.acquire().await.unwrap().forget();
    hook.release.add_permits(1);
    assert!(task.await.unwrap().is_err());
    let mut stopped = manager.stopped();
    drop(manager);
    drop(control);
    stopped.wait_for(|stopped| *stopped).await.unwrap();
    // Recovery uses a separate generation area: the old complete snapshot
    // remains owned; no ordinary refresh/fold path deletes it under readers.
    let replacement = tempfile::tempdir().unwrap();
    let (_, owner) = working_owner_fixture(
        &fixture,
        &fixture.base,
        &fixture.caller,
        "portable-verified-account",
    )
    .await;
    let (_binding, guard) = BindingControl::new();
    let area = ForkArea::new(replacement.path(), std::slice::from_ref(&fixture.path)).unwrap();
    let (recovered, _control) = WorkingManager::open(
        owner,
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        (area, ForkLimits::default()),
        root.path(),
        guard,
        "a".repeat(64),
    )
    .await
    .unwrap();
    let first = recovered
        .pin(fixture.caller.clone())
        .await
        .unwrap()
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(first.publication.publication, 1);
    assert!(first.value.to_string().contains("durable before crash"));
    assert_eq!(recovered.journal_view().await.proposals().len(), 1);
    let retained_old = old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(retained_old.publication.publication, 0);
    assert!(!retained_old
        .value
        .to_string()
        .contains("durable before crash"));
    binding.close(super::working_v2::VerifiedCloseReason::AccountSwitch);
    assert!(old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .is_err());
    let (retry_future,) = crate::store::with_event_annotations(
        crate::store::EventAnnotations {
            run_key: Some("new run after restart".into()),
            parent_key: Some("new parent after restart".into()),
            intent: Some("new retry intent after restart".into()),
        },
        async {
            (recovered
                .append(
                    fixture.caller.clone(),
                    manager_append(&fixture, "restart-original", " durable before crash"),
                )
                .unwrap(),)
        },
    )
    .await;
    let ack = retry_future.await.unwrap();
    assert_eq!(ack.publication, first.publication);
    recovered.stop_for_test().await;
    drop(_control);
    // A canonical META-only advance leaves content Seq identical. The initial
    // immutable anchor must still refuse adopting this new accepted base.
    let mut before_meta = fixture.base.pool().begin().await.unwrap();
    let native_before_meta = crate::standby::kernel_v2::coordinates(&mut before_meta)
        .await
        .unwrap();
    before_meta.rollback().await.unwrap();
    let canonical = crate::db::open_kernel_v2_in_place_writer(&fixture.path)
        .await
        .unwrap();
    crate::kernel::install_package_as(
        &canonical,
        &fixture.admin,
        &crate::v2_standard::outcome_package(),
    )
    .await
    .unwrap();
    let mut after_meta = canonical.pool().begin().await.unwrap();
    let native_after_meta = crate::standby::kernel_v2::coordinates(&mut after_meta)
        .await
        .unwrap();
    after_meta.rollback().await.unwrap();
    assert_eq!(
        native_after_meta.content_event_seq,
        native_before_meta.content_event_seq
    );
    assert!(native_after_meta.meta_event_seq > native_before_meta.meta_event_seq);
    assert!(native_after_meta.head_act > native_before_meta.head_act);
    canonical.close().await;
    let (_, changed_owner) = working_owner_fixture(
        &fixture,
        &fixture.base,
        &fixture.caller,
        "portable-verified-account",
    )
    .await;
    let third = tempfile::tempdir().unwrap();
    let third_area = ForkArea::new(third.path(), std::slice::from_ref(&fixture.path)).unwrap();
    let (_third_binding, third_guard) = BindingControl::new();
    let refused = WorkingManager::open(
        changed_owner,
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        (third_area, ForkLimits::default()),
        root.path(),
        third_guard,
        "a".repeat(64),
    )
    .await;
    assert!(
        matches!(refused,Err(error) if error.to_string().contains("pinned accepted base changed")),
        "meta-only base advance cannot reuse an old anchor despite equal content Seq"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn working_append_original_scope_annotations_and_owner_are_sealed() {
    use crate::store::{with_event_annotations, EventAnnotations};
    let fixture = fixture_with_shared_note(true).await;
    let root = tempfile::tempdir().unwrap();
    let (manager, _control, _binding) = append_manager_fixture(&fixture, root.path()).await;
    let viewer = Caller::authenticated("acct:viewer");
    assert!(crate::kernel::read_record_as(
        &fixture.base,
        &crate::mcp::kernel_v2::principal(&fixture.base, &viewer)
            .await
            .unwrap(),
        &fixture.seed
    )
    .await
    .unwrap()
    .is_some());
    assert!(manager
        .append(
            viewer.clone(),
            manager_append(&fixture, "other-principal", " forbidden")
        )
        .unwrap()
        .await
        .is_err());
    assert!(
        manager.pin(viewer.clone()).await.is_err(),
        "B must not receive A's pending header even though the accepted note is shared"
    );
    assert_eq!(manager.retained_journal_count(), 0);
    let args = manager_append(&fixture, "annotation-original", " original decoration");
    let original = EventAnnotations {
        run_key: None,
        parent_key: None,
        intent: Some("exact original intent".into()),
    };
    let (future,) = with_event_annotations(original.clone(), async {
        (manager
            .append(fixture.caller.clone(), args.clone())
            .unwrap(),)
    })
    .await;
    let unrelated = EventAnnotations {
        intent: Some("unrelated detached scope".into()),
        ..Default::default()
    };
    let ack = with_event_annotations(unrelated, future).await.unwrap();
    let events: Vec<Option<String>> =
        sqlx::query_scalar("SELECT intent FROM main.content_events WHERE record_id=? AND seq>?")
            .bind(&fixture.seed)
            .bind(ack.publication.accepted_frontier)
            .fetch_all(manager.native_db().pool())
            .await
            .unwrap();
    assert!(!events.is_empty());
    assert!(events
        .iter()
        .all(|intent| intent.as_deref() == Some("exact original intent")));
    let retained = manager.journal_view().await;
    assert_eq!(retained.proposals()[0].annotations(), original);
    let journal_path = root
        .path()
        .join("working-manager-journal")
        .join("journal")
        .join(format!("{}.json", ack.proposal_id));
    let saved_original = std::fs::read(&journal_path).unwrap();
    let events_before_retry = frontier(&manager.native_db()).await.unwrap();
    let later_decoration = EventAnnotations {
        run_key: Some("different retry run".into()),
        parent_key: Some("different retry parent".into()),
        intent: Some("different retry intent".into()),
    };
    let second_client =
        Caller::authenticated("acct:admin").with_oauth_client_id(Some("retrying-client".into()));
    let (retry_future,) = with_event_annotations(later_decoration, async {
        (manager.append(second_client, args.clone()).unwrap(),)
    })
    .await;
    let retry = retry_future.await.unwrap();
    assert_eq!(retry.proposal_id, ack.proposal_id);
    assert_eq!(retry.publication, ack.publication);
    assert_eq!(
        frontier(&manager.native_db()).await.unwrap(),
        events_before_retry,
        "exact retry emits no native event or replacement decoration"
    );
    assert_eq!(
        std::fs::read(&journal_path).unwrap(),
        saved_original,
        "exact retry never rewrites retained original bytes"
    );
    let after_retry = manager.journal_view().await;
    assert_eq!(after_retry.revision(), retained.revision());
    assert_eq!(after_retry.proposals()[0].annotations(), original);
    let claim = crate::mcp::app_attribution::AppAttribution::new(
        "example.working-scope",
        "1.0.0",
        "working-install",
    )
    .unwrap();
    let scoped = fixture.caller.clone().with_host_asserted_app(claim);
    let dispatch =
        crate::provenance::ProvenanceDispatch::from_caller(&scoped, "update_record", &args, None);
    let refused = dispatch
        .scope(async {
            manager.append(
                fixture.caller.clone(),
                manager_append(&fixture, "app-scope", " forbidden"),
            )
        })
        .await;
    assert!(
        refused.is_err(),
        "provider must inspect original ambient app scope synchronously"
    );
    assert_eq!(manager.journal_view().await.revision(), retained.revision());
    // The fixture outcome is canonical ONLY by test setup. No runtime writer
    // can create this verdict, and its payload must remain retained.
    manager.fixture_refused_verdict(&ack.proposal_id).await;
    assert!(manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "after-refusal", " held, no ACK")
        )
        .unwrap()
        .await
        .is_err());
    assert_eq!(
        manager.state(),
        super::working_v2::WorkingState::AwaitingQualifiedUndo
    );
    let view = manager.journal_view().await;
    assert!(view.has_hosted_verdict());
    assert_eq!(view.proposals()[0].arguments(), &args);
    assert!(manager
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap()
        .to_string()
        .contains("original decoration"));
    manager.stop_for_test().await;
}

/// Actual manager caller of the retained writer and trusted fold. The trust
/// mint is fixture-only; installed observer/transport qualification is separate.
#[tokio::test(flavor = "current_thread")]
async fn working_frontier_materialized_prefix_replays_tail_and_first_get_after_next_ack() {
    working_frontier_case(true, None).await;
}
#[tokio::test(flavor = "current_thread")]
async fn working_frontier_materialization_before_queue_answer_does_not_strand_typing() {
    working_frontier_case(false, None).await;
}
#[tokio::test(flavor = "current_thread")]
async fn working_frontier_completed_before_active_retains_view_without_new_ack() {
    working_frontier_case(false, Some(true)).await;
}
#[tokio::test(flavor = "current_thread")]
async fn working_frontier_in_progress_before_active_waits_actual_native_packet() {
    working_frontier_case(true, Some(false)).await;
}
#[tokio::test]
async fn working_frontier_known_no_publication_resumes_editing_but_unknown_stays_paused() {
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (_, owner) = working_owner_fixture(
        &fixture,
        &fixture.base,
        &fixture.caller,
        "portable-verified-account",
    )
    .await;
    let journal = crate::node::working_v2::WorkingJournal::fixture_installed(
        root.path(),
        owner.binding_for_test(),
    )
    .unwrap();
    let (_binding, guard) = super::working_v2::BindingControl::new();
    let area = ForkArea::new(root.path(), std::slice::from_ref(&fixture.path)).unwrap();
    let (manager, control) = super::working_v2::manager::WorkingManager::open_shared(
        owner,
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        (area, ForkLimits::default()),
        journal,
        guard,
        "a".repeat(64),
    )
    .await
    .unwrap();
    let first = manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "unchanged-A", " UNCHANGED_A"),
        )
        .unwrap()
        .await
        .unwrap();
    let before = manager
        .read(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    let wait = control.awaiting_materialization().unwrap();
    assert_eq!(
        manager
            .read(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap(),
        before
    );
    control.no_publication(wait);
    let second = tokio::time::timeout(
        Duration::from_secs(10),
        manager
            .append(
                fixture.caller.clone(),
                manager_append(&fixture, "unchanged-B", " UNCHANGED_B"),
            )
            .unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        second.publication.accepted_frontier,
        first.publication.accepted_frontier
    );
    let fresh = manager
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(fresh.to_string().matches("UNCHANGED_A").count(), 1);
    assert_eq!(fresh.to_string().matches("UNCHANGED_B").count(), 1);
    let before_unknown = manager
        .read(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    let stale_wait = control.awaiting_materialization().unwrap();
    control.requires_undo(); // Uncertain/missing handoff supersedes the known attempt.
    control.no_publication(stale_wait);
    assert_eq!(
        manager.state(),
        super::working_v2::WorkingState::AwaitingQualifiedUndo
    );
    assert!(manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "unchanged-C", " must not ACK")
        )
        .is_err());
    assert_eq!(
        manager
            .read(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap(),
        before_unknown
    );
    assert_eq!(manager.retained_journal_count(), 2);
    manager.stop_for_test().await;
}

async fn working_frontier_case(answer_first: bool, early: Option<bool>) {
    use crate::mcp::kernel_v2::writes::replay;
    use crate::standby::{kernel_v2, kernel_v2_delta, AcceptedKernelDelta};
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (_, owner) = working_owner_fixture(
        &fixture,
        &fixture.base,
        &fixture.caller,
        "portable-verified-account",
    )
    .await;
    let journal = crate::node::working_v2::WorkingJournal::fixture_installed(
        root.path(),
        owner.binding_for_test(),
    )
    .unwrap();
    let (_binding, guard) = super::working_v2::BindingControl::new();
    let area = ForkArea::new(root.path(), std::slice::from_ref(&fixture.path)).unwrap();
    let (manager, control) = super::working_v2::manager::WorkingManager::open_shared(
        owner,
        fixture.caller.clone(),
        vec![fixture.seed.clone()],
        (area, ForkLimits::default()),
        journal,
        guard,
        "a".repeat(64),
    )
    .await
    .unwrap();
    let a = manager_append(&fixture, "frontier-A", " FRONTIER_A");
    let b = manager_append(&fixture, "frontier-B", " FRONTIER_B");
    let first = manager
        .append(fixture.caller.clone(), a.clone())
        .unwrap()
        .await
        .unwrap();
    manager
        .append(fixture.caller.clone(), b.clone())
        .unwrap()
        .await
        .unwrap();
    let readonly = manager.native_db();
    let mut rejected = readonly.pool().begin().await.unwrap();
    assert!(
        crate::standby::kernel_v2::coordinates(&mut rejected)
            .await
            .is_err(),
        "populated private W is never an accepted native generation"
    );
    rejected.rollback().await.unwrap();
    let old = manager.pin(fixture.caller.clone()).await.unwrap();
    let before = old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    let anchor_path = root.path().join("working-manager-journal/pinned-base.json");
    let anchor = std::fs::read(&anchor_path).unwrap();
    let mut initial = fixture.base.pool().begin().await.unwrap();
    let native_before = kernel_v2::coordinates(&mut initial).await.unwrap();
    initial.rollback().await.unwrap();
    let f1 = manager.accepted_act().await.unwrap();
    // Canonical A is actually replayed/committed on the accepted native source.
    // No fabricated request fingerprint, local receipt or second fold engine.
    let canonical = crate::db::open_kernel_v2_in_place_writer(&fixture.path)
        .await
        .unwrap();
    let proposal = replay::ReplayProposal::from_original(
        "update_record",
        a.clone(),
        Some("frontier-A".into()),
        &Default::default(),
    )
    .unwrap();
    let mut tx = crate::db::begin_write(canonical.write_pool())
        .await
        .unwrap();
    let answer = replay::replay_write_in_transaction(
        &canonical,
        &mut tx,
        &replay::ReplayCaller {
            actor: fixture.admin.clone(),
            mint: Default::default(),
        },
        &proposal,
        &replay::ReplaySavepoint::claim(),
    )
    .await
    .unwrap();
    let replay::ReplayOutcome::Applied {
        receipt: canonical_receipt,
        ..
    } = answer
    else {
        panic!("canonical replay refused");
    };
    canonical.commit_kernel_content(tx).await.unwrap();
    let mut canonical_cut = canonical.pool().begin().await.unwrap();
    let native_wire = kernel_v2_delta::cut_versioned(
        &mut canonical_cut,
        f1,
        &[],
        kernel_v2_delta::WIRE_VERSION_3,
    )
    .await
    .unwrap();
    let delta = kernel_v2_delta::TrustedKernelDelta::assume_trusted_for_test(native_wire).unwrap();
    canonical_cut.rollback().await.unwrap();
    let verified_native_act = delta.delta().head.head_act;
    let accepted = AcceptedKernelDelta::fixture_materialized(
        "fixture-source".into(),
        "fixture-accepted".into(),
        native_before,
        delta,
    )
    .unwrap();
    let mut queued_c = None;
    let mut c_started = None;
    match early {
        Some(true) => {
            crate::node::working_v2::fixture_enrollment_before_active(&control, Some(accepted));
            assert!(manager
                .append(
                    fixture.caller.clone(),
                    manager_append(&fixture, "early-C", " no ACK after missed publication")
                )
                .is_err());
            assert_eq!(
                manager.state(),
                super::working_v2::WorkingState::AwaitingQualifiedUndo
            );
            let still = manager
                .read(fixture.caller.clone(), &fixture.seed)
                .await
                .unwrap();
            assert_eq!(still, (before.publication, before.value));
            assert_eq!(manager.retained_journal_count(), 2);
            manager.stop_for_test().await;
            canonical.close().await;
            return;
        }
        Some(false) => {
            crate::node::working_v2::fixture_enrollment_before_active(&control, None);
            let hook = super::working_v2::manager::TestHook::new(
                super::working_v2::manager::TestPoint::NativeWait,
                false,
                false,
            );
            manager.set_hook(hook.clone());
            c_started = Some(std::time::Instant::now());
            let task = tokio::spawn(
                manager
                    .append(
                        fixture.caller.clone(),
                        manager_append(&fixture, "frontier-C", " FRONTIER_C"),
                    )
                    .unwrap(),
            );
            hook.entered.acquire().await.unwrap().forget();
            assert!(
                !task.is_finished(),
                "owned C cannot ACK while native publication is in progress"
            );
            assert_eq!(
                manager.retained_journal_count(),
                2,
                "C is still waiting before fsync, no saved claim"
            );
            hook.release.add_permits(1);
            queued_c = Some(task);
        }
        None => (),
    }
    if answer_first {
        manager
            .fixture_accepted_verdict(&first.proposal_id, canonical_receipt.clone())
            .await;
    }
    let folded = if answer_first {
        None
    } else {
        let hook = super::working_v2::manager::TestHook::new(
            super::working_v2::manager::TestPoint::ReconcileCommitted,
            false,
            false,
        );
        manager.set_hook(hook.clone());
        Some(hook)
    };
    control.accepted_kernel(accepted);
    manager.observe_serving_act(verified_native_act).await;
    if let Some(folded) = folded {
        folded.entered.acquire().await.unwrap().forget();
        manager.observe_serving_act(verified_native_act).await;
        folded.release.add_permits(1);
        // Mutation waits on the same journal turn held by reconciliation, so
        // this answer is DURABLE strictly after the actual trusted fold.
        manager
            .fixture_accepted_verdict(&first.proposal_id, canonical_receipt)
            .await;
        control.canonical_changed();
    }
    let client_two = Caller::authenticated("acct:admin")
        .with_oauth_client_id(Some("second-frontier-client".into()));
    let started = c_started.unwrap_or_else(std::time::Instant::now);
    let ack = if let Some(task) = queued_c {
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
    } else {
        let c = manager
            .append(
                client_two.clone(),
                manager_append(&fixture, "frontier-C", " FRONTIER_C"),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), c)
            .await
            .unwrap()
            .unwrap()
    };
    eprintln!(
        "working_frontier_C_ingress_to_ack_us={}",
        started.elapsed().as_micros()
    );
    let first_get = std::time::Instant::now();
    // FIRST ordinary native Get after ACK, no polling/readiness/sleep/retry.
    let fresh = manager
        .read(client_two.clone(), &fixture.seed)
        .await
        .unwrap();
    eprintln!(
        "working_frontier_first_get_us={}",
        first_get.elapsed().as_micros()
    );
    assert_eq!(fresh.0, ack.publication);
    assert_eq!(
        ack.publication.publication,
        if answer_first { 4 } else { 5 },
        "reconcile/outcome refresh have publications, not proposal ordinals"
    );
    assert_eq!(manager.published_prefix().await.unwrap(), 3);
    for text in ["FRONTIER_A", "FRONTIER_B", "FRONTIER_C"] {
        assert_eq!(fresh.1.to_string().matches(text).count(), 1);
    }
    assert!(ack.publication.accepted_frontier > before.publication.accepted_frontier);
    let retained = old.get(client_two.clone(), &fixture.seed).await.unwrap();
    assert_eq!(retained.publication, before.publication);
    assert_eq!(retained.value, before.value);
    let retry = manager.append(client_two, b).unwrap().await.unwrap();
    assert_eq!(retry.publication, ack.publication);
    assert_eq!(manager.journal_view().await.proposals().len(), 3);
    assert_eq!(
        std::fs::read(anchor_path).unwrap(),
        anchor,
        "never overwrite original accepted-base provenance"
    );
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM main._native_working_bases")
        .fetch_one(manager.native_db().pool())
        .await
        .unwrap();
    assert_eq!(
        rows,
        if answer_first { 5 } else { 6 },
        "old per-publication capabilities remain bound to their own snapshot"
    );
    for pool in [
        manager.native_db().pool(),
        manager.native_db().write_pool(),
        manager.native_db().governed_pool(),
    ] {
        assert!(sqlx::query("CREATE TABLE forbidden_second_writer(v)")
            .execute(pool)
            .await
            .is_err());
    }
    if !answer_first {
        // A newer outcome command already installed the current revision. An
        // intentionally delayed OLD wake may not strand the next actual edit.
        manager.observe_serving_act(verified_native_act).await;
        manager.stale_wake_for_test(1);
        let d = manager
            .append(
                fixture.caller.clone(),
                manager_append(&fixture, "frontier-D", " FRONTIER_D"),
            )
            .unwrap();
        let next = tokio::time::timeout(Duration::from_secs(10), d)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            next.publication.publication,
            ack.publication.publication + 1
        );
        let next_first_get = manager
            .get(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap();
        for text in ["FRONTIER_A", "FRONTIER_B", "FRONTIER_C", "FRONTIER_D"] {
            assert_eq!(next_first_get.to_string().matches(text).count(), 1);
        }
    }
    manager.stop_for_test().await;
    canonical.close().await;
}

/// The actual manager, not just the owner prototype, must retain its original
/// borrowed wrapper when the existing native commit classifier is uncertain.
#[tokio::test(flavor = "current_thread")]
async fn working_frontier_actual_manager_uncertain_commit_keeps_old_view_and_stops_ack() {
    use super::working_v2::{
        manager::{TestHook, TestPoint},
        WorkingState,
    };
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (manager, _control, _binding) = append_manager_fixture(&fixture, root.path()).await;
    let old = manager.pin(fixture.caller.clone()).await.unwrap();
    let before = old
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    let hook = TestHook::new(TestPoint::Replayed, false, false);
    manager.set_hook(hook.clone());
    let task = tokio::spawn(
        manager
            .append(
                fixture.caller.clone(),
                manager_append(&fixture, "actual-manager-uncertain", " not yet published"),
            )
            .unwrap(),
    );
    hook.entered.acquire().await.unwrap().forget();
    let native = manager.native_db();
    let worker = crate::coedit::live::kernel_writes::pause_commit_worker_for_test(&native);
    let gate = crate::coedit::live::kernel_writes::test_gate(
        &native,
        crate::coedit::live::kernel_writes::TestStage::BorrowedCommitPending,
        true,
    );
    hook.release.add_permits(1);
    worker.entered().await;
    gate.entered.notified().await;
    gate.release.notify_one();
    let error = task.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("commit not established"));
    assert_eq!(manager.state(), WorkingState::Quarantined);
    assert_eq!(manager.retained_count(), 1);
    assert_eq!(manager.retained_journal_count(), 1);
    let after = manager
        .get(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(
        after, before.value,
        "first ordinary fresh read still uses complete old publication"
    );
    assert_eq!(
        old.get(fixture.caller.clone(), &fixture.seed)
            .await
            .unwrap()
            .publication,
        before.publication
    );
    assert!(manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "after-uncertain", " forbidden ACK")
        )
        .is_err());
    assert_eq!(
        manager.retained_journal_count(),
        1,
        "no next original admitted after uncertainty"
    );
    worker.release();
    manager.settle_retained().await;
    manager.stop_for_test().await;
}

#[tokio::test(flavor = "current_thread")]
async fn working_frontier_notification_overflow_is_terminal_after_owned_commit_and_drain() {
    use super::working_v2::{
        manager::{TestHook, TestPoint},
        WorkingState,
    };
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (manager, control, _binding) = append_manager_fixture(&fixture, root.path()).await;
    let before = manager
        .read(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    let hook = TestHook::new(TestPoint::Replayed, false, false);
    manager.set_hook(hook.clone());
    let task = tokio::spawn(
        manager
            .append(
                fixture.caller.clone(),
                manager_append(
                    &fixture,
                    "terminal-overflow",
                    " never acknowledged after overflow",
                ),
            )
            .unwrap(),
    );
    hook.entered.acquire().await.unwrap().forget();
    for _ in 0..17 {
        control.canonical_changed();
    }
    assert_eq!(manager.state(), WorkingState::Quarantined);
    hook.release.add_permits(1);
    assert!(
        task.await.unwrap().is_err(),
        "settled native COMMIT cannot restore ACK permission"
    );
    manager.drain_notifications_for_test().await;
    assert_eq!(
        manager.state(),
        WorkingState::Quarantined,
        "queued older notices cannot resurrect Published"
    );
    let first = manager
        .read(fixture.caller.clone(), &fixture.seed)
        .await
        .unwrap();
    assert_eq!(
        first, before,
        "old complete native view remains installed after terminal drain"
    );
    assert!(manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "after-terminal", " no later ACK")
        )
        .is_err());
    assert_eq!(manager.retained_journal_count(), 1);
    manager.stop_for_test().await;
}

#[tokio::test(flavor = "current_thread")]
async fn working_append_discovery_same_publication_keeps_old_pin_and_writer_progress() {
    use super::working_v2::manager::{TestHook, TestPoint};
    let fixture = fixture().await;
    let root = tempfile::tempdir().unwrap();
    let (manager, _control, close) = append_manager_fixture(&fixture, root.path()).await;
    let second =
        Caller::authenticated("acct:admin").with_oauth_client_id(Some("discovery-second".into()));
    let list = serde_json::json!({"steps":[{"step":"filter","types":["Document"],"kinds":["note"]}],"projection":"metadata","limit":50});
    let search = serde_json::json!({"query":"discoveryuniquefirst","limit":20});
    let old = manager.discovery_pin_for_test().await;
    assert!(old
        .query(
            Caller::authenticated("acct:viewer"),
            "query_record",
            list.clone()
        )
        .await
        .is_err());
    assert!(old
        .query(
            second.clone(),
            "query_record",
            serde_json::json!({"steps":[]})
        )
        .await
        .is_err());
    let accepted = old
        .query(second.clone(), "query_record", list.clone())
        .await
        .unwrap();
    assert!(accepted.value["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == fixture.seed));
    assert!(old
        .query(second.clone(), "search", search.clone())
        .await
        .unwrap()
        .value["hits"]
        .as_array()
        .unwrap()
        .is_empty());
    let first = manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "discovery-first", " discoveryuniquefirst"),
        )
        .unwrap()
        .await
        .unwrap();
    let fresh = manager
        .discover(second.clone(), "search", search.clone())
        .await
        .unwrap();
    assert_eq!(fresh.0, first.publication);
    assert_eq!(fresh.1["hits"][0]["id"], fixture.seed);
    let current = manager
        .discover(second.clone(), "query_record", list.clone())
        .await
        .unwrap();
    assert_eq!(current.0, first.publication);
    assert_eq!(current.1["total"], accepted.value["total"]);
    let hook = TestHook::new(TestPoint::Replayed, false, false);
    manager.set_hook(hook.clone());
    let append = tokio::spawn(
        manager
            .append(
                second.clone(),
                manager_append(&fixture, "discovery-second", " discoveryuniquesecond"),
            )
            .unwrap(),
    );
    hook.entered.acquire().await.unwrap().forget();
    let held = tokio::time::timeout(
        Duration::from_secs(5),
        manager.discover(second.clone(), "search", search.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(held.0, first.publication);
    assert_eq!(held.1, fresh.1);
    hook.release.add_permits(1);
    let next = append.await.unwrap().unwrap();
    let next_search = manager
        .discover(
            second.clone(),
            "search",
            serde_json::json!({"query":"discoveryuniquesecond"}),
        )
        .await
        .unwrap();
    assert_eq!(next_search.0, next.publication);
    assert_eq!(next_search.1["hits"][0]["id"], fixture.seed);
    assert!(old
        .query(second.clone(), "search", search)
        .await
        .unwrap()
        .value["hits"]
        .as_array()
        .unwrap()
        .is_empty());
    let old_list = old
        .query(second.clone(), "query_record", list.clone())
        .await
        .unwrap();
    assert_eq!(old_list.publication, accepted.publication);
    assert_eq!(old_list.value, accepted.value);
    let app = second.clone().with_host_asserted_app(
        crate::mcp::app_attribution::AppAttribution::new("agent.docs", "1", "fixture-install")
            .unwrap(),
    );
    assert!(manager
        .discover(app, "query_record", list.clone())
        .await
        .is_err());
    close.close(super::working_v2::VerifiedCloseReason::AccountSwitch);
    assert!(old.query(second, "query_record", list).await.is_err());
    manager.stop_for_test().await;
}

/// Shared record-family replay uses the ordinary native handlers and one
/// publication across two record kinds, with request-local Get staging.
#[tokio::test(flavor = "current_thread")]
async fn working_records_one_workspace_native_edits_links_and_pinned_reads() {
    use super::working_v2::{manager::WorkingManager, BindingControl};
    use crate::mcp::kernel_v2::writes::replay::RecordOperation as Op;
    use crate::node::working_v2::WorkingJournal;
    let fixture = fixture_with_shared_note(true).await;
    let root = tempfile::tempdir().unwrap();
    let (_, owner) = working_owner_fixture(
        &fixture,
        &fixture.base,
        &fixture.caller,
        "portable-verified-account",
    )
    .await;
    let journal = WorkingJournal::fixture_installed(root.path(), owner.binding_for_test()).unwrap();
    let (close, guard) = BindingControl::new();
    let area = ForkArea::new(root.path(), std::slice::from_ref(&fixture.path)).unwrap();
    let (manager, _) = WorkingManager::open_workspace_shared(
        owner,
        fixture.caller.clone(),
        (area, ForkLimits::default()),
        journal.clone(),
        guard,
        ("a".repeat(64), None),
    )
    .await
    .unwrap();
    let second = fixture
        .caller
        .clone()
        .with_oauth_client_id(Some("record-family-second".into()));
    let old = manager.pin(second.clone()).await.unwrap();
    let old_seed = old.get(second.clone(), &fixture.seed).await.unwrap();
    let old_task = old.get(second.clone(), &fixture.task).await.unwrap();
    assert_eq!(old_task.value["records"][0]["type"], "WorkItem");
    assert_eq!(
        old.get(second.clone(), &fixture.seed).await.unwrap().value,
        old_seed.value,
        "sequential different-id staging must not contaminate an earlier request"
    );
    manager
        .append(
            fixture.caller.clone(),
            manager_append(&fixture, "family-note-legacy-append", " FAMILY_NOTE_APPEND"),
        )
        .unwrap()
        .await
        .unwrap();
    let edit = serde_json::json!({"id":fixture.task,"name":"Family task renamed","body_set":"familytaskunique content","summary":"local metadata","home_id":fixture.home,"reason":"Shared native record family","idempotency_key":"family-task-edit"});
    let capture =
        WorkingManager::capture_record_original(second.clone(), Op::Update, edit.clone()).unwrap();
    let first = manager.append_original(capture).unwrap().await.unwrap();
    let (publication, read) = manager
        .read_arguments(
            second.clone(),
            serde_json::json!({"ids":[fixture.seed,fixture.task]}),
        )
        .await
        .unwrap();
    assert_eq!(publication, first.publication);
    let records = read["records"].as_array().unwrap();
    let task = records.iter().find(|r| r["id"] == fixture.task).unwrap();
    assert_eq!(task["name"], "Family task renamed");
    assert_eq!(task["body"], "familytaskunique content");
    assert_eq!(task["home_id"], fixture.home);
    let retained = journal
        .capture()
        .await
        .unwrap()
        .view()
        .revision()
        .to_owned();
    let retry = manager
        .append_original(
            WorkingManager::capture_record_original(
                fixture.caller.clone(),
                Op::Update,
                edit.clone(),
            )
            .unwrap(),
        )
        .unwrap()
        .await
        .unwrap();
    assert_eq!(retry.proposal_id, first.proposal_id);
    assert_eq!(retry.publication, first.publication);
    assert_eq!(journal.capture().await.unwrap().view().revision(), retained);
    let mut changed = edit;
    changed["name"] = serde_json::json!("different bytes");
    assert!(manager
        .append_original(
            WorkingManager::capture_record_original(second.clone(), Op::Update, changed).unwrap()
        )
        .unwrap()
        .await
        .is_err());
    let add = serde_json::json!({"source_id":fixture.seed,"target_id":fixture.task,"relationship":"mentions","note":"family link","idempotency_key":"family-link"});
    let linked = manager
        .append_original(
            WorkingManager::capture_record_original(second.clone(), Op::LinkAdd, add.clone())
                .unwrap(),
        )
        .unwrap()
        .await
        .unwrap();
    let (_, link_view) = manager
        .read_arguments(
            second.clone(),
            serde_json::json!({"ids":[fixture.seed],"links_limit":50}),
        )
        .await
        .unwrap();
    assert!(link_view["records"][0]["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .any(|link| link["target_id"] == fixture.task && link["relationship"] == "mentions"));
    assert_eq!(
        old.get(second.clone(), &fixture.task).await.unwrap().value,
        old_task.value,
        "old publication remains a native snapshot"
    );
    assert_eq!(
        old.get(second.clone(), &fixture.seed).await.unwrap().value,
        old_seed.value
    );
    let mut remove = add;
    remove.as_object_mut().unwrap().remove("note");
    let collision = manager
        .append_original(
            WorkingManager::capture_record_original(second.clone(), Op::LinkRemove, remove.clone())
                .unwrap(),
        )
        .unwrap()
        .await;
    assert!(
        matches!(collision, Err(crate::Error::Conflict(_))),
        "native manage_links key ownership spans add/remove selectors"
    );
    remove["idempotency_key"] = serde_json::json!("family-unlink");
    manager
        .append_original(
            WorkingManager::capture_record_original(second.clone(), Op::LinkRemove, remove)
                .unwrap(),
        )
        .unwrap()
        .await
        .unwrap();
    let (_, removed_view) = manager.read(second.clone(), &fixture.seed).await.unwrap();
    assert!(!removed_view["records"][0]["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .any(|link| link["target_id"] == fixture.task && link["relationship"] == "mentions"));
    for (archived, key) in [(true, "family-archive"), (false, "family-restore")] {
        let ack=manager.append_original(WorkingManager::capture_record_original(second.clone(),Op::Archive,serde_json::json!({"id":fixture.task,"archived":archived,"reason":"Reversible native archive","idempotency_key":key})).unwrap()).unwrap().await.unwrap();
        assert!(ack.publication.publication > linked.publication.publication);
        let (_, view) = manager.read(second.clone(), &fixture.task).await.unwrap();
        assert_eq!(view["records"][0]["archived"], archived);
    }
    let (_, search) = manager
        .discover(
            second.clone(),
            "search",
            serde_json::json!({"query":"familytaskunique"}),
        )
        .await
        .unwrap();
    assert_eq!(search["hits"][0]["id"], fixture.task);
    let (_,list)=manager.discover(second.clone(),"query_record",serde_json::json!({"steps":[{"step":"filter","types":["Document","WorkItem"]}],"projection":"metadata","limit":50})).await.unwrap();
    assert!(list["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == fixture.seed));
    assert!(list["records"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == fixture.task));
    assert!(manager
        .read(Caller::authenticated("acct:viewer"), &fixture.seed)
        .await
        .is_err());
    close.close(super::working_v2::VerifiedCloseReason::AccountSwitch);
    assert!(old.get(second, &fixture.seed).await.is_err());
    manager.stop_for_test().await;
}

/// Every common format9 family is accepted through the real native writer,
/// then one trusted kernel packet removes the accepted prefix and replays the
/// other record's pending tail. Receipt ordering cannot require a fake delta.
#[tokio::test(flavor = "current_thread")]
async fn working_records_accepted_family_prefix_replays_tail_and_late_answers() {
    for answer_first in [true, false] {
        working_records_frontier_case(answer_first, false).await;
    }
}

#[tokio::test(flavor = "current_thread")]
async fn working_restart_grounded_accepted_cut_retains_family_tail_and_next_write() {
    working_records_frontier_case(true, true).await;
}

async fn working_records_frontier_case(answer_first: bool, restart: bool) {
    use super::working_v2::{manager::WorkingManager, BindingControl};
    use crate::mcp::kernel_v2::writes::replay::{self, RecordOperation as Op};
    use crate::node::working_v2::WorkingJournal;
    use crate::standby::{kernel_v2, kernel_v2_delta, AcceptedKernelDelta};
    let f = fixture_with_shared_note(true).await;
    let root = tempfile::tempdir().unwrap();
    let (_, owner) =
        working_owner_fixture(&f, &f.base, &f.caller, "portable-verified-account").await;
    let mut journal =
        WorkingJournal::fixture_installed(root.path(), owner.binding_for_test()).unwrap();
    let (_close, guard) = BindingControl::new();
    let area_id = Uuid::new_v4().to_string();
    let area = if restart {
        let parent = root.path().join(&area_id);
        std::fs::create_dir(&parent).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        journal = journal
            .with_location_scope(root.path().to_owned(), area_id.clone())
            .unwrap();
        ForkArea::new(&parent, std::slice::from_ref(&f.path)).unwrap()
    } else {
        ForkArea::new(root.path(), std::slice::from_ref(&f.path)).unwrap()
    };
    let (manager, control) = WorkingManager::open_workspace_shared(
        owner,
        f.caller.clone(),
        (area, ForkLimits::default()),
        journal.clone(),
        guard,
        ("a".repeat(64), None),
    )
    .await
    .unwrap();
    // The retained-restart arm also proves fresh-copy source custody ends
    // before the first original: the real source writer can enter WAL while
    // the new private W remains owned. No canonical event has been added yet.
    let fresh_source_writer = if restart {
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(f.base.pool())
            .await
            .unwrap();
        assert_eq!(mode, "delete");
        let writer = crate::db::open_kernel_v2_in_place_writer(&f.path)
            .await
            .unwrap();
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(writer.pool())
            .await
            .unwrap();
        assert_eq!(mode, "wal");
        assert_eq!(journal.capture().await.unwrap().view().proposals().len(), 0);
        Some(writer)
    } else {
        None
    };
    // This native-only fixture has no imported Unfiled selector. Move
    // between its actual homes; the installed proof covers Root redirection.
    let (_, initial_task) = manager.read(f.caller.clone(), &f.task).await.unwrap();
    assert_ne!(initial_task["records"][0]["home_id"], f.home);
    let operations = vec![
        (
            Op::Update,
            serde_json::json!({"id":f.task,"name":"Accepted family task","summary":"accepted metadata","body_set":"acceptedfamilybody","home_id":f.home,"reason":"Native family frontier","idempotency_key":"family-frontier-edit"}),
        ),
        (
            Op::Archive,
            serde_json::json!({"id":f.task,"archived":true,"reason":"Native family frontier","idempotency_key":"family-frontier-archive"}),
        ),
        (
            Op::Archive,
            serde_json::json!({"id":f.task,"archived":false,"reason":"Native family frontier","idempotency_key":"family-frontier-restore"}),
        ),
        (
            Op::Archive,
            serde_json::json!({"id":f.task,"archived":false,"reason":"Explicit native no-op","idempotency_key":"family-frontier-noop"}),
        ),
        (
            Op::LinkAdd,
            serde_json::json!({"source_id":f.seed,"target_id":f.task,"relationship":"mentions","note":"accepted link","idempotency_key":"family-frontier-add"}),
        ),
        (
            Op::LinkRemove,
            serde_json::json!({"source_id":f.seed,"target_id":f.task,"relationship":"mentions","idempotency_key":"family-frontier-remove"}),
        ),
    ];
    for (op, args) in &operations {
        manager
            .append_original(
                WorkingManager::capture_record_original(f.caller.clone(), *op, args.clone())
                    .unwrap(),
            )
            .unwrap()
            .await
            .unwrap();
    }
    let b = manager_append(&f, "family-frontier-pending", " FAMILY_PENDING_B");
    let b_ack = manager
        .append(f.caller.clone(), b.clone())
        .unwrap()
        .await
        .unwrap();
    let old = manager.pin(f.caller.clone()).await.unwrap();
    let old_body = old.get(f.caller.clone(), &f.seed).await.unwrap();
    let originals = journal.capture().await.unwrap().view().proposals().to_vec();
    let canonical = match fresh_source_writer {
        Some(writer) => writer,
        None => crate::db::open_kernel_v2_in_place_writer(&f.path)
            .await
            .unwrap(),
    };
    let mut start = canonical.pool().begin().await.unwrap();
    let before = kernel_v2::coordinates(&mut start).await.unwrap();
    start.rollback().await.unwrap();
    let mut receipts = Vec::new();
    let mut packets = Vec::new();
    let mut lower = before.clone();
    for (index, (op, _)) in operations.iter().enumerate() {
        let ticket = &originals[index];
        let proposal = replay::ReplayProposal::from_original(
            ticket.operation(),
            ticket.arguments().clone(),
            ticket.arguments()["idempotency_key"]
                .as_str()
                .map(str::to_owned),
            &Default::default(),
        )
        .unwrap();
        let mut tx = crate::db::begin_write(canonical.write_pool())
            .await
            .unwrap();
        let result = replay::replay_record_in_transaction(
            &canonical,
            &mut tx,
            &replay::ReplayCaller {
                actor: f.admin.clone(),
                mint: Default::default(),
            },
            &proposal,
            &replay::ReplaySavepoint::claim(),
            *op,
            None,
        )
        .await
        .unwrap();
        let replay::ReplayOutcome::Applied { receipt, .. } = result else {
            panic!("canonical family refused: {result:?}")
        };
        let (seq, act):(i64,i64)=sqlx::query_as("SELECT seq,act FROM main.content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1").bind(crate::kernel::mcp_write_receipts::STREAM).bind(crate::kernel::mcp_write_receipts::EVENT).fetch_one(&mut *tx).await.unwrap();
        assert!(replay::record_materialized_on(
            &mut tx,
            &f.admin,
            *op,
            ticket.arguments(),
            &receipt,
            seq,
            act
        )
        .await
        .unwrap());
        let mut wrong = receipt.clone();
        wrong["id"] = serde_json::json!(f.home);
        assert!(replay::record_materialized_on(
            &mut tx,
            &f.admin,
            *op,
            ticket.arguments(),
            &wrong,
            seq,
            act
        )
        .await
        .is_err());
        if index == 0 {
            let mut wrong = ticket.arguments().clone();
            wrong["summary"] = serde_json::json!("not the native effect");
            assert!(replay::record_materialized_on(
                &mut tx, &f.admin, *op, &wrong, &receipt, seq, act
            )
            .await
            .is_err());
            // Keep the native log immutable. A receipt naming a missing
            // native event is insufficient effect evidence on this same cut.
            let missing_id = uuid::Uuid::new_v4().to_string();
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE id=?)")
                    .bind(&missing_id)
                    .fetch_one(&mut *tx)
                    .await
                    .unwrap();
            assert!(!exists);
            let mut missing = receipt.clone();
            missing["write_receipt"]["event"]["event_id"] = serde_json::json!(missing_id);
            assert!(replay::record_materialized_on(
                &mut tx,
                &f.admin,
                *op,
                ticket.arguments(),
                &missing,
                seq,
                act
            )
            .await
            .is_err());
        }
        if index == 3 {
            assert_eq!(receipt["changed"], false);
        }
        canonical.commit_kernel_content(tx).await.unwrap();
        receipts.push(receipt);
        if answer_first && (index == 1 || index == 3 || index + 1 == operations.len()) {
            let mut cut = canonical.pool().begin().await.unwrap();
            let wire = kernel_v2_delta::cut_versioned(
                &mut cut,
                lower.head_act,
                &[],
                kernel_v2_delta::WIRE_VERSION_3,
            )
            .await
            .unwrap();
            cut.rollback().await.unwrap();
            let delta = kernel_v2_delta::TrustedKernelDelta::assume_trusted_for_test(wire).unwrap();
            let next_lower = delta.delta().head.generation.clone();
            packets.push(
                AcceptedKernelDelta::fixture_materialized(
                    "fixture-source".into(),
                    "fixture-accepted".into(),
                    lower,
                    delta,
                )
                .unwrap(),
            );
            lower = next_lower;
        }
    }
    let mut cut = canonical.pool().begin().await.unwrap();
    let wire = kernel_v2_delta::cut_versioned(
        &mut cut,
        before.head_act,
        &[],
        kernel_v2_delta::WIRE_VERSION_3,
    )
    .await
    .unwrap();
    cut.rollback().await.unwrap();
    let delta = kernel_v2_delta::TrustedKernelDelta::assume_trusted_for_test(wire).unwrap();
    let accepted_act = delta.delta().head.head_act;
    let accepted = AcceptedKernelDelta::fixture_materialized(
        "fixture-source".into(),
        "fixture-accepted".into(),
        before,
        delta,
    )
    .unwrap();
    let hook = if answer_first {
        for (ticket, receipt) in originals.iter().zip(&receipts) {
            manager
                .fixture_accepted_verdict(ticket.id(), receipt.clone())
                .await;
        }
        control.canonical_changed();
        manager.drain_notifications_for_test().await;
        None
    } else {
        let hook = super::working_v2::manager::TestHook::new(
            super::working_v2::manager::TestPoint::ReconcileCommitted,
            false,
            false,
        );
        manager.set_hook(hook.clone());
        Some(hook)
    };
    let next = serde_json::json!({"id":f.task,"summary":"continued after accepted family","reason":"Continue another native edit","idempotency_key":"family-frontier-C"});
    let queued = if answer_first {
        let append = manager
            .append_original(
                WorkingManager::capture_record_original(f.caller.clone(), Op::Update, next)
                    .unwrap(),
            )
            .unwrap();
        let wait = super::working_v2::manager::TestHook::new(
            super::working_v2::manager::TestPoint::NativeWait,
            false,
            false,
        );
        manager.set_hook(wait.clone());
        let queued = tokio::spawn(append);
        wait.entered.acquire().await.unwrap().forget();
        wait.release.add_permits(1);
        manager.drain_notifications_for_test().await;
        for (packet_index, packet) in packets.into_iter().enumerate() {
            let act = packet.delta().delta().head.head_act;
            let seq = packet.delta().delta().head.generation.content_event_seq;
            let final_packet = act == accepted_act;
            let duplicate = AcceptedKernelDelta::fixture_materialized(
                packet.source().to_owned(),
                packet.destination().to_owned(),
                packet.before().clone(),
                kernel_v2_delta::TrustedKernelDelta::assume_trusted_for_test(
                    packet.delta().delta().clone(),
                )
                .unwrap(),
            )
            .unwrap();
            control.accepted_kernel(packet);
            manager.drain_notifications_for_test().await;
            if !final_packet {
                assert_eq!(manager.accepted_act().await.unwrap(), act);
                assert_eq!(
                    manager.state(),
                    super::working_v2::WorkingState::AwaitingQualifiedUndo
                );
                assert!(!queued.is_finished(), "same C job must remain unACKed");
                let (publication, current) = manager
                    .read_arguments(
                        f.caller.clone(),
                        serde_json::json!({"ids":[f.task,f.seed],"links_limit":50}),
                    )
                    .await
                    .unwrap();
                assert_eq!(publication.accepted_frontier, seq);
                let records = current["records"].as_array().unwrap();
                let task = records.iter().find(|r| r["id"] == f.task).unwrap();
                assert_eq!(task["body"], "acceptedfamilybody");
                assert_eq!(task["name"], "Accepted family task");
                assert_eq!(task["summary"], "accepted metadata");
                assert_eq!(task["home_id"], f.home);
                assert_eq!(task["archived"], false);
                let note = records.iter().find(|r| r["id"] == f.seed).unwrap();
                assert_eq!(
                    note["body"]
                        .as_str()
                        .unwrap()
                        .matches("FAMILY_PENDING_B")
                        .count(),
                    1
                );
                assert!(!note["links_out"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|link| link["target_id"] == f.task && link["relationship"] == "mentions"));
                let db = manager.native_db();
                let mut check = db.pool().begin().await.unwrap();
                let pending: Vec<String> = sqlx::query_scalar("SELECT proposal_id FROM main._native_working_applied ORDER BY original_ordinal")
                    .fetch_all(&mut *check).await.unwrap();
                let accepted_count = (packet_index + 1) * 2;
                assert_eq!(
                    pending,
                    originals[accepted_count..]
                        .iter()
                        .map(|ticket| ticket.id().to_owned())
                        .collect::<Vec<_>>()
                );
                let base: String = sqlx::query_scalar(
                    "SELECT state FROM main._native_working_bases WHERE publication=?",
                )
                .bind(publication.publication)
                .fetch_one(&mut *check)
                .await
                .unwrap();
                let base: Value = serde_json::from_str(&base).unwrap();
                assert_eq!(base["native"]["head_act"], act);
                assert_eq!(base["native"]["content_event_seq"], seq);
                // This direct fixture has no serving generation binding. The
                // actual native lower cut still advances for every packet.
                assert!(base["source_generation"].is_null());
                check.rollback().await.unwrap();
                // Stable epoch/head and both kinds of wake cannot clear the
                // explicit accepted-materialization wait at this partial cut.
                control.accepted_kernel(duplicate);
                control.canonical_changed();
                manager.drain_notifications_for_test().await;
                assert_eq!(
                    manager.state(),
                    super::working_v2::WorkingState::AwaitingQualifiedUndo
                );
                assert!(!queued.is_finished());
            }
        }
        queued
    } else {
        control.accepted_kernel(accepted);
        manager.observe_serving_act(accepted_act).await;
        let hook = hook.unwrap();
        hook.entered.acquire().await.unwrap().forget();
        hook.release.add_permits(1);
        // The cut is installed before this first durable answer. Deliberately
        // do not deliver its wake until C is fsynced and waiting behind it.
        manager
            .fixture_accepted_verdict(originals[0].id(), receipts[0].clone())
            .await;
        let fsynced = super::working_v2::manager::TestHook::new(
            super::working_v2::manager::TestPoint::Fsynced,
            false,
            false,
        );
        manager.set_hook(fsynced.clone());
        let append = manager
            .append_original(
                WorkingManager::capture_record_original(f.caller.clone(), Op::Update, next)
                    .unwrap(),
            )
            .unwrap();
        let queued = tokio::spawn(append);
        fsynced.entered.acquire().await.unwrap().forget();
        fsynced.release.add_permits(1);
        manager.drain_notifications_for_test().await;
        assert_eq!(
            manager.state(),
            super::working_v2::WorkingState::AwaitingQualifiedUndo
        );
        assert!(!queued.is_finished());
        assert_eq!(manager.published_prefix().await.unwrap(), 7);
        let view = manager.journal_view().await;
        assert_eq!(view.proposals().len(), 8);
        let suffix = &view.proposals()[7];
        assert_eq!(suffix.arguments()["idempotency_key"], "family-frontier-C");
        let db = manager.native_db();
        let mut check = db.pool().begin().await.unwrap();
        use crate::node::working_v2::WorkingCanonicalAnswer as Answer;
        assert!(manager
            .unpublished_suffix_for_test(suffix, Answer::Pending, false)
            .await
            .unwrap());
        assert!(!manager
            .unpublished_suffix_for_test(suffix, Answer::Pending, true)
            .await
            .unwrap());
        for answer in [Answer::Accepted, Answer::Refused, Answer::Unsupported] {
            assert!(!manager
                .unpublished_suffix_for_test(suffix, answer, false)
                .await
                .unwrap());
        }
        // B has a real speculative marker/receipt; A has a grounded receipt
        // without a speculative marker. Neither can masquerade as fresh C.
        assert!(!manager
            .unpublished_suffix_for_test(&originals[6], Answer::Pending, false)
            .await
            .unwrap());
        assert!(!manager
            .unpublished_suffix_for_test(&originals[0], Answer::Pending, false)
            .await
            .unwrap());
        let publication: String = sqlx::query_scalar(
            "SELECT state FROM main._native_working_publication WHERE singleton=1",
        )
        .fetch_one(&mut *check)
        .await
        .unwrap();
        let publication: super::working_v2::WorkingPublication =
            serde_json::from_str(&publication).unwrap();
        assert_ne!(view.revision(), publication.journal_revision);
        check.rollback().await.unwrap();
        for (ticket, receipt) in originals.iter().zip(&receipts).skip(1) {
            manager
                .fixture_accepted_verdict(ticket.id(), receipt.clone())
                .await;
        }
        control.canonical_changed();
        queued
    };
    let ack = tokio::time::timeout(Duration::from_secs(10), queued)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(ack.publication.accepted_frontier > b_ack.publication.accepted_frontier);
    let second = f
        .caller
        .clone()
        .with_oauth_client_id(Some("family-frontier-second".into()));
    let (publication, get) = manager
        .read_arguments(
            second.clone(),
            serde_json::json!({"ids":[f.task,f.seed],"links_limit":50}),
        )
        .await
        .unwrap(); // FIRST fresh Get after ACK.
    assert_eq!(publication, ack.publication);
    let task = get["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == f.task)
        .unwrap();
    assert_eq!(task["body"], "acceptedfamilybody");
    assert_eq!(task["summary"], "continued after accepted family");
    assert_eq!(task["home_id"], f.home);
    assert_eq!(task["archived"], false);
    let note = get["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == f.seed)
        .unwrap();
    assert_eq!(
        note["body"]
            .as_str()
            .unwrap()
            .matches("FAMILY_PENDING_B")
            .count(),
        1
    );
    assert!(!note["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .any(|link| link["target_id"] == f.task && link["relationship"] == "mentions"));
    assert_eq!(
        old.get(second.clone(), &f.seed).await.unwrap().value,
        old_body.value
    );
    assert_eq!(
        manager
            .append(second, b)
            .unwrap()
            .await
            .unwrap()
            .publication,
        ack.publication
    );
    assert_eq!(manager.retained_journal_count(), 8);
    drop(old);
    drop(control);
    manager.stop_for_test().await;
    if restart {
        let location = journal.location().unwrap().unwrap();
        let anchor = journal.anchor_bytes().unwrap();
        let originals_before = journal.capture().await.unwrap().view().proposals().to_vec();
        let path = root
            .path()
            .join(&area_id)
            .join("hosted-outbox/forks")
            .join(&location.fork)
            .join("fork.sqlite");
        let identity = identity(&path, false).unwrap();
        let (_, owner) =
            working_owner_fixture(&f, &f.base, &f.caller, "portable-verified-account").await;
        let (_close, guard) = BindingControl::new();
        let area =
            ForkArea::open_retained(&root.path().join(&area_id), std::slice::from_ref(&f.path))
                .unwrap();
        let (resumed, control) = WorkingManager::open_workspace_shared(
            owner,
            f.caller.clone(),
            (area, ForkLimits::default()),
            journal.clone(),
            guard,
            ("a".repeat(64), None),
        )
        .await
        .unwrap();
        let second = f
            .caller
            .clone()
            .with_oauth_client_id(Some("fresh-process-client".into()));
        let (published, first) = resumed
            .read_arguments(
                second.clone(),
                serde_json::json!({"ids":[f.task,f.seed],"links_limit":50}),
            )
            .await
            .unwrap();
        assert_eq!(
            first, get,
            "FIRST native Get must retain the full accepted+pending view"
        );
        assert_eq!(published, publication);
        assert!(
            identity == super::identity(&path, false).unwrap(),
            "resume cannot copy W"
        );
        assert_eq!(journal.anchor_bytes().unwrap(), anchor);
        assert_eq!(journal.location().unwrap().unwrap(), location);
        assert_eq!(
            journal.capture().await.unwrap().view().proposals(),
            originals_before
        );
        let ro = resumed.native_db();
        let denied = sqlx::query("UPDATE main.kernel_records SET home_id=home_id")
            .execute(ro.pool())
            .await
            .unwrap_err();
        assert!(
            denied.to_string().to_ascii_lowercase().contains("readonly"),
            "{denied}"
        );
        drop(ro);
        let d = resumed
            .append(
                second.clone(),
                manager_append(&f, "restart-after-cut-D", " RESTART_D"),
            )
            .unwrap()
            .await
            .unwrap();
        let (next, value) = resumed.read(second, &f.seed).await.unwrap();
        assert_eq!(next, d.publication);
        assert_eq!(value.to_string().matches("FAMILY_PENDING_B").count(), 1);
        assert_eq!(value.to_string().matches("RESTART_D").count(), 1);
        drop(control);
        resumed.stop_for_test().await;
    }
    canonical.close().await;
}

/// Corruption/compatibility refusals preserve the selected W and sole journal.
/// All mutations below are deliberate fixture corruption on an unowned W;
/// native append-only event triggers are never dropped or bypassed.
#[tokio::test(flavor = "current_thread")]
async fn working_restart_rejects_native_tamper_locator_and_further_source_cut() {
    use super::working_v2::{manager::WorkingManager, BindingControl};
    use crate::node::working_v2::WorkingJournal;
    use sha2::{Digest, Sha256};
    use sqlx::Connection;
    let f = fixture_with_shared_note(true).await;
    let canonical = crate::db::open_kernel_v2_in_place_writer(&f.path)
        .await
        .unwrap();
    let mut setup = crate::db::begin_write(canonical.write_pool())
        .await
        .unwrap();
    let blob = b"restart audit blob";
    let digest = hex::encode(Sha256::digest(blob));
    let meta = crate::blob::BlobMeta {
        id: "restart-audit-blob".into(),
        mime: None,
        size_bytes: blob.len() as i64,
        sha256: digest.clone(),
        original_filename: None,
        storage_tier: "inline".into(),
        created_at: "fixture".into(),
    };
    crate::kernel::blobs::put(&mut setup, blob, &meta)
        .await
        .unwrap();
    canonical.commit_kernel_content(setup).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let area_id = Uuid::new_v4().to_string();
    let parent = root.path().join(&area_id);
    std::fs::create_dir(&parent).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_, owner) =
        working_owner_fixture(&f, &f.base, &f.caller, "portable-verified-account").await;
    let journal = WorkingJournal::fixture_installed(root.path(), owner.binding_for_test())
        .unwrap()
        .with_location_scope(root.path().to_owned(), area_id.clone())
        .unwrap();
    let (_close, guard) = BindingControl::new();
    let area = ForkArea::new(&parent, std::slice::from_ref(&f.path)).unwrap();
    let (manager, control) = WorkingManager::open_workspace_shared(
        owner,
        f.caller.clone(),
        (area, ForkLimits::default()),
        journal.clone(),
        guard,
        ("a".repeat(64), None),
    )
    .await
    .unwrap();
    manager
        .append(
            f.caller.clone(),
            manager_append(&f, "restart-corruption-tail", " RETAINED_RESTART_TAIL"),
        )
        .unwrap()
        .await
        .unwrap();
    drop(control);
    manager.stop_for_test().await;
    let location = journal.location().unwrap().unwrap();
    let path = parent
        .join("hosted-outbox/forks")
        .join(&location.fork)
        .join("fork.sqlite");
    let id = identity(&path, false).unwrap();
    let originals = journal.capture().await.unwrap().view().proposals().to_vec();
    let factory_wal = path.parent().unwrap().join("partial.sqlite-wal");
    let factory_shm = path.parent().unwrap().join("partial.sqlite-shm");
    let unrelated = path.parent().unwrap().join("unrelated.sqlite-wal");
    let factory_snapshot = || {
        [&factory_wal, &factory_shm].map(|file| match std::fs::symlink_metadata(file) {
            Ok(_) => Some((identity(file, false).unwrap(), std::fs::read(file).unwrap())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("factory artifact inspection failed: {error}"),
        })
    };
    let factory_before = factory_snapshot();
    assert_eq!(factory_before[0].is_some(), factory_before[1].is_some());
    if let Some((_, wal)) = &factory_before[0] {
        assert!(wal.is_empty());
    }
    if let Some((_, shm)) = &factory_before[1] {
        assert_eq!(shm.len(), 32768);
    }
    assert!(!path.parent().unwrap().join("partial.sqlite").exists());
    // Establish that this exact fixture/location succeeds before deliberately
    // corrupting it; a shared early failure cannot satisfy every negative.
    let (_, owner) =
        working_owner_fixture(&f, &f.base, &f.caller, "portable-verified-account").await;
    let (_close, guard) = BindingControl::new();
    let area = ForkArea::open_retained(&parent, std::slice::from_ref(&f.path)).unwrap();
    let (baseline, baseline_control) = WorkingManager::open_workspace_shared(
        owner,
        f.caller.clone(),
        (area, ForkLimits::default()),
        journal.clone(),
        guard,
        ("a".repeat(64), None),
    )
    .await
    .unwrap();
    assert_eq!(
        baseline
            .read(f.caller.clone(), &f.seed)
            .await
            .unwrap()
            .1
            .to_string()
            .matches("RETAINED_RESTART_TAIL")
            .count(),
        1
    );
    drop(baseline_control);
    baseline.stop_for_test().await;
    assert!(identity(&path, false).unwrap() == id);
    assert!(
        factory_snapshot() == factory_before,
        "baseline must preserve the exact observed pair-or-none, identities and bytes"
    );
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&path)
        .create_if_missing(false)
        .foreign_keys(true)
        .pragma("recursive_triggers", "ON");
    for tamper in [
        "projection",
        "blob",
        "causal",
        "missing-locator",
        "account",
        "factory-wal",
        "unknown-file",
    ] {
        let mut c = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        let original_home: String =
            sqlx::query_scalar("SELECT home_id FROM main.kernel_records WHERE id=?")
                .bind(&f.task)
                .fetch_one(&mut c)
                .await
                .unwrap();
        let cutover: String = sqlx::query_scalar(
            "SELECT cutover_at FROM main.content_event_causal_cutover WHERE singleton=1",
        )
        .fetch_one(&mut c)
        .await
        .unwrap();
        let coordinates_sql = "SELECT (SELECT MAX(seq) FROM main.content_events),(SELECT MAX(seq) FROM main.meta_events),(SELECT next_act FROM main.act_state WHERE singleton=1),(SELECT count(*) FROM main.kernel_blobs)";
        let before: (i64, i64, i64, i64) = sqlx::query_as(coordinates_sql)
            .fetch_one(&mut c)
            .await
            .unwrap();
        match tamper {
            "projection" => {
                sqlx::query("UPDATE main.kernel_records SET home_id=? WHERE id=?")
                    .bind(&f.home)
                    .bind(&f.task)
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
            "blob" => {
                sqlx::query("UPDATE main.kernel_blobs SET bytes=? WHERE sha256=?")
                    .bind(b"tampered audit blob".as_slice())
                    .bind(&digest)
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
            "causal" => {
                sqlx::query("UPDATE main.content_event_causal_cutover SET cutover_at='corrupt-event-evidence' WHERE singleton=1").execute(&mut c).await.unwrap();
            }
            _ => {}
        }
        let after: (i64, i64, i64, i64) = sqlx::query_as(coordinates_sql)
            .fetch_one(&mut c)
            .await
            .unwrap();
        assert_eq!(
            before, after,
            "{tamper} must test content beyond native head/count coordinates"
        );
        c.close().await.unwrap();
        if tamper == "factory-wal" {
            if factory_before[0].is_none() {
                // Deliberately INVALID negative input, never a fabricated valid
                // startup pair: content-bearing WAL with size-correct cache.
                use std::os::unix::fs::OpenOptionsExt;
                let shm = vec![0u8; 32768];
                for (file, bytes) in [
                    (&factory_wal, b"nonempty-factory-wal".as_slice()),
                    (&factory_shm, shm.as_slice()),
                ] {
                    let mut created = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(file)
                        .unwrap();
                    std::io::Write::write_all(&mut created, bytes).unwrap();
                }
            } else {
                std::fs::write(&factory_wal, b"nonempty-factory-wal").unwrap();
            }
        }
        if tamper == "unknown-file" {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&unrelated)
                .unwrap();
            std::io::Write::write_all(&mut file, b"opaque-unrelated-bytes").unwrap();
        }
        let locator_path = root
            .path()
            .join("working-manager-journal/working-location.json");
        let saved_locator = root.path().join("saved-working-location.json");
        if tamper == "missing-locator" {
            std::fs::rename(&locator_path, &saved_locator).unwrap();
        }
        let namespace = if tamper == "account" {
            "another-portable-account"
        } else {
            "portable-verified-account"
        };
        let (_, owner) = working_owner_fixture(&f, &f.base, &f.caller, namespace).await;
        let (_close, guard) = BindingControl::new();
        let area = ForkArea::open_retained(&parent, std::slice::from_ref(&f.path)).unwrap();
        let result = WorkingManager::open_workspace_shared(
            owner,
            f.caller.clone(),
            (area, ForkLimits::default()),
            journal.clone(),
            guard,
            ("a".repeat(64), None),
        )
        .await;
        let error = result
            .err()
            .expect("tampered W must not grant private readers")
            .to_string();
        let expected = match tamper {
            "projection" => "retained working native table mismatch: kernel_records",
            "blob" => "retained working native table mismatch: kernel_blobs",
            "causal" => "retained working native table mismatch: content_event_causal_cutover",
            "missing-locator" => "retained working location missing",
            "account" => "retained working original owner mismatch",
            "factory-wal" => "retained factory verification sidecars are not inert",
            "unknown-file" => "retained working directory has unsupported files",
            _ => unreachable!(),
        };
        assert!(
            error.contains(expected),
            "{tamper}: expected {expected}, got {error}"
        );
        assert!(identity(&path, false).unwrap() == id);
        assert_eq!(
            journal.capture().await.unwrap().view().proposals(),
            originals
        );
        if tamper == "missing-locator" {
            std::fs::rename(&saved_locator, &locator_path).unwrap();
        }
        if tamper == "factory-wal" {
            assert_eq!(
                std::fs::read(&factory_wal).unwrap(),
                b"nonempty-factory-wal"
            );
            if let Some((_, bytes)) = &factory_before[0] {
                std::fs::write(&factory_wal, bytes).unwrap(); // Restore only corruption.
            } else {
                assert_eq!(std::fs::read(&factory_shm).unwrap(), vec![0u8; 32768]);
                std::fs::remove_file(&factory_wal).unwrap(); // Only test-created INVALID pair.
                std::fs::remove_file(&factory_shm).unwrap();
            }
            assert!(factory_snapshot() == factory_before);
        }
        if tamper == "unknown-file" {
            assert_eq!(
                std::fs::read(&unrelated).unwrap(),
                b"opaque-unrelated-bytes"
            );
            std::fs::remove_file(&unrelated).unwrap(); // Only the test-created extra file.
        }
        let mut c = sqlx::SqliteConnection::connect_with(&options)
            .await
            .unwrap();
        match tamper {
            "projection" => {
                let saved: String =
                    sqlx::query_scalar("SELECT home_id FROM main.kernel_records WHERE id=?")
                        .bind(&f.task)
                        .fetch_one(&mut c)
                        .await
                        .unwrap();
                assert_eq!(saved, f.home, "refusal must not repair or rebuild W");
                sqlx::query("UPDATE main.kernel_records SET home_id=? WHERE id=?")
                    .bind(&original_home)
                    .bind(&f.task)
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
            "blob" => {
                let saved: Vec<u8> =
                    sqlx::query_scalar("SELECT bytes FROM main.kernel_blobs WHERE sha256=?")
                        .bind(&digest)
                        .fetch_one(&mut c)
                        .await
                        .unwrap();
                assert_eq!(saved, b"tampered audit blob");
                sqlx::query("UPDATE main.kernel_blobs SET bytes=? WHERE sha256=?")
                    .bind(blob.as_slice())
                    .bind(&digest)
                    .execute(&mut c)
                    .await
                    .unwrap();
            }
            "causal" => {
                sqlx::query(
                    "UPDATE main.content_event_causal_cutover SET cutover_at=? WHERE singleton=1",
                )
                .bind(&cutover)
                .execute(&mut c)
                .await
                .unwrap();
            }
            _ => {}
        }
        c.close().await.unwrap();
    }
    // A genuine META-only accepted advance changes the source cut while
    // retaining content Seq. No resume from the older W is permitted.
    crate::kernel::install_package_as(&canonical, &f.admin, &crate::v2_standard::outcome_package())
        .await
        .unwrap();
    let (_, owner) =
        working_owner_fixture(&f, &f.base, &f.caller, "portable-verified-account").await;
    let (_close, guard) = BindingControl::new();
    let area = ForkArea::open_retained(&parent, std::slice::from_ref(&f.path)).unwrap();
    let error = WorkingManager::open_workspace_shared(
        owner,
        f.caller.clone(),
        (area, ForkLimits::default()),
        journal.clone(),
        guard,
        ("a".repeat(64), None),
    )
    .await
    .err()
    .expect("further source cut must retain W")
    .to_string();
    assert!(
        error.contains("retained accepted cut differs from current verified source"),
        "{error}"
    );
    assert!(identity(&path, false).unwrap() == id);
    assert_eq!(journal.location().unwrap().unwrap(), location);
    assert_eq!(
        journal.capture().await.unwrap().view().proposals(),
        originals
    );
    canonical.close().await;
}

/// Actual retained manager cleanup: typed probe and ordinary create-writer
/// conflicts each exercise both acknowledged savepoint cleanup failure sites.
#[tokio::test(flavor = "current_thread")]
async fn working_original_conflict_cleanup_failures_retain_actual_owner_and_publication() {
    use super::working_v2::{manager::WorkingManager, BindingControl, WorkingState};
    use crate::kernel::original_settlement::{
        self as settlement, AuthenticatedRoute, Original, Request, RouteGuard,
    };
    use crate::mcp::kernel_v2::writes::replay::{
        self, CapturedFirstPartyCreate, ReplayCleanupFault, ReplayCleanupStep,
    };
    use std::os::unix::fs::MetadataExt;
    struct Allowed;
    impl RouteGuard for Allowed {
        fn recheck(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<()>> + Send + '_>>
        {
            Box::pin(async { Ok(()) })
        }
    }
    for writer_conflict in [false, true] {
        for step in [
            ReplayCleanupStep::Observe,
            ReplayCleanupStep::RollbackTo,
            ReplayCleanupStep::Release,
        ] {
            let mut f = fixture().await;
            f.base.close().await;
            let canonical = crate::db::open_existing_v2_file(f.path.to_str().unwrap())
                .await
                .unwrap();
            settlement::prepare(&canonical, true).await.unwrap();
            let origin = settlement::origin(&canonical).await.unwrap();
            let append = manager_append(&f, "cleanup-probe", " NEVER_APPLIED");
            let mut captured_create = None;
            let (operation, args, identity, variant) = if writer_conflict {
                let source = serde_json::json!({"type":"Document","kind":"note","name":"Retired final ID","body":"original body","home_id":f.home,"reason":"cleanup owner proof","idempotency_key":"cleanup-create-original"});
                let scope = crate::provenance::ProvenanceDispatch::from_caller(
                    &f.caller,
                    "create_record",
                    &source,
                    None,
                );
                let captured = crate::mcp::kernel_v2::writes::with_minted_ids_for_settlement_test(
                    scope.scope(async {
                        CapturedFirstPartyCreate::capture(f.caller.clone(), source).unwrap()
                    }),
                )
                .await;
                let proposal = captured.prepare(&f.admin, None).unwrap();
                let result = (
                    "create_record",
                    proposal.args().clone(),
                    captured.context().identity(),
                    8,
                );
                captured_create = Some(captured);
                result
            } else {
                (
                    "update_record",
                    append.clone(),
                    replay::ProposalIdentity::default(),
                    7,
                )
            };
            let fingerprint = replay::proposal_fingerprint(operation, &args, &identity).unwrap();
            let digest = crate::mcp::executor_prototype::original_settlement_contract(
                variant,
                operation,
                None,
                "records_write",
                operation,
                None,
            )
            .unwrap()
            .unwrap();
            let mut original = Original {
                account_id: "acct:admin".into(),
                principal_id: f.admin.clone(),
                database_id: "route".into(),
                origin_database_id: origin.clone(),
                operation: operation.into(),
                operation_key: args["idempotency_key"].as_str().unwrap().into(),
                journal_variant: variant,
                retained_contract_digest: digest,
                catalog_executor: "records_write".into(),
                catalog_operation: operation.into(),
                retained_provider_fingerprint: fingerprint,
                arguments: args.clone(),
                assertion: "first_party".into(),
                app: None,
                mint_context: identity.mint_context,
                delegation_ref: None,
                asserting_client_id: None,
                asserting_device_id: None,
                expected_binding_sha256: String::new(),
            };
            original.expected_binding_sha256 = settlement::recompute_binding(&original).unwrap().0;
            let route = AuthenticatedRoute {
                guard: Arc::new(Allowed),
                account: "acct:admin",
                principal: &f.admin,
                database: "route",
                origin: &origin,
                node_client: "node-fixture",
            };
            let answer = settlement::settle(
                &canonical,
                &route,
                Request {
                    schema: "native.original-settlement.request.v1".into(),
                    action: "settle_original".into(),
                    purpose: "held_refusal_resolution".into(),
                    abandon_if_unapplied: true,
                    original,
                },
            )
            .await
            .unwrap();
            assert_eq!(answer["verdict"], "unapplied_terminal");
            canonical.close().await;
            f.base = crate::db::open_kernel_v2_standby_read_only(f.path.to_str().unwrap())
                .await
                .unwrap();
            let (_, base) = working_owner_fixture(&f, &f.base, &f.caller, "acct:admin").await;
            let root = tempfile::tempdir().unwrap();
            let journal = crate::node::working_v2::WorkingJournal::fixture_installed(
                root.path(),
                base.binding_for_test(),
            )
            .unwrap();
            let (_close, guard) = BindingControl::new();
            let area = ForkArea::new(root.path(), std::slice::from_ref(&f.path)).unwrap();
            let context = captured_create
                .as_ref()
                .map(|capture| capture.context().clone());
            let (manager, _) = WorkingManager::open_workspace_shared(
                base,
                f.caller.clone(),
                (area, ForkLimits::default()),
                journal.clone(),
                guard,
                ("a".repeat(64), context),
            )
            .await
            .unwrap();
            let old = manager.pin(f.caller.clone()).await.unwrap();
            let before = old.get(f.caller.clone(), &f.seed).await.unwrap();
            let working_path = manager.native_db().path().to_path_buf();
            let working_before = std::fs::metadata(&working_path).unwrap();
            assert!(working_before.is_file());
            let working_identity = (working_before.dev(), working_before.ino());
            let fault = ReplayCleanupFault::new(step);
            manager.fail_replay_cleanup_for_test(fault.clone());
            let call = if let Some(captured) = captured_create {
                // Another key cannot evade the globally retired final ID. The
                // actual native writer, rather than the retry probe, rejects it.
                let mut retained = args.clone();
                retained["idempotency_key"] = serde_json::json!("cleanup-create-new-key");
                let mut source = captured.source().clone();
                source["idempotency_key"] = retained["idempotency_key"].clone();
                let scope = crate::provenance::ProvenanceDispatch::from_caller(
                    &f.caller,
                    "create_record",
                    &source,
                    None,
                );
                let fresh = crate::mcp::kernel_v2::writes::with_minted_ids_for_settlement_test(
                    scope.scope(async {
                        CapturedFirstPartyCreate::capture(f.caller.clone(), source).unwrap()
                    }),
                )
                .await;
                let proposal = fresh.prepare(&f.admin, Some(&retained)).unwrap();
                manager
                    .append_original(WorkingManager::captured_create(&fresh, proposal).unwrap())
                    .unwrap()
            } else {
                manager.append(f.caller.clone(), append).unwrap()
            };
            let error = call.await.unwrap_err();
            if matches!(step, ReplayCleanupStep::Observe) {
                assert!(
                    matches!(error, Error::OriginalConflict(_)),
                    "typed conflict survives one acknowledged cleanup"
                );
            }
            manager.await_retained_for_test().await;
            assert_eq!(manager.state(), WorkingState::Quarantined);
            assert_eq!(
                fault.counts(),
                match step {
                    ReplayCleanupStep::RollbackTo => (1, 0),
                    ReplayCleanupStep::Release | ReplayCleanupStep::Observe => (1, 1),
                }
            );
            let after = manager.read(f.caller.clone(), &f.seed).await.unwrap();
            assert_eq!(after.0, before.publication);
            assert_eq!(after.1, before.value);
            let view = journal.capture().await.unwrap().view().clone();
            assert_eq!(
                view.proposals().len(),
                1,
                "the original remains durably recoverable"
            );
            assert_eq!(view.proposals()[0].arguments()["id"], args["id"]);
            assert_eq!(
                manager.retained_count(),
                1,
                "bounded actual owner parked after rollback"
            );
            assert!(manager
                .append(
                    f.caller.clone(),
                    manager_append(&f, "never-after-cleanup", " NEW")
                )
                .is_err());
            let working_after = std::fs::metadata(&working_path).unwrap();
            assert!(working_after.is_file());
            assert_eq!(
                (working_after.dev(), working_after.ino()),
                working_identity,
                "the actual W file is retained under the parked physical owner"
            );
            manager.settle_retained().await;
            drop(old);
            manager.stop_for_test().await;
        }
    }
}

/// Real canonical settlement/fold, with test-only sealed packet injection.
/// No automatic unrelated progress is claimed by this conservative recovery.
#[tokio::test(flavor = "current_thread")]
async fn working_original_terminal_tail_recovery_orders_answer_and_real_native_fact() {
    use super::working_v2::{
        manager::WorkingManager, BindingControl, OwnerPinnedBase, WorkingBinding, WorkingState,
    };
    use crate::kernel::original_settlement::{
        self as settlement, AuthenticatedRoute, Request, RouteGuard,
    };
    use crate::standby::{kernel_v2, kernel_v2_delta, AcceptedKernelDelta};
    struct Allowed;
    impl RouteGuard for Allowed {
        fn recheck(
            &self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = crate::Result<()>> + Send + '_>>
        {
            Box::pin(async { Ok(()) })
        }
    }
    for fact_first in [false, true] {
        let mut f = fixture().await;
        f.base.close().await;
        let canonical = crate::db::open_existing_v2_file(f.path.to_str().unwrap())
            .await
            .unwrap();
        settlement::prepare(&canonical, true).await.unwrap();
        let origin = settlement::origin(&canonical).await.unwrap();
        f.base = crate::db::open_kernel_v2_standby_read_only(f.path.to_str().unwrap())
            .await
            .unwrap();
        let mut source = f.base.pool().begin().await.unwrap();
        let native_before = kernel_v2::coordinates(&mut source).await.unwrap();
        source.rollback().await.unwrap();
        let binding = WorkingBinding {
            account_id: "acct:admin".into(),
            database_id: "route".into(),
            origin_database_id: origin.clone(),
            history_lineage: format!("v2:{origin}:{}", native_before.genesis_event_id),
            resource_origin: "https://fixture.test".into(),
            install_id: None,
        };
        let owner = OwnerPinnedBase::from_verified_owner(
            f.base.clone(),
            binding.clone(),
            native_before.genesis_event_id.clone(),
            native_before.content_event_seq,
            &f.caller,
        )
        .await
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        let journal =
            crate::node::working_v2::WorkingJournal::fixture_installed(root.path(), binding)
                .unwrap();
        let (_close, guard) = BindingControl::new();
        let area = ForkArea::new(root.path(), std::slice::from_ref(&f.path)).unwrap();
        let digest = crate::mcp::executor_prototype::original_settlement_contract(
            7,
            "update_record",
            None,
            "records_write",
            "update_record",
            None,
        )
        .unwrap()
        .unwrap();
        let (manager, control) = WorkingManager::open_workspace_shared(
            owner,
            f.caller.clone(),
            (area, ForkLimits::default()),
            journal.clone(),
            guard,
            (digest, None),
        )
        .await
        .unwrap();
        let args = manager_append(&f, "terminal-tail", " RECOVERABLE_DRAFT");
        let ack = manager
            .append(f.caller.clone(), args.clone())
            .unwrap()
            .await
            .unwrap();
        let old = manager.pin(f.caller.clone()).await.unwrap();
        let old_value = old.get(f.caller.clone(), &f.seed).await.unwrap();
        assert_eq!(
            old_value
                .value
                .to_string()
                .matches("RECOVERABLE_DRAFT")
                .count(),
            1
        );
        let retained = journal.fixture_entry_bytes(&ack.proposal_id);
        control.requires_undo();
        let original = journal.fixture_resolution_requested(&ack.proposal_id).await;
        let route = AuthenticatedRoute {
            guard: Arc::new(Allowed),
            account: "acct:admin",
            principal: &f.admin,
            database: "route",
            origin: &origin,
            node_client: "node-fixture",
        };
        let request = Request {
            schema: "native.original-settlement.request.v1".into(),
            action: "settle_original".into(),
            purpose: "held_refusal_resolution".into(),
            abandon_if_unapplied: true,
            original,
        };
        let answer = settlement::settle(&canonical, &route, request.clone())
            .await
            .unwrap();
        assert_eq!(answer["verdict"], "unapplied_terminal");
        if !fact_first {
            journal
                .fixture_resolution_verified(&ack.proposal_id, answer.clone())
                .await;
            control.canonical_changed();
            manager.drain_notifications_for_test().await;
        }
        let mut read = canonical.pool().begin().await.unwrap();
        let wire = kernel_v2_delta::cut_versioned(
            &mut read,
            native_before.head_act,
            &[],
            kernel_v2_delta::WIRE_VERSION_3,
        )
        .await
        .unwrap();
        read.rollback().await.unwrap();
        let delta = kernel_v2_delta::TrustedKernelDelta::assume_trusted_for_test(wire).unwrap();
        control.accepted_kernel(
            AcceptedKernelDelta::fixture_materialized(
                "fixture-source".into(),
                "fixture-accepted".into(),
                native_before,
                delta,
            )
            .unwrap(),
        );
        manager.drain_notifications_for_test().await;
        if fact_first {
            assert_eq!(
                manager.read(f.caller.clone(), &f.seed).await.unwrap(),
                (old_value.publication.clone(), old_value.value.clone()),
                "missing answer retains complete previous publication"
            );
            // Simulate a lost HTTP response: actual repeated producer decision
            // returns the same durable fence; no second packet is injected.
            let repeated = settlement::settle(&canonical, &route, request)
                .await
                .unwrap();
            assert_eq!(repeated, answer);
            journal
                .fixture_resolution_verified(&ack.proposal_id, repeated)
                .await;
            control.canonical_changed();
            manager.drain_notifications_for_test().await;
        }
        let second = Caller::authenticated("acct:admin")
            .with_oauth_client_id(Some("recovery-second".into()));
        let (publication, value) = manager.read(second, &f.seed).await.unwrap();
        assert!(!value.to_string().contains("RECOVERABLE_DRAFT"));
        assert!(publication.publication > ack.publication.publication);
        assert_eq!(
            manager.state(),
            WorkingState::AwaitingQualifiedUndo,
            "conservative recovery leaves queue paused"
        );
        assert!(manager
            .append(
                f.caller.clone(),
                manager_append(&f, "paused-new-edit", " NEW")
            )
            .is_err());
        let resolved_before_wake = journal.fixture_entry_bytes(&ack.proposal_id);
        let revision_before_wake = journal
            .capture()
            .await
            .unwrap()
            .view()
            .revision()
            .to_owned();
        control.canonical_changed();
        manager.drain_notifications_for_test().await;
        assert!(
            manager
                .append(
                    f.caller.clone(),
                    manager_append(&f, "paused-after-duplicate", " STILL_PAUSED")
                )
                .is_err(),
            "duplicate wake cannot reopen durable resolution admission"
        );
        assert_eq!(
            journal.capture().await.unwrap().view().revision(),
            revision_before_wake
        );
        assert_eq!(
            journal.fixture_entry_bytes(&ack.proposal_id),
            resolved_before_wake
        );
        let saved = journal.fixture_entry_bytes(&ack.proposal_id);
        let before: Value = serde_json::from_slice(&retained).unwrap();
        let after: Value = serde_json::from_slice(&saved).unwrap();
        for field in [
            "working_original",
            "arguments",
            "idempotency_key",
            "maybe_applied",
            "in_flight",
            "answer",
            "reply",
        ] {
            assert_eq!(
                before.get(field),
                after.get(field),
                "prior original/attempt bytes unchanged: {field}"
            );
        }
        assert_eq!(after["compatibility_block"], "original_resolution");
        assert_eq!(after["working_resolution"]["state"], "verified");
        assert_eq!(
            old.get(f.caller.clone(), &f.seed).await.unwrap().value,
            old_value.value,
            "old snapshot stays coherent"
        );
        manager.stop_for_test().await;
        canonical.close().await;
    }
}
