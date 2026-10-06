//! Source-only adverse coverage. Real auth and reconciled SQLite BEFORE fresh
//! enrollment; no production local Caller shortcuts, fake mutex proof or mocks.
use super::*;
use crate::authorization::AllowEntry;
use crate::db::enrolled::{Phase, TestGate, TEST_GATE};
use crate::mcp::ToolRegistry;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::Duration;
use tokio::sync::oneshot;
use yrs::updates::{decoder::Decode, encoder::Encode};
use yrs::{Doc, OffsetKind, Options, ReadTxn, Text, Transact, Update};

const SEED: &str = "seed 🐋汉e\u{301}\r\n";
struct Fixture {
    _root: tempfile::TempDir,
    path: std::path::PathBuf,
    db: Db,
    tools: Arc<ToolRegistry>,
    record: String,
}
impl Fixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("databases")).unwrap();
        let stage = root.path().join("stage.db");
        let source = crate::create_database(stage.to_str().unwrap())
            .await
            .unwrap();
        let mut tools = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut tools).unwrap();
        let created = tools
            .call(
                source.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type":"Document", "kind":"note", "name":"real session fixture",
                    "body":SEED, "reason":"fixture bootstrap before enrollment"
                }),
            )
            .await
            .unwrap();
        let record = created["id"].as_str().unwrap().to_owned();
        crate::authorization::replace_explicit_policy(
            &source,
            "test:bootstrap",
            &record,
            vec![
                AllowEntry::account("acct:alice", Capability::Edit),
                AllowEntry::account("acct:bob", Capability::Edit),
                AllowEntry::account("acct:viewer", Capability::View),
            ],
        )
        .await
        .unwrap();
        source.drain_captures_for_tests().await;
        crate::db::checkpoint_and_close_hosted_adoption_database(source)
            .await
            .unwrap();
        let generation = Uuid::new_v4().to_string();
        let path = root
            .path()
            .join("databases")
            .join(format!("{generation}.db"));
        let enrollment =
            crate::managed_custody::reserve_fresh_adoption(root.path(), &path, &generation)
                .unwrap();
        std::fs::copy(stage, &path).unwrap();
        enrollment.finalize().unwrap();
        let db = crate::db::open_existing_database_at(&path).await.unwrap();
        Self {
            _root: root,
            path,
            db,
            tools: Arc::new(tools),
            record,
        }
    }
    async fn independent(&self) -> Db {
        crate::db::open_existing_database_at(&self.path)
            .await
            .unwrap()
    }
    async fn open(&self, db: &Db, principal: &str, mode: PeerKind) -> (PeerHandle, OpenOk) {
        match submit(
            db.clone(),
            Caller::authenticated(principal),
            Command::Open {
                record: self.record.clone(),
                mode,
            },
        )
        .await
        .unwrap()
        {
            Reply::Opened { peer, state } => (peer, state),
            other => panic!("expected open: {other:?}"),
        }
    }
    async fn cut(&self, db: &Db, peer: &PeerHandle, request: Uuid) -> Result<Reply> {
        submit(
            db.clone(),
            Caller::authenticated("acct:alice"),
            Command::Version {
                peer: peer.clone(),
                reason: "explicit version".into(),
                request,
            },
        )
        .await
    }
    async fn durable(&self) -> (String, i64, i64) {
        (
            sqlx::query_scalar::<_, String>("SELECT body FROM records WHERE id=?")
                .bind(&self.record)
                .fetch_one(self.db.pool())
                .await
                .unwrap(),
            sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
                .fetch_one(self.db.pool())
                .await
                .unwrap(),
            self.db.current_act().await.unwrap(),
        )
    }
    async fn ordinary(&self, db: &Db, operation: Value) -> Result<Value> {
        let mut args = json!({"id":self.record, "reason":"ordinary authenticated update"});
        args.as_object_mut()
            .unwrap()
            .extend(operation.as_object().unwrap().clone());
        self.tools
            .call(
                db.clone(),
                Caller::authenticated("acct:alice"),
                "update_record",
                args,
            )
            .await
    }
}
struct Replica {
    doc: Doc,
}
impl Replica {
    fn new(state: &OpenOk) -> Self {
        let mut options =
            Options::with_client_id(yrs::ClientID::new(u64::from(state.client_ids[0])));
        options.offset_kind = OffsetKind::Bytes;
        let doc = Doc::with_options(options);
        doc.get_or_insert_text("body");
        doc.transact_mut()
            .apply_update(Update::decode_v1(&state.sync_step2).unwrap())
            .unwrap();
        Self { doc }
    }
    fn append(&self, text: &str) -> Vec<u8> {
        let before = self.doc.transact().state_vector();
        let body = self.doc.get_or_insert_text("body");
        {
            let mut tx = self.doc.transact_mut();
            let end = body.len(&tx);
            body.insert(&mut tx, end, text);
        }
        self.doc.transact().encode_diff_v1(&before)
    }
}
async fn update(db: &Db, peer: &PeerHandle, bytes: Vec<u8>) -> Result<Reply> {
    submit(
        db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Update {
            peer: peer.clone(),
            bytes,
        },
    )
    .await
}
fn dirty(db: &Db) -> bool {
    db.coedit_owner()
        .unwrap()
        .sessions
        .lock()
        .unwrap()
        .has_unsaved()
}
fn gate(phase: Phase) -> (Arc<TestGate>, oneshot::Receiver<()>) {
    let (tx, rx) = oneshot::channel();
    (
        Arc::new(TestGate {
            phase,
            entered: Mutex::new(Some(tx)),
            release: tokio::sync::Semaphore::new(0),
            outcome: Mutex::new(None),
            writer_close_ack: AtomicBool::new(false),
        }),
        rx,
    )
}
async fn reached(rx: oneshot::Receiver<()>) {
    tokio::time::timeout(Duration::from_secs(10), rx)
        .await
        .expect("runner reached gate")
        .unwrap();
}

#[tokio::test]
async fn independent_enrolled_handles_share_room_authority_fence_and_version() {
    let f = Fixture::new().await;
    let second = f.independent().await;
    assert!(Arc::ptr_eq(
        &f.db.coedit_owner().unwrap(),
        &second.coedit_owner().unwrap()
    ));
    let (alice, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    let (bob, _) = f.open(&second, "acct:bob", PeerKind::Edit).await;
    let (viewer, _) = f.open(&second, "acct:viewer", PeerKind::View).await;
    assert_eq!(alice.session, bob.session);
    let before = f.durable().await;
    let replica = Replica::new(&state);
    let bytes = replica.append(" / live 🧪");
    update(&second, &alice, bytes.clone()).await.unwrap();
    update(&f.db, &alice, bytes).await.unwrap(); // duplicate does not add facts
    assert_eq!(f.durable().await, before);
    assert!(dirty(&second));
    let spoof = submit(
        second.clone(),
        Caller::authenticated("acct:bob"),
        Command::Update {
            peer: alice.clone(),
            bytes: replica.append(" forged"),
        },
    )
    .await
    .unwrap_err();
    assert!(spoof.to_string().contains("authority mismatch"));
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:viewer"),
        Command::Version {
            peer: viewer.clone(),
            reason: "forbidden".into(),
            request: Uuid::new_v4(),
        }
    )
    .await
    .is_err());
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:viewer"),
        Command::Update {
            peer: viewer.clone(),
            bytes: Vec::new(),
        }
    )
    .await
    .is_err());
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:outsider"),
        Command::Sync {
            peer: alice.clone(),
            vector: vec![0],
        }
    )
    .await
    .is_err());
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:outsider"),
        Command::Open {
            record: f.record.clone(),
            mode: PeerKind::View,
        }
    )
    .await
    .is_err());
    let id = Uuid::new_v4();
    let Reply::Versioned(receipt) = f.cut(&second, &alice, id).await.unwrap() else {
        panic!("version receipt")
    };
    let committed = f.durable().await;
    assert_eq!(committed.0, format!("{SEED} / live 🧪"));
    assert_eq!(committed.1, before.1 + 1);
    assert_eq!(committed.2, before.2 + 1);
    assert!(!dirty(&second));
    let Reply::Versioned(retry) = f.cut(&f.db, &alice, id).await.unwrap() else {
        panic!("retry receipt")
    };
    assert_eq!(retry, receipt);
    assert_eq!(f.durable().await, committed);
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(receipt["event_id"].as_str().unwrap())
        .fetch_one(second.pool())
        .await
        .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(
        payload["contributors"],
        json!([{"principal":"acct:alice", "executor_kind":"authenticated_principal"}])
    );
    assert_eq!(payload["session"], alice.session.0);
    for (db, principal, peer) in [
        (&f.db, "acct:alice", alice),
        (&second, "acct:bob", bob),
        (&second, "acct:viewer", viewer),
    ] {
        submit(
            db.clone(),
            Caller::authenticated(principal),
            Command::Leave { peer },
        )
        .await
        .unwrap();
    }
    f.ordinary(&second, json!({"body_append":" ordinary resumes"}))
        .await
        .unwrap();
    second.close().await;
    f.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn all_four_prequeued_ordinary_verbs_check_fence_at_execution_after_auth() {
    for operation in [
        json!({"body":"stale", "if_body_digest":crate::mcp::tools::lifecycle::body_digest(Some(SEED))}),
        json!({"body_set":"stale", "if_body_digest":crate::mcp::tools::lifecycle::body_digest(Some(SEED))}),
        json!({"body_append":"stale"}),
        json!({"body_replace":[{"old":"seed", "new":"stale", "expected_count":1}]}),
    ] {
        let f = Fixture::new().await;
        let second = f.independent().await;
        let before = f.durable().await;
        let (hold, entered) = gate(Phase::BeforeLane);
        let tools = f.tools.clone();
        let db = f.db.clone();
        let mut args = json!({"id":f.record,"reason":"prequeued ordinary"});
        args.as_object_mut()
            .unwrap()
            .extend(operation.as_object().unwrap().clone());
        let runner_gate = hold.clone();
        let waiter = tokio::spawn(async move {
            TEST_GATE
                .scope(
                    runner_gate,
                    tools.call(
                        db,
                        Caller::authenticated("acct:alice"),
                        "update_record",
                        args,
                    ),
                )
                .await
        });
        reached(entered).await;
        let (peer, _) = f.open(&second, "acct:alice", PeerKind::Edit).await;
        hold.release.add_permits(1);
        let error = waiter.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("active session"), "{error}");
        assert!(hold.writer_close_ack.load(Ordering::Acquire));
        assert_eq!(f.durable().await, before);
        assert!(!dirty(&second));
        let error = f
            .tools
            .call(
                second.clone(),
                Caller::authenticated("acct:outsider"),
                "update_record",
                json!({"id":f.record, "body_append":"bad", "reason":"no authority"}),
            )
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("active session"));
        submit(
            second.clone(),
            Caller::authenticated("acct:alice"),
            Command::Leave { peer },
        )
        .await
        .unwrap();
        second.close().await;
        f.db.close().await;
    }
}

#[tokio::test]
async fn ordinary_winner_is_open_seed_and_unmanaged_driver_refuses() {
    let f = Fixture::new().await;
    f.ordinary(&f.db, json!({"body_append":" first"}))
        .await
        .unwrap();
    let second = f.independent().await;
    let (peer, state) = f.open(&second, "acct:alice", PeerKind::Edit).await;
    let replica = Replica::new(&state);
    use yrs::GetString;
    assert_eq!(
        replica
            .doc
            .get_or_insert_text("body")
            .get_string(&replica.doc.transact()),
        format!("{SEED} first")
    );
    submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    let ordinary = crate::create_database(":memory:").await.unwrap();
    assert!(submit(
        ordinary.clone(),
        Caller::authenticated("acct:alice"),
        Command::Open {
            record: f.record.clone(),
            mode: PeerKind::Edit
        }
    )
    .await
    .is_err());
    ordinary.close().await;
    second.close().await;
    f.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_version_waiters_complete_once_and_hold_lane_until_physical_close_ack() {
    for phase in [
        Phase::BeforeBegin,
        Phase::AfterBegin,
        Phase::AfterAppend,
        Phase::AfterCommit,
        Phase::BeforeClose,
    ] {
        let f = Fixture::new().await;
        let second = f.independent().await;
        let (peer, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
        update(&f.db, &peer, Replica::new(&state).append(" landed"))
            .await
            .unwrap();
        let before = f.durable().await;
        let request = Uuid::new_v4();
        let (hold, entered) = gate(phase);
        let runner_gate = hold.clone();
        let db = f.db.clone();
        let command_peer = peer.clone();
        let waiter = tokio::spawn(async move {
            TEST_GATE
                .scope(
                    runner_gate,
                    submit(
                        db,
                        Caller::authenticated("acct:alice"),
                        Command::Version {
                            peer: command_peer,
                            reason: "explicit version".into(),
                            request,
                        },
                    ),
                )
                .await
        });
        reached(entered).await;
        waiter.abort();
        let _ = waiter.await;
        assert!(!hold.writer_close_ack.load(Ordering::Acquire));
        let db = second.clone();
        let sync_peer = peer.clone();
        let queued = tokio::spawn(async move {
            submit(
                db,
                Caller::authenticated("acct:alice"),
                Command::Sync {
                    peer: sync_peer,
                    vector: vec![0],
                },
            )
            .await
        });
        tokio::time::timeout(
            Duration::from_secs(10),
            second.coedit_owner().unwrap().wait_for_accepted(2),
        )
        .await
        .unwrap();
        // This accepted room command cannot disclose before original physical ACK.
        assert!(!queued.is_finished());
        hold.release.add_permits(1);
        let synced = tokio::time::timeout(Duration::from_secs(10), queued)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(synced, Reply::Synced(_)));
        assert!(hold.writer_close_ack.load(Ordering::Acquire));
        assert!(hold.outcome.lock().unwrap().as_ref().unwrap().0);
        let committed = f.durable().await;
        assert_eq!(committed.0, format!("{SEED} landed"));
        assert_eq!(committed.1, before.1 + 1);
        assert_eq!(committed.2, before.2 + 1);
        assert!(!dirty(&second));
        let owner = second.coedit_owner().unwrap();
        assert!(owner
            .sessions
            .lock()
            .unwrap()
            .registry
            .version_snapshot(&peer.session)
            .unwrap()
            .contributors()
            .is_empty());
        f.cut(&second, &peer, request).await.unwrap();
        assert_eq!(f.durable().await, committed);
        submit(
            second.clone(),
            Caller::authenticated("acct:alice"),
            Command::Leave { peer },
        )
        .await
        .unwrap();
        second.close().await;
        f.db.close().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_after_append_rolls_back_without_drain_and_postcommit_failure_quarantines() {
    let f = Fixture::new().await;
    let (peer, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    update(&f.db, &peer, Replica::new(&state).append(" pending"))
        .await
        .unwrap();
    let before = f.durable().await;
    let ledger =
        f.db.coedit_owner()
            .unwrap()
            .sessions
            .lock()
            .unwrap()
            .registry
            .acknowledged_contributors(&peer.session)
            .unwrap();
    let error = TEST_FAULT
        .scope(TestFault::AfterAppend, f.cut(&f.db, &peer, Uuid::new_v4()))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("injected"));
    assert_eq!(f.durable().await, before);
    assert!(dirty(&f.db));
    assert_eq!(
        f.db.coedit_owner()
            .unwrap()
            .sessions
            .lock()
            .unwrap()
            .registry
            .acknowledged_contributors(&peer.session)
            .unwrap(),
        ledger
    );
    f.cut(&f.db, &peer, Uuid::new_v4()).await.unwrap();
    assert!(!dirty(&f.db));
    submit(
        f.db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    f.db.close().await;

    let f = Fixture::new().await;
    let second = f.independent().await;
    let (peer, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    update(
        &f.db,
        &peer,
        Replica::new(&state).append(" committed uncertain"),
    )
    .await
    .unwrap();
    let before = f.durable().await;
    let request = Uuid::new_v4();
    let (hold, entered) = gate(Phase::BeforeClose);
    let db = f.db.clone();
    let command_peer = peer.clone();
    let runner_gate = hold.clone();
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(
                runner_gate,
                TEST_FAULT.scope(
                    TestFault::AfterCommit,
                    submit(
                        db,
                        Caller::authenticated("acct:alice"),
                        Command::Version {
                            peer: command_peer,
                            reason: "explicit version".into(),
                            request,
                        },
                    ),
                ),
            )
            .await
    });
    reached(entered).await;
    assert!(!hold.writer_close_ack.load(Ordering::Acquire));
    assert!(dirty(&second));
    hold.release.add_permits(1);
    let error = waiter.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("poisoned"));
    assert!(hold.writer_close_ack.load(Ordering::Acquire));
    let committed = f.durable().await;
    assert_eq!(committed.0, format!("{SEED} committed uncertain"));
    assert_eq!(committed.1, before.1 + 1);
    assert_eq!(committed.2, before.2 + 1);
    assert_eq!(
        second
            .coedit_owner()
            .unwrap()
            .sessions
            .lock()
            .unwrap()
            .registry
            .acknowledged_contributors(&peer.session)
            .unwrap()
            .len(),
        1
    );
    assert!(f.cut(&second, &peer, request).await.is_err());
    assert!(f
        .ordinary(&second, json!({"body_append":"escape"}))
        .await
        .is_err());
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Open {
            record: f.record.clone(),
            mode: PeerKind::Edit
        }
    )
    .await
    .is_err());
    assert!(!second.drain_enrolled_execution_for_shutdown().await);
    assert!(!second.enrolled_retirement_complete());
    assert_eq!(f.durable().await, committed);
    // Deliberately unresolved: no successful shutdown or blind retry claim.
}

#[tokio::test]
async fn dirty_last_editor_leave_with_viewers_and_terminal_leave_are_nondestructive() {
    let f = Fixture::new().await;
    let second = f.independent().await;
    let (alice, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    let (viewer, _) = f.open(&second, "acct:viewer", PeerKind::View).await;
    update(&f.db, &alice, Replica::new(&state).append(" retain"))
        .await
        .unwrap();
    let body =
        f.db.coedit_owner()
            .unwrap()
            .sessions
            .lock()
            .unwrap()
            .registry
            .live_body(&alice.session)
            .unwrap();
    let error = submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave {
            peer: alice.clone(),
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("dirty session close"));
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:viewer"),
        Command::Sync {
            peer: viewer.clone(),
            vector: vec![0]
        }
    )
    .await
    .is_ok());
    submit(
        second.clone(),
        Caller::authenticated("acct:viewer"),
        Command::Leave { peer: viewer },
    )
    .await
    .unwrap();
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave {
            peer: alice.clone()
        }
    )
    .await
    .is_err());
    let (bob, _) = f.open(&second, "acct:bob", PeerKind::Edit).await;
    submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave {
            peer: alice.clone(),
        },
    )
    .await
    .unwrap();
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:bob"),
        Command::Leave { peer: bob.clone() }
    )
    .await
    .is_err());
    let owner = second.coedit_owner().unwrap();
    assert_eq!(
        owner
            .sessions
            .lock()
            .unwrap()
            .registry
            .live_body(&bob.session)
            .unwrap(),
        body
    );
    assert_eq!(
        owner
            .sessions
            .lock()
            .unwrap()
            .registry
            .acknowledged_contributors(&bob.session)
            .unwrap()
            .len(),
        1
    );
    submit(
        second.clone(),
        Caller::authenticated("acct:bob"),
        Command::Version {
            peer: bob.clone(),
            reason: "preserve departed contribution".into(),
            request: Uuid::new_v4(),
        },
    )
    .await
    .unwrap();
    assert_eq!(f.durable().await.0, body);
    submit(
        second.clone(),
        Caller::authenticated("acct:bob"),
        Command::Leave { peer: bob },
    )
    .await
    .unwrap();
    second.close().await;
    f.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retirement_checks_dirty_state_after_accepted_update_drains_and_other_handle_can_cut() {
    let f = Fixture::new().await;
    let second = f.independent().await;
    let (peer, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    assert!(!dirty(&f.db));
    let (hold, entered) = gate(Phase::BeforeLane);
    let runner_gate = hold.clone();
    let db = f.db.clone();
    let update_peer = peer.clone();
    let bytes = Replica::new(&state).append(" queued before retirement");
    let update_waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(runner_gate, update(&db, &update_peer, bytes))
            .await
    });
    reached(entered).await;
    let closing = f.db.clone();
    let close = tokio::spawn(async move { closing.drain_enrolled_execution_for_shutdown().await });
    tokio::time::timeout(
        Duration::from_secs(10),
        crate::db::enrolled::wait_for_handle_stop(&f.db),
    )
    .await
    .unwrap();
    // Shutdown cannot succeed using the clean pre-drain observation.
    assert!(!close.is_finished());
    hold.release.add_permits(1);
    update_waiter.await.unwrap().unwrap();
    assert!(!tokio::time::timeout(Duration::from_secs(10), close)
        .await
        .unwrap()
        .unwrap());
    assert!(hold.writer_close_ack.load(Ordering::Acquire));
    assert!(dirty(&second));
    assert!(!f.db.enrolled_retirement_complete());
    assert!(!f.db.pool().is_closed());
    f.cut(&second, &peer, Uuid::new_v4()).await.unwrap();
    assert_eq!(
        f.durable().await.0,
        format!("{SEED} queued before retirement")
    );
    submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    assert!(f.db.drain_enrolled_execution_for_shutdown().await);
    f.db.close().await;
    assert!(f.db.enrolled_retirement_complete());
    second.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exact_purpose_receipts_annotations_provenance_and_realtime_survive_owned_version() {
    let f = Fixture::new().await;
    let (db, hub) = crate::realtime::RealtimeHub::attach(f.db.clone(), None)
        .await
        .unwrap();
    let mut stream = hub.subscribe();
    let (peer, state) = f.open(&db, "acct:alice", PeerKind::Edit).await;
    let bytes = Replica::new(&state).append(" human 🐋");
    let update_command = Command::Update {
        peer: peer.clone(),
        bytes,
    };
    let (purpose, args) = update_command.purpose();
    let issuer = crate::provenance::ProvenanceInteractionTokenIssuer::random("session-test-ui");
    let scope = crate::provenance::verified_action_scope(purpose, &args);
    let token = issuer.issue("acct:alice", &scope, 60).unwrap();
    let human = Caller::authenticated("acct:alice")
        .with_provenance_interaction_token(&issuer, &token, &scope)
        .unwrap();
    submit(db.clone(), human.clone(), update_command)
        .await
        .unwrap();
    let before = f.durable().await;
    let wrong = submit(
        db.clone(),
        human,
        Command::Version {
            peer: peer.clone(),
            reason: "wrong update receipt".into(),
            request: Uuid::new_v4(),
        },
    )
    .await
    .unwrap_err();
    assert!(wrong.to_string().contains("scope does not allow"));
    assert_eq!(f.durable().await, before);
    let version_command = Command::Version {
        peer: peer.clone(),
        reason: "purpose bound version".into(),
        request: Uuid::new_v4(),
    };
    let (purpose, args) = version_command.purpose();
    let scope = crate::provenance::verified_action_scope(purpose, &args);
    let token = issuer.issue("acct:alice", &scope, 60).unwrap();
    let human = Caller::authenticated("acct:alice")
        .with_provenance_interaction_token(&issuer, &token, &scope)
        .unwrap();
    let annotations = crate::store::EventAnnotations {
        run_key: Some("lantern-furlong-bpyv8e".into()),
        parent_key: Some("aurora-drizzle-8ajavx".into()),
        intent: Some("owned test version".into()),
    };
    let Reply::Versioned(receipt) = crate::store::with_event_annotations(
        annotations.clone(),
        submit(db.clone(), human, version_command),
    )
    .await
    .unwrap() else {
        panic!("version")
    };
    let event_id = receipt["event_id"].as_str().unwrap();
    let event: (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT payload,actor,run_key,parent_key,intent FROM content_events WHERE id=?",
    )
    .bind(event_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(event.1, "acct:alice");
    assert_eq!(
        (event.2, event.3, event.4),
        (
            annotations.run_key,
            annotations.parent_key,
            annotations.intent
        )
    );
    let payload: Value = serde_json::from_str(&event.0).unwrap();
    assert_eq!(
        payload["contributors"],
        json!([{"principal":"acct:alice","executor_kind":"human"}])
    );
    let provenance: (String,String,String) = sqlx::query_as("SELECT a.principal,a.executor_kind,a.operation FROM provenance_action_attestations a JOIN provenance_action_outputs o ON a.id=o.action_attestation_id WHERE o.output_event_id=? AND o.output_domain='content'")
        .bind(event_id).fetch_one(db.pool()).await.unwrap();
    assert_eq!(
        provenance,
        (
            "acct:alice".into(),
            "human".into(),
            "session.version".into()
        )
    );
    tokio::time::timeout(
        Duration::from_secs(10),
        crate::realtime::wait_until_published_for_tests(&db, receipt["version"].as_i64().unwrap()),
    )
    .await
    .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(10), stream.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frame.record_id, f.record);
    submit(
        db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    crate::realtime::terminalize_hosted_router_hub(&hub);
    db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_pending_job_prevents_false_owner_retirement_when_this_handle_has_no_jobs() {
    let f = Fixture::new().await;
    let second = f.independent().await;
    let (peer, state) = f.open(&second, "acct:alice", PeerKind::Edit).await;
    let (hold, entered) = gate(Phase::BeforeLane);
    let runner_gate = hold.clone();
    let db = second.clone();
    let command_peer = peer.clone();
    let bytes = Replica::new(&state).append(" independent pending");
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(runner_gate, update(&db, &command_peer, bytes))
            .await
    });
    reached(entered).await;
    assert!(!dirty(&f.db));
    // f.db's HandleJobs is empty, but the shared owner has accepted work.
    assert!(!f.db.drain_enrolled_execution_for_shutdown().await);
    assert!(!f.db.enrolled_retirement_complete());
    hold.release.add_permits(1);
    waiter.await.unwrap().unwrap();
    assert!(hold.writer_close_ack.load(Ordering::Acquire));
    assert!(dirty(&second));
    f.db.close().await;
    assert!(!f.db.pool().is_closed());
    f.cut(&second, &peer, Uuid::new_v4()).await.unwrap();
    submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    f.db.close().await;
    assert!(f.db.enrolled_retirement_complete());
    second.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn independent_close_refuses_held_lane_without_cancelling_original_physical_cleanup() {
    let f = Fixture::new().await;
    let second = f.independent().await;
    let (peer, state) = f.open(&second, "acct:alice", PeerKind::Edit).await;
    let (hold, entered) = gate(Phase::BeforeClose);
    let runner_gate = hold.clone();
    let db = second.clone();
    let command_peer = peer.clone();
    let bytes = Replica::new(&state).append(" retained independent cleanup");
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(runner_gate, update(&db, &command_peer, bytes))
            .await
    });
    reached(entered).await;
    // The actual owner lane is held through B's original physical close. A has
    // no local accepted jobs and must refuse without waiting for that cleanup.
    assert!(!hold.writer_close_ack.load(Ordering::Acquire));
    assert!(!tokio::time::timeout(
        Duration::from_secs(10),
        f.db.drain_enrolled_execution_for_shutdown(),
    )
    .await
    .expect("independent close must stay bounded"));
    assert!(!hold.writer_close_ack.load(Ordering::Acquire));
    assert!(!waiter.is_finished());
    assert!(!f.db.enrolled_retirement_complete());
    assert!(!f.db.pool().is_closed());

    // Refusal leaves B's retained runner and admission intact. Releasing the
    // exact gate resumes the original close, then B can preserve the dirty room.
    hold.release.add_permits(1);
    waiter.await.unwrap().unwrap();
    assert!(hold.writer_close_ack.load(Ordering::Acquire));
    assert!(dirty(&second));
    f.cut(&second, &peer, Uuid::new_v4()).await.unwrap();
    assert_eq!(
        f.durable().await.0,
        format!("{SEED} retained independent cleanup")
    );
    submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    assert!(f.db.drain_enrolled_execution_for_shutdown().await);
    f.db.close().await;
    second.close().await;
}

#[tokio::test]
async fn refused_and_duplicate_updates_do_not_invent_dirty_state_or_contributors() {
    let f = Fixture::new().await;
    let (peer, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    let before = f.durable().await;
    let mut forged = state.clone();
    forged.client_ids[0] += 100; // not leased to this or any other joined peer
    let bytes = Replica::new(&forged).append(" forged new author");
    let error = update(&f.db, &peer, bytes).await.unwrap_err();
    assert!(error.to_string().contains("foreign_client_id"), "{error}");
    assert!(!dirty(&f.db));
    assert!(f
        .db
        .coedit_owner()
        .unwrap()
        .sessions
        .lock()
        .unwrap()
        .registry
        .acknowledged_contributors(&peer.session)
        .unwrap()
        .is_empty());
    update(&f.db, &peer, state.sync_step2.clone())
        .await
        .unwrap(); // only already-known seed structs
    assert!(!dirty(&f.db));
    assert_eq!(f.durable().await, before);
    let error = submit(
        f.db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Version {
            peer: peer.clone(),
            reason: " \n ".into(),
            request: Uuid::new_v4(),
        },
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("reason"));
    assert_eq!(f.durable().await, before);
    submit(
        f.db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    f.db.close().await;
}

#[tokio::test]
async fn unmanaged_independent_opens_keep_ordinary_authenticated_body_behavior() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ordinary.db");
    let first = crate::create_database(path.to_str().unwrap())
        .await
        .unwrap();
    let mut tools = ToolRegistry::new();
    crate::mcp::register_surface_tools(&mut tools).unwrap();
    let created = tools.call(first.clone(), Caller::local(), "create_record", json!({
        "type":"Document", "kind":"note", "name":"unmanaged fixture", "body":"ordinary", "reason":"fixture bootstrap"
    })).await.unwrap();
    let record = created["id"].as_str().unwrap();
    crate::authorization::replace_explicit_policy(
        &first,
        "test:bootstrap",
        record,
        vec![AllowEntry::account("acct:alice", Capability::Edit)],
    )
    .await
    .unwrap();
    let second = crate::db::open_existing_database_at(&path).await.unwrap();
    assert!(!first.is_enrolled() && !second.is_enrolled());
    for (db, text) in [(&first, " one"), (&second, " two")] {
        tools
            .call(
                db.clone(),
                Caller::authenticated("acct:alice"),
                "update_record",
                json!({"id":record,"body_append":text,"reason":"ordinary authenticated append"}),
            )
            .await
            .unwrap();
    }
    let body: String = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(record)
        .fetch_one(first.pool())
        .await
        .unwrap();
    assert_eq!(body, "ordinary one two");
    assert!(submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Open {
            record: record.into(),
            mode: PeerKind::Edit
        }
    )
    .await
    .is_err());
    second.close().await;
    first.close().await;
}

#[tokio::test]
async fn delete_only_update_without_state_vector_advance_is_dirty_until_version_and_replay_is_clean(
) {
    let f = Fixture::new().await;
    let second = f.independent().await;
    let (peer, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    let replica = Replica::new(&state);
    let vector = replica.doc.transact().state_vector();
    let encoded_vector = vector.encode_v1();
    let text = replica.doc.get_or_insert_text("body");
    text.remove_range(&mut replica.doc.transact_mut(), 0, 5); // ASCII "seed "; retain exact Unicode/CRLF
    let deletion = replica.doc.transact().encode_diff_v1(&vector);
    assert_eq!(
        replica.doc.transact().state_vector().encode_v1(),
        encoded_vector
    );
    let before = f.durable().await;
    let owner = f.db.coedit_owner().unwrap();
    let epoch = owner
        .sessions
        .lock()
        .unwrap()
        .registry
        .mutation_epoch(&peer.session)
        .unwrap();
    let Reply::Updated(ack) = update(&f.db, &peer, deletion.clone()).await.unwrap() else {
        panic!("delete ACK")
    };
    assert_eq!(ack.state_vector, encoded_vector);
    assert!(dirty(&second));
    let expected = SEED.strip_prefix("seed ").unwrap();
    let retained = {
        let state = owner.sessions.lock().unwrap();
        assert_eq!(state.registry.live_body(&peer.session).unwrap(), expected);
        assert_eq!(
            state.registry.mutation_epoch(&peer.session).unwrap(),
            epoch + 1
        );
        assert_eq!(
            state
                .registry
                .acknowledged_contributors(&peer.session)
                .unwrap(),
            vec![AcknowledgedContributor {
                principal: "acct:alice".into(),
                executor_kind: "authenticated_principal".into(),
            }]
        );
        state.registry.version_snapshot(&peer.session).unwrap()
    };
    assert!(submit(
        f.db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer: peer.clone() }
    )
    .await
    .is_err());
    // Retirement through an independent handle must not discard a deletion
    // merely because no insertion clock advanced.
    second.close().await;
    assert!(!second.enrolled_retirement_complete());
    assert!(!second.pool().is_closed());
    assert!(dirty(&f.db));
    assert_eq!(f.durable().await, before);
    {
        let state = owner.sessions.lock().unwrap();
        assert_eq!(
            state.registry.live_body(&peer.session).unwrap(),
            retained.body()
        );
        assert_eq!(
            state
                .registry
                .acknowledged_contributors(&peer.session)
                .unwrap(),
            retained.contributors()
        );
    }
    let Reply::Versioned(receipt) = f.cut(&f.db, &peer, Uuid::new_v4()).await.unwrap() else {
        panic!("version")
    };
    let committed = f.durable().await;
    assert_eq!(committed.0, expected);
    assert_eq!(committed.1, before.1 + 1);
    assert_eq!(committed.2, before.2 + 1);
    assert_eq!(
        receipt["contributors"],
        json!([{"principal":"acct:alice", "executor_kind":"authenticated_principal"}])
    );
    let payload: String = sqlx::query_scalar("SELECT payload FROM content_events WHERE id=?")
        .bind(receipt["event_id"].as_str().unwrap())
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    let payload: Value = serde_json::from_str(&payload).unwrap();
    assert_eq!(payload["body"], expected);
    assert_eq!(payload["contributors"], receipt["contributors"]);
    assert!(!dirty(&f.db));
    update(&f.db, &peer, deletion).await.unwrap();
    assert!(!dirty(&f.db));
    {
        let state = owner.sessions.lock().unwrap();
        assert_eq!(
            state.registry.mutation_epoch(&peer.session).unwrap(),
            epoch + 1
        );
        assert!(state
            .registry
            .acknowledged_contributors(&peer.session)
            .unwrap()
            .is_empty());
        assert_eq!(state.registry.live_body(&peer.session).unwrap(), expected);
    }
    assert_eq!(f.durable().await, committed);
    submit(
        f.db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    second.close().await;
    f.db.close().await;
}

#[tokio::test]
async fn same_body_insert_delete_change_is_dirty_and_version_preserves_authored_contribution() {
    let f = Fixture::new().await;
    let (peer, state) = f.open(&f.db, "acct:alice", PeerKind::Edit).await;
    let replica = Replica::new(&state);
    let before = f.durable().await;
    let vector = replica.doc.transact().state_vector();
    let text = replica.doc.get_or_insert_text("body");
    {
        let mut tx = replica.doc.transact_mut();
        text.insert(&mut tx, 0, "xy");
        text.remove_range(&mut tx, 0, 2);
    }
    let bytes = replica.doc.transact().encode_diff_v1(&vector);
    let epoch =
        f.db.coedit_owner()
            .unwrap()
            .sessions
            .lock()
            .unwrap()
            .registry
            .mutation_epoch(&peer.session)
            .unwrap();
    update(&f.db, &peer, bytes.clone()).await.unwrap();
    assert!(dirty(&f.db));
    assert_eq!(f.durable().await, before);
    {
        let owner = f.db.coedit_owner().unwrap();
        let state = owner.sessions.lock().unwrap();
        assert_eq!(state.registry.live_body(&peer.session).unwrap(), SEED);
        assert_eq!(
            state.registry.mutation_epoch(&peer.session).unwrap(),
            epoch + 1
        );
        assert_eq!(
            state
                .registry
                .acknowledged_contributors(&peer.session)
                .unwrap()
                .len(),
            1
        );
    }
    assert!(submit(
        f.db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer: peer.clone() }
    )
    .await
    .is_err());
    let Reply::Versioned(receipt) = f.cut(&f.db, &peer, Uuid::new_v4()).await.unwrap() else {
        panic!("version")
    };
    assert_eq!(
        receipt["contributors"],
        json!([{"principal":"acct:alice", "executor_kind":"authenticated_principal"}])
    );
    let committed = f.durable().await;
    assert_eq!(committed.0, SEED);
    assert_eq!(committed.1, before.1 + 1);
    assert_eq!(committed.2, before.2 + 1);
    update(&f.db, &peer, bytes).await.unwrap();
    assert!(!dirty(&f.db));
    assert_eq!(f.durable().await, committed);
    submit(
        f.db.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    f.db.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_witness_retries_dirty_session_after_independent_cut_and_leave() {
    let f = body_witness_test_step(Fixture::new).await;
    let second = body_witness_test_step(|| f.independent()).await;
    let (peer, state) =
        body_witness_test_step(|| f.open(&second, "acct:alice", PeerKind::Edit)).await;
    let bytes = Replica::new(&state).append(" body witness dirty recovery");
    body_witness_test_step(|| update(&second, &peer, bytes))
        .await
        .unwrap();
    assert!(dirty(&second));
    let witness = f.db.fence_body_retirement();
    assert!(!body_witness_test_step(|| witness.drain()).await);
    assert!(witness.body_complete());
    assert!(!witness.retirement_complete());
    assert!(!f.db.pool().is_closed());
    assert!(!f.db.write_pool().is_closed());
    assert!(!f.db.governed_pool().is_closed());

    body_witness_test_step(|| f.cut(&second, &peer, Uuid::new_v4()))
        .await
        .unwrap();
    assert_eq!(
        body_witness_test_step(|| f.durable()).await.0,
        format!("{SEED} body witness dirty recovery")
    );
    body_witness_test_step(|| {
        submit(
            second.clone(),
            Caller::authenticated("acct:alice"),
            Command::Leave { peer },
        )
    })
    .await
    .unwrap();
    assert!(!dirty(&second));
    // Retry the original witness, not a rebuilt physical cleanup.
    assert!(body_witness_test_step(|| witness.drain()).await);
    assert!(witness.retirement_complete());
    assert!(f.db.enrolled_retirement_complete());
    assert!(f.db.pool().is_closed() && f.db.pool().size() == 0);
    assert!(f.db.write_pool().is_closed() && f.db.write_pool().size() == 0);
    assert!(f.db.governed_pool().is_closed() && f.db.governed_pool().size() == 0);
    body_witness_test_step(|| second.close()).await;
}

// Construct each awaited test future outside the caller's poll frame. The
// boxed future still runs in this same task, preserving task-local admissions.
fn body_witness_test_step<F: std::future::Future>(
    make: impl FnOnce() -> F,
) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn body_witness_retries_independent_retained_lane_after_original_ack() {
    let f = Fixture::new().await;
    let second = f.independent().await;
    let (peer, state) = f.open(&second, "acct:alice", PeerKind::Edit).await;
    let (hold, entered) = gate(Phase::BeforeClose);
    // Signal the original fixture gate on unwind; this is never close ACK.
    struct ReleaseGate(Arc<TestGate>);
    impl Drop for ReleaseGate {
        fn drop(&mut self) {
            self.0.release.add_permits(1);
        }
    }
    let _release_gate = ReleaseGate(hold.clone());
    let runner_gate = hold.clone();
    let db = second.clone();
    let command_peer = peer.clone();
    let bytes = Replica::new(&state).append(" body witness held lane");
    let waiter = tokio::spawn(async move {
        TEST_GATE
            .scope(runner_gate, update(&db, &command_peer, bytes))
            .await
    });
    reached(entered).await;
    let witness = f.db.fence_body_retirement();
    assert!(!hold.writer_close_ack.load(Ordering::Acquire));
    assert!(
        !tokio::time::timeout(Duration::from_secs(10), witness.drain())
            .await
            .expect("independent witness refusal must stay bounded")
    );
    assert!(!hold.writer_close_ack.load(Ordering::Acquire));
    assert!(!waiter.is_finished());
    assert!(!witness.retirement_complete());
    assert!(!f.db.pool().is_closed());
    assert!(!f.db.write_pool().is_closed());
    assert!(!f.db.governed_pool().is_closed());

    hold.release.add_permits(1);
    waiter.await.unwrap().unwrap();
    assert!(hold.writer_close_ack.load(Ordering::Acquire));
    assert!(dirty(&second));
    f.cut(&second, &peer, Uuid::new_v4()).await.unwrap();
    assert_eq!(
        f.durable().await.0,
        format!("{SEED} body witness held lane")
    );
    submit(
        second.clone(),
        Caller::authenticated("acct:alice"),
        Command::Leave { peer },
    )
    .await
    .unwrap();
    assert!(witness.drain().await);
    assert!(witness.retirement_complete());
    assert!(f.db.enrolled_retirement_complete());
    assert!(f.db.pool().is_closed() && f.db.pool().size() == 0);
    assert!(f.db.write_pool().is_closed() && f.db.write_pool().size() == 0);
    assert!(f.db.governed_pool().is_closed() && f.db.governed_pool().size() == 0);
    second.close().await;
}
