use super::*;
use crate::v2_standard::claims_v1::{self as provider, Command};

struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
    other: String,
    record: String,
    run: RunContext,
    other_run: RunContext,
}
impl World {
    async fn fresh() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let (db, admin) = create_v2_database(
            &format!("sqlite://{}", dir.path().join("claims.db").display()),
            "account",
            "Owner",
            "acct:owner",
        )
        .await
        .unwrap();
        let other = create_principal(&db, "account", "Other", "acct:other", &admin)
            .await
            .unwrap();
        // Keep record ownership distinct from both claimants: owner floors
        // must not mask the Edit/View revocation regressions.
        let record_owner =
            create_principal(&db, "account", "Record owner", "acct:record-owner", &admin)
                .await
                .unwrap();
        replace_home_policy(
            &db,
            &admin,
            KERNEL_ROOT_ID,
            &[
                (&admin, "manage"),
                (&other, "manage"),
                (&record_owner, "edit"),
            ],
        )
        .await
        .unwrap();
        let manifest = provider::package();
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
        let record = create_record_as(&db, &record_owner, KERNEL_ROOT_ID)
            .await
            .unwrap();
        let run = Self::run_for(&db, &admin, &admin, "one").await;
        let other_run = Self::run_for(&db, &admin, &other, "other").await;
        Self {
            _dir: dir,
            db,
            admin,
            other,
            record,
            run,
            other_run,
        }
    }
    async fn run_for(db: &Db, host: &str, owner: &str, key: &str) -> RunContext {
        let principal = create_principal(db, "run", key, &format!("run:{key}"), host)
            .await
            .unwrap();
        run_ledger::register_run_as(db, host, owner, &principal)
            .await
            .unwrap()
    }
    async fn prepare(&self, run: &RunContext, key: &str, command: Command) -> ClaimRequest {
        prepare_claim_as(&self.db, run, &self.record, key, command)
            .await
            .unwrap()
    }
    async fn claim(&self) -> (ClaimRequest, ClaimReceipt) {
        let r = self.prepare(&self.run, "claim", Command::Claim).await;
        let ClaimResult::Committed(receipt) =
            commit_claim_as(&self.db, &self.run, &r).await.unwrap()
        else {
            panic!("expected receipt")
        };
        (r, receipt)
    }
    async fn release_command(&self) -> Command {
        let read = claims_as(&self.db, &self.admin, std::slice::from_ref(&self.record))
            .await
            .unwrap()
            .remove(0);
        Command::Release {
            holder_run_id: read.holder.unwrap().run_id,
            generation: read.generation.unwrap(),
            head: read.head.unwrap(),
        }
    }
    async fn count(&self) -> (i64, i64) {
        sqlx::query_as(
            "SELECT (SELECT COUNT(*) FROM content_events),(SELECT next_act FROM act_state WHERE singleton=1)",
        )
        .fetch_one(self.db.pool())
        .await
        .unwrap()
    }
    async fn select(&self, enabled: bool) {
        let p = provider::package();
        let id = p.identity().unwrap();
        adopt_package_at(
            &self.db,
            &self.admin,
            KERNEL_ROOT_ID,
            &p,
            if enabled { Some(&id) } else { None },
            if enabled { &p.declared_reads } else { &[] },
        )
        .await
        .unwrap();
    }
}
fn signature<T: std::fmt::Debug>(result: Result<T>, expected: &str) {
    let error = result.unwrap_err();
    match error {
        Error::Engine(s) | Error::Conflict(s) => assert_eq!(s, expected),
        e => panic!("{e:?}"),
    }
}
#[tokio::test]
async fn concurrent_claimers_exclude_and_foreign_manage_release_is_generic() {
    let w = World::fresh().await;
    let a = w.prepare(&w.run, "one", Command::Claim).await;
    let b = w.prepare(&w.other_run, "two", Command::Claim).await;
    let (one, two) = tokio::join!(
        commit_claim_as(&w.db, &w.run, &a),
        commit_claim_as(&w.db, &w.other_run, &b)
    );
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    let (loser, owner) = if one.is_ok() {
        (&w.other_run, &w.admin)
    } else {
        (&w.run, &w.other)
    };
    signature(if one.is_err() { one } else { two }, "already_claimed");
    let s = claims_as(&w.db, owner, std::slice::from_ref(&w.record))
        .await
        .unwrap()
        .remove(0);
    signature(
        prepare_claim_as(
            &w.db,
            loser,
            &w.record,
            "release",
            Command::Release {
                holder_run_id: s.holder.unwrap().run_id,
                generation: s.generation.unwrap(),
                head: s.head.unwrap(),
            },
        )
        .await,
        "already_claimed",
    );
}
#[tokio::test]
async fn same_run_noop_has_no_receipt_but_still_checks_edit_and_close() {
    let w = World::fresh().await;
    w.claim().await;
    let r = w.prepare(&w.run, "another-key", Command::Claim).await;
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    assert_eq!(
        commit_claim_as(&w.db, &w.run, &r).await.unwrap(),
        ClaimResult::Unchanged
    );
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "view"), (&w.other, "manage")],
    )
    .await
    .unwrap();
    signature(commit_claim_as(&w.db, &w.run, &r).await, HIDDEN_OR_MISSING);
    run_ledger::close_run_as(&w.db, &w.run).await.unwrap();
    assert!(
        claims_as(&w.db, &w.admin, std::slice::from_ref(&w.record))
            .await
            .unwrap()[0]
            .occupied
    );
    signature(
        prepare_claim_as(&w.db, &w.run, &w.record, "fresh", Command::Claim).await,
        "run_closed",
    );
}
#[tokio::test]
async fn cross_run_release_and_same_run_aba_keep_monotonic_head_and_generation() {
    let w = World::fresh().await;
    let other = World::run_for(&w.db, &w.admin, &w.admin, "same-owner").await;
    w.claim().await;
    let stale = w.release_command().await;
    let release = w.prepare(&other, "release", stale.clone()).await;
    commit_claim_as(&w.db, &other, &release).await.unwrap();
    let empty = claims_as(&w.db, &w.admin, std::slice::from_ref(&w.record))
        .await
        .unwrap()
        .remove(0);
    assert!(!empty.occupied);
    let next = w.prepare(&w.run, "reclaim", Command::Claim).await;
    assert!(next.expected_head.unwrap() > release.expected_head.unwrap());
    commit_claim_as(&w.db, &w.run, &next).await.unwrap();
    signature(
        prepare_claim_as(&w.db, &w.run, &w.record, "stale-same", stale.clone()).await,
        "stale_claim",
    );
    signature(
        prepare_claim_as(&w.db, &other, &w.record, "stale-cross", stale).await,
        "stale_claim",
    );
    let read = claims_as(&w.db, &w.admin, std::slice::from_ref(&w.record))
        .await
        .unwrap()
        .remove(0);
    assert_eq!(read.generation, Some(2));
    let release = w
        .prepare(&w.run, "release-two", w.release_command().await)
        .await;
    commit_claim_as(&w.db, &w.run, &release).await.unwrap();
    signature(
        prepare_claim_as(
            &w.db,
            &w.run,
            &w.record,
            "empty-release",
            Command::Release {
                holder_run_id: "x".into(),
                generation: 2,
                head: 0,
            },
        )
        .await,
        "unclaimed",
    );
}
#[tokio::test]
async fn close_and_permission_changes_refuse_pending_claim_without_partial_facts() {
    let w = World::fresh().await;
    let r = w.prepare(&w.run, "pending", Command::Claim).await;
    run_ledger::close_run_as(&w.db, &w.run).await.unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    signature(commit_claim_as(&w.db, &w.run, &r).await, "run_closed");
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    let w = World::fresh().await;
    let r = w.prepare(&w.run, "pending", Command::Claim).await;
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "view"), (&w.other, "manage")],
    )
    .await
    .unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    signature(commit_claim_as(&w.db, &w.run, &r).await, HIDDEN_OR_MISSING);
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
}
#[tokio::test]
async fn disable_and_selection_aba_fence_pending_claim() {
    let w = World::fresh().await;
    let r = w.prepare(&w.run, "pending", Command::Claim).await;
    w.select(false).await;
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    signature(
        commit_claim_as(&w.db, &w.run, &r).await,
        "package is disabled in this scope",
    );
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    w.select(true).await;
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    signature(
        commit_claim_as(&w.db, &w.run, &r).await,
        "claims selection head moved",
    );
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
}
#[tokio::test]
async fn target_binding_head_and_scope_eligibility_changes_fence_claim() {
    let w = World::fresh().await;
    let document = crate::v2_standard::document3_package();
    let id = install_package_as(&w.db, &w.admin, &document)
        .await
        .unwrap();
    adopt_package_at(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &document,
        Some(&id),
        &document.declared_reads,
    )
    .await
    .unwrap();
    let r = w.prepare(&w.run, "pending", Command::Claim).await;
    rebind_record_as(
        &w.db,
        &w.admin,
        &w.record,
        crate::v2_standard::DOCUMENT_FAMILY,
        "note",
        &serde_json::Map::new(),
    )
    .await
    .unwrap();
    signature(
        commit_claim_as(&w.db, &w.run, &r).await,
        "claims target binding or head moved",
    );
    let r = w.prepare(&w.run, "scope", Command::Claim).await;
    let home = create_home(&w.db, KERNEL_ROOT_ID, None, &w.admin)
        .await
        .unwrap();
    let p = provider::package();
    adopt_package_at(&w.db, &w.admin, &home, &p, None, &[])
        .await
        .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.record, &home)
        .await
        .unwrap();
    assert!(commit_claim_as(&w.db, &w.run, &r).await.is_err());
    signature(
        prepare_claim_as(&w.db, &w.run, &w.record, "new-scope", Command::Claim).await,
        "package is disabled in this scope",
    );
}
#[tokio::test]
async fn completed_retry_after_release_new_holder_and_close_needs_view_only() {
    let w = World::fresh().await;
    let retry_run = World::run_for(&w.db, &w.admin, &w.admin, "retry-owner").await;
    let (original, receipt) = w.claim().await;
    let release = w
        .prepare(&w.run, "release", w.release_command().await)
        .await;
    commit_claim_as(&w.db, &w.run, &release).await.unwrap();
    let next = w.prepare(&w.other_run, "new-holder", Command::Claim).await;
    commit_claim_as(&w.db, &w.other_run, &next).await.unwrap();
    run_ledger::close_run_as(&w.db, &w.run).await.unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "view"), (&w.other, "manage")],
    )
    .await
    .unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    assert_eq!(w.prepare(&w.run, "claim", Command::Claim).await, original);
    assert_eq!(
        commit_claim_as(&w.db, &w.run, &original).await.unwrap(),
        ClaimResult::Committed(receipt.clone())
    );
    assert_eq!(
        commit_claim_as(&w.db, &retry_run, &original).await.unwrap(),
        ClaimResult::Committed(receipt)
    );
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    replace_home_policy(&w.db, &w.other, KERNEL_ROOT_ID, &[(&w.other, "manage")])
        .await
        .unwrap();
    signature(
        commit_claim_as(&w.db, &w.run, &original).await,
        HIDDEN_OR_MISSING,
    );
}
#[tokio::test]
async fn bounded_reads_dedupe_redact_and_check_visibility_before_occupancy() {
    let w = World::fresh().await;
    w.claim().await;
    let other = create_record_as(&w.db, &w.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    let reads = claims_as(
        &w.db,
        &w.other,
        &[w.record.clone(), other.clone(), w.record.clone()],
    )
    .await
    .unwrap();
    assert_eq!(reads.len(), 2);
    assert!(reads[0].record_id < reads[1].record_id);
    let occupied = reads.iter().find(|r| r.record_id == w.record).unwrap();
    assert!(occupied.occupied && occupied.withheld);
    assert!(occupied.holder.is_none() && occupied.head.is_none() && occupied.generation.is_none());
    let own = claims_as(&w.db, &w.admin, std::slice::from_ref(&w.record))
        .await
        .unwrap()
        .remove(0);
    assert_eq!(own.holder.unwrap().principal, w.admin);
    assert!(claims_as(&w.db, &w.admin, &vec![w.record.clone(); 101])
        .await
        .is_err());
    assert!(
        claims_as(&w.db, &w.admin, &[w.record.clone(), "missing".into()])
            .await
            .is_err()
    );
    replace_home_policy(&w.db, &w.admin, KERNEL_ROOT_ID, &[(&w.admin, "manage")])
        .await
        .unwrap();
    signature(
        claims_as(&w.db, &w.other, std::slice::from_ref(&w.record)).await,
        HIDDEN_OR_MISSING,
    );
}
#[tokio::test]
async fn forged_context_attribution_assurance_keys_and_raw_writes_refuse() {
    let w = World::fresh().await;
    let r = w.prepare(&w.run, "pending", Command::Claim).await;
    let count = w.count().await;
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    signature(
        commit_claim_as(&w.db, &w.other_run, &r).await,
        HIDDEN_OR_MISSING,
    );
    let mut forged = r.clone();
    forged.principal_id = w.other.clone();
    signature(
        commit_claim_as(&w.db, &w.run, &forged).await,
        HIDDEN_OR_MISSING,
    );
    let mut forged_run = r.clone();
    forged_run.run.head += 1;
    forged_run.request_checksum.clear();
    forged_run.request_checksum = crate::meta::definition_artifact::digest_artifact_bytes(
        &serde_json::to_vec(&forged_run).unwrap(),
    );
    signature(
        commit_claim_as(&w.db, &w.run, &forged_run).await,
        "claims run witness moved",
    );
    let mut json = serde_json::to_value(&r).unwrap();
    json["assurance"] = serde_json::json!("host");
    assert!(serde_json::from_value::<ClaimRequest>(json).is_err());
    for key in ["", " space", "a\nb", &"x".repeat(257)] {
        assert!(
            prepare_claim_as(&w.db, &w.run, &w.record, key, Command::Claim)
                .await
                .is_err()
        );
    }
    for kind in [
        commit_port::PROVIDER_OUTCOME_EVENT,
        run_ledger::OPEN,
        run_ledger::CLOSE,
        run_ledger::INTENT,
    ] {
        assert!(crate::store::append(
            &w.db,
            AppendSpec {
                record_id: r.aggregate_id.clone(),
                event_type: kind.into(),
                payload: serde_json::json!({"request":r,"receipt_id":Uuid::new_v4().to_string()}),
                actor: Some(w.admin.clone())
            }
        )
        .await
        .is_err());
    }
    let mut tx = w.db.write_pool().begin().await.unwrap();
    let mut unlogged = crate::conformance::rebuild::read_all_events(&mut tx)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.event_type == run_ledger::OPEN)
        .unwrap();
    unlogged.id = Uuid::new_v4().to_string();
    signature(
        crate::projector::project(&mut tx, &unlogged).await,
        "run projection requires the kernel-issued logged event",
    );
    tx.rollback().await.unwrap();
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    let run_principal = create_principal(&w.db, "run", "Denied", "run:denied", &w.admin)
        .await
        .unwrap();
    assert!(
        run_ledger::register_run_as(&w.db, &w.other, &w.other, &run_principal)
            .await
            .is_err()
    );
    assert!(run_ledger::context_as(&w.db, &w.admin, "unknown")
        .await
        .is_err());
}
#[tokio::test]
async fn receipt_insert_failure_rolls_back_event_state_subjects_and_act_allocation() {
    let w = World::fresh().await;
    let r = w.prepare(&w.run, "pending", Command::Claim).await;
    sqlx::query("CREATE TRIGGER refuse_claim_receipt BEFORE INSERT ON kernel_provider_receipts BEGIN SELECT RAISE(ABORT,'injected receipt failure'); END").execute(w.db.write_pool()).await.unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    let error = commit_claim_as(&w.db, &w.run, &r).await.unwrap_err();
    assert!(error.to_string().contains("injected receipt failure"));
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    sqlx::query("DROP TRIGGER refuse_claim_receipt")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    commit_claim_as(&w.db, &w.run, &r).await.unwrap();
}
#[tokio::test]
async fn retry_key_conflicts_and_immutable_ledger_replay_preserve_empty_head() {
    let w = World::fresh().await;
    let (r, receipt) = w.claim().await;
    let another = create_record_as(&w.db, &w.admin, KERNEL_ROOT_ID)
        .await
        .unwrap();
    signature(
        prepare_claim_as(&w.db, &w.run, &another, "claim", Command::Claim).await,
        "claims retry key reused",
    );
    let mut forged = r.clone();
    forged.command = Command::Release {
        holder_run_id: r.run.run_id.clone(),
        generation: 1,
        head: receipt.event_seq,
    };
    forged.operation_key = "claim".into();
    assert!(commit_claim_as(&w.db, &w.run, &forged).await.is_err());
    let release = w
        .prepare(&w.run, "release", w.release_command().await)
        .await;
    commit_claim_as(&w.db, &w.run, &release).await.unwrap();
    run_ledger::close_run_as(&w.db, &w.run).await.unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    // A pre-metadata native file can recover the latest record/claim activity
    // from the existing log and validated provider subject index.
    sqlx::query("DROP TABLE kernel_record_metadata")
        .execute(w.db.write_pool())
        .await
        .unwrap();
    ensure_record_metadata(&w.db).await.unwrap();
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    let context = run_ledger::context_as(&w.db, &w.admin, &r.run.run_id)
        .await
        .unwrap();
    assert_eq!(
        commit_claim_as(&w.db, &context, &r).await.unwrap(),
        ClaimResult::Committed(receipt)
    );
    assert!(run_ledger::close_run_as(&w.db, &context).await.is_err());
}
#[test]
fn claims_manifest_has_optional_target_exact_identity_and_no_effects() {
    let p = provider::package();
    p.validate().unwrap();
    let canonical = p.canonical_value().unwrap();
    assert_eq!(canonical["operations"][0]["target"], "any-record");
    assert!(canonical["operations"][0].get("family").is_none());
    assert_eq!(
        crate::package_manifest::PackageManifest::from_canonical_value(&canonical).unwrap(),
        p
    );
    let mut foreign = p.clone();
    foreign.namespace = "fixture.claims".into();
    assert!(foreign.validate().is_err());
    let mut effects = p.clone();
    effects.operations[0].effects.push("record:edit".into());
    assert!(effects.validate().is_err());
    let mut extra = canonical.clone();
    extra["operations"][0]["family"] = serde_json::json!(provider::FAMILY);
    assert!(crate::package_manifest::PackageManifest::from_canonical_value(&extra).is_err());
}

#[tokio::test]
async fn retained_claims_one_dispatch_survives_a_newer_test_only_interpreter() {
    use super::provider_catalogue as catalogue;
    let old = crate::v2_standard::claims_retained::V1;
    fn future_pins() -> InterpretationPins {
        let mut p = provider::pins();
        p.provider = "fixture.claims/2".into();
        p.decoder = "fixture.claims.payload/2".into();
        p.reducer = "fixture.claims.fold/2".into();
        p.payload_version = 2;
        p
    }
    fn future_codec(_: &catalogue::StoredState) -> Result<serde_json::Value> {
        Err(Error::engine("future codec must not read old state"))
    }
    // This entry is only a fixture: it does not become an installable service.
    fn future_decode(_: &serde_json::Value) -> Result<catalogue::Decoded> {
        Err(Error::engine("future decoder must not decode old payload"))
    }
    let future = catalogue::Entry {
        pins: future_pins,
        decode: future_decode,
        state_codec: future_codec,
        ..crate::v2_standard::claims_retained::V1
    };
    let entries = [future, old];
    let p = provider::pins();
    let entry =
        catalogue::recorded_in(&serde_json::json!({"request":{"pins":p}}), &entries).unwrap();
    assert_eq!((entry.pins)(), p);
    let w = World::fresh().await;
    let request = w.prepare(&w.run, "pinned", Command::Claim).await;
    let payload = serde_json::to_value(claims_port::Outcome {
        request,
        receipt_id: Uuid::new_v4().to_string(),
    })
    .unwrap();
    let recorded = catalogue::recorded_in(&payload, &entries).unwrap();
    let decoded = (recorded.decode)(&payload).unwrap();
    let folded = (recorded.fold)(
        &catalogue::FoldInput {
            decoded: &decoded,
            principal: &w.admin,
            timestamp: "host time",
            event_seq: 100,
        },
        None,
    )
    .unwrap();
    assert_eq!(folded.state["holder"]["principal"], w.admin);
    assert_eq!(folded.state["holder"]["claimed_seq"], 100);
    let stored = catalogue::StoredState {
        pins: p,
        state: serde_json::json!({"record_id":"record","generation":3,"holder":null}),
        attribution: serde_json::Value::Null,
    };
    assert_eq!((entry.state_codec)(&stored).unwrap(), stored.state);
    assert!((entries[0].state_codec)(&stored).is_err());
    assert_eq!(
        crate::meta::definition_artifact::digest_artifact_bytes(include_bytes!(
            "../v2_standard/claims_v1.rs"
        )),
        crate::v2_standard::claims_retained::SOURCE_SHA
    );
}

#[tokio::test]
async fn policy_aba_and_host_ledger_linkage_are_fenced_without_new_facts() {
    let w = World::fresh().await;
    let r = w.prepare(&w.run, "pending", Command::Claim).await;
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.other, "view")],
    )
    .await
    .unwrap();
    replace_home_policy(
        &w.db,
        &w.admin,
        KERNEL_ROOT_ID,
        &[(&w.admin, "manage"), (&w.other, "manage")],
    )
    .await
    .unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    signature(
        commit_claim_as(&w.db, &w.run, &r).await,
        "claims authority frontier moved",
    );
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    assert_ne!(r.run.run_id, r.run.run_principal);
    assert!(
        run_ledger::register_run_as(&w.db, &w.admin, &w.other, &r.run.run_principal)
            .await
            .is_err()
    );
    assert!(
        run_ledger::register_run_as(&w.db, &w.admin, "unknown-owner", &r.run.run_principal)
            .await
            .is_err()
    );
    assert!(run_ledger::context_as(&w.db, &w.other, &r.run.run_id)
        .await
        .is_err());
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    let other = World::fresh().await;
    signature(
        commit_claim_as(&other.db, &w.run, &r).await,
        "run context database mismatch",
    );
}

#[tokio::test]
async fn package_definition_guard_displacement_and_target_discovery() {
    let w = World::fresh().await;
    let discovery = describe_world_as(&w.db, &w.admin).await.unwrap();
    let operations = discovery["package_operations"].as_array().unwrap();
    assert_eq!(
        operations
            .iter()
            .filter(|op| op["operation"]["provider"] == provider::PROVIDER
                && op["operation"]["target"] == "any-record")
            .count(),
        2
    );
    let home = create_home(&w.db, KERNEL_ROOT_ID, None, &w.admin)
        .await
        .unwrap();
    rehome_record_as(&w.db, &w.admin, &w.record, &home)
        .await
        .unwrap();
    let r = w.prepare(&w.run, "guard", Command::Claim).await;
    adopt_definition_at(&w.db, &w.admin, provider::FAMILY, None, &home)
        .await
        .unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    assert!(commit_claim_as(&w.db, &w.run, &r)
        .await
        .unwrap_err()
        .to_string()
        .contains("was displaced"));
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
    let pin = provider::pins().relationship;
    adopt_definition_at(&w.db, &w.admin, provider::FAMILY, Some(&pin), &home)
        .await
        .unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    let count = w.count().await;
    signature(
        commit_claim_as(&w.db, &w.run, &r).await,
        "claims package guard moved",
    );
    assert_eq!(before, dump_all_kernel_tables(&w.db).await.unwrap());
    assert_eq!(count, w.count().await);
}

/// Design fixture 51, claims half: sealed home creation is an authority
/// change, so a claim prepared before it cannot commit across it, exactly as
/// for `home_created.v1`.
#[tokio::test]
async fn sealed_home_creation_moves_the_claims_authority_frontier() {
    let w = World::fresh().await;
    let (_, _, cfg) = super::slots_home_for_tests::designate(&w.db, &w.admin).await;
    let r = w.prepare(&w.run, "before-home", Command::Claim).await;
    let event = super::slots_home_for_tests::provision_for(&w.db, &cfg, &w.other)
        .await
        .unwrap();
    let fresh = w.prepare(&w.run, "after-home", Command::Claim).await;
    assert_eq!(fresh.authority_head, event.local_seq);
    assert!(r.authority_head < fresh.authority_head);
    let count = w.count().await;
    signature(
        commit_claim_as(&w.db, &w.run, &r).await,
        "claims authority frontier moved",
    );
    assert_eq!(count, w.count().await);
    commit_claim_as(&w.db, &w.run, &fresh).await.unwrap();
}

#[tokio::test]
async fn archived_target_refuses_claims_and_unarchive_restores_eligibility() {
    let w = World::fresh().await;
    let request = prepare_claim_as(&w.db, &w.run, &w.record, "before-archive", Command::Claim)
        .await
        .unwrap();
    let head = read_record_as(&w.db, &w.admin, &w.record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    set_archived_as(&w.db, &w.admin, &w.record, true, head)
        .await
        .unwrap();
    assert!(commit_claim_as(&w.db, &w.run, &request).await.is_err());
    assert!(
        prepare_claim_as(&w.db, &w.run, &w.record, "archived", Command::Claim)
            .await
            .is_err()
    );
    let head = read_record_as(&w.db, &w.admin, &w.record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    set_archived_as(&w.db, &w.admin, &w.record, false, head)
        .await
        .unwrap();
    let request = prepare_claim_as(&w.db, &w.run, &w.record, "restored", Command::Claim)
        .await
        .unwrap();
    commit_claim_as(&w.db, &w.run, &request).await.unwrap();
    let head = read_record_as(&w.db, &w.admin, &w.record)
        .await
        .unwrap()
        .unwrap()
        .revision;
    set_archived_as(&w.db, &w.admin, &w.record, true, head)
        .await
        .unwrap();
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(dump_all_kernel_tables(&w.db).await.unwrap(), before);
}

#[tokio::test]
async fn imported_archive_state_is_not_claimable() {
    let w = World::fresh().await;
    let importer = resolve_principal_by_binding(&w.db, HOST_IMPORT_BINDING)
        .await
        .unwrap()
        .unwrap()
        .0;
    let record = Uuid::new_v4().to_string();
    import_record_as(
        &w.db,
        &importer,
        &record,
        KERNEL_ROOT_ID,
        Some(&w.admin),
        &ImportRecordState {
            archived: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(
        prepare_claim_as(&w.db, &w.run, &record, "imported-archived", Command::Claim)
            .await
            .is_err()
    );
    let before = dump_all_kernel_tables(&w.db).await.unwrap();
    replay_all_projections(&w.db).await.unwrap();
    assert_eq!(dump_all_kernel_tables(&w.db).await.unwrap(), before);
}
