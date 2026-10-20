//! Internal transaction adapter called only after trusted executor admission.
//! The caller owns signature/approval admission; this seam binds that admitted
//! preparation to a single transaction and an immutable domain receipt.
use super::*;
use crate::provenance::{ActionOutput, ProvenanceDispatch};

pub(in super::super) const PROFILE: &str = "native.sql-selected-sqlite-commit.v1";

#[derive(Clone)]
pub(in super::super) struct Approval {
    pub plan_id: String,
    pub profile: String,
    pub prepared_digest: String,
    pub prepared: super::super::SqlWritePreparation,
    pub writer_deadline: Option<std::time::Duration>,
}
impl Approval {
    /// Trusted Rust only, after verifying the signed stored plan.
    pub fn new(plan_id: String, prepared: super::super::SqlWritePreparation) -> Self {
        Self {
            plan_id,
            profile: PROFILE.into(),
            prepared_digest: crate::provenance::sql_write_preparation_digest(&projection(
                &prepared,
            )),
            prepared,
            writer_deadline: None,
        }
    }
}
fn projection(p: &super::super::SqlWritePreparation) -> Value {
    json!({"arguments":p.canonical_source_arguments,"target_id":p.target_id,"target":p.target,
        "state_revision":p.state_revision,"target_state_digest":p.target_state_digest,
        "effect":p.effect,"effect_summary":p.effect_summary,"operation_evidence":p.operation_evidence})
}

pub(in super::super) const REPLAY_WORKSPACE_BUSY: &str =
    "sql_write: workspace busy checking durable receipt; retry the same plan";

#[cfg(test)]
tokio::task_local! {
    pub(super) static REPLAY_GATE: std::sync::Arc<super::super::DispatchGate>;
}

/// Positive-proof read for slice B's Executing/Indeterminate path. A miss
/// grants no permission to execute; the outer permanent plan fence governs it.
pub(in super::super) async fn replay_receipt(
    db: &crate::Db,
    caller: &Caller,
    approval: &Approval,
) -> Result<Option<Value>> {
    validate_approval(approval)?;
    // Replay remains a deferred read transaction; do not reserve the workspace
    // writer. Hosted admission uses the same short pool budget as dispatch.
    let mut tx = match approval.writer_deadline {
        Some(deadline) => tokio::time::timeout(deadline, db.write_pool().begin())
            .await
            .map_err(|_| Error::engine(REPLAY_WORKSPACE_BUSY))??,
        None => db.write_pool().begin().await?,
    };
    #[cfg(test)]
    if let Ok(gate) = REPLAY_GATE.try_with(Clone::clone) {
        gate.entered.add_permits(1);
        gate.release
            .acquire()
            .await
            .expect("replay gate open")
            .forget();
    }
    let result = replay_in(&mut tx, caller, approval).await;
    tx.rollback().await?;
    result
}
fn validate_approval(approval: &Approval) -> Result<()> {
    if approval.plan_id.trim().is_empty()
        || approval.profile != PROFILE
        || approval.prepared_digest
            != crate::provenance::sql_write_preparation_digest(&projection(&approval.prepared))
        || !supported_evidence(&approval.prepared.operation_evidence)
    {
        return Err(denial("invalid internal commit approval"));
    }
    Ok(())
}

pub(in super::super) async fn execute(
    db: &crate::Db,
    caller: &Caller,
    approval: &Approval,
) -> Result<Value> {
    if db.is_enrolled() {
        return Err(denial(
            "internal commit does not support enrolled/coedit workspaces",
        ));
    }
    validate_approval(approval)?;
    let arguments = json!({"plan_id":approval.plan_id,"profile":approval.profile,
        "prepared_digest":approval.prepared_digest,"idempotency_key":approval.plan_id});
    // Keep the foundation's signed-plan command commitment and identity.
    // The surrounding request supplies the resolved actor/channel and intent.
    let annotations = crate::store::current_event_annotations();
    let provenance = ProvenanceDispatch::from_caller(
        caller,
        "sql_write",
        &arguments,
        annotations.intent.as_deref(),
    );
    let result = provenance.scope(async {
        let mut tx = match approval.writer_deadline {
            Some(deadline) => crate::db::begin_write_with_deadline(db.write_pool(), deadline).await?,
            None => crate::db::begin_write(db.write_pool()).await?,
        };
        if let Some(receipt) = replay_in(&mut tx, caller, approval).await? {
            tx.rollback().await?;
            return Ok(receipt);
        }
        let current = prepare_in(&mut tx, caller, approval.prepared.canonical_source_arguments.clone()).await?;
        if projection(&current) != projection(&approval.prepared) {
            return Err(denial("approved selection, authority, source basis, state or effect changed; prepare again"));
        }
        let receipt = apply_in(db, &mut tx, caller, approval).await?;
        // Any commit error remains an error, never proof of rollback. A retry
        // can only settle if replay_in finds the immutable domain receipt.
        db.commit_content(tx).await.map_err(|_| Error::engine("sql_write: commit outcome is uncertain; retry the same plan to look for its durable receipt"))?;
        Ok(receipt)
    }).await;
    if result.is_ok() {
        // Issuance was confirmed by the domain transaction. Publish its IDs
        // to the outer registry scope without replacing the anchor's binding.
        crate::provenance::confirm_committed_attestations(&provenance.receipt_ids());
    }
    result
}

async fn replay_in(tx: &mut Tx, caller: &Caller, approval: &Approval) -> Result<Option<Value>> {
    let row = sqlx::query("SELECT r.profile,r.prepared_digest,r.envelope,r.envelope_digest,r.anchor_id FROM sql_write_receipts r JOIN provenance_local_attestation_authority l ON l.attestation_id=r.anchor_id WHERE r.principal=? AND r.plan_id=? AND l.principal=r.principal AND l.operation='sql_write'")
        .bind(caller.credential()).bind(&approval.plan_id).fetch_optional(&mut **tx).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    if row.try_get::<String, _>("profile")? != approval.profile
        || row.try_get::<String, _>("prepared_digest")? != approval.prepared_digest
    {
        return Err(denial(
            "plan identity was reused with different signed content",
        ));
    }
    let envelope: Value = serde_json::from_str(&row.try_get::<String, _>("envelope")?)?;
    if row.try_get::<String, _>("envelope_digest")? != crate::provenance::digest_json(&envelope) {
        return Err(Error::engine(
            "sql_write: durable receipt integrity failure",
        ));
    }
    // This is a past receipt, not a new write. Recheck View only, without
    // reselecting or reinterpreting archived/changed state after the first call.
    for id in envelope["disclosed_ids"]
        .as_array()
        .ok_or_else(|| Error::engine("invalid receipt disclosure set"))?
    {
        let id = id
            .as_str()
            .ok_or_else(|| Error::engine("invalid receipt disclosure ID"))?;
        crate::mcp::tools::require_record_in(tx, caller, "sql_write", id, Capability::View)
            .await
            .map_err(|_| denial("committed receipt is unavailable"))?;
    }
    crate::provenance::note_replayed_action_attestation(row.try_get("anchor_id")?);
    Ok(Some(envelope["receipt"].clone()))
}

async fn apply_in(
    db: &crate::Db,
    tx: &mut Tx,
    caller: &Caller,
    approval: &Approval,
) -> Result<Value> {
    let mut allocation = crate::act::ActAllocation::new();
    let mut outputs = Vec::<ActionOutput>::new();
    let mut results = Vec::new();
    let mut disclosed = std::collections::BTreeSet::new();
    disclosed.insert(
        approval.prepared.canonical_source_arguments["folder_id"]
            .as_str()
            .ok_or_else(|| Error::engine("missing folder"))?
            .to_owned(),
    );
    if let Some(sources) = approval.prepared.effect["basis"]["sources"].as_array() {
        for source in sources {
            disclosed.insert(
                source["record_id"]
                    .as_str()
                    .ok_or_else(|| Error::engine("invalid source"))?
                    .to_owned(),
            );
        }
    }
    let targets = approval.prepared.effect["targets"]
        .as_array()
        .ok_or_else(|| Error::engine("missing approved targets"))?;
    let mut item_attestations = Vec::new();
    for (index, target) in targets.iter().enumerate() {
        let id = target["record_id"]
            .as_str()
            .ok_or_else(|| Error::engine("missing approved ID"))?;
        disclosed.insert(id.to_owned());
        // Registry write receipts disclose this original preimage identity.
        // Pin it before appending so receipt-only replay remains identical.
        let previous_event_id: String =
            sqlx::query_scalar("SELECT id FROM content_events WHERE seq=? AND record_id=?")
                .bind(
                    target["previous_seq"]
                        .as_i64()
                        .ok_or_else(|| Error::engine("missing approved sequence"))?,
                )
                .bind(id)
                .fetch_one(&mut **tx)
                .await?;
        let op = &target["operation"];
        let mut item_outputs = Vec::new();
        match op["op"].as_str() {
            Some("set_facet") | Some("archive") if op["would_append"] == true => {
                let event = crate::store::append_in(
                    db,
                    tx,
                    crate::store::AppendSpec {
                        record_id: id.into(),
                        event_type: "facet.set".into(),
                        payload: op["event_intent"]["payload"].clone(),
                        actor: Some(caller.actor().into()),
                    },
                    &mut allocation,
                )
                .await?;
                item_outputs.push(ActionOutput::content(event.id));
                let draft = crate::provenance::reserve_unkeyed_action_attestation()?;
                item_attestations.push(
                    crate::provenance::issue_action_attestation_outputs_in(
                        tx,
                        draft,
                        &item_outputs,
                    )
                    .await?,
                );
            }
            Some("archive") if op["would_append"] == false => {}
            Some("add_link") => {
                let destination = op["target_id"]
                    .as_str()
                    .ok_or_else(|| Error::engine("missing link destination"))?;
                disclosed.insert(destination.into());
                let draft = crate::provenance::reserve_unkeyed_action_attestation()?;
                let (_, appended) =
                    crate::relationship::legacy::mutate_with_reserved_attestation_in(
                        tx,
                        caller,
                        id,
                        destination,
                        "relates_to",
                        None,
                        true,
                        "manage_links",
                        &draft,
                        &mut allocation,
                    )
                    .await?;
                item_outputs = appended;
                item_attestations.push(
                    crate::provenance::issue_action_attestation_outputs_in(
                        tx,
                        draft,
                        &item_outputs,
                    )
                    .await?,
                );
            }
            _ => return Err(Error::engine("unsupported approved commit operation")),
        }
        results.push(json!({"index":index,"record_id":id,"previous_seq":target["previous_seq"],
            "previous_event_id":previous_event_id,"state_changed":op["state_changed"],"would_append":op["would_append"],"outputs":item_outputs}));
        outputs.extend(item_outputs);
        #[cfg(test)]
        if let Ok(fail_after) = FAIL_AFTER.try_with(|n| *n) {
            if index + 1 == fail_after {
                return Err(Error::engine("injected late SQL batch failure"));
            }
        }
    }
    // Outputs have one attestation owner. As in batch_write, the command
    // anchor is empty; the envelope associates the complete per-item set.
    let anchor = crate::provenance::issue_empty_command_attestation_in(tx).await?;
    let act = allocation.get_or_allocate(tx).await?;
    let receipt = json!({"plan_id":approval.plan_id,"profile":approval.profile,"status":"committed", "act":act,
        "target_count":targets.len(),"results":results,"anchor_id":anchor,"item_attestation_ids":item_attestations});
    let envelope = json!({"format":"native.sql-write-receipt.v1","plan_id":approval.plan_id,
        "profile":approval.profile,"prepared_digest":approval.prepared_digest,
        "preparation":projection(&approval.prepared),"source_basis":approval.prepared.effect.get("basis"),
        "disclosed_ids":disclosed,"outputs":outputs,"receipt":receipt});
    sqlx::query("INSERT INTO sql_write_receipts(principal,plan_id,profile,prepared_digest,anchor_id,act,envelope,envelope_digest) VALUES(?,?,?,?,?,?,?,?)")
        .bind(caller.credential()).bind(&approval.plan_id).bind(&approval.profile).bind(&approval.prepared_digest)
        .bind(&anchor).bind(act).bind(serde_json::to_string(&envelope)?).bind(crate::provenance::digest_json(&envelope)).execute(&mut **tx).await?;
    Ok(receipt)
}
#[cfg(test)]
tokio::task_local! { static FAIL_AFTER: usize; }

#[cfg(test)]
#[path = "public_commit_tests.rs"]
mod public_tests;

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    pub(super) const F: &str = "ec00b000-0000-4000-8000-000000000aa1";
    pub(super) const A: &str = "ec00b000-0000-4000-8000-000000000aa2";
    pub(super) const B: &str = "ec00b000-0000-4000-8000-000000000aa3";
    pub(super) const D: &str = "ec00b000-0000-4000-8000-000000000aa4";
    pub(super) struct Fixture {
        pub(super) db: crate::Db,
        registry: crate::mcp::ToolRegistry,
    }
    impl Fixture {
        pub(super) async fn new() -> Self {
            let db = crate::create_database(":memory:").await.unwrap();
            let mut registry = crate::mcp::ToolRegistry::new();
            crate::mcp::register_builtin_tools(&mut registry).unwrap();
            crate::mcp::register_surface_tools(&mut registry).unwrap();
            let f = Self { db, registry };
            for args in [
                json!({"id":F,"type":"Collection","kind":"folder","persistence":"enduring","name":"Scope","reason":"fixture"}),
                json!({"id":A,"type":"Document","kind":"note","home_id":F,"name":"A","facets":{"review":"pending"},"reason":"fixture"}),
                json!({"id":B,"type":"Document","kind":"note","home_id":F,"name":"B","facets":{"review":"pending"},"reason":"fixture"}),
                json!({"id":D,"type":"Document","kind":"note","name":"Source and link destination","body":"original source","reason":"fixture"}),
            ] {
                f.public("create_record", args).await;
            }
            f
        }
        pub(super) async fn public(&self, tool: &str, args: Value) -> Value {
            self.registry
                .call(self.db.clone(), Caller::local(), tool, args)
                .await
                .unwrap()
        }
        pub(super) fn request(write: Value) -> Value {
            json!({"selection_contract":CONTRACT,"folder_id":F,"statement":"SELECT id FROM children WHERE type='Document'","write":write,"reason":"bounded workflow"})
        }
        async fn approval(&self, id: &str, args: Value) -> Approval {
            Approval::new(
                id.into(),
                prepare(&self.db, &Caller::local(), args).await.unwrap(),
            )
        }
        pub(super) async fn counts(&self) -> (i64, i64, i64, i64, i64) {
            let mut c = self.db.write_pool().acquire().await.unwrap();
            sqlx::query_as("SELECT (SELECT COUNT(*) FROM content_events),(SELECT COUNT(*) FROM relationship_events),(SELECT COUNT(*) FROM provenance_action_attestations),(SELECT COUNT(*) FROM sql_write_receipts),(SELECT next_act FROM act_state WHERE singleton=1)").fetch_one(&mut *c).await.unwrap()
        }
        pub(super) async fn conform(&self) {
            assert!(crate::provenance::state_violations(&self.db)
                .await
                .unwrap()
                .is_empty());
        }
    }
    #[tokio::test]
    async fn folder_scan_caps_hidden_and_excluded_children_before_visibility() {
        use crate::authorization::{replace_explicit_policy, AllowEntry};
        for hidden in [true, false] {
            let f = Fixture::new().await;
            let account = "acct:visited-cap";
            for id in [F, A, B] {
                replace_explicit_policy(
                    &f.db,
                    "test:visited-cap",
                    id,
                    vec![AllowEntry::account(account, Capability::Manage)],
                )
                .await
                .unwrap();
            }
            replace_explicit_policy(
                &f.db,
                "test:visited-cap",
                D,
                vec![AllowEntry::account(
                    if hidden { "acct:other" } else { account },
                    Capability::Manage,
                )],
            )
            .await
            .unwrap();
            // Projection-only bulk fixture: every child inherits D's policy.
            // Hidden children have no View; visible attribution children are excluded.
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            for i in 0..MAX_VISITED_CHILDREN - 2 {
                sqlx::query("INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) VALUES(?,?,?,?,?,?)")
                    .bind(format!("native:visited-{i:05}"))
                    .bind(if hidden { "Document" } else { "Annotation" })
                    .bind(if hidden { "note" } else { "attribution" })
                    .bind("Skipped child").bind(F).bind(D).execute(&mut *tx).await.unwrap();
                if !hidden {
                    // Annotations inherit authorization through a part_of
                    // bearer, independently of their containment policy anchor.
                    sqlx::query("INSERT INTO links(id,source_id,target_id,relationship) VALUES(?,?,?,'part_of')")
                        .bind(format!("visited-bearer-{i}"))
                        .bind(format!("native:visited-{i:05}"))
                        .bind(D).execute(&mut *tx).await.unwrap();
                }
            }
            tx.commit().await.unwrap();
            let caller = Caller::authenticated(account);
            let args = Fixture::request(json!({"op":"archive"}));
            let at_cap = prepare(&f.db, &caller, args.clone()).await.unwrap();
            assert_eq!(at_cap.operation_evidence["selection"]["candidate_count"], 2);
            sqlx::query("INSERT INTO records(id,type,kind,name,home_id,policy_anchor_id) VALUES('native:visited-over','Document','note','Hidden child',?,?)")
                .bind(F).bind(D).execute(f.db.write_pool()).await.unwrap();
            let refused = prepare(&f.db, &caller, args).await.unwrap_err().to_string();
            assert!(
                refused.contains("2000 visited children; narrow folder scope"),
                "{refused}"
            );
        }
    }
    #[tokio::test]
    async fn facet_assertions_retry_original_receipt_and_bind_plan_content() {
        let f = Fixture::new().await;
        for (plan, value) in [("facet-equal", "pending"), ("facet-change", "approved")] {
            let approved = f
                .approval(
                    plan,
                    Fixture::request(json!({"op":"set_facet","key":"review","value":value})),
                )
                .await;
            let before = f.counts().await;
            let receipt = execute(&f.db, &Caller::local(), &approved).await.unwrap();
            let after = f.counts().await;
            assert_eq!(after.0, before.0 + 2);
            assert_eq!(after.1, before.1);
            assert_eq!(after.3, before.3 + 1);
            assert_eq!(after.4, before.4 + 1);
            assert_eq!(
                receipt["results"][0]["state_changed"],
                json!(value != "pending")
            );
            assert_eq!(receipt["results"][0]["would_append"], true);
            f.public(
                "update_record",
                json!({"id":A,"name":"later name","reason":"later independent edit"}),
            )
            .await;
            let stable = f.counts().await;
            assert_eq!(
                execute(&f.db, &Caller::local(), &approved).await.unwrap(),
                receipt
            );
            assert_eq!(f.counts().await, stable);
            let mut different = approved.clone();
            different.prepared.effect["reason"] = json!("different");
            different.prepared_digest =
                crate::provenance::sql_write_preparation_digest(&projection(&different.prepared));
            assert!(execute(&f.db, &Caller::local(), &different).await.is_err());
            f.conform().await;
        }
    }
    #[tokio::test]
    async fn existing_link_support_and_new_link_outputs_share_one_act_and_rollback() {
        let f = Fixture::new().await;
        f.public(
            "manage_links",
            json!({"action":"add","source_id":A,"target_id":D,"relationship":"relates_to"}),
        )
        .await;
        let approved = f
            .approval(
                "links",
                Fixture::request(json!({"op":"add_link","target_id":D})),
            )
            .await;
        let before = f.counts().await;
        assert!(FAIL_AFTER
            .scope(2, execute(&f.db, &Caller::local(), &approved))
            .await
            .is_err());
        assert_eq!(f.counts().await, before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM relationships")
                .fetch_one(f.db.pool())
                .await
                .unwrap(),
            1
        );
        let receipt = execute(&f.db, &Caller::local(), &approved).await.unwrap();
        let after = f.counts().await;
        assert_eq!(after.0, before.0);
        assert_eq!(after.1, before.1 + 3);
        assert_eq!(after.4, before.4 + 1);
        assert_eq!(
            receipt["results"][0]["outputs"].as_array().unwrap().len(),
            1
        );
        assert_eq!(
            receipt["results"][1]["outputs"].as_array().unwrap().len(),
            2
        );
        let acts:Vec<i64>=sqlx::query_scalar("SELECT DISTINCT act FROM relationship_events WHERE seq>(SELECT MAX(seq)-3 FROM relationship_events)").fetch_all(f.db.pool()).await.unwrap();
        assert_eq!(acts, vec![receipt["act"].as_i64().unwrap()]);
        assert_eq!(
            execute(&f.db, &Caller::local(), &approved).await.unwrap(),
            receipt
        );
        assert_eq!(f.counts().await, after);
        f.conform().await;
    }
    #[tokio::test]
    async fn archive_and_all_archived_batch_retain_no_event_receipt_and_act() {
        let f = Fixture::new().await;
        let args = Fixture::request(json!({"op":"archive"}));
        let first = f.approval("archive", args.clone()).await;
        let before = f.counts().await;
        execute(&f.db, &Caller::local(), &first).await.unwrap();
        assert_eq!(f.counts().await.0, before.0 + 2);
        let empty = f.approval("already-archived", args).await;
        let before = f.counts().await;
        assert!(replay_receipt(&f.db, &Caller::local(), &empty)
            .await
            .unwrap()
            .is_none());
        assert_eq!(f.counts().await, before);
        let receipt = execute(&f.db, &Caller::local(), &empty).await.unwrap();
        let after = f.counts().await;
        assert_eq!(after.0, before.0);
        assert_eq!(after.1, before.1);
        assert_eq!(after.2, before.2 + 1);
        assert_eq!(after.3, before.3 + 1);
        assert_eq!(after.4, before.4 + 1);
        assert_eq!(receipt["results"][0]["would_append"], false);
        assert_eq!(
            execute(&f.db, &Caller::local(), &empty).await.unwrap(),
            receipt
        );
        assert_eq!(f.counts().await, after);
        f.conform().await;
        // Act-only receipts and their empty anchors are included in delta closure.
        let mut c = f.db.write_pool().acquire().await.unwrap();
        let carried = crate::standby::read_companion_section_on(
            &mut c,
            "provenance_action_attestations",
            before.4,
            after.4,
        )
        .await
        .unwrap();
        assert_eq!(carried.rows.len(), 1);
        drop(c);
        let path = f.db.path().to_string_lossy().to_string();
        f.db.close().await;
        let reopened = crate::db::open_existing_database(&path).await.unwrap();
        assert_eq!(
            replay_receipt(&reopened, &Caller::local(), &empty)
                .await
                .unwrap(),
            Some(receipt)
        );
        reopened.close().await;
    }
    #[tokio::test]
    async fn stale_selection_and_source_head_refuse_without_effects() {
        let f = Fixture::new().await;
        let mut args =
            Fixture::request(json!({"op":"set_facet","key":"review","value":"approved"}));
        let omitted = f.approval("omitted", args.clone()).await;
        assert!(omitted.prepared.effect.get("basis").is_none());
        args["sources"] = json!([]);
        let empty = f.approval("empty", args.clone()).await;
        assert_eq!(empty.prepared.effect["basis"]["sources"], json!([]));
        args["sources"] = json!([D]);
        let pinned = f.approval("source-head", args.clone()).await;
        f.public(
            "update_record",
            json!({"id":D,"body_append":" additional source","reason":"source changed"}),
        )
        .await;
        let before = f.counts().await;
        assert!(execute(&f.db, &Caller::local(), &pinned).await.is_err());
        assert_eq!(f.counts().await, before);
        f.public(
            "update_record",
            json!({"id":A,"name":"changed selected state","reason":"state changed"}),
        )
        .await;
        let before = f.counts().await;
        assert!(execute(&f.db, &Caller::local(), &omitted).await.is_err());
        assert_eq!(f.counts().await, before);
        args["sources"] = Value::Null;
        assert!(prepare(&f.db, &Caller::local(), args).await.is_err());
    }
    #[tokio::test]
    async fn replay_requires_view_without_requiring_current_edit() {
        let f = Fixture::new().await;
        // Public account caller plus explicit grants uses the same canonical auth path.
        let caller = Caller::authenticated("acct:sql-commit-reader");
        for id in [F, A, B] {
            crate::authorization::replace_explicit_policy(
                &f.db,
                "test:sql-commit",
                id,
                vec![crate::authorization::AllowEntry::account(
                    "acct:sql-commit-reader",
                    Capability::Manage,
                )],
            )
            .await
            .unwrap();
        }
        let prepared = prepare(&f.db, &caller, Fixture::request(json!({"op":"archive"})))
            .await
            .unwrap();
        let approved = Approval::new("view-replay".into(), prepared);
        let receipt = execute(&f.db, &caller, &approved).await.unwrap();
        crate::authorization::replace_explicit_policy(
            &f.db,
            "test:sql-commit",
            A,
            vec![crate::authorization::AllowEntry::account(
                "acct:sql-commit-reader",
                Capability::View,
            )],
        )
        .await
        .unwrap();
        assert_eq!(execute(&f.db, &caller, &approved).await.unwrap(), receipt);
        crate::authorization::replace_explicit_policy(&f.db, "test:sql-commit", A, vec![])
            .await
            .unwrap();
        let before = f.counts().await;
        assert!(execute(&f.db, &caller, &approved)
            .await
            .unwrap_err()
            .to_string()
            .contains("unavailable"));
        assert_eq!(f.counts().await, before);
    }
    #[tokio::test]
    async fn receipt_schema_upgrade_matches_fresh_and_interchange_retains_envelopes() {
        use sqlx::Connection;
        let f = Fixture::new().await;
        let mut conn = f.db.write_pool().acquire().await.unwrap();
        crate::schema::step_down::step_down(&mut conn, 89)
            .await
            .unwrap();
        assert_eq!(
            crate::db::schema_shape_contract_sha256_for_test(&mut conn)
                .await
                .unwrap(),
            crate::db::ENGINE_89_SHAPE_CONTRACT_SHA256
        );
        let mut tx = conn.begin().await.unwrap();
        let edge = crate::migrations::EngineMigrationRegistry::production()
            .pending(89, 90)
            .unwrap()
            .pop()
            .unwrap();
        edge.preflight(&mut tx).await.unwrap();
        edge.apply(&mut tx).await.unwrap();
        sqlx::query("PRAGMA user_version=90")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let upgraded = crate::db::schema_shape_contract_sha256_for_test(&mut conn)
            .await
            .unwrap();
        drop(conn);
        let fresh = crate::create_database(":memory:").await.unwrap();
        let mut conn = fresh.write_pool().acquire().await.unwrap();
        assert_eq!(
            upgraded,
            crate::db::schema_shape_contract_sha256_for_test(&mut conn)
                .await
                .unwrap()
        );
        drop(conn);
        fresh.close().await;
        let approved = f
            .approval(
                "portable-archive",
                Fixture::request(json!({"op":"archive"})),
            )
            .await;
        let receipt = execute(&f.db, &Caller::local(), &approved).await.unwrap();
        let bytes = crate::interchange::export_canonical_interchange(&f.db)
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("import.db");
        let imported = crate::interchange::import_canonical_interchange(
            &bytes,
            &path,
            crate::interchange::ImportContinuity::ForeignBoundary,
        )
        .await
        .unwrap();
        let text: String = sqlx::query_scalar(
            "SELECT envelope FROM sql_write_receipts WHERE plan_id='portable-archive'",
        )
        .fetch_one(imported.pool())
        .await
        .unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&text).unwrap()["receipt"],
            receipt
        );
        assert!(sqlx::query("UPDATE sql_write_receipts SET profile=profile")
            .execute(imported.write_pool())
            .await
            .is_err());
        assert!(sqlx::query("DELETE FROM sql_write_receipts")
            .execute(imported.write_pool())
            .await
            .is_err());
        imported.close().await;
    }
}
