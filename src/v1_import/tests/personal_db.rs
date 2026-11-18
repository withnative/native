//! Modern hosted personal databases: created by `account_bootstrap`
//! (`create_database_named`) and first owner sign-in, with no root Manage
//! grant. Every source here is built through those ordinary v1 paths; the
//! refusal cases then remove or add exactly one witness.
use super::*;
use crate::authorization::{effective_capability, Capability, Principal};
use crate::identity::hosted::{
    reconcile_hosted_identity, HostedMembershipArrival, HostedMembershipRole,
    HostedMembershipSource,
};

struct Personal {
    dir: tempfile::TempDir,
    source: Db,
    owner: String,
    note: String,
}

impl Personal {
    fn source_path(&self) -> PathBuf {
        self.dir.path().join("source.db")
    }
    fn target_path(&self) -> PathBuf {
        self.dir.path().join("target.db")
    }
    fn roster(&self, accounts: &[&str]) -> PathBuf {
        let path = self.dir.path().join("members.txt");
        std::fs::write(&path, accounts.join("\n")).unwrap();
        path
    }
    fn options(&self, members_file: Option<PathBuf>) -> Options {
        Options {
            source: self.source_path(),
            target: self.target_path(),
            seeds: vec![],
            all: true,
            history: true,
            resume: false,
            members_file,
        }
    }
    /// An ownership refusal is decided from the source alone: neither the
    /// target nor its `.import.lock` sidecar is created.
    fn assert_untouched(&self) {
        assert!(!self.target_path().exists());
        assert!(!self.dir.path().join("target.db.import.lock").exists());
    }
    async fn raw(&self, sql: &str) {
        let mut conn = SqliteConnection::connect(self.source_path().to_str().unwrap())
            .await
            .unwrap();
        // A divergent source witness, not a v1 write: bypass FK checks.
        conn.execute("PRAGMA foreign_keys=OFF").await.unwrap();
        conn.execute(sql).await.unwrap();
        conn.close().await.unwrap();
    }
}

fn v1_registry() -> crate::mcp::ToolRegistry {
    let mut registry = crate::mcp::ToolRegistry::new();
    crate::mcp::register_builtin_tools(&mut registry).unwrap();
    crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
    registry
}

async fn arrive(db: &Db, email: &str, user: &str, role: HostedMembershipRole) -> String {
    reconcile_hosted_identity(
        db,
        email,
        user,
        &HostedMembershipArrival::new(
            role,
            HostedMembershipSource::Direct,
            "2026-11-08T00:00:00Z".into(),
        )
        .unwrap(),
        None,
    )
    .await
    .unwrap()
}

/// Sign-up provisioning, then the owner's first hosted connect, then one
/// ordinary owner note. Root keeps its genesis `members: edit` policy.
async fn personal() -> Personal {
    sole_arrival(HostedMembershipRole::Owner).await
}

/// The same shape, but the only account that ever arrived holds `role`. For
/// a non-owner arrival the note is written by the trusted local operator.
async fn sole_arrival(role: HostedMembershipRole) -> Personal {
    let dir = tempfile::tempdir().unwrap();
    let source = crate::create_database_named(
        dir.path().join("source.db").to_str().unwrap(),
        "Personal workspace",
    )
    .await
    .unwrap();
    let is_owner = role == HostedMembershipRole::Owner;
    let owner = arrive(
        &source,
        "personal-owner@example.test",
        "personal-owner",
        role,
    )
    .await;
    let note = v1_registry()
        .call(
            source.clone(),
            if is_owner {
                crate::mcp::Caller::authenticated(owner.clone())
            } else {
                crate::mcp::Caller::local()
            },
            "create_record",
            json!({"type":"Document","kind":"note","name":"Owner note","body":"synthetic personal body","home_id":"native:root","reason":"Personal fixture"}),
        )
        .await
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let root_manage: i64 = sqlx::query_scalar("SELECT count(*) FROM policy_entries WHERE policy_anchor_id='native:root' AND capability='manage'")
        .fetch_one(source.pool())
        .await
        .unwrap();
    assert_eq!(root_manage, 0, "fixture must have the personal root shape");
    Personal {
        dir,
        source,
        owner,
        note,
    }
}

fn owner_refusal(report: &Report) -> bool {
    report.admin_source.is_none()
        && report
            .refusals
            .iter()
            .any(|issue| issue.id == "native:workspace-owner" && issue.reason.contains("owner"))
}

#[tokio::test]
async fn personal_database_imports_with_exactly_the_owners_v1_access() {
    let p = personal().await;
    let roster = p.roster(&[&p.owner]);
    let report = run(p.options(Some(roster))).await.unwrap();
    assert!(
        report.refusals.is_empty() && report.review.is_empty(),
        "{} {}",
        serde_json::to_string(&report.refusals).unwrap(),
        serde_json::to_string(&report.review).unwrap()
    );
    assert_eq!(report.admin_source, Some(AdminSource::SoleAccountBinding));
    assert_eq!(
        serde_json::to_value(&report).unwrap()["admin_source"],
        "sole_account_binding"
    );
    // The only account principal is the owner: nobody else gains anything.
    assert_eq!(report.principals.keys().collect::<Vec<_>>(), vec![&p.owner]);
    // The same choice survives a resume (before any v2 write): the frozen
    // target owner must match the re-derived one.
    let mut resume = p.options(Some(p.roster(&[&p.owner])));
    resume.resume = true;
    let resumed = run(resume).await.unwrap();
    assert!(
        resumed.refusals.is_empty() && resumed.review.is_empty(),
        "{}",
        serde_json::to_string(&resumed.refusals).unwrap()
    );
    assert_eq!(resumed.admin_source, Some(AdminSource::SoleAccountBinding));
    let principal = &report.principals[&p.owner];
    let db = k::open_v2_database(p.target_path().to_str().unwrap())
        .await
        .unwrap();
    let root_owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
            .bind(KERNEL_ROOT_ID)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(root_owner.as_ref(), Some(principal));
    // The v1 root policy is the genesis members baseline, expanded over the
    // one-account roster; no account Manage entry is invented at the root.
    let root_policy: Vec<(String, String)> = sqlx::query_as(
        "SELECT subject_id,capability FROM kernel_policy_entries WHERE root_id=? ORDER BY 1,2",
    )
    .bind(KERNEL_ROOT_ID)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(root_policy, vec![(principal.clone(), "edit".to_owned())]);
    // Root home: v1 policy Edit plus the catalog Owner's root administration
    // (root policy, workspace name); v2 carries that authority as the root
    // owner floor. This is the only home-level authority the owner holds.
    let v1_owner = Principal::bound(&p.owner, true);
    assert_eq!(
        effective_capability(&p.source, v1_owner, V1_ROOT)
            .await
            .unwrap(),
        Capability::Edit
    );
    assert_eq!(
        k::kernel_effective_capability(&db, principal, KERNEL_ROOT_ID)
            .await
            .unwrap(),
        Capability::Manage
    );
    // Record by record the owner keeps their exact v1 capability. The one
    // disclosed difference is assumed ownership: a record v1 left without a
    // verified owner (engine-seeded defaults) is owned by the administrator,
    // as on HQ, so its Edit becomes Manage. v1 lets the same host owner reach
    // Manage on those records by administering the root policy.
    assert!(report.verified_ids.contains(&p.note));
    assert!(!report.assumed_owners.contains(&p.note));
    let mut compared = 0;
    let mut raised = Vec::new();
    for id in &report.verified_ids {
        let v1 = effective_capability(&p.source, v1_owner, id).await.unwrap();
        let v2 = k::kernel_effective_capability(&db, principal, id)
            .await
            .unwrap();
        if report.assumed_owners.contains(id) {
            // Administrator-owned: Manage, never less than the owner had.
            assert_eq!(v2, Capability::Manage, "{id}");
            assert!(v1 != Capability::None, "{id}");
            if v1 != v2 {
                raised.push(format!("{id}: {v1:?}->{v2:?}"));
            }
        } else {
            assert_eq!(v1, v2, "{id}");
        }
        compared += 1;
    }
    assert!(compared > report.assumed_owners.len());
    // Only engine-seeded, ownerless defaults are raised; nothing the owner
    // or anyone else authored. Printed so a reviewer can see the exact set.
    eprintln!("assumed-owner capability raises: {raised:?}");
    let ownerless_seeded: BTreeSet<String> = sqlx::query_scalar(
        // Engine-provisioned defaults, plus the owner's own bound person
        // record (created by sign-in, ownerless in v1).
        "SELECT r.id FROM records r WHERE r.owner_id IS NULL AND r.deleted_at IS NULL AND (EXISTS(SELECT 1 FROM content_events e WHERE e.record_id=r.id AND e.type='record.created' AND e.actor GLOB 'engine:*') OR r.id IN (SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1 AND identifier=?))",
    )
    .bind(&p.owner)
    .fetch_all(p.source.pool())
    .await
    .unwrap()
    .into_iter()
    .collect();
    for line in &raised {
        let id = line.split(": ").next().unwrap();
        assert!(ownerless_seeded.contains(id), "{line}");
    }
    // Ordinary owner reads and writes through the v2 tool surface.
    let read = ordinary_kernel_call(&db, &p.owner, "get_record", json!({"ids":[p.note]}))
        .await
        .unwrap();
    assert_eq!(read["records"][0]["id"], p.note.as_str());
    ordinary_kernel_call(
        &db,
        &p.owner,
        "update_record",
        json!({"id":p.note,"name":"Owner note, edited after import"}),
    )
    .await
    .unwrap();
    ordinary_kernel_call(&db, &p.owner, "create_record", json!({"type":"Document","kind":"note","name":"Written after import","body":"v2 owner write","home_id":"native:root"}))
        .await
        .unwrap();
    // An account the source never knew stays outside the workspace.
    assert!(
        ordinary_kernel_call(&db, "acct:stranger", "get_record", json!({"ids":[p.note]}))
            .await
            .map_or(true, |hidden| hidden["records"][0]["status"] == "not_found")
    );
}

#[tokio::test]
async fn personal_database_with_root_manage_keeps_the_hq_admin_source() {
    let p = personal().await;
    v1_registry().call(p.source.clone(), crate::mcp::Caller::local(), "manage_record_policy", json!({"action":"grant","record_id":"native:root","subject":{"kind":"account","account_id":p.owner},"capability":"manage","reason":"HQ-shaped owner"})).await.unwrap();
    let report = run(p.options(Some(p.roster(&[&p.owner])))).await.unwrap();
    assert!(
        report.refusals.is_empty(),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    assert_eq!(report.admin_source, Some(AdminSource::RootManage));
}

#[tokio::test]
async fn personal_database_without_members_file_refuses_before_target() {
    let p = personal().await;
    let mut options = p.options(None);
    options.all = false;
    options.history = false;
    options.seeds = vec![p.note.clone()];
    let report = run(options).await.unwrap();
    assert!(
        owner_refusal(&report),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    p.assert_untouched();
}

#[tokio::test]
async fn personal_database_with_no_account_binding_refuses_before_target() {
    let p = personal().await;
    p.raw("DELETE FROM bindings WHERE system='account'").await;
    let report = run(p.options(Some(p.roster(&[&p.owner])))).await.unwrap();
    assert!(
        owner_refusal(&report),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    p.assert_untouched();
}

#[tokio::test]
async fn database_with_two_account_bindings_refuses_before_target() {
    let p = personal().await;
    // A second ordinary hosted arrival: a member who signed in once.
    let member = arrive(
        &p.source,
        "personal-member@example.test",
        "personal-member",
        HostedMembershipRole::Member,
    )
    .await;
    for roster in [
        vec![p.owner.as_str()],
        vec![p.owner.as_str(), member.as_str()],
    ] {
        let report = run(p.options(Some(p.roster(&roster)))).await.unwrap();
        assert!(
            owner_refusal(&report),
            "{}",
            serde_json::to_string(&report.refusals).unwrap()
        );
        p.assert_untouched();
    }
}

#[tokio::test]
async fn personal_database_with_mismatched_roster_refuses_before_target() {
    let p = personal().await;
    for roster in [
        vec!["acct:someone-else"],
        vec![p.owner.as_str(), "acct:someone-else"],
        vec![],
    ] {
        let report = run(p.options(Some(p.roster(&roster)))).await.unwrap();
        assert!(
            owner_refusal(&report),
            "{}",
            serde_json::to_string(&report.refusals).unwrap()
        );
        p.assert_untouched();
    }
}

#[tokio::test]
async fn personal_database_without_matching_member_context_refuses_before_target() {
    let p = personal().await;
    for sql in [
        "UPDATE member_contexts SET person_record_id='not-the-bound-person'",
        "DELETE FROM member_contexts",
    ] {
        p.raw(sql).await;
        let report = run(p.options(Some(p.roster(&[&p.owner])))).await.unwrap();
        assert!(
            owner_refusal(&report),
            "{}",
            serde_json::to_string(&report.refusals).unwrap()
        );
        p.assert_untouched();
    }
}

#[tokio::test]
async fn sole_member_arrival_without_owner_evidence_refuses_before_target() {
    // The owner never signed in; the only arrival is an ordinary Member, who
    // has a binding, a member context and a matching roster but never held
    // the catalog Owner's root administration.
    let p = sole_arrival(HostedMembershipRole::Member).await;
    let report = run(p.options(Some(p.roster(&[&p.owner])))).await.unwrap();
    assert!(
        owner_refusal(&report)
            && report
                .refusals
                .iter()
                .any(|issue| issue.reason.contains("owner-only onboarding evidence")),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    p.assert_untouched();
}

#[tokio::test]
async fn sole_guest_arrival_refuses_before_target() {
    let p = sole_arrival(HostedMembershipRole::Guest).await;
    let report = run(p.options(Some(p.roster(&[&p.owner])))).await.unwrap();
    assert!(
        owner_refusal(&report),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    p.assert_untouched();
}

#[tokio::test]
async fn personal_database_with_deleted_bound_person_refuses_before_target() {
    let p = personal().await;
    p.raw("UPDATE records SET deleted_at='2026-11-08T00:00:00Z' WHERE id=(SELECT record_id FROM bindings WHERE system='account' AND is_canonical=1)").await;
    let report = run(p.options(Some(p.roster(&[&p.owner])))).await.unwrap();
    assert!(
        owner_refusal(&report)
            && report
                .refusals
                .iter()
                .any(|issue| issue.reason.contains("not on a live person")),
        "{}",
        serde_json::to_string(&report.refusals).unwrap()
    );
    p.assert_untouched();
}
