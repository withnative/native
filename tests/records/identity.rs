use native_ce::authorization::{AllowEntry, Capability};
use native_ce::conformance::rebuild_and_diff;
use native_ce::identity::resolve_stdio_account_identity;
use native_ce::identity::{
    self, BindingClaim, MaterializationPolicy, MutationContext, ObservationFreshness,
    ObservationProvenance, ObservationQuality, RefreshOutcome, RetentionState, SourceAvailability,
    StubHints,
};
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use serde_json::json;
use tempfile::tempdir;

fn principal(id: &str) -> BindingClaim {
    BindingClaim {
        system: "native-principal".into(),
        identifier: format!("native/{id}"),
    }
}

fn context<'a>(actor: &'a str, reason: &'a str) -> MutationContext<'a> {
    MutationContext {
        actor,
        reason,
        run_key: Some("test-agent-abc123"),
        parent_key: None,
        intent: Some("exercise identity contract"),
        internal: false,
        source_read_authorized: false,
    }
}

fn captured_provenance(revision: &str, digest: Option<&str>) -> ObservationProvenance {
    ObservationProvenance {
        source_revision: Some(revision.into()),
        source_digest: digest.map(String::from),
        freshness: ObservationFreshness::Fresh,
        retention_state: RetentionState::Captured,
        source_availability: SourceAvailability::Available,
        refresh_outcome: RefreshOutcome::Succeeded,
        retained_from_observation_id: None,
    }
}

async fn setup() -> (native_ce::Db, String) {
    let db = native_ce::create_database(":memory:").await.unwrap();
    let actor = resolve_stdio_account_identity(&db, None).await.unwrap();
    (db, actor)
}

async fn content_snapshot(db: &native_ce::Db) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT 'content:' || json_object(
                    'seq',seq,'id',id,'record_id',record_id,'type',type,'payload',payload,
                    'actor',actor,'run_key',run_key,'parent_key',parent_key,'intent',intent,
                    'created_at',created_at)
           FROM content_events
         UNION ALL
         SELECT 'meta:' || json_object(
                    'seq',seq,'id',id,'subject_id',subject_id,'type',type,'payload',payload,
                    'actor',actor,'created_at',created_at)
           FROM meta_events
         UNION ALL
         SELECT 'record:' || json_object(
                    'id',id,'type',type,'kind',kind,'name',name,'body',body,'home_id',home_id,
                    'owner_id',owner_id,'deleted_at',deleted_at)
           FROM records
          ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .unwrap()
}

async fn checkpoint_and_close(db: &native_ce::Db) {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_optional(&crate::common::fixture_write_pool(db).await)
        .await
        .unwrap();
    db.close().await;
}

#[tokio::test]
async fn repeated_and_concurrent_resolution_converge_on_one_owned_shadow() {
    let (db, actor) = setup().await;
    let claim = principal("ada");
    let hints = StubHints {
        name: Some("Ada".into()),
        ..StubHints::default()
    };
    let first_context = context(&actor, "first delivery");
    let concurrent_context = context(&actor, "concurrent delivery");
    let first_claims = [claim.clone()];
    let concurrent_claims = [claim.clone()];
    let (a, b) = tokio::join!(
        identity::resolve_external(&db, &first_context, &first_claims, &hints),
        identity::resolve_external(&db, &concurrent_context, &concurrent_claims, &hints),
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.record_id, b.record_id);
    assert_ne!(a.created, b.created);
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM bindings WHERE system='native-principal' AND identifier='native/ada'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn conflicting_claims_fail_closed_and_canonicalization_is_audited() {
    let (db, actor) = setup().await;
    let hints = StubHints {
        name: Some("Person".into()),
        ..StubHints::default()
    };
    let a = identity::resolve_external(
        &db,
        &context(&actor, "resolve a"),
        &[principal("a")],
        &hints,
    )
    .await
    .unwrap();
    let b = identity::resolve_external(
        &db,
        &context(&actor, "resolve b"),
        &[principal("b")],
        &hints,
    )
    .await
    .unwrap();
    let error = identity::resolve_external(
        &db,
        &context(&actor, "conflicting descriptor"),
        &[principal("a"), principal("b")],
        &hints,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("reconciliation conflict"));
    assert_ne!(a.record_id, b.record_id);

    identity::add_binding(
        &db,
        &context(&actor, "add new alias"),
        &a.record_id,
        &principal("a2"),
        true,
    )
    .await
    .unwrap();
    let canonical: Vec<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings WHERE record_id=? AND system='native-principal' AND is_canonical=1",
    ).bind(&a.record_id).fetch_all(db.pool()).await.unwrap();
    assert_eq!(canonical, ["native/a2"]);
    assert!(identity::state_violations(&db).await.unwrap().is_empty());
}

#[tokio::test]
async fn observations_enforce_disclosure_and_snapshot_provenance() {
    let (db, actor) = setup().await;
    let blobs_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let claim = principal("observer");
    let hints = StubHints {
        name: Some("Observed person".into()),
        ..StubHints::default()
    };
    let reported = identity::observe_external(
        &db,
        &context(&actor, "reported directory display"),
        std::slice::from_ref(&claim),
        &hints,
        &claim,
        ObservationQuality::Reported,
        MaterializationPolicy::IdentityOnly,
        None,
        &ObservationProvenance::default(),
        Some("Observed person"),
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert!(reported.provenance_attachment_id.is_none());
    let body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&reported.record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(body.is_none());
    let blobs_after_identity_only: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(
        blobs_after_identity_only, blobs_before,
        "identity_only must not retain readable bytes"
    );

    let denied = identity::observe_external(
        &db,
        &context(&actor, "unverified fetched snapshot"),
        std::slice::from_ref(&claim),
        &hints,
        &claim,
        ObservationQuality::Fetched,
        MaterializationPolicy::Snapshot,
        None,
        &captured_provenance("remote-revision-1", Some("source:abc123")),
        None,
        Some(b"remote body"),
        Some("text/plain"),
        Some("snapshot.txt"),
    )
    .await
    .unwrap_err();
    assert!(denied
        .to_string()
        .contains("snapshot_authorization_failure"));

    let mut trusted = context(&actor, "gateway-authorized snapshot");
    trusted.internal = true;
    trusted.source_read_authorized = true;
    let snapshot = identity::observe_external(
        &db,
        &trusted,
        std::slice::from_ref(&claim),
        &hints,
        &claim,
        ObservationQuality::Fetched,
        MaterializationPolicy::Snapshot,
        None,
        &captured_provenance("remote-revision-1", Some("source:abc123")),
        None,
        Some(b"remote body"),
        Some("text/plain"),
        Some("snapshot.txt"),
    )
    .await
    .unwrap();
    let attachment = snapshot.provenance_attachment_id.clone().unwrap();
    let kind: String = sqlx::query_scalar("SELECT kind FROM records WHERE id=?")
        .bind(&attachment)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(kind, "attachment");
    let shadow_body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id=?")
        .bind(&snapshot.record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(
        shadow_body.is_none(),
        "snapshot bytes never become canonical shadow body"
    );
    let reason: String =
        sqlx::query_scalar("SELECT reason FROM external_observations WHERE id = ?")
            .bind(&snapshot.observation_id)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(reason, "gateway-authorized snapshot");
    let persisted: (
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
    ) = sqlx::query_as(
        "SELECT source_revision,source_digest,freshness,retention_state,
                    source_availability,refresh_outcome
               FROM external_observations WHERE id = ?",
    )
    .bind(&snapshot.observation_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        persisted,
        (
            Some("remote-revision-1".into()),
            Some("source:abc123".into()),
            "fresh".into(),
            "captured".into(),
            "available".into(),
            "succeeded".into(),
        )
    );
}

#[tokio::test]
async fn captured_snapshot_attachment_inherits_shadow_authorization_and_replays() {
    let (db, actor) = setup().await;
    let claim = principal("authorized-snapshot-reader");
    let mut trusted = context(&actor, "capture caller-readable snapshot");
    trusted.source_read_authorized = true;
    let snapshot = identity::observe_external(
        &db,
        &trusted,
        std::slice::from_ref(&claim),
        &StubHints::default(),
        &claim,
        ObservationQuality::Fetched,
        MaterializationPolicy::Snapshot,
        None,
        &captured_provenance("source-rev-readable", Some("sha256:readable")),
        None,
        Some(b"caller-relative snapshot"),
        Some("text/plain"),
        Some("readable.txt"),
    )
    .await
    .unwrap();
    let attachment_id = snapshot.provenance_attachment_id.unwrap();

    let bearers: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links
          WHERE source_id = ? AND relationship = 'part_of'
          ORDER BY target_id",
    )
    .bind(&attachment_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        bearers.as_slice(),
        std::slice::from_ref(&snapshot.record_id)
    );

    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &snapshot.record_id,
        vec![AllowEntry::account(
            "acct_snapshot_viewer",
            Capability::View,
        )],
    )
    .await
    .unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let caller = Caller::authenticated("acct_snapshot_viewer");
    let record = registry
        .call(
            db.clone(),
            caller.clone(),
            "get_record",
            json!({ "ids": [&attachment_id] }),
        )
        .await
        .unwrap();
    assert_eq!(record["records"][0]["status"], "found");
    let bytes = registry
        .call(
            db.clone(),
            caller.clone(),
            "read_attachment",
            json!({ "attachment_id": &attachment_id }),
        )
        .await
        .unwrap();
    assert_eq!(bytes["content"], "caller-relative snapshot");

    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &snapshot.record_id,
        vec![AllowEntry::account("acct_other", Capability::Manage)],
    )
    .await
    .unwrap();
    let hidden = registry
        .call(
            db.clone(),
            caller.clone(),
            "get_record",
            json!({ "ids": [&attachment_id] }),
        )
        .await
        .unwrap();
    assert_eq!(hidden["records"][0]["status"], "not_found");
    assert!(registry
        .call(
            db.clone(),
            caller,
            "read_attachment",
            json!({ "attachment_id": &attachment_id }),
        )
        .await
        .is_err());

    assert!(rebuild_and_diff(&db).await.unwrap().equal);
}

#[tokio::test]
async fn failed_refresh_retains_prior_artifact_as_stale_without_relabelling_it() {
    let (db, actor) = setup().await;
    let claim = principal("retained-refresh");
    let mut trusted = context(&actor, "capture initial remote revision");
    trusted.source_read_authorized = true;
    let captured = identity::observe_external(
        &db,
        &trusted,
        std::slice::from_ref(&claim),
        &StubHints::default(),
        &claim,
        ObservationQuality::Fetched,
        MaterializationPolicy::Snapshot,
        None,
        &captured_provenance("source-rev-7", Some("sha256:source-seven")),
        None,
        Some(b"immutable revision seven"),
        Some("text/plain"),
        Some("revision-seven.txt"),
    )
    .await
    .unwrap();
    let captured_attachment = captured.provenance_attachment_id.clone().unwrap();
    let blobs_before_refresh: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let retained_provenance = ObservationProvenance {
        source_revision: None,
        source_digest: None,
        freshness: ObservationFreshness::Stale,
        retention_state: RetentionState::Retained,
        source_availability: SourceAvailability::Unavailable,
        refresh_outcome: RefreshOutcome::Failed,
        retained_from_observation_id: Some(captured.observation_id.clone()),
    };
    let retained = identity::observe_external(
        &db,
        &MutationContext {
            reason: "authorized refresh could not reach the source",
            ..trusted
        },
        std::slice::from_ref(&claim),
        &StubHints::default(),
        &claim,
        ObservationQuality::Fetched,
        MaterializationPolicy::Snapshot,
        None,
        &retained_provenance,
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(
        retained.provenance_attachment_id.as_deref(),
        Some(captured_attachment.as_str())
    );
    assert_eq!(
        retained.provenance.source_revision.as_deref(),
        Some("source-rev-7")
    );
    assert_eq!(
        retained.provenance.source_digest.as_deref(),
        Some("sha256:source-seven")
    );
    assert_eq!(retained.provenance.freshness, ObservationFreshness::Stale);
    assert_eq!(
        retained.provenance.retention_state,
        RetentionState::Retained
    );
    assert_eq!(retained.provenance.refresh_outcome, RefreshOutcome::Failed);
    let persisted: (
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
    ) = sqlx::query_as(
        "SELECT freshness,retention_state,refresh_outcome,source_revision,source_digest,
                    provenance_attachment_id
               FROM external_observations WHERE id = ?",
    )
    .bind(&retained.observation_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(
        persisted,
        (
            "stale".into(),
            "retained".into(),
            "failed".into(),
            Some("source-rev-7".into()),
            Some("sha256:source-seven".into()),
            captured_attachment,
        )
    );
    let blobs_after_refresh: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blobs")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(blobs_after_refresh, blobs_before_refresh);
    let shadow_body: Option<String> = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
        .bind(&retained.record_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert!(shadow_body.is_none());
}

#[tokio::test]
async fn observe_external_mcp_contract_handles_and_renders_typed_provenance() {
    let (db, actor) = setup().await;
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let schema = &registry.get("observe_external").unwrap().input_schema;
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .contains(&json!("provenance")));
    assert_eq!(
        schema["properties"]["provenance"]["properties"]["retention_state"]["enum"],
        json!(["none", "captured", "retained"])
    );
    assert!(schema["properties"]["provenance"]["properties"]
        .get("source_revision")
        .is_some());
    assert!(schema["properties"].get("actor").is_none());

    let value = registry
        .call(
            db.clone(),
            Caller::authenticated(actor.clone()),
            "observe_external",
            json!({
                "bindings": [{"system":"native-principal","identifier":"native/mcp-observed"}],
                "source_binding": {"system":"native-principal","identifier":"native/mcp-observed"},
                "quality": "reported",
                "materialization_policy": "identity_only",
                "provenance": {
                    "freshness": "unknown",
                    "retention_state": "none",
                    "source_availability": "unknown",
                    "refresh_outcome": "not_attempted"
                },
                "reason": "exercise typed MCP provenance"
            }),
        )
        .await
        .unwrap();
    assert_eq!(value["provenance"]["retention_state"], "none");
    let observed_actor: String =
        sqlx::query_scalar("SELECT actor FROM external_observations WHERE id = ?")
            .bind(value["observation_id"].as_str().unwrap())
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(observed_actor, actor);
    let rendered = native_ce::mcp::render::render("observe_external", &value).unwrap();
    assert!(rendered.contains("Provenance: unknown/none; source unknown; refresh not_attempted."));
}

#[tokio::test]
async fn view_only_resolution_hit_preserves_noncanonical_state_and_audit() {
    let (db, actor) = setup().await;
    let primary = principal("pure-hit-primary");
    let alias = principal("pure-hit-alias");
    let resolved = identity::resolve_external(
        &db,
        &context(&actor, "create visible identity"),
        std::slice::from_ref(&primary),
        &StubHints::default(),
    )
    .await
    .unwrap();
    identity::add_binding(
        &db,
        &context(&actor, "add noncanonical alias"),
        &resolved.record_id,
        &alias,
        false,
    )
    .await
    .unwrap();
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &resolved.record_id,
        vec![AllowEntry::account("acct_viewer", Capability::View)],
    )
    .await
    .unwrap();
    let before_flags: Vec<(String, i64)> = sqlx::query_as(
        "SELECT identifier,is_canonical FROM bindings WHERE record_id=? ORDER BY identifier",
    )
    .bind(&resolved.record_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    let before_audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM binding_audit")
        .fetch_one(db.pool())
        .await
        .unwrap();

    let hit = identity::resolve_external(
        &db,
        &context("acct_viewer", "read a pure resolution hit"),
        std::slice::from_ref(&alias),
        &StubHints::default(),
    )
    .await
    .unwrap();
    assert_eq!(hit.record_id, resolved.record_id);
    assert!(!hit.created);
    assert!(hit.bindings_added.is_empty());
    let after_flags: Vec<(String, i64)> = sqlx::query_as(
        "SELECT identifier,is_canonical FROM bindings WHERE record_id=? ORDER BY identifier",
    )
    .bind(&resolved.record_id)
    .fetch_all(db.pool())
    .await
    .unwrap();
    let after_audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM binding_audit")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(after_flags, before_flags);
    assert_eq!(after_audit, before_audit);
}

#[tokio::test]
async fn invisible_binding_owners_are_checked_and_never_disclosed() {
    let (db, actor) = setup().await;
    let hidden_claim = principal("hidden-owner");
    let hidden = identity::resolve_external(
        &db,
        &context(&actor, "create hidden owner"),
        std::slice::from_ref(&hidden_claim),
        &StubHints::default(),
    )
    .await
    .unwrap();
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &hidden.record_id,
        vec![AllowEntry::account(&actor, Capability::Manage)],
    )
    .await
    .unwrap();
    let visible_claim = principal("viewer-target");
    let visible = identity::resolve_external(
        &db,
        &context(&actor, "create collision target"),
        std::slice::from_ref(&visible_claim),
        &StubHints::default(),
    )
    .await
    .unwrap();
    native_ce::authorization::replace_explicit_policy(
        &db,
        "test:policy",
        &visible.record_id,
        vec![AllowEntry::account("acct_viewer", Capability::Manage)],
    )
    .await
    .unwrap();

    let probe = identity::resolve_external(
        &db,
        &context("acct_viewer", "probe hidden identity"),
        std::slice::from_ref(&hidden_claim),
        &StubHints::default(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(probe.contains("binding_not_visible"), "{probe}");
    assert!(!probe.contains(&hidden.record_id));

    let conflict = identity::resolve_external(
        &db,
        &context("acct_viewer", "resolve mixed visibility claims"),
        &[visible_claim.clone(), hidden_claim.clone()],
        &StubHints::default(),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(conflict.contains("binding_not_visible"), "{conflict}");
    assert!(!conflict.contains(&hidden.record_id));
    assert!(!conflict.contains(&visible.record_id));

    let collision = identity::add_binding(
        &db,
        &context("acct_viewer", "try hidden collision"),
        &visible.record_id,
        &hidden_claim,
        false,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(collision.contains("binding_not_visible"), "{collision}");
    assert!(!collision.contains(&hidden.record_id));
    assert!(!collision.contains(&visible.record_id));
}

#[tokio::test]
async fn remove_and_binding_only_reconcile_are_truthful_stale_safe_and_content_free() {
    let (db, actor) = setup().await;
    let source_primary = principal("reconcile-source");
    let alias = principal("reconcile-alias");
    let source = identity::resolve_external(
        &db,
        &context(&actor, "create reconcile source"),
        std::slice::from_ref(&source_primary),
        &StubHints::default(),
    )
    .await
    .unwrap();
    identity::add_binding(
        &db,
        &context(&actor, "add removable alias"),
        &source.record_id,
        &alias,
        false,
    )
    .await
    .unwrap();
    assert!(identity::remove_binding(
        &db,
        &context(&actor, "remove alias once"),
        &source.record_id,
        &alias,
    )
    .await
    .unwrap());
    assert!(!identity::remove_binding(
        &db,
        &context(&actor, "remove alias twice"),
        &source.record_id,
        &alias,
    )
    .await
    .unwrap());
    identity::add_binding(
        &db,
        &context(&actor, "restore alias for transfer"),
        &source.record_id,
        &alias,
        false,
    )
    .await
    .unwrap();
    assert!(!identity::canonicalize_binding(
        &db,
        &context(&actor, "canonical no-op"),
        &source.record_id,
        &source_primary,
    )
    .await
    .unwrap());
    let target = identity::resolve_external(
        &db,
        &context(&actor, "create reconcile target"),
        &[principal("reconcile-target")],
        &StubHints::default(),
    )
    .await
    .unwrap();
    let before_content = content_snapshot(&db).await;
    let before_audit: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM binding_audit")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let preview = identity::reconcile_bindings(
        &db,
        &context(&actor, ""),
        &target.record_id,
        &source.record_id,
        std::slice::from_ref(&alias),
        false,
    )
    .await
    .unwrap();
    assert_eq!(preview.as_slice(), std::slice::from_ref(&alias));
    assert_eq!(content_snapshot(&db).await, before_content);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM binding_audit")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before_audit
    );
    let applied = identity::reconcile_bindings(
        &db,
        &context(&actor, "transfer selected alias only"),
        &target.record_id,
        &source.record_id,
        std::slice::from_ref(&alias),
        true,
    )
    .await
    .unwrap();
    assert_eq!(applied.as_slice(), std::slice::from_ref(&alias));
    assert_eq!(content_snapshot(&db).await, before_content);
    let owner: String =
        sqlx::query_scalar("SELECT record_id FROM bindings WHERE system=? AND identifier=?")
            .bind(&alias.system)
            .bind(&alias.identifier)
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(owner, target.record_id);
    let action: String = sqlx::query_scalar(
        "SELECT action FROM binding_audit WHERE system=? AND identifier=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(&alias.system)
    .bind(&alias.identifier)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(action, "transfer");
    let stale = identity::reconcile_bindings(
        &db,
        &context(&actor, "retry stale transfer"),
        &target.record_id,
        &source.record_id,
        std::slice::from_ref(&alias),
        true,
    )
    .await
    .unwrap_err();
    assert!(stale.to_string().contains("stale expected owner"));
}

#[tokio::test]
async fn native_record_codec_resolves_a_real_shadow_with_slashes_in_the_origin_record_id() {
    let (db, actor) = setup().await;
    let origin_db_id = identity::database_id(&db).await.unwrap();
    let identifier =
        identity::encode_native_record(&origin_db_id, "remote/record/with/slashes").unwrap();
    assert_eq!(
        identity::decode_native_record(&identifier).unwrap(),
        (origin_db_id, "remote/record/with/slashes".into())
    );
    let claim = BindingClaim {
        system: "native-record".into(),
        identifier: identifier.clone(),
    };
    let resolved = identity::resolve_external(
        &db,
        &context(&actor, "resolve remote native record"),
        std::slice::from_ref(&claim),
        &StubHints {
            record_type: Some("Entity".into()),
            kind: Some("person".into()),
            name: Some("Remote identity".into()),
        },
    )
    .await
    .unwrap();
    let stored: String = sqlx::query_scalar(
        "SELECT identifier FROM bindings WHERE record_id=? AND system='native-record'",
    )
    .bind(&resolved.record_id)
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(stored, identifier);
}

#[tokio::test]
async fn manage_bindings_reports_an_already_canonical_binding_as_unchanged() {
    let (db, actor) = setup().await;
    let claim = principal("canonical-tool-noop");
    let resolved = identity::resolve_external(
        &db,
        &context(&actor, "create canonical tool fixture"),
        std::slice::from_ref(&claim),
        &StubHints::default(),
    )
    .await
    .unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    let result = registry
        .call(
            db.clone(),
            Caller::authenticated(actor),
            "manage_bindings",
            json!({
                "action": "canonicalize",
                "record_id": resolved.record_id,
                "binding": claim,
                "reason": "verify a canonical no-op"
            }),
        )
        .await
        .unwrap();
    assert_eq!(result["status"], "unchanged");
    assert_eq!(result["changed"], false);
}

#[tokio::test]
async fn observation_failure_rolls_back_shadow_binding_blob_attachment_and_audit() {
    let (db, actor) = setup().await;
    sqlx::query(
        "CREATE TRIGGER reject_external_observation
         BEFORE INSERT ON external_observations BEGIN
           SELECT RAISE(ABORT, 'late observation failure');
         END",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let before: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM records),
                (SELECT COUNT(*) FROM content_events),
                (SELECT COUNT(*) FROM bindings),
                (SELECT COUNT(*) FROM binding_audit),
                (SELECT COUNT(*) FROM blobs),
                (SELECT COUNT(*) FROM external_observations)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let claim = principal("rollback-observation");
    let mut trusted = context(&actor, "late failure must be atomic");
    trusted.internal = true;
    trusted.source_read_authorized = true;
    let error = identity::observe_external(
        &db,
        &trusted,
        std::slice::from_ref(&claim),
        &StubHints::default(),
        &claim,
        ObservationQuality::Fetched,
        MaterializationPolicy::Snapshot,
        None,
        &captured_provenance("rollback-revision", None),
        None,
        Some(b"snapshot bytes"),
        Some("text/plain"),
        Some("snapshot.txt"),
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("late observation failure"));
    let after: (i64, i64, i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM records),
                (SELECT COUNT(*) FROM content_events),
                (SELECT COUNT(*) FROM bindings),
                (SELECT COUNT(*) FROM binding_audit),
                (SELECT COUNT(*) FROM blobs),
                (SELECT COUNT(*) FROM external_observations)",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(after, before);
}

#[tokio::test]
async fn governed_registry_drift_and_non_authoritative_sources_fail_closed() {
    let (db, actor) = setup().await;
    sqlx::query(
        "UPDATE binding_systems SET authoritative_provenance=0 WHERE system='native-principal'",
    )
    .execute(&crate::common::fixture_write_pool(&db).await)
    .await
    .unwrap();
    let violations = identity::state_violations(&db).await.unwrap();
    assert!(violations
        .iter()
        .any(|violation| violation.contains("governed built-in definitions")));
    let claim = principal("untrusted-provenance");
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM external_observations")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let error = identity::observe_external(
        &db,
        &context(&actor, "reject non-authoritative source"),
        std::slice::from_ref(&claim),
        &StubHints::default(),
        &claim,
        ObservationQuality::Reported,
        MaterializationPolicy::IdentityOnly,
        None,
        &ObservationProvenance::default(),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("not authoritative"));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM external_observations")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn rekey_requires_exact_preimage_and_preserves_old_identity_only_as_provenance() {
    let root = tempdir().unwrap();
    let source = root.path().join("fork.db");
    let backup = root.path().join("preimage.db");
    let db = native_ce::create_database(&source.to_string_lossy())
        .await
        .unwrap();
    let old_id = identity::database_id(&db).await.unwrap();
    checkpoint_and_close(&db).await;
    std::fs::copy(&source, &backup).unwrap();

    let wrong = identity::rekey_database_offline(
        &source,
        &backup,
        "ndb_00000000000000000000000000000000",
        "test:rekey",
        "wrong confirmation",
    )
    .await
    .unwrap_err();
    assert!(wrong.to_string().contains("confirmation"));

    let tampered = rusqlite::Connection::open(&backup).unwrap();
    tampered
        .execute(
            "UPDATE content_events SET actor='tampered-with-same-head' WHERE seq=(SELECT MIN(seq) FROM content_events)",
            [],
        )
        .unwrap();
    drop(tampered);
    let mismatch = identity::rekey_database_offline(
        &source,
        &backup,
        &old_id,
        "test:rekey",
        "reject same-head tampering",
    )
    .await
    .unwrap_err();
    assert!(mismatch.to_string().contains("complete authoritative logs"));

    std::fs::copy(&source, &backup).unwrap();
    let new_id = identity::rekey_database_offline(
        &source,
        &backup,
        &old_id,
        "test:rekey",
        "create an independently writable fork",
    )
    .await
    .unwrap();
    assert!(identity::is_database_id(&new_id));
    assert_ne!(new_id, old_id);
    let reopened = native_ce::open_existing_database(&source.to_string_lossy())
        .await
        .unwrap();
    assert_eq!(identity::database_id(&reopened).await.unwrap(), new_id);
    let chain: Vec<(String, Option<String>, String, String, String)> = sqlx::query_as(
        "SELECT action,old_origin_db_id,new_origin_db_id,actor,reason
           FROM database_identity_audit ORDER BY seq",
    )
    .fetch_all(reopened.pool())
    .await
    .unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].0, "mint");
    assert_eq!(chain[1].0, "rekey");
    assert_eq!(chain[1].1.as_deref(), Some(old_id.as_str()));
    assert_eq!(chain[1].2, new_id);
    assert_eq!(chain[1].3, "test:rekey");
    assert_eq!(chain[1].4, "create an independently writable fork");
    let old_active: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM database_identity WHERE origin_db_id=?")
            .bind(&old_id)
            .fetch_one(reopened.pool())
            .await
            .unwrap();
    assert_eq!(old_active, 0);
    assert!(identity::state_violations(&reopened)
        .await
        .unwrap()
        .is_empty());
}

// ---- reserved instruction folder reconciliation ----

async fn reserved_folder_home_id(db: &native_ce::Db) -> Option<String> {
    sqlx::query_scalar("SELECT home_id FROM records WHERE id = 'native:agent-instructions'")
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn provisioning_event_count(db: &native_ce::Db) -> i64 {
    sqlx::query_scalar(
        "SELECT COUNT(*) FROM content_events
          WHERE record_id = 'native:agent-instructions' AND type = 'record.updated'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap()
}

/// Moving the reserved folder is a write the engine accepts, and it used to
/// make provisioning refuse every subsequent connect — including the calls that
/// would have repaired it. The seeded placement is authoritative, so connecting
/// restores it instead of locking the workspace out.
#[tokio::test]
async fn connect_restores_a_reserved_instruction_folder_moved_by_an_ordinary_write() {
    let (db, _actor) = setup().await;
    assert_eq!(
        reserved_folder_home_id(&db).await.as_deref(),
        Some("native:root")
    );

    let elsewhere = native_ce::store::create_record(
        &db,
        json!({"type":"Collection","kind":"folder","name":"Elsewhere","home_id":"native:root"}),
    )
    .await
    .unwrap();
    native_ce::store::update_record(
        &db,
        "native:agent-instructions",
        json!({"home_id": elsewhere, "reason": "file the folder somewhere else"}),
    )
    .await
    .unwrap();
    assert_eq!(
        reserved_folder_home_id(&db).await.as_deref(),
        Some(elsewhere.as_str())
    );

    resolve_stdio_account_identity(&db, None).await.unwrap();
    assert_eq!(
        reserved_folder_home_id(&db).await.as_deref(),
        Some("native:root")
    );

    // Reconciliation is not a per-connect write: once the drift is gone the
    // next connect must append nothing, or every session would grow the log.
    let after_repair = provisioning_event_count(&db).await;
    resolve_stdio_account_identity(&db, None).await.unwrap();
    assert_eq!(provisioning_event_count(&db).await, after_repair);
    assert_eq!(
        reserved_folder_home_id(&db).await.as_deref(),
        Some("native:root")
    );
}
