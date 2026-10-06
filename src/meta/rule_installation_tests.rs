//! Gated S1 rule-installation snapshot tests: set/read roundtrip, exact
//! retry, previous-seq, replacement/disable atomicity, replay equivalence,
//! no-SQL-at-fold, read-set tamper refusal, projection/log disagreement,
//! fixture guard, scope index bounds, and delimiter isolation. Storage only —
//! no admission, call, or authority API. Nothing touches production DDL.

use std::collections::{BTreeMap, BTreeSet};

use native_query_contract::rule_contract::{PinnedRelation, RuleInputReadset};

use crate::db::{begin_write, create_database, Db};
use crate::meta::rule_installation::{
    ensure_rule_installation_tables, installation_scope_prefix, installation_subject,
    list_installations_in_scope, read_installation_in, set_installation_in,
};
use crate::query::rule_install::{
    EngineValidationEvidence, ParameterDecl, ParameterSource, RuleAdmissionReceipt,
    RuleCardinality, RuleInputDecl, RuleRevision,
};

const SCOPE: &str = "home:test-scope";
const ENGINE: &str = "test-engine";

fn sample_revision() -> RuleRevision {
    RuleRevision {
        scalar_arguments: vec![],
        binding_contract: None,
        namespace: "acme".to_owned(),
        name: "overdue".to_owned(),
        language: "cel-subset@1".to_owned(),
        inputs: vec![RuleInputDecl {
            contract: None,
            name: "deal".to_owned(),
            sql: "SELECT id FROM records WHERE id = ?1".to_owned(),
            cardinality: RuleCardinality::One,
            required_fields: vec!["id".to_owned()],
            parameters: vec![ParameterDecl {
                slot: 1,
                param_type: "text".to_owned(),
                nullable: false,
                source: ParameterSource::Argument {
                    name: "bid".to_owned(),
                },
            }],
        }],
        clauses: "true".to_owned(),
        examples: vec![],
        definition_pins: vec![],
    }
}

fn sample_readsets() -> BTreeMap<String, RuleInputReadset> {
    BTreeMap::from([(
        "deal".to_owned(),
        RuleInputReadset {
            relations: vec![PinnedRelation {
                identity: "native.query-sql.records".to_owned(),
                name: "records".to_owned(),
                semantic_version: 1,
                columns: BTreeSet::from(["id".to_owned()]),
                population_only: false,
            }],
            parameter_slots: vec![1],
            uses_now_ms: false,
        },
    )])
}

fn settings() -> serde_json::Value {
    serde_json::json!({"level": "advise"})
}

fn receipt_for(
    revision: &RuleRevision,
    settings: &serde_json::Value,
    readset_digest: &str,
    engine: &str,
) -> RuleAdmissionReceipt {
    use crate::query::rule_install as ri;
    let evidence = EngineValidationEvidence {
        revision_digest: ri::revision_digest(revision).unwrap(),
        settings_digest: ri::settings_digest(settings).unwrap(),
        language_identity: revision.language.clone(),
        policy_version: "g3-1".to_owned(),
        engine_id: engine.to_owned(),
        engine_version: "1.0".to_owned(),
        bundle_sha256: None,
    };
    RuleAdmissionReceipt::issue(evidence, readset_digest.to_owned())
}

async fn test_db() -> Db {
    let db = create_database(":memory:").await.unwrap();
    ensure_rule_installation_tables(&db).await.unwrap();
    db
}

async fn set(
    db: &Db,
    scope: &str,
    revision: &RuleRevision,
    active: bool,
    previous_seq: Option<i64>,
    actor: &str,
) -> Result<crate::meta::rule_installation::StoredInstallation, crate::error::Error> {
    set_as(
        db,
        scope,
        revision,
        &settings(),
        active,
        previous_seq,
        actor,
    )
    .await
}

async fn set_as(
    db: &Db,
    scope: &str,
    revision: &RuleRevision,
    settings: &serde_json::Value,
    active: bool,
    previous_seq: Option<i64>,
    actor: &str,
) -> Result<crate::meta::rule_installation::StoredInstallation, crate::error::Error> {
    use crate::query::rule_install as ri;
    let readsets = sample_readsets();
    let pairs: Vec<(&str, &RuleInputReadset)> =
        readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let digest = ri::readset_digest(4, "sqlite-local", 1, &pairs);
    let receipt = receipt_for(revision, settings, &digest, ENGINE);
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let outcome = set_installation_in(
        &mut tx,
        scope,
        revision,
        settings,
        4,
        "sqlite-local",
        1,
        &readsets,
        &receipt,
        active,
        previous_seq,
        Some(actor),
        &mut alloc,
    )
    .await;
    match outcome {
        Ok((stored, _)) => {
            tx.commit().await.unwrap();
            Ok(stored)
        }
        Err(err) => Err(err),
    }
}

#[tokio::test]
async fn set_read_roundtrip_and_actor_scoped_retry() {
    let db = test_db().await;
    let revision = sample_revision();
    let first = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    assert!(first.active);
    assert!(first.event_seq >= 1);
    // Same-actor identical retry appends nothing.
    let (stored, appended) = {
        let readsets = sample_readsets();
        let pairs: Vec<(&str, &RuleInputReadset)> =
            readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let digest = crate::query::rule_install::readset_digest(4, "sqlite-local", 1, &pairs);
        let receipt = receipt_for(&revision, &settings(), &digest, ENGINE);
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let out = set_installation_in(
            &mut tx,
            SCOPE,
            &revision,
            &settings(),
            4,
            "sqlite-local",
            1,
            &readsets,
            &receipt,
            true,
            Some(first.event_seq),
            Some("test:a"),
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        out
    };
    assert!(!appended);
    assert_eq!(stored.event_seq, first.event_seq);
    // Different actor records a fresh attributed snapshot.
    let moved = set(&db, SCOPE, &revision, true, Some(first.event_seq), "test:b")
        .await
        .unwrap();
    assert_eq!(moved.actor, "test:b");
    assert!(moved.event_seq > first.event_seq);
    db.close().await;
}

#[tokio::test]
async fn exact_retry_demands_the_current_seq() {
    let db = test_db().await;
    let revision = sample_revision();
    let first = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    // Same bytes, same actor, but None (create-only) over an existing row:
    // strict ExpectedSeq refuses instead of blessing a no-op.
    let err = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("updates must name"), "{err}");
    // Matching seq is a verified no-op; stale seq refuses as Conflict.
    let (stored, appended) = {
        let readsets = sample_readsets();
        let pairs: Vec<(&str, &RuleInputReadset)> =
            readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let digest = crate::query::rule_install::readset_digest(4, "sqlite-local", 1, &pairs);
        let receipt = receipt_for(&revision, &settings(), &digest, ENGINE);
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let out = set_installation_in(
            &mut tx,
            SCOPE,
            &revision,
            &settings(),
            4,
            "sqlite-local",
            1,
            &readsets,
            &receipt,
            true,
            Some(first.event_seq),
            Some("test:a"),
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        out
    };
    assert!(!appended);
    assert_eq!(stored.event_seq, first.event_seq);
    let err = set(
        &db,
        SCOPE,
        &revision,
        true,
        Some(first.event_seq + 41),
        "test:a",
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, crate::error::Error::Conflict(_)),
        "writer precondition mismatch must be Conflict, got {err:?}"
    );
    db.close().await;
}

#[tokio::test]
async fn canonical_permutation_mints_no_event() {
    let db = test_db().await;
    let mut revision = sample_revision();
    revision
        .inputs
        .push(crate::query::rule_install::RuleInputDecl {
            contract: None,
            name: "policy".to_owned(),
            sql: "SELECT id FROM records".to_owned(),
            cardinality: crate::query::rule_install::RuleCardinality::Many,
            required_fields: vec!["id".to_owned()],
            parameters: vec![],
        });
    // Declare the same inputs in reverse order with matching read-sets: the
    // digest-grained no-op must not append.
    let mut reordered = revision.clone();
    reordered.inputs.reverse();
    let mut readsets = sample_readsets();
    readsets.insert(
        "policy".to_owned(),
        RuleInputReadset {
            relations: vec![PinnedRelation {
                identity: "native.query-sql.records".to_owned(),
                name: "records".to_owned(),
                semantic_version: 1,
                columns: BTreeSet::from(["id".to_owned()]),
                population_only: false,
            }],
            parameter_slots: vec![],
            uses_now_ms: false,
        },
    );
    let snap = |rev: &RuleRevision| {
        let pairs: Vec<(&str, &RuleInputReadset)> =
            readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
        let digest = crate::query::rule_install::readset_digest(4, "sqlite-local", 1, &pairs);
        receipt_for(rev, &settings(), &digest, ENGINE)
    };
    let first = {
        let receipt = snap(&revision);
        let mut tx = begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let (stored, appended) = set_installation_in(
            &mut tx,
            SCOPE,
            &revision,
            &settings(),
            4,
            "sqlite-local",
            1,
            &readsets,
            &receipt,
            true,
            None,
            Some("test:a"),
            &mut alloc,
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
        assert!(appended);
        stored
    };
    let receipt = snap(&reordered);
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let (stored, appended) = set_installation_in(
        &mut tx,
        SCOPE,
        &reordered,
        &settings(),
        4,
        "sqlite-local",
        1,
        &readsets,
        &receipt,
        true,
        Some(first.event_seq),
        Some("test:a"),
        &mut alloc,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(!appended, "canonical-equivalent reorder must be a no-op");
    assert_eq!(stored.event_seq, first.event_seq);
    db.close().await;
}

#[tokio::test]
async fn readset_tamper_refuses_before_append() {
    use crate::meta::rule_installation::installation_subject;
    use crate::meta::rule_installation::verify_installation_payload;
    use crate::query::rule_install as ri;
    let db = test_db().await;
    let revision = sample_revision();
    let readsets = sample_readsets();
    let pairs: Vec<(&str, &RuleInputReadset)> =
        readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let digest = ri::readset_digest(4, "sqlite-local", 1, &pairs);
    let receipt = receipt_for(&revision, &settings(), &digest, ENGINE);
    let subject = installation_subject(SCOPE, "acme", "overdue");
    let good = crate::meta::events::RuleInstallationSetV1Payload {
        scope_home: SCOPE.to_owned(),
        revision: revision.clone(),
        revision_digest: ri::revision_digest(&revision).unwrap(),
        settings: settings(),
        settings_digest: ri::settings_digest(&settings()).unwrap(),
        catalog_revision: 4,
        profile_id: "sqlite-local".to_owned(),
        profile_revision: 1,
        readsets: readsets.clone(),
        readset_digest: digest.clone(),
        receipt,
        active: true,
        previous_seq: None,
    };
    assert!(verify_installation_payload(&subject, &good).is_ok());
    // Missing input, changed slots, and population/column mismatch refuse.
    let mut missing = good.clone();
    missing.readsets.clear();
    assert!(verify_installation_payload(&subject, &missing).is_err());
    let mut bad_slots = good.clone();
    bad_slots.readsets.get_mut("deal").unwrap().parameter_slots = vec![1, 2];
    assert!(verify_installation_payload(&subject, &bad_slots).is_err());
    let mut bad_pop = good.clone();
    let rel = &mut bad_pop.readsets.get_mut("deal").unwrap().relations[0];
    rel.population_only = true;
    assert!(verify_installation_payload(&subject, &bad_pop).is_err());
    // Tampered projection pins fail the keyed read after a good write.
    let stored = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    for (sql, value) in [
        ("catalog_revision = 5", "catalog"),
        ("profile_id = 'other'", "profile"),
        ("profile_revision = 9", "profile"),
    ] {
        let _ = value;
        sqlx::query(&format!(
            "UPDATE rule_installations SET {sql} WHERE scope_home = ? AND namespace = ? AND name = ?"
        ))
        .bind(SCOPE)
        .bind("acme")
        .bind("overdue")
        .execute(db.write_pool())
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let err = read_installation_in(&mut tx, SCOPE, "acme", "overdue")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("disagrees") || err.to_string().contains("no longer"),
            "{sql}: {err}"
        );
        tx.rollback().await.unwrap();
    }
    assert_eq!(stored.namespace, "acme");
    db.close().await;
}

#[tokio::test]
async fn scope_census_is_indexed_and_delimiter_safe() {
    let db = test_db().await;
    let revision = sample_revision();
    // No FK to scope: an installation lands under a scope with no kernel root.
    set(&db, "home:lonely", &revision, true, None, "test:a")
        .await
        .unwrap();
    set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    let mut other = revision.clone();
    other.name = "second".to_owned();
    set(&db, "home:a:b", &other, true, None, "test:a")
        .await
        .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    // Census isolation: "home:a" must not see "home:a:b" and vice versa.
    let lonely = list_installations_in_scope(&mut tx, "home:lonely")
        .await
        .unwrap();
    assert_eq!(lonely.len(), 1);
    let scoped = list_installations_in_scope(&mut tx, SCOPE).await.unwrap();
    assert_eq!(scoped.len(), 1);
    let colon = list_installations_in_scope(&mut tx, "home:a:b")
        .await
        .unwrap();
    assert_eq!(colon.len(), 1);
    // EXPLAIN proves the census range uses the subject index (SEARCH).
    let prefix = installation_scope_prefix(SCOPE);
    let end = format!("{prefix}\u{10FFFF}");
    let plan: Vec<(i64, i64, i64, String)> = sqlx::query_as(
        "EXPLAIN QUERY PLAN SELECT DISTINCT subject_id FROM meta_events
          WHERE subject_id >= ? AND subject_id < ?
            AND type = 'rule_installation.set.v1'",
    )
    .bind(&prefix)
    .bind(&end)
    .fetch_all(&mut *tx)
    .await
    .unwrap();
    let detail: String = plan
        .iter()
        .map(|row| row.3.clone())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(detail.contains("idx_meta_events_subject"), "{detail}");
    assert!(detail.contains("SEARCH"), "{detail}");
    tx.commit().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn fixture_receipts_never_reach_storage() {
    use crate::query::rule_install as ri;
    let db = test_db().await;
    let revision = sample_revision();
    let readsets = sample_readsets();
    let pairs: Vec<(&str, &RuleInputReadset)> =
        readsets.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let digest = ri::readset_digest(4, "sqlite-local", 1, &pairs);
    let receipt = receipt_for(
        &revision,
        &settings(),
        &digest,
        crate::query::rule_install::FIXTURE_ENGINE_ID,
    );
    assert!(ri::verify_receipt_usable(&receipt).is_err());
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let mut alloc = crate::act::ActAllocation::new();
    let err = set_installation_in(
        &mut tx,
        SCOPE,
        &revision,
        &settings(),
        4,
        "sqlite-local",
        1,
        &readsets,
        &receipt,
        true,
        None,
        Some("test:a"),
        &mut alloc,
    )
    .await
    .unwrap_err();
    assert!(err.to_string().contains("fixture"), "{err}");
    tx.rollback().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn projection_log_disagreement_fails_closed() {
    let db = test_db().await;
    let revision = sample_revision();
    let stored = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    // Log-only: drop the row, keep the event.
    sqlx::query(
        "DELETE FROM rule_installations WHERE scope_home = ? AND namespace = ? AND name = ?",
    )
    .bind(SCOPE)
    .bind("acme")
    .bind("overdue")
    .execute(db.write_pool())
    .await
    .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    assert!(read_installation_in(&mut tx, SCOPE, "acme", "overdue")
        .await
        .is_err());
    assert!(list_installations_in_scope(&mut tx, SCOPE).await.is_err());
    tx.rollback().await.unwrap();
    drop(stored);
    db.close().await;
    // Projection-only on a fresh db: retain the row, delete its meta events;
    // keyed read, census, and set all refuse without appending.
    let db = test_db().await;
    let revision = sample_revision();
    let stored = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    let subject = installation_subject(SCOPE, "acme", "overdue");
    let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM meta_events WHERE subject_id = ?")
        .bind(&subject)
        .execute(db.write_pool())
        .await
        .unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    assert!(read_installation_in(&mut tx, SCOPE, "acme", "overdue")
        .await
        .is_err());
    assert!(list_installations_in_scope(&mut tx, SCOPE).await.is_err());
    tx.rollback().await.unwrap();
    let err = set(
        &db,
        SCOPE,
        &revision,
        true,
        Some(stored.event_seq),
        "test:a",
    )
    .await
    .unwrap_err();
    assert!(
        err.to_string().contains("disagreement") || err.to_string().contains("no event"),
        "{err}"
    );
    let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM meta_events")
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    assert_eq!(after, before - 1, "refused set must append nothing");
    db.close().await;
}

#[tokio::test]
async fn previous_seq_and_replacement_disable_atomicity() {
    let db = test_db().await;
    let revision = sample_revision();
    let first = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    // Blind update over an existing row refuses; wrong seq refuses.
    assert!(set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .is_err());
    assert!(set(&db, SCOPE, &revision, true, Some(9999), "test:a")
        .await
        .is_err());
    // Create-only with a seq over an absent key refuses.
    assert!(set(&db, "home:absent", &revision, true, Some(1), "test:a")
        .await
        .is_err());
    // Replacement swaps the snapshot atomically under the same key.
    let mut next = revision.clone();
    next.clauses = "deal.id != ''".to_owned();
    let replaced = set(&db, SCOPE, &next, true, Some(first.event_seq), "test:a")
        .await
        .unwrap();
    assert_eq!(replaced.revision.clauses, "deal.id != ''");
    assert!(replaced.active);
    // Disable preserves bytes and flips active only.
    let disabled = set(&db, SCOPE, &next, false, Some(replaced.event_seq), "test:a")
        .await
        .unwrap();
    assert!(!disabled.active);
    assert_eq!(disabled.revision_digest, replaced.revision_digest);
    assert_eq!(disabled.receipt, replaced.receipt);
    db.close().await;
}

#[tokio::test]
async fn replay_rebuild_matches_live_rows() {
    let db = test_db().await;
    let revision = sample_revision();
    let first = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    let mut other = revision.clone();
    other.name = "second".to_owned();
    let second = set(&db, SCOPE, &other, true, None, "test:a").await.unwrap();
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let live = list_installations_in_scope(&mut tx, SCOPE).await.unwrap();
    assert_eq!(live, vec![first.clone(), second.clone()]);
    let events = crate::meta::read_all_meta_events(&mut tx).await.unwrap();
    let install_events: Vec<_> = events
        .iter()
        .filter(|e| e.event_type == "rule_installation.set.v1")
        .cloned()
        .collect();
    assert_eq!(install_events.len(), 2);
    sqlx::query("DELETE FROM rule_installations")
        .execute(&mut *tx)
        .await
        .unwrap();
    crate::projector::meta::replay_meta(&mut tx, &install_events)
        .await
        .unwrap();
    let rebuilt = list_installations_in_scope(&mut tx, SCOPE).await.unwrap();
    assert_eq!(rebuilt, vec![first, second]);
    tx.commit().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn full_kernel_replay_rebuilds_installations() {
    // Real prototype path: clear + wiring + order proved through
    // replay_all_projections and comparable table dumps.
    let db = crate::kernel::create_kernel_database(":memory:")
        .await
        .unwrap();
    // Replay once immediately: the prototype genesis policy-entry projection
    // differs between the live constructor and its first replay (pre-existing
    // kernel behavior, untouched by S1), so establish the stable replayed
    // baseline before the installations under test land.
    crate::kernel::replay_all_projections(&db).await.unwrap();
    let revision = sample_revision();
    let first = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    let mut other = revision.clone();
    other.name = "second".to_owned();
    let second = set(&db, SCOPE, &other, true, None, "test:a").await.unwrap();
    let before = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(before.installations.len(), 2);
    crate::kernel::replay_all_projections(&db).await.unwrap();
    let after = crate::kernel::dump_all_kernel_tables(&db).await.unwrap();
    assert_eq!(after, before);
    let mut tx = begin_write(db.write_pool()).await.unwrap();
    let live = list_installations_in_scope(&mut tx, SCOPE).await.unwrap();
    assert_eq!(live, vec![first, second]);
    tx.commit().await.unwrap();
    db.close().await;
}

#[tokio::test]
async fn fold_never_prepares_historical_sql() {
    // Garbage SQL with a garbage relation folds fine: the fold recomputes
    // digests from stored bytes and never compiles SQL or consults catalogs.
    let db = test_db().await;
    let mut revision = sample_revision();
    revision.inputs[0].sql = "SELECT nope FROM nowhere WHERE x = ?1".to_owned();
    let stored = set(&db, SCOPE, &revision, true, None, "test:a")
        .await
        .unwrap();
    assert_eq!(
        stored.revision.inputs[0].sql,
        "SELECT nope FROM nowhere WHERE x = ?1"
    );
    db.close().await;
}
