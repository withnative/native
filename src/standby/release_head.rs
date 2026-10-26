//! Release receipt equality only. This never admits a delta or opens a Db.
//!
//! Engine 87/88 authored revision-6 head v2 at b4ab6a91. Its coordinate
//! inventories and governed binding seeds are frozen below. The source schema
//! is checked against the engine's frozen physical shape inside the same
//! read-only transaction as the observation. Source-history application_id
//! remains separate: this observes the producer wire contract, not fidelity.

use super::authority_probe::{authority_act_head_sql_for, AuthorityActHeadV1, BindingSystemSeedV1};
use crate::{Error, Result};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};
use std::path::Path;

const REVISION6_LOGS: [&str; 10] = [
    "content_events",
    "policy_events",
    "awareness_events",
    "notification_candidate_events",
    "binding_audit",
    "database_identity_audit",
    "meta_events",
    "control_events",
    "derivation_events",
    "relationship_events",
];
const REVISION6_NON_SEQUENCED: [&str; 3] = [
    "awareness_command_intents",
    "external_observations",
    "provenance_attestation_validity_events",
];

pub(crate) fn release_revision(schema: i64) -> Result<u64> {
    match schema {
        87 | 88 => Ok(6),
        89 => Ok(7),
        // Engine 93 adds a derived partial index only. Engine 92 adds only trigger-maintained folds (`content_event_heads`),
        // no interchange section. Engine 91 adds derived authorization counters and transaction-only
        // birth certification; canonical act inventories and wire remain 8.
        90..=93 => Ok(8),
        _ => Err(Error::engine("unsupported release act-head source schema")),
    }
}

/// Validate a release envelope, not standby/delta authority. Unknown schema
/// and schema/wire mismatches refuse; a revision-6 head stays revision 6.
pub fn validate_release_act_head(head: &AuthorityActHeadV1) -> Result<()> {
    let revision = release_revision(head.source_engine_schema)?;
    if head.native_interchange_revision != revision {
        return Err(Error::engine("release act-head schema/revision mismatch"));
    }
    if matches!(revision, 6 | 7) {
        head.coordinates().validate_inventory(
            revision,
            &REVISION6_LOGS,
            &REVISION6_NON_SEQUENCED,
            &revision6_binding_seeds(),
        )
    } else {
        head.validate()
    }
}

/// Observe a qualified release source without migrating, repairing, opening a
/// writable pool or changing source-history markers. Includes live WAL state;
/// as with the current authority probe, hash file bytes after this observation
/// (SQLite can materialize empty WAL/SHM sidecars). Caller owns writer custody.
pub async fn read_release_act_head_from_path(path: &Path) -> Result<AuthorityActHeadV1> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(true)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options).await?;
    let result = async {
        sqlx::query("PRAGMA query_only=ON")
            .execute(&mut connection)
            .await?;
        sqlx::query("BEGIN DEFERRED")
            .execute(&mut connection)
            .await?;
        crate::db::refuse_v2_database(&mut connection).await?;
        let schema: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut connection)
            .await?;
        let revision = release_revision(schema)?;
        crate::db::validate_supported_engine_migration_source(&mut connection, schema).await?;
        let sql = if matches!(revision, 6 | 7) {
            authority_act_head_sql_for(revision, &REVISION6_LOGS, &REVISION6_NON_SEQUENCED)
        } else {
            authority_act_head_sql_for(
                revision,
                &crate::act::CANONICAL_EVENT_TABLES,
                &crate::act::NON_SEQUENCED_ACT_STAMPED_TABLES,
            )
        };
        let raw: String = sqlx::query_scalar(&sql).fetch_one(&mut connection).await?;
        let head: AuthorityActHeadV1 = serde_json::from_str(&raw)
            .map_err(|e| Error::engine(format!("invalid release act-head: {e}")))?;
        validate_release_act_head(&head)?;
        Ok(head)
    }
    .await;
    // Close rolls back even failed reads; never leave a transaction/pool live.
    connection.close().await?;
    result
}

fn revision6_binding_seeds() -> Vec<BindingSystemSeedV1> {
    vec![
        BindingSystemSeedV1 {
            system: "account".into(),
            normalizer: "account-v1".into(),
            compatible_type: Some("Entity".into()),
            compatible_kind: Some("person".into()),
            visibility: "reserved".into(),
            add_policy: "internal".into(),
            remove_policy: "internal".into(),
            canonicalize_policy: "internal".into(),
            transfer_policy: "internal".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 0,
            authoritative_provenance: 1,
            required_durable: 1,
        },
        BindingSystemSeedV1 {
            system: "email".into(),
            normalizer: "email-v1".into(),
            compatible_type: Some("Entity".into()),
            compatible_kind: Some("person".into()),
            visibility: "reserved".into(),
            add_policy: "internal".into(),
            remove_policy: "internal".into(),
            canonicalize_policy: "internal".into(),
            transfer_policy: "internal".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 0,
            authoritative_provenance: 1,
            required_durable: 0,
        },
        BindingSystemSeedV1 {
            system: "native-principal".into(),
            normalizer: "native-principal-v1".into(),
            compatible_type: Some("Entity".into()),
            compatible_kind: Some("person".into()),
            visibility: "public".into(),
            add_policy: "record_manage".into(),
            remove_policy: "record_manage".into(),
            canonicalize_policy: "record_manage".into(),
            transfer_policy: "record_manage".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 1,
            authoritative_provenance: 1,
            required_durable: 1,
        },
        BindingSystemSeedV1 {
            system: "native-record".into(),
            normalizer: "native-record-v1".into(),
            compatible_type: None,
            compatible_kind: None,
            visibility: "public".into(),
            add_policy: "record_manage".into(),
            remove_policy: "record_manage".into(),
            canonicalize_policy: "record_manage".into(),
            transfer_policy: "record_manage".into(),
            reconciliation_rule: "binding_only".into(),
            stub_allowed: 1,
            authoritative_provenance: 1,
            required_durable: 1,
        },
    ]
}

#[cfg(test)]
mod tests {
    #[test]
    fn release_current_schema_and_wire_pair_requires_explicit_qualification() {
        assert_eq!(crate::db::CURRENT_ENGINE_SCHEMA_VERSION, 93);
        assert_eq!(crate::interchange::REVISION, 8);
        assert_eq!(
            super::release_revision(93).unwrap(),
            crate::interchange::REVISION
        );
        assert_eq!(super::release_revision(91).unwrap(), 8);
        assert_eq!(super::release_revision(90).unwrap(), 8);
        assert!(
            super::release_revision(94).is_err(),
            "future schemas still require qualification"
        );
    }
}
