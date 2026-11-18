//! Release receipt equality only. This never admits a delta or opens a Db.
//!
//! Engine 87/88 authored revision-6 head v2 at b4ab6a91. Its coordinate
//! inventories and governed binding seeds are frozen below. The source schema
//! is checked against the engine's frozen physical shape inside the same
//! read-only transaction as the observation. Source-history application_id
//! remains separate: this observes the producer wire contract, not fidelity.

use super::authority_probe::{authority_act_head_sql_for, AuthorityActHeadV1, BindingSystemSeedV1};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, SqliteConnection};
use std::path::Path;

/// Release-only equality evidence. Keep the v1 wire document unchanged; v2
/// has its own closed coordinate contract and is never relabelled as v1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReleaseTenantHead {
    V1(Box<AuthorityActHeadV1>),
    KernelV2(KernelReleaseHead),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReleaseHead {
    pub contract: String,
    pub origin_database_id: String,
    pub generation: super::kernel_v2::KernelGeneration,
}

impl From<AuthorityActHeadV1> for ReleaseTenantHead {
    fn from(head: AuthorityActHeadV1) -> Self {
        Self::V1(Box::new(head))
    }
}

impl ReleaseTenantHead {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::V1(head) => validate_release_act_head(head),
            Self::KernelV2(head) => {
                if head.contract != "native.release-kernel-v2-head.v1"
                    || !crate::identity::is_database_id(&head.origin_database_id)
                {
                    return Err(Error::engine("invalid kernel-v2 release head"));
                }
                // Equality evidence only. Physical release observation also
                // qualifies the exact source/target DDL and readiness in its
                // read-only transaction. The preparation floor is never a
                // receiver-registry member or a serving authorization.
                head.generation.validate_shape()?;
                if super::shapes::v2(
                    head.generation.reader_format,
                    &head.generation.schema_sha256,
                )
                .is_none()
                    && !(head.generation.reader_format == super::kernel_v2::INITIAL_READER_FORMAT
                        && head.generation.schema_sha256
                            == super::kernel_v2::RELEASE_PRE_WEBHOOK_SOURCE_V1_SCHEMA_SHA256)
                {
                    return Err(Error::engine("unsupported kernel-v2 release shape"));
                }
                Ok(())
            }
        }
    }
}

/// Bounded observation stages, suitable for release-controller diagnostics.
/// These codes contain no filename, tenant identity, SQL or underlying error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReleaseHeadObservationPhase {
    Open,
    Transaction,
    V2Marker,
    V2Schema,
    V2WebhookKeysConflict,
    V2WebhookKeysUnreadable,
    V2Readiness,
    V2Coordinates,
    V2Origin,
    Contract,
    Close,
    V1Head,
}

impl ReleaseHeadObservationPhase {
    pub fn code(self) -> &'static str {
        match self {
            Self::Open => "head_open",
            Self::Transaction => "head_transaction",
            Self::V2Marker => "head_v2_marker",
            Self::V2Schema => "head_v2_schema",
            Self::V2WebhookKeysConflict => "head_v2_webhook_keys_conflict",
            Self::V2WebhookKeysUnreadable => "head_v2_webhook_keys_unreadable",
            Self::V2Readiness => "head_v2_readiness",
            Self::V2Coordinates => "head_v2_coordinates",
            Self::V2Origin => "head_v2_origin",
            Self::Contract => "head_contract",
            Self::Close => "head_close",
            Self::V1Head => "head_v1",
        }
    }
}

#[derive(Debug)]
pub struct ReleaseHeadObservationFailure {
    pub phase: ReleaseHeadObservationPhase,
    source: Error,
}

impl ReleaseHeadObservationFailure {
    pub fn into_error(self) -> Error {
        self.source
    }
}

/// Observe v2 coordinates in one read-only SQLite transaction, or delegate
/// to the historical v1 reader. Builds without v2 support continue to refuse
/// v2; recognition never opens a writable Db, repairs projections, or changes
/// an application marker. Caller owns writer custody across recognition.
pub async fn read_release_tenant_head_from_path(path: &Path) -> Result<ReleaseTenantHead> {
    read_release_tenant_head_diagnosed(path)
        .await
        .map_err(ReleaseHeadObservationFailure::into_error)
}

pub async fn read_release_tenant_head_diagnosed(
    path: &Path,
) -> std::result::Result<ReleaseTenantHead, ReleaseHeadObservationFailure> {
    #[cfg(any(test, feature = "v2-kernel-probe"))]
    {
        let mut phase = ReleaseHeadObservationPhase::Open;
        let observed = async {
            let options = SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false)
                .read_only(true)
                .busy_timeout(std::time::Duration::from_secs(5));
            let mut connection = SqliteConnection::connect_with(&options).await?;
            let result = async {
                phase = ReleaseHeadObservationPhase::Transaction;
                sqlx::query("PRAGMA query_only=ON")
                    .execute(&mut connection)
                    .await?;
                sqlx::query("BEGIN DEFERRED")
                    .execute(&mut connection)
                    .await?;
                if !super::kernel_v2::is_v2(&mut connection).await? {
                    return Ok(None);
                }
                let generation =
                    super::kernel_v2::release_coordinates(&mut connection, &mut phase).await?;
                phase = ReleaseHeadObservationPhase::V2Origin;
                let origin_database_id =
                    super::kernel_v2::origin(&mut connection, &generation).await?;
                let head = ReleaseTenantHead::KernelV2(KernelReleaseHead {
                    contract: "native.release-kernel-v2-head.v1".into(),
                    origin_database_id,
                    generation,
                });
                phase = ReleaseHeadObservationPhase::Contract;
                head.validate()?;
                Ok::<_, Error>(Some(head))
            }
            .await;
            // Preserve the first observation failure if closing also fails.
            let closed = connection.close().await;
            let head = result?;
            phase = ReleaseHeadObservationPhase::Close;
            closed?;
            Ok::<_, Error>(head)
        }
        .await;
        if let Some(head) =
            observed.map_err(|source| ReleaseHeadObservationFailure { phase, source })?
        {
            return Ok(head);
        }
    }
    read_release_act_head_from_path(path)
        .await
        .map(Into::into)
        .map_err(|source| ReleaseHeadObservationFailure {
            phase: ReleaseHeadObservationPhase::V1Head,
            source,
        })
}

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
        // Engine 94 adds receiver-local cancellation anchors; portable evidence
        // uses the existing control log, with no new interchange section.
        // Engine 93 adds a derived partial index only. Engine 92 adds only trigger-maintained folds (`content_event_heads`),
        // no interchange section. Engine 91 adds derived authorization counters and transaction-only
        // birth certification; canonical act inventories and wire remain 8.
        90..=94 => Ok(8),
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
    use super::*;

    #[test]
    fn release_current_schema_and_wire_pair_requires_explicit_qualification() {
        assert_eq!(crate::db::CURRENT_ENGINE_SCHEMA_VERSION, 94);
        assert_eq!(crate::interchange::REVISION, 8);
        assert_eq!(
            super::release_revision(94).unwrap(),
            crate::interchange::REVISION
        );
        assert_eq!(super::release_revision(93).unwrap(), 8);
        assert_eq!(super::release_revision(92).unwrap(), 8);
        assert_eq!(super::release_revision(91).unwrap(), 8);
        assert_eq!(super::release_revision(90).unwrap(), 8);
        assert!(
            super::release_revision(95).is_err(),
            "future schemas still require qualification"
        );
    }

    #[tokio::test]
    async fn release_94_qualifies_exact_shape_and_wire_without_admitting_future_or_drift() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("release.db");
        let db = crate::create_database(path.to_str().unwrap())
            .await
            .unwrap();
        db.close().await;
        let head = read_release_act_head_from_path(&path).await.unwrap();
        assert_eq!(head.source_engine_schema, 94);
        assert_eq!(head.native_interchange_revision, 8);
        head.validate().unwrap();
        let mut wrong_wire = head.clone();
        wrong_wire.native_interchange_revision = 7;
        assert!(validate_release_act_head(&wrong_wire).is_err());

        let options = SqliteConnectOptions::new().filename(&path);
        let mut conn = SqliteConnection::connect_with(&options).await.unwrap();
        for version in [93, 95] {
            sqlx::query(&format!("PRAGMA user_version={version}"))
                .execute(&mut conn)
                .await
                .unwrap();
            assert!(
                read_release_act_head_from_path(&path).await.is_err(),
                "a relabelled 94 shape must not qualify as {version}"
            );
        }
        sqlx::query("PRAGMA user_version=94")
            .execute(&mut conn)
            .await
            .unwrap();
        crate::schema::step_down::step_down(&mut conn, 93)
            .await
            .unwrap();
        let previous = read_release_act_head_from_path(&path).await.unwrap();
        assert_eq!(previous.source_engine_schema, 93);
        assert_eq!(previous.native_interchange_revision, 8);
        sqlx::query("DROP INDEX idx_records_unfiled_message_owner")
            .execute(&mut conn)
            .await
            .unwrap();
        assert!(
            read_release_act_head_from_path(&path).await.is_err(),
            "schema 93 still requires its frozen physical shape"
        );
        conn.close().await.unwrap();
    }
}

#[cfg(test)]
#[path = "release_head_v2_tests.rs"]
mod v2_tests;
