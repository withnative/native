//! Closed provenance contract for hosted snapshots accepted by a local standby.
//!
//! Scalar coordinates fence the sequenced canonical domains plus selected
//! policy revisions. They are necessary but not sufficient promotion
//! evidence: append-only domains without a global sequence require prefix
//! inclusion checks, and unfenced mutable substrate must remain equal unless a
//! conformance-checked authority proves how to rebuild it. Equal frontiers are
//! interchangeable only when the complete snapshot digest is identical.

use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection, Row};

use crate::error::{Error, Result};

pub const STANDBY_SNAPSHOT_MANIFEST_CONTRACT: &str = "native.standby-snapshot-manifest.v1";
pub const STANDBY_FRONTIER_CONTRACT: &str = "native.canonical-frontier.v1";
pub const STANDBY_CONSUMER_CONTRACT: &str = "native.standby-consumer.v1";
pub const STANDBY_SNAPSHOT_MEDIA_TYPE: &str = "application/vnd.sqlite3";

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandbyConsumerIdentity {
    pub contract: String,
    pub version: u32,
    pub platform: StandbyConsumerPlatform,
    pub source_sha: String,
    pub artifact_sha256: String,
    pub engine_schema_version: i64,
    pub ddl_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum StandbyConsumerPlatform {
    #[serde(rename = "linux-x86_64")]
    LinuxX8664,
}

/// Identity observed by the installer from the installed executable and its
/// build-info surface. This is evidence; the producer-side consumer value is
/// only a structurally validated declaration bound into the manifest.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedInstalledConsumerIdentity {
    pub platform: StandbyConsumerPlatform,
    pub source_sha: String,
    pub artifact_sha256: String,
    pub engine_schema_version: i64,
    pub ddl_sha256: String,
}

impl StandbyConsumerIdentity {
    pub fn validate_declaration(&self) -> Result<()> {
        if self.contract != STANDBY_CONSUMER_CONTRACT || self.version != 1 {
            return Err(Error::engine("unknown standby consumer contract"));
        }
        if !lowercase_hex(&self.source_sha, 40) {
            return Err(Error::engine(
                "standby consumer source_sha must be 40 lowercase hexadecimal characters",
            ));
        }
        if !lowercase_hex(&self.artifact_sha256, 64)
            || !lowercase_hex(&self.ddl_sha256, 64)
            || self.engine_schema_version <= 0
        {
            return Err(Error::engine("standby consumer declaration is invalid"));
        }
        Ok(())
    }

    pub fn validate_observed_installed(
        &self,
        observed: &ObservedInstalledConsumerIdentity,
    ) -> Result<()> {
        self.validate_declaration()?;
        if !lowercase_hex(&observed.source_sha, 40)
            || !lowercase_hex(&observed.artifact_sha256, 64)
            || !lowercase_hex(&observed.ddl_sha256, 64)
            || observed.engine_schema_version <= 0
        {
            return Err(Error::engine(
                "observed installed standby identity is invalid",
            ));
        }
        if self.platform != observed.platform
            || self.source_sha != observed.source_sha
            || self.artifact_sha256 != observed.artifact_sha256
            || self.engine_schema_version != observed.engine_schema_version
            || self.ddl_sha256 != observed.ddl_sha256
        {
            return Err(Error::engine(
                "installed standby does not match the manifest-bound consumer declaration",
            ));
        }
        Ok(())
    }
}

/// Closed scalar rollback fence for sequenced canonical domains and selected
/// policy revisions. Disposable operational bookkeeping is excluded.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalFrontierV1 {
    pub contract: String,
    pub version: u32,
    pub content_event_seq: i64,
    pub policy_event_seq: i64,
    pub awareness_event_seq: i64,
    pub notification_candidate_event_seq: i64,
    pub binding_audit_seq: i64,
    pub database_identity_audit_seq: i64,
    pub meta_event_seq: i64,
    pub control_event_seq: i64,
    pub derivation_event_seq: i64,
    pub relationship_event_seq: i64,
    pub authorization_revision_epoch: i64,
    pub storage_portability_policy_revision: i64,
}

impl CanonicalFrontierV1 {
    fn coordinates(&self) -> [i64; 12] {
        [
            self.content_event_seq,
            self.policy_event_seq,
            self.awareness_event_seq,
            self.notification_candidate_event_seq,
            self.binding_audit_seq,
            self.database_identity_audit_seq,
            self.meta_event_seq,
            self.control_event_seq,
            self.derivation_event_seq,
            self.relationship_event_seq,
            self.authorization_revision_epoch,
            self.storage_portability_policy_revision,
        ]
    }

    pub fn validate(&self) -> Result<()> {
        if self.contract != STANDBY_FRONTIER_CONTRACT || self.version != 1 {
            return Err(Error::engine("unknown canonical frontier contract"));
        }
        if self.coordinates().into_iter().any(|head| head < 0) {
            return Err(Error::engine(
                "canonical frontier coordinates must be nonnegative",
            ));
        }
        Ok(())
    }

    pub fn is_componentwise_non_regressing_from(&self, current: &Self) -> Result<bool> {
        self.validate()?;
        current.validate()?;
        Ok(self
            .coordinates()
            .into_iter()
            .zip(current.coordinates())
            .all(|(candidate, installed)| candidate >= installed))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandbySnapshotEngineIdentity {
    pub name: String,
    pub source_sha: String,
    pub schema_version: i64,
    pub ddl_sha256: String,
}

/// Producer build identity supplied by the hosting composition root. Release
/// builds use [`ProducerBuildIdentity::compiled`]; the explicit constructor is
/// also the deterministic integration-test seam and applies the same checks.
#[derive(Clone, Debug)]
pub struct ProducerBuildIdentity {
    source_sha: String,
    ddl_sha256: String,
}

impl ProducerBuildIdentity {
    pub fn new(source_sha: String, ddl_sha256: String) -> Result<Self> {
        if !lowercase_hex(&source_sha, 40) || !lowercase_hex(&ddl_sha256, 64) {
            return Err(Error::engine(
                "standby snapshot producer build identity is invalid",
            ));
        }
        Ok(Self {
            source_sha,
            ddl_sha256,
        })
    }

    pub fn compiled() -> Result<Self> {
        Self::new(
            crate::FULL_GIT_SHA.into(),
            crate::schema::FROZEN_DDL_SHA256.into(),
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandbySnapshotBytes {
    pub media_type: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StandbySnapshotManifest {
    pub contract: String,
    pub version: u32,
    pub hosted_route_database_id: String,
    pub origin_database_id: String,
    /// Conservative RPO time, sampled immediately before `VACUUM INTO`.
    pub captured_at: String,
    pub snapshot_completed_at: String,
    pub engine: StandbySnapshotEngineIdentity,
    pub consumer: StandbyConsumerIdentity,
    pub frontier: CanonicalFrontierV1,
    pub snapshot: StandbySnapshotBytes,
}

impl StandbySnapshotManifest {
    pub fn validate(&self) -> Result<()> {
        if self.contract != STANDBY_SNAPSHOT_MANIFEST_CONTRACT || self.version != 1 {
            return Err(Error::engine("unknown standby snapshot manifest contract"));
        }
        if self.hosted_route_database_id.trim().is_empty()
            || self.hosted_route_database_id.len() > 256
            || !crate::identity::is_database_id(&self.origin_database_id)
        {
            return Err(Error::engine(
                "standby snapshot database identity is invalid",
            ));
        }
        let captured = chrono::DateTime::parse_from_rfc3339(&self.captured_at)
            .map_err(|_| Error::engine("standby snapshot capture time is invalid"))?;
        let completed = chrono::DateTime::parse_from_rfc3339(&self.snapshot_completed_at)
            .map_err(|_| Error::engine("standby snapshot completion time is invalid"))?;
        if captured > completed {
            return Err(Error::engine(
                "standby snapshot capture time follows completion",
            ));
        }
        if self.engine.name != crate::ENGINE_NAME
            || !lowercase_hex(&self.engine.source_sha, 40)
            || self.engine.schema_version != crate::CURRENT_ENGINE_SCHEMA_VERSION
            || self.engine.ddl_sha256 != crate::schema::FROZEN_DDL_SHA256
        {
            return Err(Error::engine("standby snapshot engine identity is invalid"));
        }
        self.consumer.validate_declaration()?;
        if self.consumer.engine_schema_version != self.engine.schema_version
            || self.consumer.ddl_sha256 != self.engine.ddl_sha256
        {
            return Err(Error::engine(
                "standby consumer is not exactly schema-compatible with the snapshot",
            ));
        }
        self.frontier.validate()?;
        if self.snapshot.media_type != STANDBY_SNAPSHOT_MEDIA_TYPE
            || self.snapshot.size_bytes == 0
            || !lowercase_hex(&self.snapshot.sha256, 64)
        {
            return Err(Error::engine("standby snapshot byte identity is invalid"));
        }
        Ok(())
    }

    /// Scalar precheck for promotion. A true result still requires deep
    /// database proof: prefix inclusion for unsequenced append-only domains,
    /// governed projection validation, and the applicable rules for unfenced
    /// mutable state. Equal vectors with different snapshot bytes may represent
    /// a valid unsequenced provenance advance.
    pub fn is_safe_scalar_successor_of(&self, current: &Self) -> Result<bool> {
        self.validate()?;
        current.validate()?;
        if self.hosted_route_database_id != current.hosted_route_database_id
            || self.origin_database_id != current.origin_database_id
        {
            return Ok(false);
        }
        if !self
            .frontier
            .is_componentwise_non_regressing_from(&current.frontier)?
        {
            return Ok(false);
        }
        Ok(true)
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_jcs::to_vec(self).map_err(Into::into)
    }
}

#[derive(Clone, Debug)]
pub struct HostedStandbyManifestContext {
    pub hosted_route_database_id: String,
    pub consumer: StandbyConsumerIdentity,
    producer: ProducerBuildIdentity,
}

impl HostedStandbyManifestContext {
    pub fn new(
        hosted_route_database_id: String,
        consumer: StandbyConsumerIdentity,
    ) -> Result<Self> {
        Self::new_with_producer(
            hosted_route_database_id,
            consumer,
            ProducerBuildIdentity::compiled()?,
        )
    }

    #[doc(hidden)]
    pub fn new_with_producer(
        hosted_route_database_id: String,
        consumer: StandbyConsumerIdentity,
        producer: ProducerBuildIdentity,
    ) -> Result<Self> {
        if hosted_route_database_id.trim().is_empty() || hosted_route_database_id.len() > 256 {
            return Err(Error::engine(
                "standby snapshot hosted route database id is invalid",
            ));
        }
        consumer.validate_declaration()?;
        if consumer.engine_schema_version != crate::CURRENT_ENGINE_SCHEMA_VERSION
            || consumer.ddl_sha256 != producer.ddl_sha256
        {
            return Err(Error::engine(
                "standby consumer is not exactly schema-compatible with the producer",
            ));
        }
        Ok(Self {
            hosted_route_database_id,
            consumer,
            producer,
        })
    }
}

pub(crate) async fn manifest_from_completed_export(
    path: &Path,
    size_bytes: u64,
    sha256: String,
    captured_at: String,
    snapshot_completed_at: String,
    context: HostedStandbyManifestContext,
) -> Result<StandbySnapshotManifest> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(true)
        .immutable(true);
    let mut connection = sqlx::SqliteConnection::connect_with(&options).await?;
    let row = sqlx::query(
        "SELECT
         (SELECT origin_db_id FROM database_identity WHERE singleton=1) origin_database_id,
         (SELECT user_version FROM pragma_user_version) schema_version,
         COALESCE((SELECT MAX(seq) FROM content_events),0) content_event_seq,
         COALESCE((SELECT MAX(seq) FROM policy_events),0) policy_event_seq,
         COALESCE((SELECT MAX(seq) FROM awareness_events),0) awareness_event_seq,
         COALESCE((SELECT MAX(seq) FROM notification_candidate_events),0) notification_candidate_event_seq,
         COALESCE((SELECT MAX(seq) FROM binding_audit),0) binding_audit_seq,
         COALESCE((SELECT MAX(seq) FROM database_identity_audit),0) database_identity_audit_seq,
         COALESCE((SELECT MAX(seq) FROM meta_events),0) meta_event_seq,
         COALESCE((SELECT MAX(seq) FROM control_events),0) control_event_seq,
         COALESCE((SELECT MAX(seq) FROM derivation_events),0) derivation_event_seq,
         COALESCE((SELECT MAX(seq) FROM relationship_events),0) relationship_event_seq,
         COALESCE((SELECT epoch FROM authorization_revision WHERE id=1),0) authorization_revision_epoch,
         COALESCE((SELECT policy_revision FROM storage_portability_policy WHERE singleton=1),0) storage_portability_policy_revision",
    )
    .fetch_one(&mut connection)
    .await?;
    let schema_version: i64 = row.try_get("schema_version")?;
    let manifest = StandbySnapshotManifest {
        contract: STANDBY_SNAPSHOT_MANIFEST_CONTRACT.into(),
        version: 1,
        hosted_route_database_id: context.hosted_route_database_id,
        origin_database_id: row.try_get("origin_database_id")?,
        captured_at,
        snapshot_completed_at,
        engine: StandbySnapshotEngineIdentity {
            name: crate::ENGINE_NAME.into(),
            source_sha: context.producer.source_sha,
            schema_version,
            ddl_sha256: context.producer.ddl_sha256,
        },
        consumer: context.consumer,
        frontier: CanonicalFrontierV1 {
            contract: STANDBY_FRONTIER_CONTRACT.into(),
            version: 1,
            content_event_seq: row.try_get("content_event_seq")?,
            policy_event_seq: row.try_get("policy_event_seq")?,
            awareness_event_seq: row.try_get("awareness_event_seq")?,
            notification_candidate_event_seq: row.try_get("notification_candidate_event_seq")?,
            binding_audit_seq: row.try_get("binding_audit_seq")?,
            database_identity_audit_seq: row.try_get("database_identity_audit_seq")?,
            meta_event_seq: row.try_get("meta_event_seq")?,
            control_event_seq: row.try_get("control_event_seq")?,
            derivation_event_seq: row.try_get("derivation_event_seq")?,
            relationship_event_seq: row.try_get("relationship_event_seq")?,
            authorization_revision_epoch: row.try_get("authorization_revision_epoch")?,
            storage_portability_policy_revision: row
                .try_get("storage_portability_policy_revision")?,
        },
        snapshot: StandbySnapshotBytes {
            media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
            size_bytes,
            sha256,
        },
    };
    connection.close().await?;
    manifest.validate()?;
    Ok(manifest)
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Recompute every database-owned manifest field from the staged image.
pub(crate) async fn validate_completed_export_manifest(
    path: &Path,
    manifest: &StandbySnapshotManifest,
) -> Result<()> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(true);
    let mut connection = sqlx::SqliteConnection::connect_with(&options).await?;
    let row = sqlx::query("SELECT
      (SELECT origin_db_id FROM database_identity WHERE singleton=1) origin_database_id,
      (SELECT user_version FROM pragma_user_version) schema_version,
      COALESCE((SELECT MAX(seq) FROM content_events),0) content_event_seq,
      COALESCE((SELECT MAX(seq) FROM policy_events),0) policy_event_seq,
      COALESCE((SELECT MAX(seq) FROM awareness_events),0) awareness_event_seq,
      COALESCE((SELECT MAX(seq) FROM notification_candidate_events),0) notification_candidate_event_seq,
      COALESCE((SELECT MAX(seq) FROM binding_audit),0) binding_audit_seq,
      COALESCE((SELECT MAX(seq) FROM database_identity_audit),0) database_identity_audit_seq,
      COALESCE((SELECT MAX(seq) FROM meta_events),0) meta_event_seq,
      COALESCE((SELECT MAX(seq) FROM control_events),0) control_event_seq,
      COALESCE((SELECT MAX(seq) FROM derivation_events),0) derivation_event_seq,
      COALESCE((SELECT MAX(seq) FROM relationship_events),0) relationship_event_seq,
      COALESCE((SELECT epoch FROM authorization_revision WHERE id=1),0) authorization_revision_epoch,
      COALESCE((SELECT policy_revision FROM storage_portability_policy WHERE singleton=1),0) storage_portability_policy_revision").fetch_one(&mut connection).await?;
    let f = &manifest.frontier;
    let matches = manifest.origin_database_id == row.try_get::<String, _>("origin_database_id")?
        && manifest.engine.schema_version == row.try_get::<i64, _>("schema_version")?
        && f.content_event_seq == row.try_get::<i64, _>("content_event_seq")?
        && f.policy_event_seq == row.try_get::<i64, _>("policy_event_seq")?
        && f.awareness_event_seq == row.try_get::<i64, _>("awareness_event_seq")?
        && f.notification_candidate_event_seq
            == row.try_get::<i64, _>("notification_candidate_event_seq")?
        && f.binding_audit_seq == row.try_get::<i64, _>("binding_audit_seq")?
        && f.database_identity_audit_seq == row.try_get::<i64, _>("database_identity_audit_seq")?
        && f.meta_event_seq == row.try_get::<i64, _>("meta_event_seq")?
        && f.control_event_seq == row.try_get::<i64, _>("control_event_seq")?
        && f.derivation_event_seq == row.try_get::<i64, _>("derivation_event_seq")?
        && f.relationship_event_seq == row.try_get::<i64, _>("relationship_event_seq")?
        && f.authorization_revision_epoch
            == row.try_get::<i64, _>("authorization_revision_epoch")?
        && f.storage_portability_policy_revision
            == row.try_get::<i64, _>("storage_portability_policy_revision")?;
    connection.close().await?;
    if !matches {
        return Err(Error::engine(
            "standby manifest does not describe staged snapshot",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frontier(value: i64) -> CanonicalFrontierV1 {
        CanonicalFrontierV1 {
            contract: STANDBY_FRONTIER_CONTRACT.into(),
            version: 1,
            content_event_seq: value,
            policy_event_seq: value,
            awareness_event_seq: value,
            notification_candidate_event_seq: value,
            binding_audit_seq: value,
            database_identity_audit_seq: value,
            meta_event_seq: value,
            control_event_seq: value,
            derivation_event_seq: value,
            relationship_event_seq: value,
            authorization_revision_epoch: value,
            storage_portability_policy_revision: value,
        }
    }

    fn manifest(frontier_value: i64, digest: char) -> StandbySnapshotManifest {
        StandbySnapshotManifest {
            contract: STANDBY_SNAPSHOT_MANIFEST_CONTRACT.into(),
            version: 1,
            hosted_route_database_id: "route-1".into(),
            origin_database_id: "ndb_0123456789abcdef0123456789abcdef".into(),
            captured_at: "2026-09-01T00:00:00Z".into(),
            snapshot_completed_at: "2026-09-01T00:00:01Z".into(),
            engine: StandbySnapshotEngineIdentity {
                name: crate::ENGINE_NAME.into(),
                source_sha: "a".repeat(40),
                schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
                ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
            },
            consumer: StandbyConsumerIdentity {
                contract: STANDBY_CONSUMER_CONTRACT.into(),
                version: 1,
                platform: StandbyConsumerPlatform::LinuxX8664,
                source_sha: "b".repeat(40),
                artifact_sha256: "c".repeat(64),
                engine_schema_version: crate::CURRENT_ENGINE_SCHEMA_VERSION,
                ddl_sha256: crate::schema::FROZEN_DDL_SHA256.into(),
            },
            frontier: frontier(frontier_value),
            snapshot: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
                size_bytes: 1,
                sha256: digest.to_string().repeat(64),
            },
        }
    }

    #[test]
    fn every_scalar_coordinate_blocks_rollback() {
        let current = frontier(2);
        let value = serde_json::to_value(frontier(3)).unwrap();
        for field in [
            "content_event_seq",
            "policy_event_seq",
            "awareness_event_seq",
            "notification_candidate_event_seq",
            "binding_audit_seq",
            "database_identity_audit_seq",
            "meta_event_seq",
            "control_event_seq",
            "derivation_event_seq",
            "relationship_event_seq",
            "authorization_revision_epoch",
            "storage_portability_policy_revision",
        ] {
            let mut candidate: CanonicalFrontierV1 = serde_json::from_value(value.clone()).unwrap();
            match field {
                "content_event_seq" => candidate.content_event_seq = 1,
                "policy_event_seq" => candidate.policy_event_seq = 1,
                "awareness_event_seq" => candidate.awareness_event_seq = 1,
                "notification_candidate_event_seq" => {
                    candidate.notification_candidate_event_seq = 1
                }
                "binding_audit_seq" => candidate.binding_audit_seq = 1,
                "database_identity_audit_seq" => candidate.database_identity_audit_seq = 1,
                "meta_event_seq" => candidate.meta_event_seq = 1,
                "control_event_seq" => candidate.control_event_seq = 1,
                "derivation_event_seq" => candidate.derivation_event_seq = 1,
                "relationship_event_seq" => candidate.relationship_event_seq = 1,
                "authorization_revision_epoch" => candidate.authorization_revision_epoch = 1,
                "storage_portability_policy_revision" => {
                    candidate.storage_portability_policy_revision = 1
                }
                _ => unreachable!(),
            }
            assert!(
                !candidate
                    .is_componentwise_non_regressing_from(&current)
                    .unwrap(),
                "{field}"
            );
        }

        let mut unknown = serde_json::to_value(frontier(3)).unwrap();
        unknown["future_coordinate"] = serde_json::json!(3);
        assert!(serde_json::from_value::<CanonicalFrontierV1>(unknown).is_err());
        let mut wrong_version = frontier(3);
        wrong_version.version = 2;
        assert!(wrong_version.validate().is_err());
    }

    #[test]
    fn installed_consumer_validation_is_exact() {
        let declaration = StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.into(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            engine_schema_version: 45,
            ddl_sha256: "c".repeat(64),
        };
        let mut observed = ObservedInstalledConsumerIdentity {
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "a".repeat(40),
            artifact_sha256: "b".repeat(64),
            engine_schema_version: 45,
            ddl_sha256: "c".repeat(64),
        };
        declaration.validate_observed_installed(&observed).unwrap();
        observed.artifact_sha256 = "d".repeat(64);
        assert!(declaration.validate_observed_installed(&observed).is_err());
        observed.artifact_sha256 = "b".repeat(64);
        observed.engine_schema_version += 1;
        assert!(declaration.validate_observed_installed(&observed).is_err());
    }

    #[test]
    fn scalar_successor_preserves_identity_and_componentwise_non_regression() {
        let current = manifest(2, 'd');
        assert!(manifest(2, 'd')
            .is_safe_scalar_successor_of(&current)
            .unwrap());
        assert!(manifest(2, 'e')
            .is_safe_scalar_successor_of(&current)
            .unwrap());
        assert!(manifest(3, 'e')
            .is_safe_scalar_successor_of(&current)
            .unwrap());

        let mut wrong_route = manifest(3, 'e');
        wrong_route.hosted_route_database_id = "route-2".into();
        assert!(!wrong_route.is_safe_scalar_successor_of(&current).unwrap());
        let mut wrong_origin = manifest(3, 'e');
        wrong_origin.origin_database_id = "ndb_abcdef0123456789abcdef0123456789".into();
        assert!(!wrong_origin.is_safe_scalar_successor_of(&current).unwrap());
    }
}
