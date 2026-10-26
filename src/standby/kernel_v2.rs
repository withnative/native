//! Kernel-v2 generation coordinates. These never interpret the v1 frontier.
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const ENGINE: &str = "native-kernel-v2";
pub const MANIFEST: &str = "native.standby-snapshot-manifest.kernel-v2.v1";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGeneration {
    pub application_id: i64,
    pub genesis_event_id: String,
    pub content_event_seq: i64,
    pub meta_event_seq: i64,
    pub head_act: i64,
    pub schema_sha256: String,
    pub projection_tables: Vec<String>,
    pub blob_count: i64,
}

impl KernelGeneration {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.application_id != crate::db::V2_APPLICATION_ID
            || uuid::Uuid::parse_str(&self.genesis_event_id).is_err()
            || self.content_event_seq < 1
            || self.meta_event_seq < 0
            || self.head_act < 1
            || self.blob_count < 0
            || self.schema_sha256.len() != 64
            || !self
                .schema_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.projection_tables.is_empty()
            || !self.projection_tables.windows(2).all(|w| w[0] < w[1])
        {
            return Err(Error::engine("invalid kernel-v2 generation coordinates"));
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "v2-kernel-probe"))]
mod enabled {
    use super::*;
    use crate::standby_snapshot::*;
    use sqlx::{Connection, SqliteConnection};
    use std::path::Path;

    type SchemaInventory = Vec<(String, String, String, Option<String>)>;

    /// Shared account lookup. Absence is distinct from a database/read error so
    /// hosted member capture can refuse without inventing an authority loss.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) async fn account_on(
        conn: &mut SqliteConnection,
        binding: &str,
    ) -> Result<Option<(String, String)>> {
        Ok(sqlx::query_as(
            "SELECT auth_binding,principal_id FROM main.kernel_principals WHERE kind='account' AND auth_binding=?",
        ).bind(binding).fetch_optional(conn).await?)
    }

    /// One canonical account selection for verified v2 generations. Preserve
    /// the portable credential, never substitute the kernel principal UUID.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) async fn resolve_account_on(
        conn: &mut SqliteConnection,
        selected: Option<&str>,
    ) -> Result<(String, String)> {
        if let Some(binding) = selected {
            return account_on(conn, binding).await?.ok_or_else(|| {
                Error::engine("selected standby account has no kernel-v2 account auth_binding")
            });
        }
        let accounts: Vec<(String, String)> = sqlx::query_as(
            "SELECT auth_binding,principal_id FROM main.kernel_principals WHERE kind='account' ORDER BY auth_binding",
        ).fetch_all(conn).await?;
        if accounts.len() == 1 {
            Ok(accounts.into_iter().next().unwrap())
        } else {
            Err(Error::engine(
                "kernel-v2 standby requires an unambiguous account binding",
            ))
        }
    }

    pub(crate) async fn is_v2(conn: &mut SqliteConnection) -> Result<bool> {
        Ok(sqlx::query_scalar::<_, i64>("PRAGMA application_id")
            .fetch_one(conn)
            .await?
            == crate::db::V2_APPLICATION_ID)
    }

    async fn schema(conn: &mut SqliteConnection) -> Result<SchemaInventory> {
        let mut inventory: SchemaInventory = sqlx::query_as("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetch_all(conn).await?;
        // Hosted MCP writes lazily create this durable retry ledger. It is
        // neither canonical event history nor a kernel projection, so a v2
        // generation may contain it but delta folding does not reproduce it.
        // Check the exact compiled DDL before omitting it from the owned
        // projection schema and generation coordinates.
        if let Some(index) = inventory
            .iter()
            .position(|(_, name, _, _)| name == "kernel_mcp_write_receipts")
        {
            let entry = &inventory[index];
            if entry.0 != "table"
                || entry.2 != "kernel_mcp_write_receipts"
                || entry.3.as_deref()
                    != Some(
                        crate::kernel::MCP_WRITE_RECEIPTS_DDL
                            .replacen(" IF NOT EXISTS", "", 1)
                            .as_str(),
                    )
            {
                return Err(Error::engine(
                    "kernel-v2 MCP receipt schema differs from compiled adapter",
                ));
            }
            inventory.remove(index);
        }
        // This optional physical accelerator is absent from older generations.
        // Validate its exact definition before omitting it from compatibility
        // coordinates, preserving the pre-index schema hash across deltas.
        if let Some(index) = inventory
            .iter()
            .position(|(_, name, _, _)| name == "idx_kernel_realtime_authority")
        {
            let entry = &inventory[index];
            if entry.0 != "index"
                || entry.2 != "content_events"
                || entry.3.as_deref()
                    != Some(crate::kernel::notifications::REALTIME_AUTHORITY_INDEX)
            {
                return Err(Error::engine(
                    "kernel-v2 optional realtime index differs from compiled schema",
                ));
            }
            inventory.remove(index);
        }
        // Normalize only the exact admitted accelerator. Older N1 bases lack
        // it; both actual and expected inventories must keep their old hash.
        if let Some(index) = inventory
            .iter()
            .position(|(_, name, _, _)| name == "idx_kernel_named_view_admissions")
        {
            let entry = &inventory[index];
            if entry.0 != "index"
                || entry.2 != "content_events"
                || entry.3.as_deref()
                    != Some(
                        crate::kernel::NAMED_VIEW_EVENT_INDEX_DDL
                            .replacen(" IF NOT EXISTS", "", 1)
                            .as_str(),
                    )
            {
                return Err(Error::engine(
                    "kernel-v2 optional named-view index differs from compiled schema",
                ));
            }
            inventory.remove(index);
        }
        if let Some(index) = inventory
            .iter()
            .position(|(_, name, _, _)| name == "idx_kernel_named_view_lifecycle")
        {
            let entry = &inventory[index];
            if entry.0 != "index"
                || entry.2 != "content_events"
                || entry.3.as_deref()
                    != Some(
                        crate::named_views::INDEX_DDL
                            .replacen(" IF NOT EXISTS", "", 1)
                            .as_str(),
                    )
            {
                return Err(Error::engine(
                    "kernel-v2 optional lifecycle index differs from compiled schema",
                ));
            }
            inventory.remove(index);
        }
        Ok(inventory)
    }

    async fn expected_schema() -> Result<&'static SchemaInventory> {
        static SCHEMA: tokio::sync::OnceCell<SchemaInventory> = tokio::sync::OnceCell::const_new();
        SCHEMA
            .get_or_try_init(|| async {
                let (db, _) = crate::kernel::create_v2_database(
                    ":memory:",
                    "account",
                    "Schema reference",
                    "standby:schema-reference",
                )
                .await?;
                let result = schema(&mut *db.pool().acquire().await?).await;
                db.close().await;
                result
            })
            .await
    }

    pub(crate) async fn coordinates(conn: &mut SqliteConnection) -> Result<KernelGeneration> {
        if !is_v2(conn).await? {
            return Err(Error::engine(
                "kernel-v2 generation requires the NKV2 marker",
            ));
        }
        crate::kernel::verify_v2_ready_on(conn).await?;
        let actual = schema(conn).await?;
        if &actual != expected_schema().await? {
            return Err(Error::engine(
                "kernel-v2 generation schema differs from compiled owned schema",
            ));
        }
        let version: i64 = sqlx::query_scalar("PRAGMA user_version")
            .fetch_one(&mut *conn)
            .await?;
        if version != 0 {
            return Err(Error::engine(
                "kernel-v2 generation has a v1 schema version",
            ));
        }
        let genesis_event_id: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE seq=1 AND type='kernel.root_created.v1'",
        )
        .fetch_one(&mut *conn)
        .await?;
        let (content_event_seq,meta_event_seq,head_act,blob_count): (i64,i64,i64,i64) = sqlx::query_as("SELECT COALESCE((SELECT MAX(seq) FROM content_events),0),COALESCE((SELECT MAX(seq) FROM meta_events),0),(SELECT next_act FROM act_state WHERE singleton=1),(SELECT COUNT(*) FROM kernel_blobs)").fetch_one(&mut *conn).await?;
        let projection_tables = actual
            .iter()
            .filter(|(kind, name, _, _)| {
                kind == "table"
                    && ![
                        "content_events",
                        "meta_events",
                        "act_state",
                        "act_cutover",
                        "content_event_causal_frontier",
                        "content_event_causal_cutover",
                        "kernel_blobs",
                    ]
                    .contains(&name.as_str())
            })
            .map(|(_, name, _, _)| name.clone())
            .collect();
        let result = KernelGeneration {
            application_id: crate::db::V2_APPLICATION_ID,
            genesis_event_id,
            content_event_seq,
            meta_event_seq,
            head_act,
            blob_count,
            schema_sha256: sha256_bytes(&serde_jcs::to_vec(&actual)?),
            projection_tables,
        };
        result.validate()?;
        Ok(result)
    }

    pub(crate) async fn origin(
        conn: &mut SqliteConnection,
        generation: &KernelGeneration,
    ) -> Result<String> {
        // Imported HQ keeps its configured v1 origin. A native v2 workspace is
        // identified by its immutable genesis UUID, never by a pathname.
        let origins: Vec<String> = sqlx::query_scalar("SELECT DISTINCT json_extract(payload,'$.legacy.payload.source_origin') FROM content_events WHERE type='kernel.legacy_recorded.v1' AND json_extract(payload,'$.legacy.event_type')='v1.snapshot_provenance' AND json_extract(payload,'$.legacy.payload.source_origin') IS NOT NULL ORDER BY 1").fetch_all(conn).await?;
        match origins.as_slice() {
            [] => Ok(format!(
                "ndb_{}",
                uuid::Uuid::parse_str(&generation.genesis_event_id)
                    .map_err(|_| Error::engine("invalid v2 genesis"))?
                    .simple()
            )),
            [origin] if crate::identity::is_database_id(origin) => Ok(origin.clone()),
            _ => Err(Error::engine(
                "kernel-v2 generation has ambiguous source origins",
            )),
        }
    }

    pub(crate) async fn blob_inventory_path(path: &Path) -> Result<Vec<String>> {
        let mut conn = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .read_only(true),
        )
        .await?;
        let result =
            sqlx::query_scalar("SELECT sha256 FROM kernel_blobs ORDER BY sha256 LIMIT 65537")
                .fetch_all(&mut conn)
                .await;
        conn.close().await?;
        let inventory = result?;
        super::super::kernel_v2_delta::validate_blob_inventory(&inventory)?;
        Ok(inventory)
    }

    pub(crate) async fn verify_path(path: &Path) -> Result<KernelGeneration> {
        let mut conn = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false)
                .read_only(true),
        )
        .await?;
        let result = coordinates(&mut conn).await;
        conn.close().await?;
        result
    }

    pub(crate) async fn manifest(
        path: &Path,
        size_bytes: u64,
        sha256: String,
        captured_at: String,
        snapshot_completed_at: String,
        context: HostedStandbyManifestContext,
    ) -> Result<StandbySnapshotManifest> {
        let mut conn = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false)
                .read_only(true),
        )
        .await?;
        let kernel = coordinates(&mut conn).await?;
        let origin_database_id = origin(&mut conn, &kernel).await?;
        conn.close().await?;
        let manifest = StandbySnapshotManifest {
            contract: MANIFEST.into(),
            version: 1,
            hosted_route_database_id: context.hosted_route_database_id,
            origin_database_id,
            captured_at,
            snapshot_completed_at,
            engine: StandbySnapshotEngineIdentity {
                name: ENGINE.into(),
                source_sha: context.producer.source_sha,
                schema_version: 0,
                ddl_sha256: kernel.schema_sha256.clone(),
            },
            consumer: context.consumer,
            frontier: CanonicalFrontierV1 {
                contract: STANDBY_FRONTIER_CONTRACT.into(),
                version: 1,
                content_event_seq: 0,
                policy_event_seq: 0,
                awareness_event_seq: 0,
                notification_candidate_event_seq: 0,
                binding_audit_seq: 0,
                database_identity_audit_seq: 0,
                meta_event_seq: 0,
                control_event_seq: 0,
                derivation_event_seq: 0,
                relationship_event_seq: 0,
                authorization_revision_epoch: 0,
                storage_portability_policy_revision: 0,
            },
            head_act: Some(kernel.head_act),
            kernel_v2: Some(kernel),
            materialization: StandbyGenerationMaterialization::Snapshot,
            snapshot: StandbySnapshotBytes {
                media_type: STANDBY_SNAPSHOT_MEDIA_TYPE.into(),
                size_bytes,
                sha256,
            },
        };
        manifest.validate()?;
        Ok(manifest)
    }

    pub(crate) async fn validate_manifest(
        path: &Path,
        manifest: &StandbySnapshotManifest,
        advanced: bool,
    ) -> Result<()> {
        let mut conn = SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(false)
                .read_only(true),
        )
        .await?;
        let actual = coordinates(&mut conn).await?;
        let origin = origin(&mut conn, &actual).await?;
        conn.close().await?;
        let expected = manifest
            .kernel_v2
            .as_ref()
            .ok_or_else(|| Error::engine("v2 manifest lacks kernel coordinates"))?;
        let compatible = actual.genesis_event_id == expected.genesis_event_id
            && actual.schema_sha256 == expected.schema_sha256
            && actual.projection_tables == expected.projection_tables;
        if origin != manifest.origin_database_id
            || !compatible
            || if advanced {
                actual.head_act < expected.head_act
                    || actual.content_event_seq < expected.content_event_seq
                    || actual.meta_event_seq < expected.meta_event_seq
                    || actual.blob_count < expected.blob_count
            } else {
                actual != *expected
            }
        {
            return Err(Error::engine(
                "kernel-v2 manifest does not describe generation",
            ));
        }
        Ok(())
    }
}
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) use enabled::*;
