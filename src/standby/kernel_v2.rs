//! Kernel-v2 generation coordinates. These never interpret the v1 frontier.
use serde::{Deserialize, Serialize};

use crate::{Error, Result};

pub const ENGINE: &str = "native-kernel-v2";
pub const MANIFEST: &str = "native.standby-snapshot-manifest.kernel-v2.v1";

/// Bump for incompatible read semantics, independently of the manifest contract.
pub const KERNEL_V2_READER_FORMAT: u32 = 1;

// Release-only source floor v1, qualified against the owned DDL at
// 793c3280fdf341212f8b59812a8bd70785ed104b before the three webhook indexes
// added by a9c61e4d6. Hash serde_jcs of the normalized inventory ordered by
// type/name. This identity grants no receiver admission or serving.
// Never derive this floor by subtracting objects from a future candidate.
pub(crate) const RELEASE_PRE_WEBHOOK_SOURCE_V1_SCHEMA_SHA256: &str =
    "1f20a9c2c8b1f3b0b250648349b34447586861a39568ceb2c16f67d0c035eadd";
/// Omitted coordinates always mean this historical format, never the current one.
pub const INITIAL_READER_FORMAT: u32 = 1;
pub const INITIAL_READER_SCHEMA_SHA256: &str =
    "0295db140abe29a6c4c2dce429e325eb37d1235031a6d1068d2df561e8618da7";
pub const KERNEL_V2_READER_SCHEMA_SHA256: &str = INITIAL_READER_SCHEMA_SHA256;

pub(crate) fn initial_reader_format() -> u32 {
    INITIAL_READER_FORMAT
}
pub(crate) fn is_initial_reader_format(value: &u32) -> bool {
    *value == INITIAL_READER_FORMAT
}

/// Consumer-declared v2 format. The initial value is omitted on the wire so
/// pre-coordinate nodes and hosted readers keep accepting the same JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelV2Reader {
    pub schema_sha256: String,
    pub reader_format: u32,
}

impl Default for KernelV2Reader {
    fn default() -> Self {
        Self {
            schema_sha256: INITIAL_READER_SCHEMA_SHA256.into(),
            reader_format: INITIAL_READER_FORMAT,
        }
    }
}

impl KernelV2Reader {
    pub fn compiled() -> Self {
        Self {
            schema_sha256: KERNEL_V2_READER_SCHEMA_SHA256.into(),
            reader_format: KERNEL_V2_READER_FORMAT,
        }
    }

    pub fn is_initial(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelGeneration {
    #[serde(
        default = "initial_reader_format",
        skip_serializing_if = "is_initial_reader_format"
    )]
    pub reader_format: u32,
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
        self.validate_shape()?;
        if crate::standby::shapes::v2(self.reader_format, &self.schema_sha256).is_none() {
            return Err(Error::engine(crate::standby::shapes::UNSUPPORTED));
        }
        Ok(())
    }

    /// Structural evidence only, used for replacement and qualified release
    /// observations. This alone grants no receiver admission or serving.
    pub(crate) fn validate_shape(&self) -> Result<()> {
        if self.reader_format == 0
            || self.application_id != crate::db::V2_APPLICATION_ID
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

    // Source identity alone cannot establish that this preparer still reaches
    // a future candidate's ready shape. Bind both ends of the transition.
    pub(crate) const RELEASE_PRE_WEBHOOK_SOURCE_V1_TARGET_SCHEMA_SHA256: &str =
        "0295db140abe29a6c4c2dce429e325eb37d1235031a6d1068d2df561e8618da7";
    const RELEASE_PRE_WEBHOOK_SOURCE_V1_INDEXES: [(&str, &str); 3] = [
        ("idx_kernel_webhook_events", "CREATE INDEX IF NOT EXISTS idx_kernel_webhook_events ON content_events(record_id,type,seq) WHERE type GLOB 'kernel.webhook_*'"),
        ("idx_kernel_webhook_configuration", "CREATE UNIQUE INDEX IF NOT EXISTS idx_kernel_webhook_configuration ON content_events(record_id) WHERE type='kernel.webhook_configured.v1'"),
        ("idx_kernel_webhook_accepted_key", "CREATE UNIQUE INDEX IF NOT EXISTS idx_kernel_webhook_accepted_key ON content_events(record_id,json_extract(payload,'$.submission_key')) WHERE type='kernel.webhook_accepted.v1'"),
    ];

    /// Only this observer can construct the witness, after the frozen hash
    /// and DDL checks. The non-serving readiness helper cannot be called
    /// without that qualification and never returns the witness to a caller.
    pub(crate) struct QualifiedPreWebhookSourceV1(());

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
        let inventory: SchemaInventory = sqlx::query_as("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetch_all(&mut *conn).await?;
        #[cfg(feature = "v2-kernel-probe")]
        let inventory = {
            let mut inventory = inventory;
            let private = crate::kernel::working_undo::certification_objects(conn).await?;
            inventory.retain(|(kind, name, table, sql)| {
                !private.iter().any(|p| {
                    kind == &p.0
                        && name == &p.1
                        && table == &p.2
                        && sql.as_deref() == Some(p.3.as_str())
                })
            });
            inventory
        };
        normalize_native_inventory(inventory)
    }

    // Shared exact compatibility normalization. Private W removes its own
    // separately checked closure BEFORE entering here; accepted admission is
    // unchanged and still refuses occupied private state.
    fn normalize_native_inventory(mut inventory: SchemaInventory) -> Result<SchemaInventory> {
        // Derived access-epoch accelerator (Native b171a9d): exact-name
        // exclusion only, so it never enters the certified schema; any other
        // object, including unknown ones, stays visible.
        inventory.retain(|(kind, name, _, _)| {
            !(kind == "table" && name == crate::kernel::access_fence::ACCESS_EPOCH_TABLE)
        });
        // SQL event staging is a disposable local cache. Neither its schema
        // nor its progress participates in generation/replication coordinates.
        inventory.retain(|object| {
            !crate::kernel::sql_event_projection::certification_object(object)
                && !crate::kernel::sql_record_projection::certification_object(object)
        });
        // Stored visibility marking objects are local accelerators: exempt by
        // exact type, name, table and DDL only (73ad275 C1). A drifted or
        // unknown `p_*` object stays in the inventory and fails certification.
        inventory.retain(|object| !crate::kernel::stored_visibility::certification_object(object));
        // Older files created the retry ledger lazily. Preserve the admitted
        // compatibility schema floor after checking its exact DDL. Its rows
        // are now event-rebuilt and certified by the projection digests and
        // the separate projection_tables inventory below.
        if let Some(index) = inventory
            .iter()
            .position(|(_, name, _, _)| name == "kernel_mcp_write_receipts")
        {
            let entry = &inventory[index];
            let compiled =
                crate::kernel::MCP_TYPED_WRITE_RECEIPTS_DDL.replacen(" IF NOT EXISTS", "", 1);
            let legacy="CREATE TABLE kernel_mcp_write_receipts (principal_id TEXT NOT NULL, operation TEXT NOT NULL, operation_key TEXT NOT NULL, request_json TEXT NOT NULL, receipt_json TEXT NOT NULL, PRIMARY KEY(principal_id,operation,operation_key))";
            if entry.0 != "table" || entry.2 != "kernel_mcp_write_receipts" {
                return Err(Error::engine("invalid keyed outcome table identity"));
            }
            if entry.3.as_deref() == Some(legacy) {
                inventory.remove(index);
            } else if entry.3.as_deref() != Some(compiled.as_str()) {
                return Err(Error::engine("kernel-v2 keyed outcome schema differs"));
            }
            // Typed table stays in the format2 exact owned inventory.
        }
        if let Some(index) = inventory
            .iter()
            .position(|(_, name, _, _)| name == crate::kernel::mcp_write_receipts::INDEX)
        {
            let entry = &inventory[index];
            if entry.0 != "index"
                || entry.2 != "content_events"
                || entry.3.as_deref()
                    != Some(
                        crate::kernel::mcp_write_receipts::INDEX_DDL
                            .replacen(" IF NOT EXISTS", "", 1)
                            .as_str(),
                    )
            {
                return Err(Error::engine(
                    "kernel-v2 keyed outcome index differs from compiled adapter",
                ));
            }
            inventory.remove(index);
        }
        // A standby copy advanced in place records its apply receipts here, in
        // the fold's own transaction. Local bookkeeping: permitted with either
        // exact compiled DDL (the second adds the set digest), not part of the
        // generation's coordinates. Likewise the optional accumulator cache.
        let local = crate::standby::generation_store::kernel_in_place::RECEIPTS_TABLE;
        let accumulator = crate::standby::generation_store::kernel_in_place::ACCUMULATOR_TABLE;
        for (table, accepted) in [
            (
                local,
                &[
                    crate::standby::generation_store::kernel_in_place::RECEIPTS_DDL,
                    crate::standby::generation_store::kernel_in_place::RECEIPTS_DDL_V2,
                ][..],
            ),
            (
                accumulator,
                &[crate::standby::generation_store::kernel_in_place::ACCUMULATOR_DDL][..],
            ),
        ] {
            if let Some(index) = inventory.iter().position(|(_, name, _, _)| name == table) {
                let entry = &inventory[index];
                if entry.0 != "table"
                    || entry.2 != table
                    || !entry
                        .3
                        .as_deref()
                        .is_some_and(|sql| accepted.contains(&sql))
                {
                    return Err(Error::engine(
                        "kernel-v2 local bookkeeping schema differs from compiled adapter",
                    ));
                }
                inventory.remove(index);
            }
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
                || !entry.3.as_deref().is_some_and(|sql| {
                    [
                        crate::kernel::notifications::REALTIME_AUTHORITY_INDEX,
                        crate::kernel::notifications::REALTIME_AUTHORITY_INDEX_V1,
                        crate::kernel::notifications::REALTIME_AUTHORITY_INDEX_V2,
                    ]
                    .contains(&sql)
                })
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
        // These physical candidate accelerators do not change logical
        // generation coordinates. Normalize only their exact compiled DDL;
        // serving and release readiness still require both indexes, including
        // the narrowly qualified pre-webhook preparation path.
        //
        // The four optional link endpoint indexes are also physical-only.
        // Older generations keep their hash across explicit preparation.
        // A same-name index with different keys or predicates still refuses
        // standby certification.
        for (name, table, expected) in [
            (
                "idx_kernel_app_write_ordinal",
                "content_events",
                crate::standby::shapes::APP_INDEX,
            ),
            (
                "idx_kernel_record_names",
                "kernel_record_fields",
                crate::kernel::record_metadata::NAME_LOOKUP_INDEX,
            ),
            (
                "idx_kernel_record_logical_homes",
                "content_events",
                crate::kernel::record_metadata::LOGICAL_HOME_LOOKUP_INDEX,
            ),
            (
                "idx_kernel_link4_edges_source",
                "kernel_link4_edges",
                crate::kernel::LINK4_SOURCE_INDEX,
            ),
            (
                "idx_kernel_link4_edges_target",
                "kernel_link4_edges",
                crate::kernel::LINK4_TARGET_INDEX,
            ),
            (
                "idx_kernel_provider_link_rows_source",
                "kernel_provider_link_rows",
                crate::kernel::provider_link_reads::LINK_ROWS_SOURCE_INDEX,
            ),
            (
                "idx_kernel_provider_link_rows_target",
                "kernel_provider_link_rows",
                crate::kernel::provider_link_reads::LINK_ROWS_TARGET_INDEX,
            ),
        ] {
            if let Some(index) = inventory
                .iter()
                .position(|(_, actual, _, _)| actual == name)
            {
                let entry = &inventory[index];
                // SQLite stores the canonical CREATE statement without IF
                // NOT EXISTS; strip it before comparing with the executable
                // DDL the same way serving readiness does.
                let canonical = expected.replacen(" IF NOT EXISTS", "", 1);
                if entry.0 != "index"
                    || entry.2 != table
                    || entry.3.as_deref() != Some(canonical.as_str())
                {
                    return Err(Error::engine(format!(
                        "kernel-v2 lookup index {name} differs from compiled schema"
                    )));
                }
                inventory.remove(index);
            }
        }
        Ok(inventory)
    }

    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) async fn working_undo_schema_inventory(
        conn: &mut SqliteConnection,
    ) -> Result<SchemaInventory> {
        schema(conn).await
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
        crate::kernel::mcp_write_receipts::require_profile_on(conn).await?;
        crate::kernel::verify_v2_ready_on(conn).await?;
        let actual = schema(conn).await?;
        let entry = owned_shape(&actual)?.ok_or_else(|| {
            Error::engine("kernel-v2 generation schema differs from compiled owned schema")
        })?;
        require_shape_readiness(conn, entry).await?;
        let generation = coordinates_from_owned_schema(conn, actual).await?;
        generation.validate()?;
        Ok(generation)
    }

    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) async fn outcome_native_entry_on(
        conn: &mut SqliteConnection,
    ) -> Result<&'static crate::standby::shapes::Entry> {
        if !is_v2(conn).await? {
            return Err(Error::engine("outcome wrong engine"));
        }
        super::super::super::kernel::verify_v2_ready_on(conn).await?;
        let actual = schema(conn).await?;
        let entry = owned_shape(&actual)?
            .ok_or_else(|| Error::engine("outcome native inventory unsupported"))?;
        require_shape_readiness(conn, entry).await?;
        Ok(entry)
    }

    async fn require_shape_readiness(
        conn: &mut SqliteConnection,
        entry: &crate::standby::shapes::Entry,
    ) -> Result<()> {
        for ddl in entry.required_indexes {
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='index' AND sql=?)",
            )
            .bind(ddl)
            .fetch_one(&mut *conn)
            .await?;
            if !present {
                return Err(Error::engine(
                    "receiver shape requires its exact declared index",
                ));
            }
        }
        for (table, columns) in entry.nullable_prefix_columns {
            for column in *columns {
                let nullable: bool = sqlx::query_scalar(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?) WHERE name=? AND \"notnull\"=0 AND dflt_value IS NULL)"
                ).bind(table).bind(column).fetch_one(&mut *conn).await?;
                if !nullable {
                    return Err(Error::engine(
                        "receiver shape requires its declared nullable column",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Fresh native schema provenance for private W. No caller can supply an
    /// ignored-object list or convert this into accepted verification. Mint
    /// BEFORE private DDL on the verified copy; every use rechecks the entire
    /// exact closure against the same physical collector inside a real Tx.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) struct WorkingKernelSchema {
        raw_native: SchemaInventory,
        owned_native: SchemaInventory,
    }
    #[cfg(feature = "v2-kernel-probe")]
    impl WorkingKernelSchema {
        pub(crate) async fn from_fresh_native(conn: &mut SqliteConnection) -> Result<Self> {
            use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
            let private:i64=sqlx::query_scalar("SELECT count(*) FROM main.sqlite_schema WHERE name IN ('working_undo','working_undo_control','working_undo_boundaries','_native_working_publication','_native_working_applied','_native_working_bases')").fetch_one(&mut *conn).await?;
            if private != 0 || SqliteTransactionManager::get_transaction_depth(conn) != 1 {
                return Err(Error::engine(
                    "working native schema must be captured in its fresh top-level transaction",
                ));
            }
            let _native = coordinates(conn).await?;
            let raw_native=sqlx::query_as("SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetch_all(&mut *conn).await?;
            Ok(Self {
                raw_native,
                owned_native: schema(conn).await?,
            })
        }
        pub(crate) async fn from_retained_native(
            verified: &Self,
            conn: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
            collector: &crate::kernel::working_undo::Collector,
        ) -> Result<Self> {
            let private = crate::kernel::working_undo::with_handle(conn, |raw| {
                collector
                    .check(raw)
                    .map_err(|e| Error::engine(e.to_string()))?;
                Ok(collector.private_objects())
            })
            .await?;
            let mut closure = private;
            closure.extend(
                crate::kernel::working_undo_schema::WORKING_METADATA
                    .into_iter()
                    .map(|(name, ddl)| {
                        ("table".into(), name.into(), name.into(), Some(ddl.into()))
                    }),
            );
            let actual:SchemaInventory=sqlx::query_as("SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetch_all(&mut **conn).await?;
            if closure.iter().any(|row| !actual.contains(row)) {
                return Err(Error::engine("retained private closure differs"));
            }
            let raw_native = actual
                .into_iter()
                .filter(|row| !closure.contains(row))
                .collect::<SchemaInventory>();
            let owned_native = normalize_native_inventory(raw_native.clone())?;
            if owned_native != verified.owned_native {
                return Err(Error::engine(
                    "retained native schema differs from verified owner",
                ));
            }
            let result = Self {
                raw_native,
                owned_native,
            };
            // Retained capture is still populated here. Admit only its exact
            // owned inventory; undo/compare below proves the grounded cut.
            if !is_v2(conn).await? {
                return Err(Error::engine("retained working inventory needs NKV2"));
            }
            result
                .require_exact_outcome_inventory_on(conn, collector)
                .await
                .map_err(|error| Error::engine(error.code()))?;
            Ok(result)
        }
        /// Profile-only validation on the actual owned writer, including active
        /// populated capture. This grants no coordinate/content authority.
        pub(crate) async fn require_exact_outcome_inventory_on(
            &self,
            tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
            collector: &crate::kernel::working_undo::Collector,
        ) -> std::result::Result<
            &'static crate::standby::shapes::Entry,
            crate::kernel::original_settlement::outcome_profile::OutcomeProfileError,
        > {
            use crate::kernel::original_settlement::outcome_profile::OutcomeProfileError as E;
            use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
            if SqliteTransactionManager::get_transaction_depth(tx) != 1 {
                return Err(E::TransactionRequired);
            }
            let private = crate::kernel::working_undo::with_handle(tx, |raw| {
                collector
                    .check(raw)
                    .map_err(|_| Error::engine("outcome owner mismatch"))?;
                Ok(collector.private_objects())
            })
            .await
            .map_err(|_| E::OwnerMismatch)?;
            let mut expected = self.raw_native.clone();
            expected.extend(
                crate::kernel::working_undo_schema::WORKING_METADATA
                    .into_iter()
                    .map(|(name, ddl)| {
                        ("table".into(), name.into(), name.into(), Some(ddl.into()))
                    }),
            );
            expected.extend(private);
            expected.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
            let actual:SchemaInventory=sqlx::query_as("SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetch_all(&mut **tx).await.map_err(|source|E::Storage{source})?;
            if actual != expected {
                return Err(E::OwnerMismatch);
            }
            let safe: bool = sqlx::query_scalar(
                "SELECT available=1 FROM main.working_undo_control WHERE singleton=1",
            )
            .fetch_one(&mut **tx)
            .await
            .map_err(|source| E::Storage { source })?;
            if !safe {
                return Err(E::CaptureUnavailable);
            }
            owned_shape(&self.owned_native)
                .map_err(|_| E::UnsupportedNativeInventory)?
                .ok_or(E::UnsupportedNativeInventory)
        }

        /// Restart-only native content audit. Source is a pinned RO snapshot
        /// of the fresh verified serving lease; W has had its entire captured
        /// speculative tail removed in its actual owner transaction. This is
        /// private admission, never a certificate or a delta producer.
        pub(crate) async fn same_native_contents_on(
            &self,
            working: &mut SqliteConnection,
            source: &mut SqliteConnection,
            collector: &crate::kernel::working_undo::Collector,
        ) -> Result<()> {
            if self.coordinates_on(working, collector).await? != coordinates(source).await? {
                return Err(Error::engine(
                    "retained working native cut differs from verified source",
                ));
            }
            let source_schema:SchemaInventory=sqlx::query_as("SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")
                .fetch_all(&mut *source).await?;
            if normalize_native_inventory(source_schema)? != self.owned_native {
                return Err(Error::engine("verified source native inventory changed"));
            }
            const AUTHORITY_AND_BLOBS: &[&str] = &[
                "content_events",
                "meta_events",
                "act_state",
                "act_cutover",
                "content_event_causal_frontier",
                "content_event_causal_cutover",
                "content_event_heads",
                "kernel_blobs",
            ];
            for (kind, name, _, _) in &self.raw_native {
                if kind != "table"
                    || (!AUTHORITY_AND_BLOBS.contains(&name.as_str())
                        && !crate::kernel::projection_dump::included_in_projection(true, name))
                {
                    continue;
                }
                let quoted = format!("\"{}\"", name.replace('"', "\"\""));
                type NativeColumn = (i64, String, String, i64, Option<String>, i64);
                let columns: Vec<NativeColumn> =
                    sqlx::query_as(&format!("PRAGMA main.table_info({quoted})"))
                        .fetch_all(&mut *source)
                        .await?;
                let mut keys = columns.iter().filter(|c| c.5 > 0).collect::<Vec<_>>();
                keys.sort_by_key(|c| c.5);
                if keys.is_empty() {
                    keys = columns.iter().collect();
                }
                let order = keys
                    .iter()
                    .map(|c| format!("\"{}\"", c.1.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join(",");
                let sql = format!("SELECT * FROM main.{quoted} ORDER BY {order}");
                let expected = crate::kernel::projection_dump::digest_rows(
                    source,
                    name,
                    &sql,
                    &[],
                    columns.len(),
                )
                .await?;
                let actual = crate::kernel::projection_dump::digest_rows(
                    working,
                    name,
                    &sql,
                    &[],
                    columns.len(),
                )
                .await?;
                if actual != expected {
                    return Err(Error::engine(format!(
                        "retained working native table mismatch: {name}"
                    )));
                }
            }
            Ok(())
        }
        pub(crate) async fn coordinates_on(
            &self,
            conn: &mut SqliteConnection,
            collector: &crate::kernel::working_undo::Collector,
        ) -> Result<KernelGeneration> {
            use sqlx::{sqlite::SqliteTransactionManager, TransactionManager};
            if SqliteTransactionManager::get_transaction_depth(conn) != 1 || !is_v2(conn).await? {
                return Err(Error::engine(
                    "working native coordinates need their top-level NKV2 transaction",
                ));
            }
            let private = crate::kernel::working_undo::with_handle(conn, |raw| {
                collector
                    .check(raw)
                    .map_err(|e| Error::engine(e.to_string()))?;
                Ok(collector.private_objects())
            })
            .await?;
            let mut expected = self.raw_native.clone();
            expected.extend(
                crate::kernel::working_undo_schema::WORKING_METADATA
                    .into_iter()
                    .map(|(name, ddl)| {
                        ("table".into(), name.into(), name.into(), Some(ddl.into()))
                    }),
            );
            expected.extend(private);
            expected.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
            let actual:SchemaInventory=sqlx::query_as("SELECT type,name,tbl_name,sql FROM main.sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetch_all(&mut *conn).await?;
            if actual != expected {
                return Err(Error::engine(
                    "working native/private inventory differs from admitted closure",
                ));
            }
            let ready:bool=sqlx::query_scalar("SELECT enabled=0 AND available=1 AND NOT EXISTS(SELECT 1 FROM main.working_undo) AND NOT EXISTS(SELECT 1 FROM main.working_undo_boundaries) FROM main.working_undo_control WHERE singleton=1").fetch_one(&mut *conn).await?;
            if !ready {
                return Err(Error::engine(
                    "working native fold needs complete inverse and disabled available capture",
                ));
            }
            // Reuse only native field extraction with the originally verified
            // native schema. NEVER certify/verify populated W as accepted.
            let generation = coordinates_from_owned_schema(conn, self.owned_native.clone()).await?;
            generation.validate()?;
            Ok(generation)
        }
    }

    /// A release receipt compares an outgoing preimage before the candidate's
    /// explicit webhook preparation. This admits only the exact current shape
    /// or the frozen, versioned pre-webhook source floor. It grants no
    /// serving, standby generation, import or materialization admission.
    pub(crate) async fn release_coordinates(
        conn: &mut SqliteConnection,
        phase: &mut crate::standby::ReleaseHeadObservationPhase,
    ) -> Result<KernelGeneration> {
        use crate::standby::ReleaseHeadObservationPhase as Phase;
        *phase = Phase::V2Marker;
        if !is_v2(conn).await? {
            return Err(Error::engine(
                "kernel-v2 release head requires the NKV2 marker",
            ));
        }
        *phase = Phase::V2Schema;
        let actual = schema(conn).await?;
        let expected = expected_schema().await?;
        if let Some(entry) = owned_shape(&actual)? {
            *phase = Phase::V2Readiness;
            crate::kernel::verify_v2_ready_on(conn).await?;
            require_shape_readiness(conn, entry).await?;
        } else {
            if sha256_bytes(&serde_jcs::to_vec(&actual)?)
                != RELEASE_PRE_WEBHOOK_SOURCE_V1_SCHEMA_SHA256
                || ![
                    RELEASE_PRE_WEBHOOK_SOURCE_V1_TARGET_SCHEMA_SHA256,
                    KERNEL_V2_READER_SCHEMA_SHA256,
                ]
                .contains(&sha256_bytes(&serde_jcs::to_vec(expected)?).as_str())
                || crate::kernel::webhooks::PREPARATION_INDEXES
                    != RELEASE_PRE_WEBHOOK_SOURCE_V1_INDEXES
            {
                return Err(Error::engine(
                    "kernel-v2 release head has an unsupported owned schema",
                ));
            }
            let qualified = QualifiedPreWebhookSourceV1(());
            crate::kernel::verify_v2_release_before_webhook_preparation_on(conn, &qualified, phase)
                .await?;
        }
        // Preserve the observed owned-schema hash. Filling in the missing
        // indexes would disagree with the outgoing receipt and hide changes.
        *phase = Phase::V2Coordinates;
        coordinates_from_owned_schema(conn, actual).await
    }

    // Extract only after the caller's schema/readiness qualification. Receiver
    // callers must additionally validate registry membership; the release-only
    // caller instead qualifies its exact frozen preparation floor above.
    fn owned_shape(
        actual: &SchemaInventory,
    ) -> Result<Option<&'static crate::standby::shapes::Entry>> {
        let hash = sha256_bytes(&serde_jcs::to_vec(actual)?);
        Ok(crate::standby::shapes::REGISTRY.iter().find(|e| {
            e.family == crate::standby::shapes::Family::KernelV2 && e.schema_sha256 == hash
        }))
    }

    async fn coordinates_from_owned_schema(
        conn: &mut SqliteConnection,
        actual: SchemaInventory,
    ) -> Result<KernelGeneration> {
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
        let mut projection_tables: Vec<String> = actual
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
        // The optional ledger retains its normalized compatibility schema,
        // but is now a certified, event-rebuilt projection when present.
        let receipts: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='kernel_mcp_write_receipts')").fetch_one(&mut *conn).await?;
        if receipts {
            projection_tables.push("kernel_mcp_write_receipts".into());
            projection_tables.sort();
            projection_tables.dedup();
        }
        let result = KernelGeneration {
            reader_format: owned_shape(&actual)?
                .map(|e| e.reader_format)
                .unwrap_or(INITIAL_READER_FORMAT),
            application_id: crate::db::V2_APPLICATION_ID,
            genesis_event_id,
            content_event_seq,
            meta_event_seq,
            head_act,
            blob_count,
            schema_sha256: sha256_bytes(&serde_jcs::to_vec(&actual)?),
            projection_tables,
        };
        result.validate_shape()?;
        Ok(result)
    }

    // CROSS JOIN keeps the narrow, certified headers on the outside even when
    // statistics would otherwise favor scanning the large retained event log.
    const ORIGIN_SQL: &str = "SELECT DISTINCT json_extract(e.payload,'$.legacy.payload.source_origin') FROM kernel_legacy_sql_events h CROSS JOIN content_events e ON e.seq=h.seq WHERE h.event_type='v1.snapshot_provenance' AND e.type='kernel.legacy_recorded.v1' AND json_extract(e.payload,'$.legacy.event_type')='v1.snapshot_provenance' AND json_extract(e.payload,'$.legacy.payload.source_origin') IS NOT NULL ORDER BY 1";

    pub(crate) async fn origin(
        conn: &mut SqliteConnection,
        generation: &KernelGeneration,
    ) -> Result<String> {
        // Imported HQ keeps its configured v1 origin. A native v2 workspace is
        // identified by its immutable genesis UUID, never by a pathname.
        // A missing/stale header projection must refuse, never hide an imported
        // origin behind the native-genesis fallback. The payload stays canonical.
        crate::kernel::legacy_history::require_sql_frontier_on(conn).await?;
        let origins: Vec<String> = sqlx::query_scalar(ORIGIN_SQL).fetch_all(conn).await?;
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
        // Keep coverage, index discovery and native coordinates in one read
        // snapshot. Optional-index hints cannot race schema changes here.
        let mut read = conn.begin().await?;
        crate::kernel::mcp_write_receipts::require_covered_on(&mut read).await?;
        let kernel = coordinates(&mut read).await?;
        let origin_database_id = origin(&mut read, &kernel).await?;
        read.rollback().await?;
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
        let result = validate_manifest_on(&mut conn, manifest, advanced).await;
        conn.close().await?;
        result
    }

    /// [`validate_manifest`] on a connection the caller already holds, so a
    /// check that pins one snapshot can run it on that snapshot.
    pub(crate) async fn validate_manifest_on(
        conn: &mut SqliteConnection,
        manifest: &StandbySnapshotManifest,
        advanced: bool,
    ) -> Result<()> {
        let actual = coordinates(conn).await?;
        let origin = origin(conn, &actual).await?;
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

    #[cfg(test)]
    mod origin_tests {
        use super::*;
        use crate::kernel as k;
        use serde_json::json;

        #[tokio::test]
        async fn compiled_reader_schema_matches_owned_schema() {
            assert_eq!(
                KernelV2Reader::compiled().schema_sha256,
                sha256_bytes(&serde_jcs::to_vec(expected_schema().await.unwrap()).unwrap()),
                "update the compiled reader schema coordinate when owned schema changes; keep the historical default fixed",
            );
        }

        async fn fixture() -> (crate::Db, String, KernelGeneration) {
            let (db, _) = k::create_v2_database(":memory:", "account", "Owner", "acct:owner")
                .await
                .unwrap();
            let host = k::resolve_principal_by_binding(&db, k::HOST_IMPORT_BINDING)
                .await
                .unwrap()
                .unwrap()
                .0;
            let generation = coordinates(&mut db.pool().acquire().await.unwrap())
                .await
                .unwrap();
            (db, host, generation)
        }

        async fn provenance(db: &crate::Db, host: &str, source_origin: &str, sealed: bool) {
            let mut payload = json!({"source_origin":source_origin});
            if !sealed {
                payload["record_id"] = json!(crate::events::KERNEL_ROOT_ID);
            }
            k::import_event_as(
                db,
                host,
                crate::events::KERNEL_ROOT_ID,
                &k::LegacyEvent {
                    source: None,
                    id: uuid::Uuid::new_v4().to_string(),
                    event_type: "v1.snapshot_provenance".into(),
                    payload,
                    created_at: "2026-11-08T00:00:00Z".into(),
                    actor: None,
                    run_key: None,
                },
            )
            .await
            .unwrap();
        }

        #[tokio::test]
        async fn origin_preserves_native_imported_and_ambiguous_identity() {
            let (db, host, generation) = fixture().await;
            let native = format!(
                "ndb_{}",
                uuid::Uuid::parse_str(&generation.genesis_event_id)
                    .unwrap()
                    .simple()
            );
            assert_eq!(
                origin(&mut db.pool().acquire().await.unwrap(), &generation)
                    .await
                    .unwrap(),
                native
            );
            let imported = format!("ndb_{}", uuid::Uuid::new_v4().simple());
            // Older sealed provenance uses the outer subject for its SQL header.
            provenance(&db, &host, &imported, true).await;
            provenance(&db, &host, &imported, false).await;
            assert_eq!(
                origin(&mut db.pool().acquire().await.unwrap(), &generation)
                    .await
                    .unwrap(),
                imported
            );
            provenance(&db, &host, &native, false).await;
            assert!(origin(&mut db.pool().acquire().await.unwrap(), &generation)
                .await
                .unwrap_err()
                .to_string()
                .contains("ambiguous source origins"));
        }

        #[tokio::test]
        async fn origin_refuses_invalid_origins_and_uncertified_headers() {
            let (db, host, generation) = fixture().await;
            provenance(&db, &host, "invalid-origin", false).await;
            let mut conn = db.write_pool().acquire().await.unwrap();
            assert!(origin(&mut conn, &generation)
                .await
                .unwrap_err()
                .to_string()
                .contains("ambiguous source origins"));
            for assignment in ["scanned_seq=0", "gap_free=0", "provenance_headers=0"] {
                let mut tx = sqlx::Acquire::begin(&mut *conn).await.unwrap();
                sqlx::query(&format!(
                    "UPDATE kernel_legacy_sql_progress SET {assignment}"
                ))
                .execute(&mut *tx)
                .await
                .unwrap();
                assert!(origin(&mut tx, &generation)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("legacy SQL projection needs catchup"));
                tx.rollback().await.unwrap();
            }
            sqlx::query("DELETE FROM kernel_legacy_sql_progress")
                .execute(&mut *conn)
                .await
                .unwrap();
            assert!(
                origin(&mut conn, &generation)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("legacy SQL projection needs catchup"),
                "missing frontier cannot fall back to genesis"
            );
        }

        #[tokio::test]
        async fn origin_plan_reads_headers_before_canonical_payloads() {
            let (db, host, generation) = fixture().await;
            let native = format!(
                "ndb_{}",
                uuid::Uuid::parse_str(&generation.genesis_event_id)
                    .unwrap()
                    .simple()
            );
            let unrelated = k::LegacyEvent {
                source: None,
                id: "unrelated-origin-payload".into(),
                event_type: "body_changed".into(),
                payload: json!({"source_origin":format!("ndb_{}", uuid::Uuid::new_v4().simple())}),
                created_at: "2026-11-08T00:00:00Z".into(),
                actor: None,
                run_key: None,
            };
            k::import_event_as(&db, &host, crate::events::KERNEL_ROOT_ID, &unrelated)
                .await
                .unwrap();
            let mut conn = db.write_pool().acquire().await.unwrap();
            // A forged candidate header cannot promote another legacy type.
            let inserted = sqlx::query("INSERT INTO kernel_legacy_sql_events SELECT seq,'forged','native:root','v1.snapshot_provenance',NULL,NULL,NULL,'2026-11-08','snapshot_provenance' FROM content_events WHERE id=?").bind(&unrelated.id).execute(&mut *conn).await.unwrap();
            assert_eq!(inserted.rows_affected(), 1);
            assert_eq!(origin(&mut conn, &generation).await.unwrap(), native);
            let plan: Vec<(i64, i64, i64, String)> =
                sqlx::query_as(&format!("EXPLAIN QUERY PLAN {ORIGIN_SQL}"))
                    .fetch_all(&mut *conn)
                    .await
                    .unwrap();
            let details: Vec<_> = plan.iter().map(|row| row.3.as_str()).collect();
            assert!(
                details.iter().any(|line| line.starts_with("SCAN h")),
                "{details:?}"
            );
            assert!(
                details
                    .iter()
                    .any(|line| line.starts_with("SEARCH e USING INTEGER PRIMARY KEY")),
                "{details:?}"
            );
            assert!(
                !details.iter().any(|line| line.starts_with("SCAN e")),
                "{details:?}"
            );
        }
    }
}
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(crate) use enabled::*;
