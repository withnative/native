//! Borrowed, read-only outcome profile qualification. No DDL and no cleanup.
// The node-owned adapter deliberately joins separately; keep this sealed seam crate-private.
#![allow(dead_code)]
use super::{lookup_outcome_on, KeyedOutcome};
use crate::{
    kernel::{mcp_write_receipts as receipts, working_undo::Collector},
    standby::{
        kernel_v2::{self, WorkingKernelSchema},
        shapes,
    },
};
use sqlx::{
    sqlite::SqliteTransactionManager, Sqlite, SqliteConnection, Transaction, TransactionManager,
};
type Result<T> = std::result::Result<T, OutcomeProfileError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutcomeProfile {
    Legacy1,
    Typed2,
}
pub(crate) type LegacyReceiptProbe = Option<(String, String)>;
pub(crate) enum OutcomeLookup<'p> {
    Legacy(&'p LegacyReceiptProbe),
    Typed(&'p KeyedOutcome),
}
enum OwnedLookup {
    Legacy(LegacyReceiptProbe),
    Typed(KeyedOutcome),
}
pub(crate) struct VerifiedOutcomeSnapshot<'c> {
    conn: &'c mut SqliteConnection,
    profile: OutcomeProfile,
    empty: bool,
    _owner: Option<(&'c WorkingKernelSchema, &'c Collector)>,
    cached: Option<OwnedLookup>,
}
#[derive(Debug, thiserror::Error)]
pub(crate) enum OutcomeProfileError {
    #[error("outcome_transaction_required")]
    TransactionRequired,
    #[error("outcome_wrong_engine")]
    WrongEngine,
    #[error("outcome_connection_mode_mismatch")]
    WrongConnectionMode,
    #[error("outcome_native_profile_unsupported")]
    UnsupportedNativeInventory,
    #[error("outcome_schema_unsupported")]
    UnsupportedOutcomeInventory,
    #[error("outcome_profile_mixed")]
    MixedProfile,
    #[error("outcome_owner_mismatch")]
    OwnerMismatch,
    #[error("outcome_capture_unavailable")]
    CaptureUnavailable,
    #[error("outcome_coverage_unverified")]
    CoverageUnverified {
        #[source]
        source: Box<crate::Error>,
    },
    #[error("outcome_storage_unavailable")]
    Storage {
        #[source]
        source: sqlx::Error,
    },
}
impl From<sqlx::Error> for OutcomeProfileError {
    fn from(source: sqlx::Error) -> Self {
        Self::Storage { source }
    }
}
impl OutcomeProfileError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::TransactionRequired => "outcome_transaction_required",
            Self::WrongEngine => "outcome_wrong_engine",
            Self::WrongConnectionMode => "outcome_connection_mode_mismatch",
            Self::UnsupportedNativeInventory => "outcome_native_profile_unsupported",
            Self::UnsupportedOutcomeInventory => "outcome_schema_unsupported",
            Self::MixedProfile => "outcome_profile_mixed",
            Self::OwnerMismatch => "outcome_owner_mismatch",
            Self::CaptureUnavailable => "outcome_capture_unavailable",
            Self::CoverageUnverified { .. } => "outcome_coverage_unverified",
            Self::Storage { .. } => "outcome_storage_unavailable",
        }
    }
}
async fn physical(conn: &mut SqliteConnection, working: bool) -> Result<()> {
    if SqliteTransactionManager::get_transaction_depth(conn) != 1 {
        return Err(OutcomeProfileError::TransactionRequired);
    }
    let active = crate::kernel::working_undo::with_handle(conn, |raw| {
        use rusqlite::config::DbConfig;
        Ok((
            !raw.is_autocommit(),
            raw.query_row("PRAGMA recursive_triggers", [], |r| r.get::<_, bool>(0))
                .map_err(|_| crate::Error::engine("pragma read"))?,
            raw.query_row("PRAGMA foreign_keys", [], |r| r.get::<_, bool>(0))
                .map_err(|_| crate::Error::engine("pragma read"))?,
            raw.db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER)
                .map_err(|_| crate::Error::engine("trigger state"))?,
        ))
    })
    .await
    .map_err(|_| OutcomeProfileError::WrongConnectionMode)?;
    if !active.0 {
        return Err(OutcomeProfileError::TransactionRequired);
    }
    if active.1 != working || !active.2 || !active.3 {
        return Err(OutcomeProfileError::WrongConnectionMode);
    }
    let marker: i64 = sqlx::query_scalar("PRAGMA main.application_id")
        .fetch_one(&mut *conn)
        .await?;
    let version: i64 = sqlx::query_scalar("PRAGMA main.user_version")
        .fetch_one(&mut *conn)
        .await?;
    if marker != crate::db::V2_APPLICATION_ID || version != 0 {
        return Err(OutcomeProfileError::WrongEngine);
    }
    Ok(())
}
async fn layout(
    conn: &mut SqliteConnection,
    entry: &shapes::Entry,
) -> Result<(OutcomeProfile, bool)> {
    let table:Option<String>=sqlx::query_scalar("SELECT sql FROM main.sqlite_schema WHERE type='table' AND name='kernel_mcp_write_receipts'").fetch_optional(&mut *conn).await?;
    let fenced:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id='kernel:mcp-write-receipts' AND type='kernel.mcp_write_fenced.v1')").fetch_one(&mut *conn).await?;
    if entry.reader_format == 1 {
        let forbidden:i64=sqlx::query_scalar("SELECT count(*) FROM main.sqlite_schema WHERE name IN ('idx_kernel_mcp_write_fence_events','idx_kernel_mcp_retired_record_id','kernel_mcp_terminal_no_replace','kernel_mcp_terminal_no_delete','kernel_mcp_outcome_immutable')").fetch_one(&mut *conn).await?;
        if fenced || forbidden != 0 {
            return Err(OutcomeProfileError::MixedProfile);
        }
        match table {
            Some(sql)
                if sql
                    == crate::kernel::MCP_WRITE_RECEIPTS_DDL.replacen(" IF NOT EXISTS", "", 1) =>
            {
                Ok((OutcomeProfile::Legacy1, false))
            }
            None => {
                let facts:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id='kernel:mcp-write-receipts')").fetch_one(&mut *conn).await?;
                if facts {
                    Err(OutcomeProfileError::MixedProfile)
                } else {
                    Ok((OutcomeProfile::Legacy1, true))
                }
            }
            _ => Err(OutcomeProfileError::UnsupportedOutcomeInventory),
        }
    } else if entry.reader_format == 2 {
        if table.as_deref()
            != Some(
                crate::kernel::MCP_TYPED_WRITE_RECEIPTS_DDL
                    .replacen(" IF NOT EXISTS", "", 1)
                    .as_str(),
            )
        {
            return Err(OutcomeProfileError::UnsupportedOutcomeInventory);
        }
        receipts::fences::require_current_guards_on(conn)
            .await
            .map_err(|_| OutcomeProfileError::UnsupportedOutcomeInventory)?;
        for (name, ddl) in [
            (receipts::INDEX, receipts::INDEX_DDL),
            (
                "idx_kernel_mcp_write_fence_events",
                receipts::fences::INDEX_DDL,
            ),
            (
                "idx_kernel_mcp_retired_record_id",
                receipts::fences::RETIRED_DDL,
            ),
        ] {
            let actual: Option<String> = sqlx::query_scalar(
                "SELECT sql FROM main.sqlite_schema WHERE type='index' AND name=?",
            )
            .bind(name)
            .fetch_optional(&mut *conn)
            .await?;
            if actual.as_deref() != Some(ddl.replacen(" IF NOT EXISTS", "", 1).as_str()) {
                return Err(OutcomeProfileError::UnsupportedOutcomeInventory);
            }
        }
        Ok((OutcomeProfile::Typed2, false))
    } else {
        Err(OutcomeProfileError::UnsupportedNativeInventory)
    }
}
pub(crate) async fn verified_outcomes_on<'c>(
    conn: &'c mut SqliteConnection,
) -> Result<VerifiedOutcomeSnapshot<'c>> {
    physical(conn, false).await?;
    let private:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE name IN ('working_undo','working_undo_control','_native_working_applied')) OR EXISTS(SELECT 1 FROM temp.sqlite_schema WHERE type='trigger')").fetch_one(&mut *conn).await?;
    if private {
        return Err(OutcomeProfileError::OwnerMismatch);
    }
    let entry = kernel_v2::outcome_native_entry_on(conn)
        .await
        .map_err(|_| OutcomeProfileError::UnsupportedNativeInventory)?;
    let (profile, empty) = layout(conn, entry).await?;
    Ok(VerifiedOutcomeSnapshot {
        conn,
        profile,
        empty,
        _owner: None,
        cached: None,
    })
}
pub(crate) async fn verified_working_outcomes_on<'c, 'conn>(
    owner: &'c WorkingKernelSchema,
    tx: &'c mut Transaction<'conn, Sqlite>,
    collector: &'c Collector,
) -> Result<VerifiedOutcomeSnapshot<'c>> {
    physical(tx, true).await?;
    let entry = owner
        .require_exact_outcome_inventory_on(tx, collector)
        .await?;
    let (profile, empty) = layout(tx, entry).await?;
    Ok(VerifiedOutcomeSnapshot {
        conn: tx,
        profile,
        empty,
        _owner: Some((owner, collector)),
        cached: None,
    })
}
impl VerifiedOutcomeSnapshot<'_> {
    pub(crate) fn profile(&self) -> OutcomeProfile {
        self.profile
    }
    pub(crate) async fn lookup<'p>(
        &'p mut self,
        principal: &str,
        operation: &str,
        key: &str,
    ) -> Result<OutcomeLookup<'p>> {
        self.cached = Some(match self.profile {
            OutcomeProfile::Legacy1 => OwnedLookup::Legacy(if self.empty {
                None
            } else {
                sqlx::query_as("SELECT request_json,receipt_json FROM main.kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?").bind(principal).bind(operation).bind(key).fetch_optional(&mut *self.conn).await?
            }),
            OutcomeProfile::Typed2 => OwnedLookup::Typed(
                lookup_outcome_on(self.conn, principal, operation, key)
                    .await
                    .map_err(|source| OutcomeProfileError::CoverageUnverified {
                        source: Box::new(source),
                    })?,
            ),
        });
        match self.cached.as_ref().expect("stored outcome") {
            OwnedLookup::Legacy(v) => Ok(OutcomeLookup::Legacy(v)),
            OwnedLookup::Typed(v) => Ok(OutcomeLookup::Typed(v)),
        }
    }
}
impl OutcomeLookup<'_> {
    pub(crate) fn terminal_conflict(&self) -> Option<crate::OriginalConflict> {
        let Self::Typed(KeyedOutcome::Terminal { fact, native }) = self else {
            return None;
        };
        Some(crate::OriginalConflict {
            schema: "native.original-conflict.v1".into(),
            kind: crate::OriginalConflictKind::KeyFenced,

            record_id: None,
            fence_id: fact.terminal.fence_id.clone(),
            native_fence: native.clone(),
            namespace_sha256: fact.terminal.namespace_sha256.clone(),
            fenced_original_binding_sha256: fact.terminal.original_binding_sha256.clone(),
            requested_original_binding_sha256: None,
        })
    }
}

#[cfg(all(test, feature = "mcp-executor-prototype"))]
#[path = "outcome_profile_tests.rs"]
mod tests;
