//! Registration-time capability for producing a consistent database snapshot.
//!
//! The tool layer owns the wire contract; each runtime supplies the mechanism
//! that can honour it. Hosted and stdio implementations live in `hosting`, so
//! tool handlers never acquire a hidden `Hosting` dependency and the registry
//! handler signature stays unchanged (decision 256ceb4).

use std::sync::Arc;

use futures::future::BoxFuture;

use crate::db::Db;
use crate::error::Result;

use super::registry::Caller;
use crate::standby_snapshot::{StandbyConsumerIdentity, StandbySnapshotManifest};

pub const SNAPSHOT_MAX_PAGE_BYTES: usize = 512 * 1024;
pub const SNAPSHOT_DEFAULT_PAGE_BYTES: usize = 64 * 1024;
pub const SNAPSHOT_COMPLETED_CACHE_CAP: usize = 16;

#[derive(Debug, Clone)]
pub struct SnapshotRequest {
    pub export_id: Option<String>,
    pub offset: u64,
    pub length: usize,
    pub standby_consumer: Option<StandbyConsumerIdentity>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SnapshotPage {
    pub export_id: String,
    pub file_name: String,
    pub media_type: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub offset: u64,
    pub length: usize,
    pub eof: bool,
    pub data_base64: String,
    pub expires_in_seconds: u64,
    /// Present only when an authenticated hosted request explicitly binds a
    /// released standby consumer. Ordinary hosted and local exports remain
    /// generic and make no standby provenance claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest: Option<StandbySnapshotManifest>,
}

pub trait SnapshotSource: Send + Sync {
    fn page(
        &self,
        db: Db,
        caller: Caller,
        request: SnapshotRequest,
    ) -> BoxFuture<'static, Result<SnapshotPage>>;
}

pub type SnapshotSourceRef = Arc<dyn SnapshotSource>;
