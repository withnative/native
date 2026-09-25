//! Registration-time capability for the owner-only authority act transport.
//!
//! The tool layer owns the wire contract; each runtime supplies the mechanism
//! that can honour it. Hosted implements the mechanism over the catalog-backed
//! route and re-checks membership on every call; stdio never registers the
//! capability at all, so a local process cannot expose hosted trust. This keeps
//! the registry handler signature unchanged and the tool handlers free of a
//! hidden `Hosting` dependency (the same seam as [`super::snapshot`]).

use std::sync::Arc;

use futures::future::BoxFuture;

use crate::db::Db;
use crate::error::Result;

use super::registry::Caller;
use crate::standby::delta_transport::{AuthorityActDeltaResponseV1, AuthorityActHeadResponseV1};

/// One exact-cut request. The client supplies `F1` only: `F2` is whatever head
/// the authority observes in the same read transaction.
#[derive(Debug, Clone, Copy)]
pub struct AuthorityActDeltaRequest {
    pub from_exclusive_act: i64,
}

pub trait AuthorityActSource: Send + Sync {
    /// The cheap replicated act-head probe.
    fn head(
        &self,
        db: Db,
        caller: Caller,
    ) -> BoxFuture<'static, Result<AuthorityActHeadResponseV1>>;

    /// The exact canonical cut from `from_exclusive_act` to the observed head.
    fn delta(
        &self,
        db: Db,
        caller: Caller,
        request: AuthorityActDeltaRequest,
    ) -> BoxFuture<'static, Result<AuthorityActDeltaResponseV1>>;
}

pub type AuthorityActSourceRef = Arc<dyn AuthorityActSource>;
