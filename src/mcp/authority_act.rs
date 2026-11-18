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

/// One exact-cut request. The client supplies `F1` and, for v2, its verified base blob keys. `F2` is the head
/// the authority observes in the same read transaction.
#[derive(Debug, Clone)]
pub struct AuthorityActDeltaRequest {
    pub from_exclusive_act: i64,
    pub blob_inventory: Option<Vec<String>>,
    /// The kernel-v2 delta wire version the client asks for. `None` is version
    /// 1, as every request has always been.
    pub kernel_delta_version: Option<u32>,
}

impl AuthorityActDeltaRequest {
    /// The wire version to cut at. An absent field is version 1. Version 2 is
    /// honoured only when the authority offers it, and version 3 (no
    /// projection digest) only when it offers that; otherwise a request is
    /// answered with the newest version offered below it, down to version 1,
    /// which every client parses. Anything else is refused.
    pub fn negotiated_kernel_delta_version(
        &self,
        v2_offered: bool,
        v3_offered: bool,
    ) -> Result<u32> {
        let v2_or_1 = if v2_offered { 2 } else { 1 };
        match self.kernel_delta_version {
            None | Some(1) => Ok(1),
            Some(2) => Ok(v2_or_1),
            Some(3) => Ok(if v3_offered { 3 } else { v2_or_1 }),
            Some(_) => Err(crate::error::Error::engine(
                "authority_act_delta: kernel_delta_version must be 1, 2 or 3",
            )),
        }
    }
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
