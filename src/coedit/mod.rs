//! Live co-editing of record bodies (`session.body.v1`), increment 1.
//!
//! Module name: `coedit` (rather than `session_body`) because the engine
//! already owns a `record_body` helper for single-writer bodies, and this
//! module is the multi-peer live-session core that will later hang transport,
//! persistence ("versions"), and commit paths off — "coedit" names that
//! seam; `session_body` would collide with it conceptually.
//!
//! Shared state per record is one Yjs doc with a single root [`YText`]
//! named `body` holding the Markdown source. All text offsets are UTF-8
//! **byte** offsets at every boundary: every [`Doc`] here is built with
//! [`OffsetKind::Bytes`], and clients must encode/decode with the same kind.
//!
//! This increment is in-process only: no persistence, no transport, no
//! rate limiting, no access-loss tracking (see TODOs on [`RefusalCode`]).
//!
//! [`YText`]: yrs::TextRef
//! [`Doc`]: yrs::Doc
//! [`OffsetKind::Bytes`]: yrs::OffsetKind::Bytes

#[allow(dead_code)] // Inactive stage-1 consumer; no public ingress until follow-on review.
pub(crate) mod driver;
mod refusal;
mod registry;
#[cfg(test)]
mod tests;
pub(crate) mod version_metadata;

pub use refusal::{RefusalCode, Refused};
pub use registry::{
    Ack, AcknowledgedContributor, DrainOutcome, OpenOk, OpenParams, PeerId, PeerKind, SessionId,
    SessionRegistry, VersionSnapshot, MAX_ATTRIBUTED_IDENTITIES, MAX_ATTRIBUTED_IDENTITY_BYTES,
};
