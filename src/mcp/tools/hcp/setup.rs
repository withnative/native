//! The workspace opt-in check.
//!
//! `Resolution/preference` is not a built-in kind. A workspace enables HCP by
//! defining it in its `kind:Resolution` vocabulary (`manage_vocabularies`
//! `propose_value` with complete KindMetadataV1, then `promote_value`, both
//! plan-gated admin operations). Every HCP tool checks that the kind is
//! **active** before it reads or writes anything, and refuses with
//! `HCP_NOT_CONFIGURED` otherwise. `/hcp` never proposes or promotes the kind
//! itself: that decision belongs to a workspace admin.
//!
//! The check is one indexed read per call and is never cached, so a promotion
//! takes effect on the next request and a deprecation stops HCP at once.

use crate::db::Db;
use crate::error::Result;
use crate::meta::kind::{resolve_on, KindClassification};

/// Error code for a workspace that has not enabled HCP preferences.
pub(super) const NOT_CONFIGURED: &str = "HCP_NOT_CONFIGURED";

const DOCS: &str = "see \"HCP preference interface\" in docs/hosted-mcp.md";

/// `None` when `Resolution/preference` is an active kind in this workspace;
/// otherwise the refusal message, specific to the kind's current state.
pub(super) async fn not_configured(db: &Db) -> Result<Option<String>> {
    let mut conn = db.pool().acquire().await?;
    let resolution = resolve_on(&mut conn, "Resolution", "preference").await?;
    let state = match resolution.classification {
        KindClassification::ActiveCanonical => return Ok(None),
        KindClassification::Proposed => {
            "the `preference` kind is proposed but has not been promoted, so a workspace \
             admin must promote it"
        }
        KindClassification::DeprecatedAlias | KindClassification::DeprecatedNonAlias => {
            "the `preference` kind has been deprecated, so a workspace admin must define \
             it again"
        }
        KindClassification::Unknown => {
            "the `preference` kind is not defined, so a workspace admin must define it \
             (propose it in the kind:Resolution vocabulary, then promote it)"
        }
    };
    Ok(Some(format!(
        "HCP preferences are not enabled in this workspace: {state}; {DOCS}."
    )))
}
