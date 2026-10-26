//! The workspace opt-in check.
//!
//! `Resolution/hcp_entry` is not a built-in kind. A workspace enables the HCP
//! v2 interface by defining it in its `kind:Resolution` vocabulary
//! (`manage_vocabularies` `propose_value` with complete KindMetadataV1, then
//! `promote_value`, both plan-gated admin operations). Every tool checks that
//! the kind is **active** before it reads or writes anything and refuses
//! otherwise. This module never proposes or promotes the kind: that decision
//! belongs to a workspace admin.
//!
//! V2 uses its native definition mechanism instead: the two exported version1
//! artifacts must be installed and adopted at the workspace root. Imported v1
//! vocabulary rows cannot enable this path. Neither engine's opt-in is cached;
//! disabling its workspace configuration stops the next request.

use crate::db::Db;
use crate::error::Result;
use crate::meta::kind::{resolve_on, KindClassification};

/// The kind that holds one HCP entry.
pub(super) const KIND: &str = "hcp_entry";

/// Error `type` for a workspace that has not enabled the interface. It is not
/// one of the Core errors (HCP v2 §5.5): no Core error says "this provider is
/// not set up for this person", and `scope-denied` would suggest a grant
/// problem the person cannot fix.
pub(super) const NOT_CONFIGURED: &str = "native:not-configured";

const DOCS: &str = "see \"HCP v2 entry interface\" in docs/hosted-mcp.md";

/// `None` when `Resolution/hcp_entry` is an active kind in this workspace;
/// otherwise the refusal message, specific to the kind's current state.
pub(super) async fn not_configured(db: &Db) -> Result<Option<String>> {
    let mut conn = db.pool().acquire().await?;
    let resolution = resolve_on(&mut conn, "Resolution", KIND).await?;
    let state = match resolution.classification {
        KindClassification::ActiveCanonical => return Ok(None),
        KindClassification::Proposed => {
            "the `hcp_entry` kind is proposed but has not been promoted, so a workspace \
             admin must promote it"
        }
        KindClassification::DeprecatedAlias | KindClassification::DeprecatedNonAlias => {
            "the `hcp_entry` kind has been deprecated, so a workspace admin must define \
             it again"
        }
        KindClassification::Unknown => {
            "the `hcp_entry` kind is not defined, so a workspace admin must define it \
             (propose it in the kind:Resolution vocabulary, then promote it)"
        }
    };
    Ok(Some(format!(
        "HCP is not enabled in this workspace: {state}; {DOCS}."
    )))
}

/// Explicit workspace opt-in artifacts. Installing/adopting these is an admin
/// decision; HCP request handlers never install or adopt them.
pub const KERNEL_ENTRY_DEFINITION: &str = include_str!("hcp.entry.defn.json");
pub const KERNEL_SUGGESTION_DEFINITION: &str = include_str!("hcp.suggestion.defn.json");
pub const KERNEL_ENTRY_FAMILY: &str = "hcp.entry";
pub const KERNEL_SUGGESTION_FAMILY: &str = "hcp.suggestion";

#[cfg(feature = "v2-kernel-probe")]
pub(super) async fn not_configured_kernel(db: &Db) -> Result<Option<String>> {
    let mut conn = db.pool().acquire().await?;
    for family in [KERNEL_ENTRY_FAMILY, KERNEL_SUGGESTION_FAMILY] {
        let selected = crate::kernel::resolve_effective_adoption_verified(
            &mut conn,
            family,
            crate::events::KERNEL_ROOT_ID,
        )
        .await?;
        let expected = if family == KERNEL_ENTRY_FAMILY {
            KERNEL_ENTRY_DEFINITION
        } else {
            KERNEL_SUGGESTION_DEFINITION
        };
        let expected_digest =
            crate::meta::definition_artifact::digest_artifact_bytes(expected.as_bytes());
        if !matches!(selected, Some(crate::kernel::ScopedAdoption::Adopted(pin)) if pin.version==1 && pin.digest==expected_digest)
        {
            return Ok(Some(format!("HCP is not enabled in this v2 workspace: a workspace admin must explicitly install and adopt {family}.")));
        }
    }
    Ok(None)
}
