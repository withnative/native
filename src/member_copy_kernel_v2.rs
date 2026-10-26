//! Native member source authorization, evaluated inside the producer's read
//! transaction. This is server-internal capture/fence evidence, not a member
//! manifest and never a canonical snapshot that may be downloaded by a member.
//!
//! The hosted caller must already be reconciled through H3 under request
//! admission. This reader never activates identity, provisions a principal or
//! changes schema. Catalog C1/W/C2 checks remain the hosting adapter's job.
use crate::{
    authorization::Capability, events::KERNEL_ROOT_ID, kernel, standby::kernel_v2, Error, Result,
};
pub mod file_fence;
pub mod profile;

use sha2::{Digest, Sha256};
use sqlx::SqliteConnection;

/// A loss of copy authority is a purge instruction, not transport unavailability.
/// This internal reason is deliberately not added to the v1 wire protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberAuthorityLoss {
    RosterMembership,
    RootView,
}

/// A don't-serve outcome without proof that this account previously held copy
/// authority. This is NOT a purge instruction: withhold reads/bytes and require
/// authenticated source/identity verification before any retained copy serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemberSourceRefusal {
    NotActivated,
    UnknownAccountBinding,
    SourceIdentityMismatch,
}

/// No Debug/Serialize: these facts and the authorization fence must never enter
/// a member response. In particular the hash binds undisclosed global heads.
#[derive(Eq, PartialEq)]
pub struct NativeMemberCut {
    pub origin_database_id: String,
    pub genesis_event_id: String,
    pub account_binding: String,
    pub principal_id: String,
    authorization_fence: String,
}

impl NativeMemberCut {
    /// Declare only this captured account's native identity. The hosting
    /// producer obtains this cut from its authenticated read snapshot; neither
    /// an account override nor a candidate file is an input. The private
    /// authorization fence/global generation coordinates remain server-only.
    pub fn profile_identity(&self) -> crate::replica_generation::NativeMemberProfileIdentity {
        crate::replica_generation::NativeMemberProfileIdentity {
            account_binding: self.account_binding.clone(),
            principal_id: self.principal_id.clone(),
            genesis_event_id: self.genesis_event_id.clone(),
        }
    }
}

/// Typed authority loss lets the later transport/lifecycle adapter purge a
/// member copy even when no replacement generation can be produced.
pub enum NativeMemberSource {
    Ready(NativeMemberCut),
    Revoked(MemberAuthorityLoss),
    Refused(MemberSourceRefusal),
}

/// The caller owns a coherent read transaction spanning this capture and the
/// eventual native-profile materialization. Recheck the same fence before
/// releasing bytes; no caller or account mapping may be cached across requests.
/// `expected_origin` must come from the requested database's independently
/// verified catalog/install binding; never derive it from the just-opened file.
/// The hosting adapter must obtain account_binding from authenticated request
/// context, never caller-supplied tool arguments. A wrong file is a refusal,
/// never evidence to purge a different workspace's retained member copy.
pub async fn capture_in(
    conn: &mut SqliteConnection,
    expected_origin: &str,
    account_binding: &str,
) -> Result<NativeMemberSource> {
    capture_identity_in(
        conn,
        expected_origin,
        MemberIdentity::Account(account_binding),
    )
    .await
}

/// Hosted transport seam. The catalogue identity must come from a freshly
/// authenticated request, never an account/origin in a tool or HTTP body.
/// Resolve the immutable H3 mapping, including former members, solely to
/// evaluate the same typed roster/root revocations. No email matching or
/// identity activation occurs here.
pub async fn capture_authenticated_catalog_in(
    conn: &mut SqliteConnection,
    expected_origin: &str,
    authenticated_catalog_id: &str,
) -> Result<NativeMemberSource> {
    capture_identity_in(
        conn,
        expected_origin,
        MemberIdentity::Catalog(authenticated_catalog_id),
    )
    .await
}

enum MemberIdentity<'a> {
    Account(&'a str),
    Catalog(&'a str),
}

async fn capture_identity_in(
    conn: &mut SqliteConnection,
    expected_origin: &str,
    identity: MemberIdentity<'_>,
) -> Result<NativeMemberSource> {
    if !kernel_v2::is_v2(conn).await? {
        return Err(Error::engine(
            "native member capture requires an NKV2 source",
        ));
    }
    let generation = kernel_v2::coordinates(conn).await?;
    let origin_database_id = kernel_v2::origin(conn, &generation).await?;
    // Establish source identity before either Ready or a purge instruction.
    // Roster/root state in another database is not authority for this request.
    if !crate::identity::is_database_id(expected_origin) || origin_database_id != expected_origin {
        return Ok(NativeMemberSource::Refused(
            MemberSourceRefusal::SourceIdentityMismatch,
        ));
    }
    if !kernel::hosted_identity::activated_on(conn).await? {
        return Ok(NativeMemberSource::Refused(
            MemberSourceRefusal::NotActivated,
        ));
    }
    let account_binding = match identity {
        MemberIdentity::Account(account) => account.to_owned(),
        MemberIdentity::Catalog(catalog_id) => {
            let Some(account) =
                kernel::hosted_identity::retained_catalog_account_on(conn, catalog_id).await?
            else {
                return Ok(NativeMemberSource::Refused(
                    MemberSourceRefusal::UnknownAccountBinding,
                ));
            };
            account
        }
    };
    let Some((account_binding, principal_id)) =
        kernel_v2::account_on(conn, &account_binding).await?
    else {
        return Ok(NativeMemberSource::Refused(
            MemberSourceRefusal::UnknownAccountBinding,
        ));
    };
    if !kernel::hosted_identity::admitted(conn, &principal_id).await? {
        return Ok(NativeMemberSource::Revoked(
            MemberAuthorityLoss::RosterMembership,
        ));
    }
    if !kernel::kernel_effective_capability_on(conn, &principal_id, KERNEL_ROOT_ID)
        .await?
        .allows(Capability::View)
    {
        return Ok(NativeMemberSource::Revoked(MemberAuthorityLoss::RootView));
    }
    let fence = serde_jcs::to_vec(&serde_json::json!({
        "engine":kernel_v2::ENGINE,"origin":origin_database_id,
        "account":account_binding,"principal":principal_id,"generation":generation,
    }))?;
    Ok(NativeMemberSource::Ready(NativeMemberCut {
        origin_database_id,
        genesis_event_id: generation.genesis_event_id,
        account_binding,
        principal_id,
        authorization_fence: hex::encode(Sha256::digest(fence)),
    }))
}

#[cfg(test)]
#[path = "member_copy_kernel_v2_tests.rs"]
mod tests;
