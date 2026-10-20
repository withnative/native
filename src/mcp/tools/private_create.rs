//! Atomic caller-account privacy shared by ordinary and canonical create paths.
use super::super::registry::Caller;
use crate::authorization::{AllowEntry, Capability};
use crate::error::{Error, Result};
use sqlx::{Sqlite, Transaction};

pub(super) async fn install_account_only_policy_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    tool: &str,
    id: &str,
    act: &mut crate::act::ActAllocation,
) -> Result<()> {
    if super::is_legacy_local(caller) {
        return Err(Error::engine(format!(
            "{tool}: 'access_policy' requires a portable account caller"
        )));
    }
    let target = crate::authorization::authorization_target_on(tx, id)
        .await
        .map_err(|_| Error::engine(format!("{tool}: record {id} does not exist")))?;
    if target != id {
        return Err(Error::engine(format!(
            "{tool}: 'access_policy' is not supported for derived records; the authorization bearer {target} owns the policy boundary"
        )));
    }
    crate::authorization::replace_explicit_policy_on(
        tx,
        caller.actor(),
        id,
        vec![AllowEntry::account(caller.credential(), Capability::Manage)],
        act,
    )
    .await
}
