//! Resolve a host-authenticated user to the portable identity stored in their
//! content file.
//!
//! Authentication and routing remain catalog concerns. Attribution does not:
//! the value written to `content_events.actor` must remain meaningful after the
//! SQLite file is ejected, so a canonical account token and its person record
//! live in the file's direct-write `bindings` substrate.

use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Db;
use crate::error::Result;
use crate::identity::account::{
    canonical_account_from_rows, identity_invariant, is_account_token, require_canonical_account,
    require_live_person,
};
use crate::store::{append_in, AppendSpec};

mod cleanup;

#[doc(hidden)]
pub use cleanup::{
    apply_hosted_membership_cleanup, project_hosted_membership_cleanup,
    HostedMembershipCleanupCounts, HostedMembershipCleanupProjection,
};

/// Hosted membership role carried into portable onboarding.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedMembershipRole {
    Owner,
    Member,
}

/// Immutable source of a hosted membership arrival.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedMembershipSource {
    Personal,
    Direct,
    Invitation,
}

/// Checked immutable arrival facts. Mutable hosted onboarding state is
/// deliberately absent.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedMembershipArrival(crate::instruction_templates::TrustedMembershipArrival);

impl HostedMembershipArrival {
    pub fn new(
        role: HostedMembershipRole,
        source: HostedMembershipSource,
        created_at: String,
    ) -> Result<Self> {
        let arrival = crate::instruction_templates::TrustedMembershipArrival {
            role: match role {
                HostedMembershipRole::Owner => {
                    crate::instruction_templates::TrustedMembershipRole::Owner
                }
                HostedMembershipRole::Member => {
                    crate::instruction_templates::TrustedMembershipRole::Member
                }
            },
            source: match source {
                HostedMembershipSource::Personal => {
                    crate::instruction_templates::TrustedMembershipSource::Personal
                }
                HostedMembershipSource::Direct => {
                    crate::instruction_templates::TrustedMembershipSource::Direct
                }
                HostedMembershipSource::Invitation => {
                    crate::instruction_templates::TrustedMembershipSource::Invitation
                }
            },
            created_at,
        };
        arrival.validate()?;
        Ok(Self(arrival))
    }
}

/// Existing portable identity facts returned without provisioning or repair.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedPortableIdentity {
    pub account_id: String,
    pub person_record_id: String,
}

/// Read-only principal state used before hosted custody is allowed to mint.
#[doc(hidden)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostedIdentityPreflight {
    pub existing_principal: Option<String>,
    pub addressable: bool,
}

/// Validate and canonicalize a principal supplied by hosted account custody.
#[doc(hidden)]
pub fn validate_hosted_principal(principal: &str) -> Result<String> {
    crate::identity::normalize_identifier("native-principal", principal)
}

/// Resolve `email` to the file's canonical account token, provisioning the
/// first person identity when necessary.
///
/// Established identities validate in a read snapshot. Provisioning and repair
/// re-read all state in one `BEGIN IMMEDIATE` transaction, keeping malformed
/// state failures from partially repairing the file.
#[cfg(test)]
pub(crate) async fn resolve_account_identity(
    db: &Db,
    email: &str,
    catalog_user_id: &str,
) -> Result<String> {
    resolve_account_identity_inner(db, email, catalog_user_id, None).await
}

/// Hosted resolution with trusted, immutable membership-arrival facts from
/// the catalog. The descriptor is consumed only for portable onboarding
/// classification; mutable workbench onboarding state never crosses this
/// boundary.
#[cfg(test)]
pub(crate) async fn resolve_account_identity_with_arrival(
    db: &Db,
    email: &str,
    catalog_user_id: &str,
    arrival: &HostedMembershipArrival,
) -> Result<String> {
    resolve_account_identity_inner(db, email, catalog_user_id, Some(arrival)).await
}

/// Hosted resolution plus the account-scoped public federation address. The
/// provider is called before this function so custody I/O never occurs while
/// the workspace's serialized write transaction is held.
#[doc(hidden)]
pub async fn reconcile_hosted_identity(
    db: &Db,
    email: &str,
    catalog_user_id: &str,
    arrival: &HostedMembershipArrival,
    public_principal: Option<&str>,
) -> Result<String> {
    resolve_account_identity_inner_with_principal(
        db,
        email,
        catalog_user_id,
        Some(arrival),
        public_principal,
    )
    .await
}

/// Read an already-established portable identity without provisioning or
/// repairing anything. Membership roster reads and offboarding use this seam
/// so observing catalog membership can never create content records.
#[doc(hidden)]
pub async fn existing_hosted_identity(
    db: &Db,
    email: &str,
) -> Result<Option<HostedPortableIdentity>> {
    // Read-only observation: roster/offboarding must never take the
    // serialised writer. The read pool is a different snapshot, which is
    // safe here because no caller holds an open write transaction whose
    // uncommitted writes this lookup must observe.
    let mut connection = db.pool().begin().await?;
    let identity = existing_hosted_identity_in_snapshot(&mut connection, email).await?;
    connection.rollback().await?;
    Ok(identity)
}

/// In-transaction form used by core-owned projections that must bind identity
/// lookup and dependent content rows to one SQLite snapshot.
pub(crate) async fn existing_hosted_identity_in_snapshot(
    connection: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    email: &str,
) -> Result<Option<HostedPortableIdentity>> {
    let row =
        sqlx::query("SELECT record_id FROM bindings WHERE system = 'email' AND identifier = ?")
            .bind(email)
            .fetch_optional(&mut **connection)
            .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let person_record_id = row.try_get::<String, _>("record_id")?;
    require_live_person(connection, &format!("email '{email}'"), &person_record_id).await?;
    let account_id = require_canonical_account(connection, &person_record_id).await?;
    Ok(Some(HostedPortableIdentity {
        account_id,
        person_record_id,
    }))
}

/// Validate an existing hosted identity before custody is allowed to mint a
/// first principal. Returning an existing principal lets the caller refuse an
/// unmanaged continuity conflict without irreversibly creating new custody.
#[doc(hidden)]
pub async fn preflight_hosted_identity(
    db: &Db,
    email: &str,
    catalog_user_id: &str,
) -> Result<HostedIdentityPreflight> {
    let mut tx = db.write_pool().begin().await?;
    let row = sqlx::query("SELECT record_id FROM bindings WHERE system='email' AND identifier=?")
        .bind(email)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(row) = row else {
        tx.rollback().await?;
        return Ok(HostedIdentityPreflight {
            existing_principal: None,
            addressable: false,
        });
    };
    let record_id = row.try_get::<String, _>("record_id")?;
    require_live_person(&mut tx, &format!("email '{email}'"), &record_id).await?;

    let accounts: Vec<(String, i64)> = sqlx::query_as(
        "SELECT identifier,is_canonical FROM bindings
         WHERE record_id=? AND system='account' ORDER BY identifier",
    )
    .bind(&record_id)
    .fetch_all(&mut *tx)
    .await?;
    let canonical_accounts = accounts
        .iter()
        .filter(|(_, canonical)| *canonical == 1)
        .collect::<Vec<_>>();
    let account_ready = match canonical_accounts.as_slice() {
        [(identifier, _)] if is_account_token(identifier) => true,
        [] if accounts.iter().all(|(identifier, _)| {
            identifier == catalog_user_id && !is_account_token(identifier)
        }) =>
        {
            false
        }
        [(..)] => {
            return Err(identity_invariant(format!(
                "person record '{record_id}' has malformed canonical account token"
            )))
        }
        _ => {
            return Err(identity_invariant(format!(
                "person record '{record_id}' has ambiguous account bindings"
            )))
        }
    };

    let principals: Vec<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings
         WHERE record_id=? AND system='native-principal' AND is_canonical=1
         ORDER BY identifier",
    )
    .bind(&record_id)
    .fetch_all(&mut *tx)
    .await?;
    let principal = match principals.as_slice() {
        [] => None,
        [principal] => Some(crate::identity::normalize_identifier(
            "native-principal",
            principal,
        )?),
        _ => {
            return Err(identity_invariant(format!(
                "person record '{record_id}' has multiple canonical native-principal bindings"
            )))
        }
    };
    tx.rollback().await?;
    let addressable = account_ready && principal.is_some();
    Ok(HostedIdentityPreflight {
        existing_principal: principal,
        addressable,
    })
}

#[cfg(test)]
async fn resolve_account_identity_inner(
    db: &Db,
    email: &str,
    catalog_user_id: &str,
    arrival: Option<&HostedMembershipArrival>,
) -> Result<String> {
    resolve_account_identity_inner_with_principal(db, email, catalog_user_id, arrival, None).await
}

async fn resolve_account_identity_inner_with_principal(
    db: &Db,
    email: &str,
    catalog_user_id: &str,
    arrival: Option<&HostedMembershipArrival>,
    public_principal: Option<&str>,
) -> Result<String> {
    if let Some(account) =
        reconciled_identity_in_read_snapshot(db, email, catalog_user_id, arrival, public_principal)
            .await?
    {
        return Ok(account);
    }
    // Never upgrade the read snapshot: repair re-reads all state under the
    // existing serialized transaction, preserving atomic invariant checks.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;

    let email_binding =
        sqlx::query("SELECT record_id FROM bindings WHERE system = 'email' AND identifier = ?")
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;

    let (account_token, person_record_id, provisioned, alias_inserted, account_repaired) =
        if let Some(binding) = email_binding {
            let record_id = binding.try_get::<String, _>("record_id")?;
            require_live_person(&mut tx, &format!("email '{email}'"), &record_id).await?;
            let (account_token, account_repaired) =
                ensure_canonical_account(&mut tx, catalog_user_id, &record_id).await?;
            // A hit proves this resolver has already provisioned or adopted the
            // identity. Never rescan the append-only history here: validate an
            // alias when one exists, but keep normal connects O(bindings lookup).
            validate_existing_legacy_alias(&mut tx, catalog_user_id, &record_id).await?;
            let alias_inserted = if account_repaired {
                migrate_legacy_actor_alias(&mut tx, catalog_user_id, &record_id).await?
            } else {
                false
            };
            (
                account_token,
                record_id,
                false,
                alias_inserted,
                account_repaired,
            )
        } else {
            let record_id = Uuid::new_v4().to_string();
            let token_hex = Uuid::new_v4().simple().to_string();
            let account_token = format!("acct_{token_hex}");
            // The address is the best name available at hosted provisioning: it
            // is true, it distinguishes two members, and it reads as obviously
            // provisional, so it invites a rename instead of persisting unread
            // the way `Account <hex>` does. Stdio minting has no email and stays
            // on the hex.
            let name = email.to_string();

            append_in(
                db,
                &mut tx,
                AppendSpec {
                    record_id: record_id.clone(),
                    event_type: "record.created".into(),
                    payload: json!({
                        "type": "Entity",
                        "kind": "person",
                        "name": name,
                    }),
                    actor: Some(account_token.clone()),
                },
            )
            .await?;
            crate::identity::add_binding_internal_in(
                &mut tx,
                &account_token,
                "provision verified hosted email identity",
                &record_id,
                "email",
                email,
                true,
            )
            .await?;
            crate::identity::add_binding_internal_in(
                &mut tx,
                &account_token,
                "mint canonical portable account identity",
                &record_id,
                "account",
                &account_token,
                true,
            )
            .await?;
            // Provisioning is the one migration boundary. The resolver-created
            // email binding is the durable proof that this unindexed legacy scan
            // has already happened and must not run again on future connects.
            let alias_inserted =
                migrate_legacy_actor_alias(&mut tx, catalog_user_id, &record_id).await?;
            (account_token, record_id, true, alias_inserted, false)
        };

    let principal_changed = match public_principal {
        Some(principal) => {
            ensure_canonical_principal(&mut tx, &account_token, &person_record_id, principal)
                .await?
        }
        None => false,
    };

    let instruction_state_changed = if let Some(arrival) = arrival {
        crate::instruction_templates::provision_member_in(
            db,
            &mut tx,
            &account_token,
            &person_record_id,
            crate::instruction_templates::MemberProvisioningAuthority::Hosted(&arrival.0),
        )
        .await?
    } else {
        false
    };

    if provisioned
        || alias_inserted
        || account_repaired
        || principal_changed
        || instruction_state_changed
    {
        db.commit_content(tx).await?;
    } else {
        // A clean hit is a read-only operation. Explicit rollback makes it
        // impossible to mistake releasing the reserved lock for a content
        // mutation when auditing this first direct-write binding path.
        tx.rollback().await?;
    }
    Ok(account_token)
}

/// Established requests use the independent read pool. Missing repairable
/// state returns None; malformed established state still fails validation.
async fn reconciled_identity_in_read_snapshot(
    db: &Db,
    email: &str,
    catalog_user_id: &str,
    arrival: Option<&HostedMembershipArrival>,
    public_principal: Option<&str>,
) -> Result<Option<String>> {
    let mut tx = db.pool().begin().await?;
    let person: Option<String> =
        sqlx::query_scalar("SELECT record_id FROM bindings WHERE system='email' AND identifier=?")
            .bind(email)
            .fetch_optional(&mut *tx)
            .await?;
    let Some(person) = person else {
        tx.rollback().await?;
        return Ok(None);
    };
    // One optional fetch replaces the old EXISTS-then-SELECT pair: the same
    // snapshot answers both, so an empty result still means "repairable" and
    // falls back to the repair path below. Liveness is checked before row
    // validation, preserving the established error ordering (live-person
    // failures precede malformed/multiple-account failures).
    let account_rows: Vec<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings WHERE record_id=? AND system='account' AND is_canonical=1",
    )
    .bind(&person)
    .fetch_all(&mut *tx)
    .await?;
    if account_rows.is_empty() {
        tx.rollback().await?;
        return Ok(None);
    }
    require_live_person(&mut tx, &format!("email '{email}'"), &person).await?;
    let Some(account) = canonical_account_from_rows(&person, &account_rows)? else {
        // Unreachable: empty input was returned as repairable above, and the
        // shared validator only yields None for empty input. Stay repair-safe
        // rather than panicking if that contract ever changes.
        tx.rollback().await?;
        return Ok(None);
    };
    validate_existing_legacy_alias(&mut tx, catalog_user_id, &person).await?;
    if let Some(principal) = public_principal {
        // Same EXISTS-then-SELECT fold for the principal: one fetch, empty
        // still repairs, non-empty validates read-only (never writes here).
        let canonical: Vec<String> = sqlx::query_scalar(
            "SELECT identifier FROM bindings WHERE record_id=? AND system='native-principal' AND is_canonical=1 ORDER BY identifier",
        ).bind(&person).fetch_all(&mut *tx).await?;
        if canonical.is_empty() {
            tx.rollback().await?;
            return Ok(None);
        }
        validate_canonical_principal(&person, principal, &canonical)?;
    }
    if let Some(arrival) = arrival {
        if !crate::instruction_templates::member_provisioning_is_read_only_in(
            &mut tx, &account, &arrival.0,
        )
        .await?
        {
            tx.rollback().await?;
            return Ok(None);
        }
        // Run the same validation as the repair path. The readiness check
        // excludes every provisioning branch; SQLite's read-only connection
        // additionally prevents an accidental write if those branches change.
        crate::instruction_templates::provision_member_in(
            db,
            &mut tx,
            &account,
            &person,
            crate::instruction_templates::MemberProvisioningAuthority::Hosted(&arrival.0),
        )
        .await?;
    }
    tx.rollback().await?;
    Ok(Some(account))
}

async fn ensure_canonical_account(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    catalog_user_id: &str,
    record_id: &str,
) -> Result<(String, bool)> {
    let rows = sqlx::query(
        "SELECT identifier FROM bindings
         WHERE record_id = ? AND system = 'account' AND is_canonical = 1",
    )
    .bind(record_id)
    .fetch_all(&mut **tx)
    .await?;
    match rows.as_slice() {
        [row] => {
            let token = row.try_get::<String, _>("identifier")?;
            if !is_account_token(&token) {
                return Err(identity_invariant(format!(
                    "person record '{record_id}' has malformed canonical account token"
                )));
            }
            Ok((token, false))
        }
        [] => {
            // A portable-looking non-canonical token is ambiguous historical
            // state: do not guess whether to promote it or mint a replacement.
            let aliases: Vec<String> = sqlx::query_scalar(
                "SELECT identifier FROM bindings
                 WHERE record_id = ? AND system = 'account' ORDER BY identifier",
            )
            .bind(record_id)
            .fetch_all(&mut **tx)
            .await?;
            if aliases.iter().any(|identifier| is_account_token(identifier)) {
                return Err(identity_invariant(format!(
                    "person record '{record_id}' has a non-canonical portable account binding"
                )));
            }
            if aliases
                .iter()
                .any(|identifier| identifier != catalog_user_id)
            {
                return Err(identity_invariant(format!(
                    "person record '{record_id}' has an unexpected non-canonical account binding"
                )));
            }
            validate_existing_legacy_alias(tx, catalog_user_id, record_id).await?;
            let token = format!("acct_{}", Uuid::new_v4().simple());
            crate::identity::add_binding_internal_in(
                tx,
                &token,
                "repair missing canonical hosted account identity",
                record_id,
                "account",
                &token,
                true,
            )
            .await?;
            Ok((token, true))
        }
        _ => Err(identity_invariant(format!(
            "person record '{record_id}' must have exactly one canonical account binding (found {})",
            rows.len()
        ))),
    }
}

async fn ensure_canonical_principal(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    actor: &str,
    record_id: &str,
    public_principal: &str,
) -> Result<bool> {
    // Validate the provider output even on a no-op, rather than trusting an
    // injected or future remote provider to obey the binding grammar.
    let normalized = crate::identity::normalize_identifier("native-principal", public_principal)?;
    let canonical: Vec<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings
         WHERE record_id = ? AND system = 'native-principal' AND is_canonical = 1
         ORDER BY identifier",
    )
    .bind(record_id)
    .fetch_all(&mut **tx)
    .await?;
    match canonical.as_slice() {
        [] => {
            crate::identity::add_binding_internal_in(
                tx,
                actor,
                "bind account-scoped federation principal to hosted member",
                record_id,
                "native-principal",
                &normalized,
                true,
            )
            .await
        }
        rows => validate_canonical_principal_rows(record_id, &normalized, rows).map(|()| false),
    }
}

/// Read-only half of [`ensure_canonical_principal`]: check an already
/// normalized custody principal against already-fetched canonical rows.
///
/// Callers never pass empty input: the repair path normalizes before fetching
/// (so an invalid provider string errors there even with no established
/// state), and the read probe returns missing state as repairable before
/// normalizing (so only the probe defers provider validation until state is
/// known to exist). A single normalized match is a no-op; multiples or a
/// mismatch refuse without writing. Shared by the warm read probe and the
/// repair path so both enforce the same refusal.
fn validate_canonical_principal_rows(
    record_id: &str,
    normalized: &str,
    canonical: &[String],
) -> Result<()> {
    match canonical {
        [existing] if existing == normalized => Ok(()),
        [..] => Err(identity_invariant(format!(
            "person record '{record_id}' has a canonical native-principal inconsistent with account custody"
        ))),
    }
}

/// Probe-side adapter: normalize the provider output (even on a no-op, as the
/// repair path does), then run the shared read-only check. Never writes.
/// Missing rows never reach this adapter — the probe returns `Ok(None)`
/// first — so deferring normalization past the empty check is a probe-only
/// repair behavior, not leniency in the shared refusal logic.
fn validate_canonical_principal(
    record_id: &str,
    public_principal: &str,
    canonical: &[String],
) -> Result<()> {
    // Validate the provider output even on a no-op, rather than trusting an
    // injected or future remote provider to obey the binding grammar.
    let normalized = crate::identity::normalize_identifier("native-principal", public_principal)?;
    validate_canonical_principal_rows(record_id, &normalized, canonical)
}

async fn validate_existing_legacy_alias(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    catalog_user_id: &str,
    record_id: &str,
) -> Result<()> {
    let existing = sqlx::query(
        "SELECT record_id, is_canonical FROM bindings
         WHERE system = 'account' AND identifier = ?",
    )
    .bind(catalog_user_id)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(row) = existing {
        let owner = row.try_get::<String, _>("record_id")?;
        let canonical = row.try_get::<i64, _>("is_canonical")?;
        if owner != record_id || canonical != 0 {
            return Err(identity_invariant(format!(
                "legacy catalog identity '{catalog_user_id}' is already bound incompatibly"
            )));
        }
    }
    Ok(())
}

async fn migrate_legacy_actor_alias(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    catalog_user_id: &str,
    record_id: &str,
) -> Result<bool> {
    #[cfg(test)]
    LEGACY_SCAN_COUNT
        .try_with(|count| count.fetch_add(1, std::sync::atomic::Ordering::SeqCst))
        .ok();
    let has_legacy_events =
        sqlx::query_scalar::<_, i64>("SELECT EXISTS(SELECT 1 FROM content_events WHERE actor = ?)")
            .bind(catalog_user_id)
            .fetch_one(&mut **tx)
            .await?
            != 0;
    if !has_legacy_events {
        return Ok(false);
    }

    validate_existing_legacy_alias(tx, catalog_user_id, record_id).await?;
    let alias_exists = sqlx::query_scalar::<_, i64>(
        "SELECT EXISTS(
             SELECT 1 FROM bindings WHERE system = 'account' AND identifier = ?
         )",
    )
    .bind(catalog_user_id)
    .fetch_one(&mut **tx)
    .await?
        != 0;
    if alias_exists {
        return Ok(false);
    }
    crate::identity::add_binding_internal_in(
        tx,
        "engine:legacy-account-migration",
        "preserve legacy catalog actor attribution",
        record_id,
        "account",
        catalog_user_id,
        false,
    )
    .await?;
    Ok(true)
}

#[cfg(test)]
tokio::task_local! {
    static LEGACY_SCAN_COUNT: std::sync::Arc<std::sync::atomic::AtomicUsize>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{create_record_as, delete_record_as};
    use sqlx::Row;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    async fn db() -> Db {
        crate::create_database(":memory:").await.unwrap()
    }

    async fn counts(db: &Db) -> (i64, i64, i64) {
        let records = sqlx::query_scalar("SELECT COUNT(*) FROM records")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let events = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let bindings = sqlx::query_scalar("SELECT COUNT(*) FROM bindings")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        (records, events, bindings)
    }

    #[tokio::test]
    async fn established_hosted_identity_does_not_wait_for_an_active_writer() {
        let db = db().await;
        let arrival = HostedMembershipArrival::new(
            HostedMembershipRole::Owner,
            HostedMembershipSource::Personal,
            crate::store::now_iso(),
        )
        .unwrap();
        let account = reconcile_hosted_identity(
            &db,
            "ada@example.com",
            "catalog-ada",
            &arrival,
            Some("native/ada"),
        )
        .await
        .unwrap();
        let before = counts(&db).await;
        let writer = crate::db::begin_write(db.write_pool()).await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reconcile_hosted_identity(
                &db,
                "ada@example.com",
                "catalog-ada",
                &arrival,
                Some("native/ada"),
            ),
        )
        .await;
        writer.rollback().await.unwrap();
        assert_eq!(
            result
                .expect("established identity waited for the writer")
                .unwrap(),
            account
        );
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn read_probe_preserves_repair_and_rejects_inconsistent_member_context() {
        let db = db().await;
        let arrival = HostedMembershipArrival::new(
            HostedMembershipRole::Owner,
            HostedMembershipSource::Personal,
            crate::store::now_iso(),
        )
        .unwrap();
        let account =
            reconcile_hosted_identity(&db, "ada@example.com", "catalog-ada", &arrival, None)
                .await
                .unwrap();
        sqlx::query("UPDATE records SET name='drifted' WHERE id=?")
            .bind(crate::instruction_templates::INSTRUCTIONS_FOLDER_ID)
            .execute(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            reconcile_hosted_identity(&db, "ada@example.com", "catalog-ada", &arrival, None,)
                .await
                .unwrap(),
            account
        );
        let name: String = sqlx::query_scalar("SELECT name FROM records WHERE id=?")
            .bind(crate::instruction_templates::INSTRUCTIONS_FOLDER_ID)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(name, "Agent instructions");
        sqlx::query(
            "UPDATE member_contexts SET person_record_id=root_record_id WHERE account_id=?",
        )
        .bind(&account)
        .execute(db.write_pool())
        .await
        .unwrap();
        let writer = crate::db::begin_write(db.write_pool()).await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reconcile_hosted_identity(&db, "ada@example.com", "catalog-ada", &arrival, None),
        )
        .await;
        writer.rollback().await.unwrap();
        let error = result
            .expect("invariant validation waited for the writer")
            .unwrap_err();
        assert!(
            error.to_string().contains("different person identity"),
            "{error}"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn fresh_resolution_creates_one_portable_identity_and_is_idempotent() {
        let db = db().await;
        let token = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
            .await
            .unwrap();
        assert!(is_account_token(&token), "{token}");
        assert_eq!(counts(&db).await, (3, 3, 2));

        let row = sqlx::query(
            "SELECT r.id, r.type, r.kind, r.name, e.actor
             FROM records r JOIN content_events e ON e.record_id = r.id
             WHERE r.type = 'Entity' AND r.kind = 'person'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        let record_id = row.get::<String, _>("id");
        assert_eq!(row.get::<String, _>("type"), "Entity");
        assert_eq!(row.get::<String, _>("kind"), "person");
        // Hosted provisioning knows the address, so the person is readable from
        // the first event rather than being named after the account hex.
        assert_eq!(row.get::<String, _>("name"), "ada@example.com");
        assert_eq!(row.get::<String, _>("actor"), token);
        assert_ne!(record_id, token);

        let again = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
            .await
            .unwrap();
        assert_eq!(again, token);
        assert_eq!(counts(&db).await, (3, 3, 2));
        db.close().await;
    }

    #[tokio::test]
    async fn trusted_arrivals_provision_private_contexts_defaults_and_distinct_obligations() {
        use crate::authorization::{Capability, Principal};
        use crate::instruction_templates::{MEMBER_PROGRAMME_ID, OWNER_PROGRAMME_ID};

        let db = db().await;
        assert!(HostedMembershipArrival::new(
            HostedMembershipRole::Member,
            HostedMembershipSource::Personal,
            crate::store::now_iso(),
        )
        .is_err());
        assert!(HostedMembershipArrival::new(
            HostedMembershipRole::Owner,
            HostedMembershipSource::Personal,
            "not-an-rfc3339-timestamp".into(),
        )
        .is_err());
        let owner_arrival = HostedMembershipArrival::new(
            HostedMembershipRole::Owner,
            HostedMembershipSource::Personal,
            crate::store::now_iso(),
        )
        .unwrap();
        let owner = resolve_account_identity_with_arrival(
            &db,
            "owner@example.com",
            "catalog-owner",
            &owner_arrival,
        )
        .await
        .unwrap();
        let owner_root: String =
            sqlx::query_scalar("SELECT root_record_id FROM member_contexts WHERE account_id=?")
                .bind(&owner)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(
            sqlx::query_as::<_, (String, String)>(
                "SELECT programme_id,state FROM member_obligations WHERE account_id=?",
            )
            .bind(&owner)
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            (OWNER_PROGRAMME_ID.into(), "pending".into())
        );
        assert_eq!(
            crate::authorization::effective_capability(
                &db,
                Principal::bound(&owner, true),
                &owner_root,
            )
            .await
            .unwrap(),
            Capability::Manage
        );
        crate::authorization::require_capability(
            &db,
            Principal::bound(&owner, true),
            "native:workspace-agent-instructions",
            Capability::Edit,
        )
        .await
        .expect("the trusted workspace owner can edit shared instructions");

        let member_arrival = HostedMembershipArrival::new(
            HostedMembershipRole::Member,
            HostedMembershipSource::Invitation,
            crate::store::now_iso(),
        )
        .unwrap();
        let member = resolve_account_identity_with_arrival(
            &db,
            "member@example.com",
            "catalog-member",
            &member_arrival,
        )
        .await
        .unwrap();
        assert_eq!(
            sqlx::query_as::<_, (String, String)>(
                "SELECT programme_id,state FROM member_obligations WHERE account_id=?",
            )
            .bind(&member)
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            (MEMBER_PROGRAMME_ID.into(), "pending".into())
        );
        assert_eq!(
            crate::authorization::effective_capability(
                &db,
                Principal::bound(&member, true),
                &owner_root,
            )
            .await
            .unwrap(),
            Capability::None
        );
        assert_eq!(
            crate::authorization::effective_capability(
                &db,
                Principal::bound(&member, true),
                "native:agent-instructions",
            )
            .await
            .unwrap(),
            Capability::View
        );
        crate::authorization::require_capability(
            &db,
            Principal::bound(&member, true),
            "native:workspace-agent-instructions",
            Capability::Edit,
        )
        .await
        .expect_err("a non-owner member remains view-only");

        let control_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        assert_eq!(
            resolve_account_identity_with_arrival(
                &db,
                "member@example.com",
                "catalog-member",
                &member_arrival,
            )
            .await
            .unwrap(),
            member
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM control_events")
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
            control_before
        );
        db.close().await;
    }

    #[tokio::test]
    async fn simultaneous_first_resolutions_converge() {
        let db = db().await;
        let first = resolve_account_identity(&db, "ada@example.com", "catalog-ada");
        let second = resolve_account_identity(&db, "ada@example.com", "catalog-ada");
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap(), second.unwrap());
        assert_eq!(counts(&db).await, (3, 3, 2));
        db.close().await;
    }

    #[tokio::test]
    async fn legacy_history_is_scanned_once_on_miss_and_never_on_hits() {
        let db = db().await;
        let scans = Arc::new(AtomicUsize::new(0));
        LEGACY_SCAN_COUNT
            .scope(scans.clone(), async {
                let token = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
                    .await
                    .unwrap();
                assert_eq!(scans.load(Ordering::SeqCst), 1);

                for _ in 0..3 {
                    assert_eq!(
                        resolve_account_identity(&db, "ada@example.com", "catalog-ada")
                            .await
                            .unwrap(),
                        token
                    );
                }
                assert_eq!(
                    scans.load(Ordering::SeqCst),
                    1,
                    "an email hit must not scan the append-only event log"
                );
            })
            .await;
        assert_eq!(counts(&db).await, (3, 3, 2));
        db.close().await;
    }

    #[tokio::test]
    async fn secondary_email_binding_resolves_the_same_account_without_writing() {
        let db = db().await;
        let token = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
            .await
            .unwrap();
        let record_id = sqlx::query_scalar::<_, String>(
            "SELECT record_id FROM bindings WHERE system = 'email' AND identifier = 'ada@example.com'",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'email', 'ada+work@example.com', 0)",
        )
        .bind(record_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let before = counts(&db).await;

        let secondary =
            resolve_account_identity(&db, "ada+work@example.com", "catalog-ada-secondary")
                .await
                .unwrap();
        assert_eq!(secondary, token);
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn legacy_actor_gets_an_alias_without_rewriting_history_and_resolves_offline() {
        let db = db().await;
        let old_record = create_record_as(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": "legacy" }),
            Some("catalog-ada"),
        )
        .await
        .unwrap();
        resolve_account_identity(&db, "ada@example.com", "catalog-ada")
            .await
            .unwrap();

        let actor =
            sqlx::query_scalar::<_, String>("SELECT actor FROM content_events WHERE record_id = ?")
                .bind(&old_record)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        assert_eq!(actor, "catalog-ada", "the authoritative event is untouched");
        let aliases = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM bindings
             WHERE system = 'account' AND identifier = 'catalog-ada' AND is_canonical = 0",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(aliases, 1);

        let who = sqlx::query_scalar::<_, String>(
            "SELECT COALESCE(p.name, e.actor)
             FROM content_events e
             LEFT JOIN bindings b ON b.system = 'account' AND b.identifier = e.actor
             LEFT JOIN records p ON p.id = b.record_id
             WHERE e.record_id = ?",
        )
        .bind(&old_record)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(who, "ada@example.com");
        db.close().await;
    }

    #[tokio::test]
    async fn hosted_reconciliation_repairs_missing_account_and_binds_principal_once() {
        let db = db().await;
        let record_id = create_record_as(
            &db,
            json!({ "type": "Entity", "kind": "person", "name": "Ada" }),
            Some("catalog-ada"),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'email', 'ada@example.com', 1)",
        )
        .bind(&record_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let arrival = HostedMembershipArrival::new(
            HostedMembershipRole::Member,
            HostedMembershipSource::Invitation,
            crate::store::now_iso(),
        )
        .unwrap();

        let account = reconcile_hosted_identity(
            &db,
            "ada@example.com",
            "catalog-ada",
            &arrival,
            Some("native/ada"),
        )
        .await
        .unwrap();
        assert!(is_account_token(&account));
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT identifier FROM bindings
                 WHERE record_id=? AND system='native-principal' AND is_canonical=1",
            )
            .bind(&record_id)
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            "native/ada"
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bindings
                 WHERE record_id=? AND system='account' AND identifier='catalog-ada'
                   AND is_canonical=0",
            )
            .bind(&record_id)
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            1
        );

        let before = counts(&db).await;
        assert_eq!(
            reconcile_hosted_identity(
                &db,
                "ada@example.com",
                "catalog-ada",
                &arrival,
                Some("native/ada"),
            )
            .await
            .unwrap(),
            account
        );
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn hosted_reconciliation_refuses_a_principal_custody_mismatch_without_rewriting() {
        let db = db().await;
        let arrival = HostedMembershipArrival::new(
            HostedMembershipRole::Owner,
            HostedMembershipSource::Personal,
            crate::store::now_iso(),
        )
        .unwrap();
        reconcile_hosted_identity(
            &db,
            "ada@example.com",
            "catalog-ada",
            &arrival,
            Some("native/ada"),
        )
        .await
        .unwrap();
        let before = counts(&db).await;

        let error = reconcile_hosted_identity(
            &db,
            "ada@example.com",
            "catalog-ada",
            &arrival,
            Some("native/not-ada"),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("inconsistent with account custody"),
            "{error}"
        );
        assert_eq!(counts(&db).await, before);
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT identifier FROM bindings
                 WHERE system='native-principal' AND is_canonical=1",
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            "native/ada"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn malformed_email_hits_fail_closed_and_leave_the_file_unchanged() {
        for malformed in ["malformed_account", "wrong_kind", "deleted_person"] {
            let db = db().await;
            let record_id = create_record_as(
                &db,
                json!({
                    "type": "Entity",
                    "kind": if malformed == "wrong_kind" { "organization" } else { "person" },
                    "name": "fixture"
                }),
                Some("fixture"),
            )
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO bindings (record_id, system, identifier, is_canonical)
                 VALUES (?, 'email', 'ada@example.com', 1)",
            )
            .bind(&record_id)
            .execute(db.write_pool())
            .await
            .unwrap();
            let identifier = if malformed == "malformed_account" {
                "catalog-shaped-not-portable"
            } else {
                "acct_00000000000000000000000000000000"
            };
            sqlx::query(
                "INSERT INTO bindings (record_id, system, identifier, is_canonical)
                 VALUES (?, 'account', ?, 1)",
            )
            .bind(&record_id)
            .bind(identifier)
            .execute(db.write_pool())
            .await
            .unwrap();
            if malformed == "deleted_person" {
                delete_record_as(&db, &record_id, Some("fixture"))
                    .await
                    .unwrap();
            }
            let before = counts(&db).await;
            let error = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("identity invariant failed"),
                "{malformed}: {error}"
            );
            assert_eq!(counts(&db).await, before, "{malformed}");
            db.close().await;
        }
    }

    #[tokio::test]
    async fn email_binding_to_a_missing_record_fails_closed() {
        let db = db().await;
        // This shape requires bypassing the FK just as a corrupted/imported
        // SQLite file would. Restore enforcement before returning the pooled
        // connection so the resolver itself runs under normal rules.
        let mut conn = db.write_pool().acquire().await.unwrap();
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&mut *conn)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES ('missing-person', 'email', 'ada@example.com', 1)",
        )
        .execute(&mut *conn)
        .await
        .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *conn)
            .await
            .unwrap();
        drop(conn);
        let before = counts(&db).await;

        let error = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("points to missing record"));
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn conflicting_legacy_alias_rolls_back_fresh_provisioning() {
        let db = db().await;
        let other = create_record_as(
            &db,
            json!({ "type": "Entity", "kind": "person", "name": "other" }),
            Some("fixture"),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', 'catalog-ada', 0)",
        )
        .bind(other)
        .execute(db.write_pool())
        .await
        .unwrap();
        create_record_as(
            &db,
            json!({ "type": "WorkItem", "kind": "task", "name": "legacy" }),
            Some("catalog-ada"),
        )
        .await
        .unwrap();
        let before = counts(&db).await;

        let error = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("already bound incompatibly"));
        assert_eq!(counts(&db).await, before);
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM bindings WHERE system = 'email' AND identifier = 'ada@example.com'"
            )
            .fetch_one(db.write_pool())
            .await
            .unwrap(),
            0
        );
        db.close().await;
    }

    #[tokio::test]
    async fn existing_hosted_identity_miss_returns_none_without_provisioning() {
        let db = db().await;
        let before = counts(&db).await;
        assert!(existing_hosted_identity(&db, "nobody@example.com")
            .await
            .unwrap()
            .is_none());
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn existing_hosted_identity_reads_without_a_writer_pool_slot() {
        let db = db().await;
        let account = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
            .await
            .unwrap();
        // Occupy every write-pool slot (five; see open_pool): a read that
        // touched the writer pool would wait and time out.
        let mut held = Vec::new();
        for _ in 0..5 {
            held.push(db.write_pool().acquire().await.unwrap());
        }
        let found = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            existing_hosted_identity(&db, "ada@example.com"),
        )
        .await
        .expect("established identity read must not acquire a writer-pool slot")
        .unwrap()
        .expect("established identity must resolve");
        drop(held);
        assert_eq!(found.account_id, account);
        db.close().await;
    }

    async fn probe_arrival() -> HostedMembershipArrival {
        HostedMembershipArrival::new(
            HostedMembershipRole::Member,
            HostedMembershipSource::Invitation,
            crate::store::now_iso(),
        )
        .unwrap()
    }

    async fn person_with_email(db: &Db, email: &str) -> String {
        let record_id = create_record_as(
            db,
            json!({ "type": "Entity", "kind": "person", "name": "Ada" }),
            Some("fixture"),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'email', ?, 1)",
        )
        .bind(&record_id)
        .bind(email)
        .execute(db.write_pool())
        .await
        .unwrap();
        record_id
    }

    async fn add_canonical_account(db: &Db, record_id: &str, identifier: &str) {
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(record_id)
        .bind(identifier)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn read_probe_repairs_missing_canonical_but_rejects_corrupt_state() {
        // Anchor custody principals to the existing binding grammar rather
        // than bare literals (normalization is identity for valid input).
        let principal = validate_hosted_principal("native/ada").unwrap();
        let mismatch = validate_hosted_principal("native/not-ada").unwrap();
        // Each case runs in its own block: the module's `db()` helper is
        // shadowed by a `let db` binding within a block, as in the existing
        // malformed-hit test.
        {
            // Control: missing canonical account repairs through the probe.
            let db = db().await;
            let record_id = person_with_email(&db, "ada@example.com").await;
            let account = reconcile_hosted_identity(
                &db,
                "ada@example.com",
                "catalog-ada",
                &probe_arrival().await,
                Some(principal.as_str()),
            )
            .await
            .unwrap();
            assert!(is_account_token(&account));
            assert_eq!(
                sqlx::query_scalar::<_, String>(
                    "SELECT identifier FROM bindings
                      WHERE record_id=? AND system='native-principal' AND is_canonical=1",
                )
                .bind(&record_id)
                .fetch_one(db.write_pool())
                .await
                .unwrap(),
                principal
            );
            db.close().await;
        }

        // Malformed, multiple, non-person, and deleted states fail closed with
        // no writes; the legacy-alias conflict refuses as well.
        for case in [
            "malformed_account",
            "multiple_accounts",
            "wrong_kind",
            "deleted_person",
            "legacy_alias_conflict",
        ] {
            let db = db().await;
            let record_id = if case == "wrong_kind" {
                let record_id = create_record_as(
                    &db,
                    json!({ "type": "Entity", "kind": "organization", "name": "Not a person" }),
                    Some("fixture"),
                )
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO bindings (record_id, system, identifier, is_canonical)
                     VALUES (?, 'email', 'ada@example.com', 1)",
                )
                .bind(&record_id)
                .execute(db.write_pool())
                .await
                .unwrap();
                record_id
            } else {
                person_with_email(&db, "ada@example.com").await
            };
            match case {
                "malformed_account" => {
                    add_canonical_account(&db, &record_id, "catalog-shaped-not-portable").await
                }
                "multiple_accounts" => {
                    // A healthy schema prevents this state. Remove only the
                    // test fixture's uniqueness guard to exercise defensive
                    // validation of an already-corrupt canonical projection.
                    sqlx::query("DROP INDEX idx_bindings_one_canonical_per_system")
                        .execute(db.write_pool())
                        .await
                        .unwrap();
                    add_canonical_account(&db, &record_id, "acct_00000000000000000000000000000000")
                        .await;
                    add_canonical_account(&db, &record_id, "acct_11111111111111111111111111111111")
                        .await;
                }
                "wrong_kind" | "deleted_person" => {
                    add_canonical_account(&db, &record_id, "acct_00000000000000000000000000000000")
                        .await
                }
                "legacy_alias_conflict" => {
                    add_canonical_account(&db, &record_id, "acct_00000000000000000000000000000000")
                        .await;
                    let other = create_record_as(
                        &db,
                        json!({ "type": "Entity", "kind": "person", "name": "other" }),
                        Some("fixture"),
                    )
                    .await
                    .unwrap();
                    sqlx::query(
                        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
                         VALUES (?, 'account', 'catalog-ada', 0)",
                    )
                    .bind(other)
                    .execute(db.write_pool())
                    .await
                    .unwrap();
                }
                _ => unreachable!(),
            }
            if case == "deleted_person" {
                delete_record_as(&db, &record_id, Some("fixture"))
                    .await
                    .unwrap();
            }
            let before = counts(&db).await;
            let error = reconcile_hosted_identity(
                &db,
                "ada@example.com",
                "catalog-ada",
                &probe_arrival().await,
                Some(principal.as_str()),
            )
            .await
            .unwrap_err()
            .to_string();
            let expected = match case {
                "multiple_accounts" => "exactly one canonical account binding",
                "legacy_alias_conflict" => "already bound incompatibly",
                _ => "identity invariant failed",
            };
            assert!(error.contains(expected), "{case}: {error}");
            assert_eq!(counts(&db).await, before, "{case}");
            db.close().await;
        }

        // An established principal inconsistent with custody refuses without
        // rewriting, through the same deduped probe.
        let db = db().await;
        let arrival_value = probe_arrival().await;
        reconcile_hosted_identity(
            &db,
            "ada@example.com",
            "catalog-ada",
            &arrival_value,
            Some(principal.as_str()),
        )
        .await
        .unwrap();
        let before = counts(&db).await;
        let error = reconcile_hosted_identity(
            &db,
            "ada@example.com",
            "catalog-ada",
            &arrival_value,
            Some(mismatch.as_str()),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            error.contains("inconsistent with account custody"),
            "{error}"
        );
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn hit_validates_a_conflicting_legacy_alias_without_rescanning_history() {
        let db = db().await;
        let scans = Arc::new(AtomicUsize::new(0));
        LEGACY_SCAN_COUNT
            .scope(scans.clone(), async {
                resolve_account_identity(&db, "ada@example.com", "catalog-ada")
                    .await
                    .unwrap();
                let other = create_record_as(
                    &db,
                    json!({ "type": "Entity", "kind": "person", "name": "other" }),
                    Some("fixture"),
                )
                .await
                .unwrap();
                sqlx::query(
                    "INSERT INTO bindings (record_id, system, identifier, is_canonical)
                     VALUES (?, 'account', 'catalog-ada', 0)",
                )
                .bind(other)
                .execute(db.write_pool())
                .await
                .unwrap();
                let before = counts(&db).await;

                let error = resolve_account_identity(&db, "ada@example.com", "catalog-ada")
                    .await
                    .unwrap_err();
                assert!(error.to_string().contains("already bound incompatibly"));
                assert_eq!(counts(&db).await, before);
                assert_eq!(
                    scans.load(Ordering::SeqCst),
                    1,
                    "a conflicting hit must use only the indexed binding lookup"
                );
            })
            .await;
        db.close().await;
    }
}
