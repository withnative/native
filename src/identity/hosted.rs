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
    identity_invariant, is_account_token, require_canonical_account, require_live_person,
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
/// The complete lookup/create/legacy-alias operation is serialized by one
/// `BEGIN IMMEDIATE` transaction. This is deliberately not implemented as a
/// read followed by a retrying insert: the transaction is also the boundary
/// that keeps malformed-state failures from partially repairing the file.
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
    let mut connection = db.write_pool().begin().await?;
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
        [] => crate::identity::add_binding_internal_in(
            tx,
            actor,
            "bind account-scoped federation principal to hosted member",
            record_id,
            "native-principal",
            &normalized,
            true,
        )
        .await,
        [existing] if existing == &normalized => Ok(false),
        [..] => Err(identity_invariant(format!(
            "person record '{record_id}' has a canonical native-principal inconsistent with account custody"
        ))),
    }
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
