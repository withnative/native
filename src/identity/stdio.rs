//! Filesystem-owned account identity for the public node.
//!
//! These helpers deliberately know nothing about hosted catalogues or provider
//! credentials. They derive their authority entirely from the portable file.

use serde_json::json;
use sqlx::Row;
use uuid::Uuid;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::store::{append_in, AppendSpec};

use super::account::{
    identity_invariant, is_account_token, require_canonical_account, require_live_person,
};

/// Resolve the account identity a filesystem-owned stdio process adopts.
///
/// Unlike hosted resolution there is no external email or catalog principal:
/// the file is the authority. A fresh file provisions one portable person
/// identity, a single-account file adopts it, and a multi-account file requires
/// an explicit canonical account token. The whole inspect/provision operation
/// runs under `BEGIN IMMEDIATE`, so concurrent first starts converge on one
/// identity rather than creating one apiece.
pub async fn resolve_stdio_account_identity(
    db: &Db,
    selected_account: Option<&str>,
) -> Result<String> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let rows = sqlx::query(
        "SELECT record_id, identifier, is_canonical FROM bindings
         WHERE system = 'account'
         ORDER BY identifier",
    )
    .fetch_all(&mut *tx)
    .await?;

    if rows.is_empty() {
        if let Some(selected) = selected_account {
            tx.rollback().await?;
            return Err(stdio_selection_error(
                &selected_account_error(selected),
                &[],
            ));
        }

        let record_id = Uuid::new_v4().to_string();
        let token_hex = Uuid::new_v4().simple().to_string();
        let account_token = format!("acct_{token_hex}");
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: record_id.clone(),
                event_type: "record.created".into(),
                payload: json!({
                    "type": "Entity",
                    "kind": "person",
                    "name": format!("Account {}", &token_hex[..8]),
                }),
                actor: Some(account_token.clone()),
            },
        )
        .await?;
        crate::identity::add_binding_internal_in(
            &mut tx,
            &account_token,
            "mint canonical stdio account identity",
            &record_id,
            "account",
            &account_token,
            true,
        )
        .await?;
        crate::instruction_templates::provision_member_in(
            db,
            &mut tx,
            &account_token,
            &record_id,
            crate::instruction_templates::MemberProvisioningAuthority::Standalone,
        )
        .await?;
        db.commit_content(tx).await?;
        return Ok(account_token);
    }

    let canonical_rows = rows
        .iter()
        .filter(|row| row.get::<i64, _>("is_canonical") == 1)
        .collect::<Vec<_>>();
    if canonical_rows.is_empty() {
        tx.rollback().await?;
        return Err(stdio_identity_invariant());
    }

    let mut accounts = Vec::with_capacity(canonical_rows.len());
    for row in canonical_rows {
        let record_id = row.try_get::<String, _>("record_id")?;
        let account_token = row.try_get::<String, _>("identifier")?;
        // Never put an unvalidated external identifier into a diagnostic. A
        // malformed value may itself be an email address or another secret.
        if !is_account_token(&account_token) {
            return Err(stdio_identity_invariant());
        }
        require_live_person(&mut tx, &format!("account '{account_token}'"), &record_id).await?;
        let canonical = require_canonical_account(&mut tx, &record_id).await?;
        if canonical != account_token {
            return Err(identity_invariant(format!(
                "account binding '{account_token}' is not the canonical identity for person record '{record_id}'"
            )));
        }
        accounts.push((account_token, record_id));
    }

    let selected =
        match selected_account {
            Some(selected) if accounts.iter().any(|(account, _)| account == selected) => accounts
                .iter()
                .find(|(account, _)| account == selected)
                .cloned()
                .expect("selected account was found"),
            Some(selected) => {
                tx.rollback().await?;
                return Err(stdio_selection_error(
                    &selected_account_error(selected),
                    &accounts
                        .iter()
                        .map(|(account, _)| account.clone())
                        .collect::<Vec<_>>(),
                ));
            }
            None if accounts.len() == 1 => accounts[0].clone(),
            None => {
                tx.rollback().await?;
                return Err(stdio_selection_error(
                "multiple accounts are present; pass --account <token> or set NATIVE_CE_ACCOUNT",
                &accounts.iter().map(|(account, _)| account.clone()).collect::<Vec<_>>(),
            ));
            }
        };

    let changed = crate::instruction_templates::provision_member_in(
        db,
        &mut tx,
        &selected.0,
        &selected.1,
        crate::instruction_templates::MemberProvisioningAuthority::Standalone,
    )
    .await?;
    if changed {
        db.commit_content(tx).await?;
    } else {
        tx.rollback().await?;
    }
    Ok(selected.0)
}

fn stdio_selection_error(detail: &str, accounts: &[String]) -> Error {
    let available = if accounts.is_empty() {
        "none".to_string()
    } else {
        accounts.join(", ")
    };
    Error::engine(format!(
        "stdio account selection failed: {detail}. Available accounts: {available}"
    ))
}

fn selected_account_error(selected: &str) -> String {
    if is_account_token(selected) {
        format!("selected account '{selected}' is not available")
    } else {
        "selected account token is malformed".to_string()
    }
}

fn stdio_identity_invariant() -> Error {
    identity_invariant("account bindings do not form a valid canonical account identity set")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::create_record_as;

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

    async fn add_account(db: &Db, token: &str, name: &str) -> String {
        let record_id = create_record_as(
            db,
            json!({ "type": "Entity", "kind": "person", "name": name }),
            Some(token),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(&record_id)
        .bind(token)
        .execute(db.write_pool())
        .await
        .unwrap();
        record_id
    }

    #[tokio::test]
    async fn stdio_fresh_resolution_provisions_one_person_without_an_email() {
        let db = db().await;
        let token = resolve_stdio_account_identity(&db, None).await.unwrap();
        assert!(is_account_token(&token), "{token}");
        assert_eq!(counts(&db).await, (11, 11, 1));

        let row = sqlx::query(
            "SELECT r.type, r.kind, r.name, e.actor, b.system, b.identifier, b.is_canonical
             FROM records r
             JOIN content_events e ON e.record_id = r.id
             JOIN bindings b ON b.record_id = r.id",
        )
        .fetch_one(db.write_pool())
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("type"), "Entity");
        assert_eq!(row.get::<String, _>("kind"), "person");
        // There is no address on this path, so the hex stays. Hosted
        // provisioning names the person after their email; stdio deliberately
        // does not follow it.
        assert_eq!(
            row.get::<String, _>("name"),
            format!("Account {}", &token[5..13])
        );
        assert_eq!(row.get::<String, _>("actor"), token);
        assert_eq!(row.get::<String, _>("system"), "account");
        assert_eq!(row.get::<String, _>("identifier"), token);
        assert_eq!(row.get::<i64, _>("is_canonical"), 1);
        db.close().await;
    }

    #[tokio::test]
    async fn stdio_single_account_is_adopted_without_writing() {
        let db = db().await;
        let token = resolve_stdio_account_identity(&db, None).await.unwrap();
        let before = counts(&db).await;
        assert_eq!(
            resolve_stdio_account_identity(&db, None).await.unwrap(),
            token
        );
        assert_eq!(
            resolve_stdio_account_identity(&db, Some(&token))
                .await
                .unwrap(),
            token
        );
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn stdio_account_survives_close_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("portable.db");
        let db = crate::create_database(&path.to_string_lossy())
            .await
            .unwrap();
        let token = resolve_stdio_account_identity(&db, None).await.unwrap();
        db.close().await;

        let reopened = crate::open_existing_database(&path.to_string_lossy())
            .await
            .unwrap();
        assert_eq!(
            resolve_stdio_account_identity(&reopened, None)
                .await
                .unwrap(),
            token
        );
        reopened.close().await;
    }

    #[tokio::test]
    async fn simultaneous_stdio_first_starts_converge() {
        let db = db().await;
        let first = resolve_stdio_account_identity(&db, None);
        let second = resolve_stdio_account_identity(&db, None);
        let (first, second) = tokio::join!(first, second);
        assert_eq!(first.unwrap(), second.unwrap());
        assert_eq!(counts(&db).await, (11, 11, 1));
        db.close().await;
    }

    #[tokio::test]
    async fn stdio_multi_account_files_require_a_valid_explicit_token() {
        let db = db().await;
        let ada = "acct_00000000000000000000000000000000";
        let grace = "acct_11111111111111111111111111111111";
        let ada_id = add_account(&db, ada, "Ada").await;
        add_account(&db, grace, "Grace").await;
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'email', 'ada@example.com', 1)",
        )
        .bind(&ada_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', 'legacy@example.com', 0)",
        )
        .bind(&ada_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let before = counts(&db).await;

        let ambiguous = resolve_stdio_account_identity(&db, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(ambiguous.contains("multiple accounts"), "{ambiguous}");
        assert!(ambiguous.contains(ada), "{ambiguous}");
        assert!(ambiguous.contains(grace), "{ambiguous}");
        assert!(!ambiguous.contains("ada@example.com"), "{ambiguous}");
        assert!(!ambiguous.contains("legacy@example.com"), "{ambiguous}");

        assert_eq!(
            resolve_stdio_account_identity(&db, Some(grace))
                .await
                .unwrap(),
            grace
        );
        let after_provisioning = counts(&db).await;
        let unknown = "acct_22222222222222222222222222222222";
        let invalid = resolve_stdio_account_identity(&db, Some(unknown))
            .await
            .unwrap_err()
            .to_string();
        assert!(invalid.contains("not available"), "{invalid}");
        assert!(invalid.contains(unknown), "{invalid}");
        assert!(invalid.contains(ada), "{invalid}");
        assert!(invalid.contains(grace), "{invalid}");
        assert!(!invalid.contains("ada@example.com"), "{invalid}");
        assert!(!invalid.contains("legacy@example.com"), "{invalid}");

        let malformed = resolve_stdio_account_identity(&db, Some("secret@example.com"))
            .await
            .unwrap_err()
            .to_string();
        assert!(malformed.contains("token is malformed"), "{malformed}");
        assert!(!malformed.contains("secret@example.com"), "{malformed}");
        assert!(malformed.contains(ada), "{malformed}");
        assert!(malformed.contains(grace), "{malformed}");
        assert_ne!(after_provisioning, before);
        assert_eq!(counts(&db).await, after_provisioning);
        db.close().await;
    }

    #[tokio::test]
    async fn stdio_explicit_selection_on_an_empty_file_refuses_without_provisioning() {
        let db = db().await;
        let error =
            resolve_stdio_account_identity(&db, Some("acct_00000000000000000000000000000000"))
                .await
                .unwrap_err()
                .to_string();
        assert!(error.contains("not available"), "{error}");
        assert_eq!(counts(&db).await, (2, 2, 0));
        db.close().await;
    }

    #[tokio::test]
    async fn stdio_noncanonical_only_account_state_fails_closed_without_provisioning() {
        let db = db().await;
        let record_id = create_record_as(
            &db,
            json!({ "type": "Entity", "kind": "person", "name": "Legacy" }),
            Some("fixture"),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', 'legacy-catalog-identity', 0)",
        )
        .bind(record_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let before = counts(&db).await;

        let error = resolve_stdio_account_identity(&db, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("identity invariant failed"), "{error}");
        assert!(!error.contains("legacy-catalog-identity"), "{error}");
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn stdio_malformed_account_identifiers_are_never_disclosed() {
        let db = db().await;
        let record_id = create_record_as(
            &db,
            json!({ "type": "Entity", "kind": "organization", "name": "Wrong" }),
            Some("fixture"),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', 'secret@example.com', 1)",
        )
        .bind(record_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        let before = counts(&db).await;

        let error = resolve_stdio_account_identity(&db, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("identity invariant failed"), "{error}");
        assert!(!error.contains("secret@example.com"), "{error}");
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }

    #[tokio::test]
    async fn stdio_rejects_an_account_binding_to_a_non_person() {
        let db = db().await;
        let token = "acct_00000000000000000000000000000000";
        let record_id = create_record_as(
            &db,
            json!({ "type": "Entity", "kind": "organization", "name": "Wrong" }),
            Some(token),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings (record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(record_id)
        .bind(token)
        .execute(db.write_pool())
        .await
        .unwrap();
        let before = counts(&db).await;
        let error = resolve_stdio_account_identity(&db, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("live Entity with kind='person'"), "{error}");
        assert_eq!(counts(&db).await, before);
        db.close().await;
    }
}
