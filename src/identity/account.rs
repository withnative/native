//! Shared validation for canonical portable account identities.

use sqlx::Row;

use crate::error::{Error, Result};

pub(crate) async fn require_live_person(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    binding: &str,
    record_id: &str,
) -> Result<()> {
    let record = sqlx::query("SELECT type, kind, deleted_at FROM records WHERE id = ?")
        .bind(record_id)
        .fetch_optional(&mut **tx)
        .await?;
    let Some(record) = record else {
        return Err(identity_invariant(format!(
            "{binding} points to missing record '{record_id}'"
        )));
    };
    let record_type = record.try_get::<String, _>("type")?;
    let kind = record.try_get::<Option<String>, _>("kind")?;
    let deleted_at = record.try_get::<Option<String>, _>("deleted_at")?;
    if record_type != "Entity" || kind.as_deref() != Some("person") || deleted_at.is_some() {
        return Err(identity_invariant(format!(
            "{binding} must point to a live Entity with kind='person' (found record '{record_id}')"
        )));
    }
    Ok(())
}

pub(crate) async fn require_canonical_account(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    record_id: &str,
) -> Result<String> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT identifier FROM bindings
         WHERE record_id = ? AND system = 'account' AND is_canonical = 1",
    )
    .bind(record_id)
    .fetch_all(&mut **tx)
    .await?;
    match canonical_account_from_rows(record_id, &rows)? {
        Some(token) => Ok(token),
        None => Err(identity_invariant(format!(
            "person record '{record_id}' must have exactly one canonical account binding (found 0)"
        ))),
    }
}

/// Validate already-fetched canonical account identifiers for `record_id`
/// against the single portable-identity authority.
///
/// Empty means "no canonical account": repairable, so the caller falls back
/// to provisioning/repair (`Ok(None)`). Exactly one portable token is the
/// established case; anything else (a malformed token, multiples) is corrupt
/// state and fails closed. Shared by the warm read probe and the repair path
/// so both enforce the same invariant without copying its error strings.
pub(crate) fn canonical_account_from_rows(
    record_id: &str,
    rows: &[String],
) -> Result<Option<String>> {
    match rows {
        [token] => {
            if !is_account_token(token) {
                return Err(identity_invariant(format!(
                    "person record '{record_id}' has malformed canonical account token"
                )));
            }
            Ok(Some(token.clone()))
        }
        [] => Ok(None),
        _ => Err(identity_invariant(format!(
            "person record '{record_id}' must have exactly one canonical account binding (found {})",
            rows.len()
        ))),
    }
}

pub(crate) fn is_account_token(token: &str) -> bool {
    token.len() == 37
        && token.starts_with("acct_")
        && token[5..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn identity_invariant(detail: impl std::fmt::Display) -> Error {
    Error::engine(format!(
        "in-file account identity invariant failed: {detail}"
    ))
}
