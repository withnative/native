//! Complete private personal projection observation, encoding v2 (schema79).
//! This is state comparison only. It is not a cursor, admission or receipt.
use crate::{db::Db, Error, Result};
use futures::TryStreamExt;
use sha2::{Digest, Sha256};
use sqlx::{Row, TypeInfo, ValueRef};

const INSTALL_COLUMNS: [&str; 16] = [
    "account_id",
    "package",
    "version",
    "digest",
    "artifact_id",
    "consented_source_revision",
    "declaration_digest",
    "consented_declaration",
    "adoption",
    "request",
    "status",
    "event_id",
    "event_seq",
    "updated_at",
    "adoption_provenance",
    "body_read_admission_event_id",
];
const ORDER_COLUMNS: [&str; 5] = [
    "account_id",
    "tab_order",
    "event_id",
    "event_seq",
    "updated_at",
];

// Deliberately no Debug/Display/serde/raw accessor. Only the future bound
// scope may compare this observation; none of its bytes belong on the wire.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct PersonalAlphaRegistryFingerprint([u8; 32]);

fn refused() -> Error {
    Error::engine("personal alpha registry observation failed")
}

fn next_count(count: u64) -> Result<u64> {
    count.checked_add(1).ok_or_else(refused)
}

struct Encoding(Sha256);
impl Encoding {
    fn new(account: &str) -> Result<Self> {
        let mut value = Self(Sha256::new());
        value
            .0
            .update(b"native.personal-alpha-registry-projection.v2\0");
        value.text(account)?;
        Ok(value)
    }
    fn text(&mut self, value: &str) -> Result<()> {
        let length = u64::try_from(value.len()).map_err(|_| refused())?;
        self.0.update([0x01]);
        self.0.update(length.to_be_bytes());
        self.0.update(value.as_bytes());
        Ok(())
    }
    fn table(&mut self, name: &str, columns: &[&str]) -> Result<()> {
        self.0.update([0x10]);
        self.text(name)?;
        self.0.update(
            u32::try_from(columns.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        for column in columns {
            self.text(column)?;
        }
        Ok(())
    }
    fn row(&mut self, row: &sqlx::sqlite::SqliteRow, columns: &[&str]) -> Result<()> {
        self.0.update([0x20]);
        for (index, column) in columns.iter().enumerate() {
            let raw = row.try_get_raw(index).map_err(|_| refused())?;
            let is_integer = *column == "event_seq";
            if raw.is_null() {
                if !matches!(
                    *column,
                    "request" | "adoption_provenance" | "body_read_admission_event_id"
                ) {
                    return Err(refused());
                }
                self.0.update([0x00]);
            } else if is_integer && raw.type_info().name() == "INTEGER" {
                self.0.update([0x02]);
                self.0.update(
                    row.try_get::<i64, _>(index)
                        .map_err(|_| refused())?
                        .to_be_bytes(),
                );
            } else if !is_integer && raw.type_info().name() == "TEXT" {
                self.text(row.try_get::<&str, _>(index).map_err(|_| refused())?)?;
            } else {
                // No affinity casts, malformed-row skips, or value-bearing errors.
                return Err(refused());
            }
        }
        self.0.update([0x21]);
        Ok(())
    }
    fn end_table(&mut self, count: u64) {
        self.0.update([0x11]);
        self.0.update(count.to_be_bytes());
    }
    fn finish(mut self) -> PersonalAlphaRegistryFingerprint {
        self.0.update([0x12]);
        PersonalAlphaRegistryFingerprint(self.0.finalize().into())
    }
}

#[cfg(test)]
pub(super) async fn probe(db: &Db, account: &str) -> Result<PersonalAlphaRegistryFingerprint> {
    probe_checked(db, account, || Ok(())).await
}

pub(super) async fn probe_checked(
    db: &Db,
    account: &str,
    check: impl Fn() -> Result<()>,
) -> Result<PersonalAlphaRegistryFingerprint> {
    if account.trim().is_empty() {
        return Err(refused());
    }
    check()?;
    let transaction = db.pool().begin().await;
    check()?;
    let mut tx = transaction.map_err(|_| refused())?;
    let mut encoding = Encoding::new(account)?;
    for (name, columns, query) in [
        ("alpha_tab_installs", INSTALL_COLUMNS.as_slice(),
         "SELECT account_id,package,version,digest,artifact_id,consented_source_revision,declaration_digest,consented_declaration,adoption,request,status,event_id,event_seq,updated_at,adoption_provenance,body_read_admission_event_id FROM alpha_tab_installs WHERE account_id=? ORDER BY package COLLATE BINARY"),
        ("alpha_tab_orders", ORDER_COLUMNS.as_slice(),
         "SELECT account_id,tab_order,event_id,event_seq,updated_at FROM alpha_tab_orders WHERE account_id=?"),
    ] {
        encoding.table(name, columns)?;
        let mut count = 0_u64;
        {
            let mut rows = sqlx::query(query).bind(account).fetch(&mut *tx);
            loop {
                check()?;
                let result = rows.try_next().await;
                check()?;
                let row = result.map_err(|_| refused())?;
                let Some(row) = row else { break; };
                encoding.row(&row, columns)?;
                count = next_count(count)?;
            }
        }
        encoding.end_table(count);
        #[cfg(test)]
        if name == "alpha_tab_installs" {
            if let Ok((entered, release)) = BETWEEN_TABLES.try_with(Clone::clone) {
                entered.notify_one();
                check()?;
                release.notified().await;
                check()?;
            }
        }
    }
    // No complete token before the read transaction finishes successfully.
    check()?;
    let result = tx.commit().await;
    check()?;
    result.map_err(|_| refused())?;
    Ok(encoding.finish())
}

#[cfg(test)]
tokio::task_local! {
    pub(super) static BETWEEN_TABLES: (std::sync::Arc<tokio::sync::Notify>, std::sync::Arc<tokio::sync::Notify>);
}

#[cfg(test)]
#[path = "personal_registry_tests.rs"]
mod tests;
