//! Explicit maintenance of existing canonical files. Never used by serving.
use crate::{authorization::Capability, db::Db, kernel, Error, Result};
use serde_json::{json, Value};
use sqlx::{Connection, SqliteConnection};
use std::{path::Path, process::ExitCode};

pub const USAGE: &str = "usage: native maintenance saved-tabs --db <existing-v2.db> --as <admin-account-binding>\n       native maintenance keyed-receipts --db <existing.db> --as <admin-account-binding>\n\nStop the workspace server before running this command against its canonical database.\nPrepares additive projections and installs/adopts the compiled saved-tab package.\nsaved-tabs accepts existing marked v2 files only. keyed-receipts accepts current v1 or marked v2.\nNever use a node's read-only local generation.\nRe-running preserves saved identities, names and retirement history. JSON on stdout.\n";

pub fn run_cli(args: &[String]) -> ExitCode {
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "--help" | "-h"))
    {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let mut args = args.iter();
    let command = args.next().map(String::as_str);
    if !matches!(command, Some("saved-tabs" | "keyed-receipts")) {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let mut db = None;
    let mut account = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--db" if db.is_none() => db = args.next().cloned(),
            "--as" if account.is_none() => account = args.next().cloned(),
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let (Some(db), Some(account)) = (db, account) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("native maintenance: {error}");
            return ExitCode::from(1);
        }
    };
    let result = runtime.block_on(async {
        match command {
            Some("keyed-receipts") => prepare_keyed_receipts(Path::new(&db), &account).await,
            _ => prepare_saved_tabs(Path::new(&db), &account).await,
        }
    });
    match result {
        Ok(result) => {
            println!("{result}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("native maintenance: {error}");
            ExitCode::from(1)
        }
    }
}

/// File-owning operator path, independent of import activation. Authenticate the
/// account/root authority before any schema preparation or canonical append.
pub async fn prepare_saved_tabs(path: &Path, account: &str) -> Result<Value> {
    if !path.is_file() || !crate::identity::account::is_account_token(account) {
        return Err(Error::engine(
            "maintenance requires an existing v2 file and canonical account binding",
        ));
    }
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(true);
    let mut probe = SqliteConnection::connect_with(&options).await?;
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut probe)
        .await?;
    probe.close().await?;
    if marker != crate::db::V2_APPLICATION_ID {
        return Err(Error::engine(
            "maintenance refuses unmarked, v1 or foreign databases",
        ));
    }
    let path = path
        .to_str()
        .ok_or_else(|| Error::engine("database path must be UTF-8"))?;
    let db = crate::db::open_existing_v2_file(path).await?;
    let result = prepare_on(&db, account).await;
    db.close().await;
    result
}
async fn prepare_on(db: &Db, account: &str) -> Result<Value> {
    let actor = kernel::resolve_caller_principal_by_binding(db, account)
        .await?
        .filter(|(_, kind, _)| kind == "account")
        .map(|(id, _, _)| id)
        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
    let mut read = db.pool().begin().await?;
    kernel::kernel_require(
        &mut read,
        &actor,
        crate::events::KERNEL_ROOT_ID,
        Capability::Manage,
    )
    .await?;
    let tables:i64=sqlx::query_scalar("SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('kernel_saved_tabs','kernel_saved_tab_operations')").fetch_one(&mut *read).await?;
    let history: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE type='kernel.saved_tab_changed.v1')",
    )
    .fetch_one(&mut *read)
    .await?;
    read.rollback().await?;
    kernel::prepare_v2_database(db).await?;
    if tables != 2 && history {
        kernel::replay_all_projections(db).await?;
    }
    let manifest = crate::v2_standard::saved_tabs::package();
    let identity = kernel::install_package_as(db, &actor, &manifest).await?;
    let mut read = db.pool().begin().await?;
    let available = kernel::saved_tabs::available_on(&mut read).await?;
    read.rollback().await?;
    if !available {
        kernel::adopt_package_at(
            db,
            &actor,
            crate::events::KERNEL_ROOT_ID,
            &manifest,
            Some(&identity),
            &[],
        )
        .await?;
    }
    kernel::verify_v2_ready(db).await?;
    Ok(
        json!({"outcome":"ready","package":"native.saved_tabs/saved_tabs@1","reconstructed":tables!=2 && history}),
    )
}

/// Offline canonical maintenance. The file must already be a current v1 or
/// marked v2 database; account/root Manage admission precedes preparation.
pub async fn prepare_keyed_receipts(path: &Path, account: &str) -> Result<Value> {
    if !path.is_file() || !crate::identity::account::is_account_token(account) {
        return Err(Error::engine(
            "keyed-receipts requires an existing canonical file and account binding",
        ));
    }
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(true);
    let mut probe = SqliteConnection::connect_with(&options).await?;
    let marker: i64 = sqlx::query_scalar("PRAGMA application_id")
        .fetch_one(&mut probe)
        .await?;
    probe.close().await?;
    let filename = path
        .to_str()
        .ok_or_else(|| Error::engine("database path must be UTF-8"))?;
    let v2 = marker == crate::db::V2_APPLICATION_ID;
    let v1 = marker == 0
        || (crate::interchange::source_history_application_id(1)
            ..=crate::interchange::source_history_application_id(crate::interchange::REVISION))
            .contains(&marker);
    // Ordinary writable v1 open can reconcile the meta tier. Authorize on
    // physically read-only pools first, before that opener can change rows.
    if v1 {
        let admission = crate::db::open_existing_database_standby_read_only(filename).await?;
        let authorized = require_v1_receipt_maintenance_authority(&admission, account).await;
        admission.close().await;
        authorized?;
    }
    let db = if v2 {
        crate::db::open_existing_v2_file(filename).await?
    } else if v1 {
        // This opener verifies the exact current engine schema and refuses
        // foreign files and member profiles without creating or migrating.
        crate::db::open_existing_database(filename).await?
    } else {
        return Err(Error::engine(
            "keyed-receipts refuses foreign or member-profile databases",
        ));
    };
    let result = prepare_keyed_receipts_on(&db, account, v2).await;
    db.close().await;
    result
}

async fn prepare_keyed_receipts_on(db: &Db, account: &str, v2: bool) -> Result<Value> {
    if v2 {
        let actor = kernel::resolve_caller_principal_by_binding(db, account)
            .await?
            .filter(|(_, kind, _)| kind == "account")
            .map(|(id, _, _)| id)
            .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
        let mut read = db.pool().begin().await?;
        kernel::kernel_require(
            &mut read,
            &actor,
            crate::events::KERNEL_ROOT_ID,
            Capability::Manage,
        )
        .await?;
        read.rollback().await?;
        kernel::mcp_write_receipts::prepare(db).await?;
        let mut read = db.pool().begin().await?;
        kernel::mcp_write_receipts::require_covered_on(&mut read).await?;
        read.rollback().await?;
    } else {
        require_v1_receipt_maintenance_authority(db, account).await?;
        crate::provenance::prepare_keyed_receipt_anchors(db).await?;
        let mut read = db.pool().begin().await?;
        crate::provenance::verify_keyed_receipt_anchor_coverage_on(&mut read).await?;
        read.rollback().await?;
    }
    Ok(json!({"outcome":"ready","engine":if v2 {"v2"} else {"v1"},"maintenance":"keyed-receipts"}))
}

async fn require_v1_receipt_maintenance_authority(db: &Db, account: &str) -> Result<()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM bindings b JOIN records r ON r.id=b.record_id \
         WHERE b.system='account' AND b.identifier=? AND b.is_canonical=1 \
           AND r.type='Entity' AND r.kind='person' AND r.deleted_at IS NULL)",
    )
    .bind(account)
    .fetch_one(db.pool())
    .await?;
    if !valid {
        return Err(Error::engine("canonical account binding is unavailable"));
    }
    crate::authorization::require_capability(
        db,
        crate::authorization::Principal::bound(account, false),
        crate::schema::ROOT_RECORD_ID,
        Capability::Manage,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod keyed_receipt_tests;
