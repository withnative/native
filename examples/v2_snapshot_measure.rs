//! Counts/bytes/timings only. Refuses original files, symlinks and hard links.
//! Run only on a fresh disposable import directory; never a hosted DATA_DIR.
use native_ce::{db, kernel, query::QueryPrincipal, workspace_snapshot as ws};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Instant,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn disposable(root: &Path, name: &str) -> Result<PathBuf> {
    let path = root.join(name);
    let metadata = std::fs::symlink_metadata(&path)?;
    if !metadata.is_file() {
        return Err("regular disposable file required".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("hard-linked inputs refused".into());
        }
    }
    Ok(path)
}

#[tokio::main]
async fn main() {
    if execute().await.is_err() {
        // Validators may quote private values. Never emit engine diagnostics.
        eprintln!("Counts-only snapshot measurement refused; no private diagnostics emitted");
        std::process::exit(1);
    }
}

async fn pages(db: &db::Db, principal: QueryPrincipal, token: &str) -> Result<Value> {
    let mut report = serde_json::Map::new();
    let mut records = BTreeMap::new();
    let mut facets = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut events = Vec::new();
    let mut previous_adapter_bytes = 0;
    for (name, section) in [
        ("records", ws::SnapshotSection::Records),
        ("facets", ws::SnapshotSection::Facets),
        ("links", ws::SnapshotSection::Links),
        ("content_events", ws::SnapshotSection::ContentEvents),
    ] {
        let started = Instant::now();
        let mut after = None;
        let mut rows = 0;
        let mut bytes = 0;
        let mut page_count = 0;
        loop {
            let page = db
                .page_workspace_snapshot(principal.clone(), token, section, 1000, after.as_deref())
                .await?
                .map_err(|_| "paging restarted")?;
            bytes += serde_json::to_vec(&page.rows)?.len();
            rows += page.rows.len();
            page_count += 1;
            for row in page.rows {
                if !matches!(section, ws::SnapshotSection::ContentEvents) {
                    previous_adapter_bytes += serde_json::to_vec(&row)?.len() * 2 + 1024;
                }
                match section {
                    ws::SnapshotSection::Records => {
                        let row: ws::SnapshotRecord = serde_json::from_value(row)?;
                        records.insert(row.id.clone(), row);
                    }
                    ws::SnapshotSection::Facets => {
                        let row: ws::SnapshotFacet = serde_json::from_value(row)?;
                        facets.insert(row.id.clone(), row);
                    }
                    ws::SnapshotSection::Links => {
                        let row: ws::SnapshotLink = serde_json::from_value(row)?;
                        links.insert(row.id.clone(), row);
                    }
                    ws::SnapshotSection::ContentEvents => {
                        events.push(serde_json::from_value::<ws::SnapshotEvent>(row)?)
                    }
                }
            }
            if !page.has_more {
                break;
            }
            let next = page.after_id.ok_or("missing page cursor")?;
            if after.as_ref() == Some(&next) {
                return Err("page cursor did not advance".into());
            }
            after = Some(next);
        }
        report.insert(name.into(),json!({"rows":rows,"pages":page_count,"json_bytes":bytes,"page_and_decode_ms":started.elapsed().as_secs_f64()*1000.0}));
    }
    report.insert(
        "previous_adapter_estimated_bytes".into(),
        json!(previous_adapter_bytes),
    );
    report.insert(
        "previous_adapter_within_cap".into(),
        json!(previous_adapter_bytes <= ws::SNAPSHOT_MAX_BYTES),
    );
    report.insert(
        "estimated_pin_bytes".into(),
        json!(ws::estimate_entry_bytes(
            principal.credential().len(),
            &records,
            &facets,
            &links,
            &events
        )),
    );
    Ok(Value::Object(report))
}

async fn measure(db: &db::Db, accounts: &[String], concurrent: bool) -> Result<Value> {
    let mut report = Vec::new();
    let mut pins = Vec::new();
    // Three member browser slots plus five agent/window slots, using their
    // actual imported member credentials. No invented principal or grants.
    for slot in 0..if concurrent { 8 } else { accounts.len() } {
        let principal = QueryPrincipal::authenticated(&accounts[slot % accounts.len()], true);
        let started = Instant::now();
        let pin = db.open_workspace_snapshot(principal.clone()).await?;
        let open_ms = started.elapsed().as_secs_f64() * 1000.0;
        let Some(pin) = pin else {
            report.push(json!({"slot":slot,"token_returned":false,"open_ms":open_ms}));
            continue;
        };
        let sections = pages(db, principal.clone(), &pin.token).await?;
        pins.push((principal, pin.token));
        report
            .push(json!({"slot":slot,"token_returned":true,"open_ms":open_ms,"sections":sections}));
    }
    let mut retained = 0;
    for (principal, token) in &pins {
        if db
            .page_workspace_snapshot(
                principal.clone(),
                token,
                ws::SnapshotSection::Records,
                1,
                None,
            )
            .await?
            .is_ok()
        {
            retained += 1;
        }
    }
    Ok(
        json!({"member_accounts_measured":accounts.len(),"slots":report,"tokens_held_at_end":retained,"all_returned_tokens_retained":retained==pins.len()}),
    )
}

async fn execute() -> Result<()> {
    let root =
        PathBuf::from(std::env::args().nth(1).ok_or("directory required")?).canonicalize()?;
    if root.parent() != Some(Path::new("/tmp"))
        || !root.file_name().is_some_and(|n| {
            n.to_string_lossy()
                .starts_with("native-hq-snapshot-measurement-")
        })
    {
        return Err("fresh temporary measurement directory required".into());
    }
    let source = disposable(&root, "v1.db")?;
    let target = disposable(&root, "v2.db")?;
    let import: Value = serde_json::from_slice(&std::fs::read(disposable(&root, "import.json")?)?)?;
    if import["capture_complete"] != true || import["mismatches"] != 0 {
        return Err("complete verified import required".into());
    }
    let v1 = db::open_v1_database(source.to_str().ok_or("path")?).await?;
    let v2 = kernel::open_v2_database(target.to_str().ok_or("path")?).await?;
    kernel::verify_v2_ready(&v2).await?;
    let raw:String=sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_members_roster.v1' ORDER BY seq DESC LIMIT 1").fetch_one(v2.pool()).await?;
    let mut accounts: Vec<String> =
        serde_json::from_value(serde_json::from_str::<Value>(&raw)?["members"].clone())?;
    let admin:String=sqlx::query_scalar("SELECT subject_id FROM policy_entries WHERE policy_anchor_id='native:root' AND subject_kind='account' AND capability='manage' AND effect='allow'").fetch_one(v1.pool()).await?;
    if !accounts.contains(&admin) {
        return Err("admin not in imported roster".into());
    }
    accounts.sort();
    accounts.retain(|id| id != &admin);
    accounts.insert(0, admin);
    accounts.truncate(3);
    let started = Instant::now();
    let index = native_ce::workspace_index::build_on(v1.pool()).await?;
    let v1_index = json!({"estimated_bytes":index.estimated_bytes(),"within_cap":index.within_cap(native_ce::workspace_index::MAX_INDEX_BYTES),"build_ms":started.elapsed().as_secs_f64()*1000.0});
    drop(index);
    let old = measure(&v1, &accounts, false).await?;
    let new = measure(&v2, &accounts, true).await?;
    v1.close().await;
    v2.close().await;
    println!(
        "{}",
        serde_json::to_string(
            &json!({"build_sha":native_ce::FULL_GIT_SHA,"capture_complete":true,"v1_index":v1_index,"v1":old,"v2":new,"per_pin_cap_bytes":ws::SNAPSHOT_MAX_BYTES,"v2_handle_budget_bytes":ws::SNAPSHOT_V2_MAX_BYTES,"v2_token_cap":ws::SNAPSHOT_V2_MAX_TOKENS})
        )?
    );
    Ok(())
}
