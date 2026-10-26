//! Content-bound human supersession review and deterministic database payoff.
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteConnectOptions, Row, SqlitePool};

use super::{Interaction, Options};
use crate::mcp::{register_builtin_tools, register_surface_tools, ToolRegistry};
use crate::native_cli::{enrichment, import::Discovery};
use crate::{Error, Result};

#[derive(Clone)]
struct Binding {
    id: String,
    title: String,
    record_type: String,
    lifecycle: Option<String>,
    date: Option<String>,
}
async fn read_pool(db: &Path) -> Result<SqlitePool> {
    Ok(SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(db)
            .read_only(true)
            .create_if_missing(false),
    )
    .await?)
}
async fn bindings(pool: &SqlitePool, discovery: &Discovery) -> Result<BTreeMap<String, Binding>> {
    let rows = sqlx::query("SELECT r.id,r.name,r.type,r.lifecycle,s.value AS root,p.value AS path,f.value AS file,d.value AS date FROM records r JOIN facet_values s ON s.record_id=r.id AND s.key='source_root' JOIN facet_values p ON p.record_id=r.id AND p.key='source_path' LEFT JOIN facet_values f ON f.record_id=r.id AND f.key='source_file' LEFT JOIN facet_values d ON d.record_id=r.id AND d.key='stated_date' WHERE r.deleted_at IS NULL ORDER BY r.id").fetch_all(pool).await?;
    let mut bindings = BTreeMap::new();
    for row in rows {
        let root: String = row.try_get("root")?;
        if !discovery.roots.contains(&root) {
            continue;
        }
        let path: String = row
            .try_get::<Option<String>, _>("file")?
            .unwrap_or(row.try_get("path")?);
        let binding = Binding {
            id: row.try_get("id")?,
            title: row.try_get("name")?,
            record_type: row.try_get("type")?,
            lifecycle: row.try_get("lifecycle")?,
            date: row.try_get("date")?,
        };
        if bindings
            .insert(enrichment::key(&root, &path), binding)
            .is_some()
        {
            return Err(Error::engine(
                "duplicate source binding; resolve before review",
            ));
        }
    }
    Ok(bindings)
}
fn pair_key(pair: &[String; 2]) -> Result<String> {
    let mut pair = pair.clone();
    pair.sort();
    Ok(serde_json::to_string(&pair)?)
}
fn hash_for(key: &str, discovery: &Discovery) -> Option<String> {
    discovery
        .entries
        .iter()
        .find(|e| {
            e.file.as_ref().is_some_and(|f| {
                enrichment::key(&e.root, f) == key || format!("{}::{f}", e.root) == key
            })
        })
        .and_then(|e| e.content_sha256.clone())
}
fn current_hashes(pair: &[String; 2], discovery: &Discovery) -> Option<Value> {
    Some(json!({&pair[0]:hash_for(&pair[0],discovery)?, &pair[1]:hash_for(&pair[1],discovery)?}))
}
fn atomic_sidecar(path: &Path, data: &Value) -> Result<()> {
    let mut file = tempfile::NamedTempFile::new_in(
        path.parent()
            .ok_or_else(|| Error::engine("sidecar has no parent"))?,
    )?;
    serde_json::to_writer_pretty(file.as_file_mut(), data)?;
    file.as_file().sync_all()?;
    file.persist(path).map_err(|e| {
        Error::engine(format!(
            "cannot save review decisions: {e}; re-run safely to resume"
        ))
    })?;
    Ok(())
}
pub(super) async fn run(
    opts: &Options,
    discovery: &Discovery,
    db: &Path,
    path: &Path,
    io: &mut Interaction<'_>,
    step: &mut Value,
) -> Result<()> {
    if !path.exists() {
        *step = json!({"candidates":[],"decisions":[],"pending":0});
        return Ok(());
    }
    // Reuse import's source, format and whole-file hash checks. Only current
    // content may be reviewed, and neither a stale nor foreign pair is guessed.
    let plan = enrichment::ImportPlan::load(path, &discovery.roots, &discovery.entries)?;
    let mut data: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    let sidecar: enrichment::Sidecar = serde_json::from_value(data.clone())?;
    let mut candidates = sidecar.supersession_candidates;
    for candidate in &mut candidates {
        candidate.rank();
    }
    candidates.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.pair.cmp(&b.pair)));
    // Match ImportPlan's exact selected keys; accepting an extra legacy alias
    // here could bypass the hash check when both key forms exist in a sidecar.
    let valid: BTreeSet<String> = plan
        .notes
        .keys()
        .map(|&i| {
            let e = &discovery.entries[i];
            let canonical = enrichment::key(&e.root, e.file.as_deref().unwrap());
            if sidecar.notes.contains_key(&canonical) {
                canonical
            } else {
                format!("{}::{}", e.root, e.file.as_deref().unwrap())
            }
        })
        .collect();
    let mut decisions = data
        .get("supersession_decisions")
        .cloned()
        .unwrap_or(json!({}));
    if !decisions.is_object() {
        return Err(Error::engine(
            "invalid supersession_decisions: expected an object",
        ));
    }
    let pool = read_pool(db).await?;
    let mut bound = bindings(&pool, discovery).await?;
    pool.close().await;
    // Legacy aliases are supported only after ImportPlan's ambiguity checks.
    for entry in &discovery.entries {
        if let Some(file) = &entry.file {
            if let Some(record) = bound.get(&enrichment::key(&entry.root, file)).cloned() {
                bound.insert(format!("{}::{file}", entry.root), record);
            }
        }
    }
    let mut pending = Vec::new();
    let mut seen = BTreeSet::new();
    for mut c in candidates {
        if let (Some(n), Some(o)) = (&c.newer, &c.older) {
            c.pair = [n.clone(), o.clone()];
        }
        if c.pair[0] == c.pair[1] || !c.pair.iter().all(|k| valid.contains(k)) {
            continue;
        }
        let key = pair_key(&c.pair)?;
        if !seen.insert(key.clone()) {
            continue;
        }
        let Some(hashes) = current_hashes(&c.pair, discovery) else {
            continue;
        };
        if decisions[&key]["content_sha256"] == hashes {
            continue;
        }
        pending.push((c, key, hashes));
    }
    let pending_total = pending.len();
    let mut shown = Vec::new();
    let mut by_id = BTreeMap::new();
    for (i, (c, key, hashes)) in pending.iter().enumerate() {
        let mut keys = c.pair.clone();
        keys.sort();
        let digest = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                key,
                &hashes[&keys[0]],
                &hashes[&keys[1]]
            ))?)
        );
        let id = format!("s-{}", &digest[..16]);
        if by_id.insert(id.clone(), i + 1).is_some() {
            return Err(Error::engine(
                "candidate id collision; re-list after refreshing enrichment",
            ));
        }
        let title = |key: &str| {
            bound
                .get(key)
                .map(|r| r.title.clone())
                .unwrap_or_else(|| key.to_owned())
        };
        let newer = c.newer.as_deref().map(title);
        let older = c.older.as_deref().map(title);
        let selectable = c
            .newer
            .as_ref()
            .zip(c.older.as_ref())
            .is_some_and(|(n, o)| n != o && bound.contains_key(n) && bound.contains_key(o));
        shown.push(json!({"id":id,"pair":c.pair,"newer":c.newer,"older":c.older,"newer_title":newer,"older_title":older,"evidence":c.evidence,"explicit":c.explicit,"score":c.score,"preselected":c.explicit && selectable,"selectable":selectable}));
        if i >= 15 {
            continue;
        }
        let ordinal = if io.interactive {
            format!("{}. ", i + 1)
        } else {
            String::new()
        };
        io.say(&format!(
            "{ordinal}({id}) {} {} → {} [{}; score {}]\n   Evidence: {}",
            if c.explicit && selectable {
                "[x]"
            } else {
                "[ ]"
            },
            newer.as_deref().unwrap_or("direction unknown"),
            older.unwrap_or_else(|| title(&c.pair[1])),
            if c.explicit { "explicit" } else { "inferred" },
            c.score,
            c.evidence.as_deref().unwrap_or("not supplied")
        ))?;
    }
    let all = shown;
    let shown = &all[..all.len().min(15)];
    *step = json!({"candidates":shown,"decisions":[],"pending":pending_total,"stale_enrichment":plan.stale});
    let resolve_ids = |ids: &[String]| -> Result<BTreeSet<usize>> {
        ids.iter()
            .map(|id| {
                by_id.get(id).copied().ok_or_else(|| {
                    Error::engine(format!(
            "unknown or stale candidate id {id}; re-list with --review-supersession --yes --json"
        ))
                })
            })
            .collect()
    };
    let mut accept = resolve_ids(&opts.accept)?;
    let mut reject = resolve_ids(&opts.reject)?;
    if io.interactive && !shown.is_empty() && accept.is_empty() && reject.is_empty() {
        (accept, reject) = io.choose(
            "Supersession: Enter accepts checked only; numbers accept selected only; 'reject 1,2' rejects selected; 'reject-rest' accepts checked and rejects rest (or '1,2 reject-rest'); 'skip' leaves all undecided: ",
            |reply| {
                let reply = reply.to_ascii_lowercase();
                let (accept, reject) = if ["skip", "s"].contains(&reply.as_str()) {
                    (BTreeSet::new(), BTreeSet::new())
                } else if let Some(selected) = reply.strip_prefix("reject ") {
                    (BTreeSet::new(), super::numbers(selected)?.into_iter().collect())
                } else {
                    let reject_rest = reply.ends_with("reject-rest");
                    let selected = reply.strip_suffix("reject-rest").unwrap_or(&reply).trim();
                    let accept: BTreeSet<_> = if selected.is_empty() {
                        shown.iter().enumerate().filter(|(_, c)| c["preselected"] == true).map(|(i, _)| i + 1).collect()
                    } else { super::numbers(selected)?.into_iter().collect() };
                    let reject = if reject_rest { (1..=shown.len()).filter(|n| !accept.contains(n)).collect() } else { BTreeSet::new() };
                    (accept, reject)
                };
                validate_choices(&accept, &reject, shown)?;
                Ok((accept, reject))
            }
        )?;
    }
    validate_choices(&accept, &reject, &all)?;
    if !accept.is_empty() {
        let current = crate::native_cli::import::discover(&opts.dirs)?;
        for &number in &accept {
            let (candidate, _, hashes) = &pending[number - 1];
            if current_hashes(&candidate.pair, &current).as_ref() != Some(hashes) {
                return Err(Error::engine("notes changed during review; re-run native init to refresh enrichment/import before confirming supersession"));
            }
        }
    }
    let db_handle = if accept.is_empty() {
        None
    } else {
        Some(
            crate::open_existing_database(
                db.to_str()
                    .ok_or_else(|| Error::engine("database path is not UTF-8"))?,
            )
            .await?,
        )
    };
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry)?;
    register_surface_tools(&mut registry)?;
    let caller = if let Some(db) = &db_handle {
        Some(crate::native_cli::sqlite_owner_caller(
            crate::identity::resolve_stdio_account_identity(db, None).await?,
        ))
    } else {
        None
    };
    let mut recorded = Vec::new();
    let outcome=async {
        // Validate the whole selection before any decision or link is written.
        if let Some(db) = &db_handle {
            for &number in &accept {
                let c = &pending[number - 1].0;
                let n = &bound[c.newer.as_ref().unwrap()].id;
                let o = &bound[c.older.as_ref().unwrap()].id;
                refuse_reverse(db.pool(), n, o).await?;
            }
        }
        for number in accept.union(&reject).copied() {
            let (c,key,hashes)=&pending[number-1];
            let accepted=accept.contains(&number);
            if accepted {
                let n=&bound[c.newer.as_ref().unwrap()].id;
                let o=&bound[c.older.as_ref().unwrap()].id;
                let db=db_handle.as_ref().unwrap();
                let exists: i64=sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=? AND relationship='supersedes'").bind(n).bind(o).fetch_one(db.pool()).await?;
                if exists==0 {
                    refuse_reverse(db.pool(), n, o).await?;
                    Box::pin(registry.call(db.clone(),caller.as_ref().unwrap().clone(),"manage_links",json!({"action":"add","source_id":n,"target_id":o,"relationship":"supersedes","note":c.evidence}))).await?;
                }
            }
            let decision=json!({"id":all[number-1]["id"],"pair":c.pair,"newer":c.newer,"older":c.older,"decision":if accepted {"accepted"}else{"rejected"},"decided_at":chrono::Utc::now().to_rfc3339(),"content_sha256":hashes});
            decisions[key]=decision.clone();
            data["supersession_decisions"]=decisions.clone();
            // Checkpoint each decision after its ordinary tool write. If saving
            // fails, existing-link detection makes a retry safe.
            atomic_sidecar(path,&data)?;
            recorded.push(decision);
            step["decisions"] = json!(recorded);
            step["pending"] = json!(pending_total - recorded.len());
        }
        Ok::<(),Error>(())
    }.await;
    if let Some(db) = db_handle {
        db.close().await;
    }
    outcome?;
    let remaining = pending_total - recorded.len();
    if remaining > 0 {
        io.say(&format!("{remaining} supersession candidate(s) left for review. Run native init --review-supersession with the same vault(s) and --db. Nothing is auto-accepted."))?;
    }
    Ok(())
}
fn validate_choices(
    accept: &BTreeSet<usize>,
    reject: &BTreeSet<usize>,
    shown: &[Value],
) -> Result<()> {
    if accept.intersection(reject).next().is_some() {
        return Err(Error::engine(
            "a candidate cannot be both accepted and rejected",
        ));
    }
    for &number in accept.union(reject) {
        if number == 0 || number > shown.len() {
            return Err(Error::engine("candidate number out of range"));
        }
        if accept.contains(&number) && shown[number - 1]["selectable"] != true {
            return Err(Error::engine(
                "cannot accept a supersession with unknown direction or missing import binding",
            ));
        }
    }
    Ok(())
}
async fn refuse_reverse(pool: &SqlitePool, newer: &str, older: &str) -> Result<()> {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE source_id=? AND target_id=? AND relationship='supersedes'")
        .bind(older).bind(newer).fetch_one(pool).await?;
    if exists > 0 {
        return Err(Error::engine("reverse supersedes link already exists; re-list candidates and resolve the conflicting direction before accepting"));
    }
    Ok(())
}

pub(super) async fn payoff(db: &Path, discovery: &Discovery) -> Result<Value> {
    let pool = read_pool(db).await?;
    let outcome=async {
        let records=bindings(&pool,discovery).await?;
        let mut tasks:Vec<_>=records.values().filter(|r|r.record_type=="WorkItem" && matches!(r.lifecycle.as_deref(),Some("open"|"in_progress"))).collect();
        tasks.sort_by(|a,b|a.title.cmp(&b.title).then_with(||a.id.cmp(&b.id)));
        let mut decisions:Vec<_>=records.values().filter(|r|r.record_type=="Resolution").collect();
        decisions.sort_by(|a,b|b.date.cmp(&a.date).then_with(||a.title.cmp(&b.title)).then_with(||a.id.cmp(&b.id)));
        let ids:BTreeSet<_>=records.values().map(|r|r.id.as_str()).collect();
        let mut supersessions=0;
        for row in sqlx::query("SELECT source_id,target_id FROM links WHERE relationship='supersedes'").fetch_all(&pool).await? {
            let source:String=row.try_get("source_id")?; let target:String=row.try_get("target_id")?;
            if ids.contains(source.as_str()) && ids.contains(target.as_str()) {supersessions+=1;}
        }
        let items=|records: &[&Binding],limit| records.iter().take(limit).map(|r|json!({"id":r.id,"title":r.title,"stated_date":r.date})).collect::<Vec<_>>();
        Ok(json!({"tasks":{"count":tasks.len(),"items":items(&tasks,5)},"decisions":{"count":decisions.len(),"items":items(&decisions,3)},"confirmed_supersessions":supersessions}))
    }.await;
    pool.close().await;
    outcome
}
