//! Tool — `get_workspace_snapshot` (M3, epic 6b1f3c2).
//!
//! One tool with three actions sharing one response vocabulary. `open` pins
//! the caller's filtered public snapshot under a token; `page` reads sections
//! of that pin; `catch_up` diffs the pin against a fresh M2 view. Every answer
//! carries the stamp triple plus exactly one of a payload, `restart_required`,
//! or `unavailable` — the last being the honest generic signal for M2 `None`,
//! which must never read as an empty workspace.

use serde::Deserialize;
use serde_json::{json, Value};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::parse_args;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::workspace_snapshot::{
    CatchUpOutcome, SnapshotSection, SNAPSHOT_PAGE_DEFAULT, SNAPSHOT_PAGE_MAX,
};

#[derive(Debug, Deserialize)]
struct WorkspaceSnapshotArgs {
    action: String,
    #[serde(default)]
    snapshot_token: Option<String>,
    #[serde(default)]
    section: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    after_id: Option<String>,
    /// Opt into a fence-moved delta on `catch_up`: when the
    /// authorization/relationship/unit fences moved but M2 holds a fresh
    /// filtered view, return the exact diff with `fence_moved: true`
    /// instead of `restart_required`. Defaults to false (today's restarts).
    #[serde(default)]
    accept_fence_moved: bool,
}

fn unavailable() -> Value {
    json!({
        "unavailable": true,
        "reason": "index_unavailable",
        "retry_hint": "retry_fresh",
    })
}

fn restart(reason: &str) -> Value {
    json!({
        "restart_required": true,
        "reason": reason,
    })
}

async fn get_workspace_snapshot(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: WorkspaceSnapshotArgs = parse_args("get_workspace_snapshot", arguments)?;
    let principal = (&caller).into();
    match args.action.as_str() {
        "open" => match db.open_workspace_snapshot(principal).await? {
            Some(opened) => Ok(json!({
                "snapshot_token": opened.token,
                "content_seq": opened.content_seq,
                "authorization_epoch": opened.authorization_epoch,
                "relationship_seq": opened.relationship_seq,
            })),
            None => Ok(unavailable()),
        },
        "page" => {
            let token = args.snapshot_token.as_deref().ok_or_else(|| {
                Error::engine("get_workspace_snapshot page requires snapshot_token")
            })?;
            let section_name = args.section.as_deref().ok_or_else(|| {
                Error::engine(
                    "get_workspace_snapshot page requires section: records|facets|links|content_events",
                )
            })?;
            let section = SnapshotSection::parse(section_name).ok_or_else(|| {
                Error::engine(
                    "get_workspace_snapshot page requires section: records|facets|links|content_events",
                )
            })?;
            let limit = args
                .limit
                .unwrap_or(SNAPSHOT_PAGE_DEFAULT)
                .min(SNAPSHOT_PAGE_MAX);
            match db
                .page_workspace_snapshot(principal, token, section, limit, args.after_id.as_deref())
                .await?
            {
                Ok(page) => Ok(json!({
                    "snapshot_token": page.token,
                    "content_seq": page.content_seq,
                    "authorization_epoch": page.authorization_epoch,
                    "relationship_seq": page.relationship_seq,
                    "section": page.section,
                    "rows": page.rows,
                    "after_id": page.after_id,
                    "has_more": page.has_more,
                })),
                Err(lookup) => match lookup {
                    crate::workspace_snapshot::SnapshotLookup::Restart { reason } => {
                        Ok(restart(reason))
                    }
                },
            }
        }
        "catch_up" => {
            let token = args.snapshot_token.as_deref().ok_or_else(|| {
                Error::engine("get_workspace_snapshot catch_up requires snapshot_token")
            })?;
            match db
                .catch_up_workspace_snapshot(principal, token, args.accept_fence_moved)
                .await?
            {
                CatchUpOutcome::Delta(delta) => {
                    // `fence_moved` is emitted only when the caller opted in:
                    // an opt-out delta carries exactly the keys main has.
                    let mut out = json!({
                        "snapshot_token": delta.token,
                        "content_seq": delta.content_seq,
                        "authorization_epoch": delta.authorization_epoch,
                        "relationship_seq": delta.relationship_seq,
                        "upsert_records": delta.upsert_records,
                        "delete_record_ids": delta.delete_record_ids,
                        "upsert_facets": delta.upsert_facets,
                        "delete_facet_ids": delta.delete_facet_ids,
                        "delete_facet_keys": delta.delete_facet_keys,
                        "upsert_links": delta.upsert_links,
                        "delete_link_ids": delta.delete_link_ids,
                        "delete_link_keys": delta.delete_link_keys,
                        "content_events": delta.content_events,
                    });
                    if args.accept_fence_moved {
                        out["fence_moved"] = json!(delta.fence_moved);
                    }
                    Ok(out)
                }
                CatchUpOutcome::Restart { reason } => Ok(restart(reason)),
                CatchUpOutcome::Unavailable => Ok(unavailable()),
            }
        }
        other => Err(Error::engine(format!(
            "get_workspace_snapshot unknown action '{other}': expected open|page|catch_up"
        ))),
    }
}
/// Register `get_workspace_snapshot` alongside the other query tools.
/// Caller-filtered read: the handler derives the principal from the caller,
/// never from arguments, and serves only the governed-minus-body projection.
pub fn register_workspace_snapshot_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::GetWorkspaceSnapshot,
        "Pinned per-principal workspace snapshot over the materialised index: \
         open pins the caller's filtered records/facets/links plus stamps, \
         page reads one section of that pin across calls, catch_up diffs the \
         pin against a fresh view with exact row upserts/deletes and a new \
          token. Fence moves, expired tokens, or wide gaps return \
          restart_required (discard and re-open); catch_up with \
          accept_fence_moved:true returns the exact diff with fence_moved:true \
          on a fence move instead; an unavailable index returns \
         unavailable with retry_hint (use the governed read path, never an \
         empty model).",
        json!({
            "type": "object",
            "properties": {
                "action": { "type": "string", "enum": ["open", "page", "catch_up"], "description": "open pins a fresh snapshot; page reads one section of a token; catch_up diffs a token against the current view." },
                "snapshot_token": { "type": "string", "description": "Opaque pin from open (required for page and catch_up)." },
                "section": { "type": "string", "description": "Page section for action=page: records|facets|links|content_events." },
                "limit": { "type": "integer", "minimum": 1, "maximum": 1000, "description": "Max rows in this page (default 500)." },
                "after_id": { "type": "string", "description": "Resume cursor from the previous page's after_id." },
                "accept_fence_moved": { "type": "boolean", "description": "For action=catch_up: return the exact diff with fence_moved:true when authorization/relationship/unit fences moved instead of restart_required. Defaults to false." }
            },
            "required": ["action"],
            "additionalProperties": false
        }),
        get_workspace_snapshot,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::mcp::{register_surface_tools, ToolRegistry};
    use crate::store::{create_record, update_record};

    const COMMON_ID: &str = "9e795003-0000-4000-8000-000000000001";
    const ALICE_ID: &str = "9e795003-0000-4000-8000-000000000002";
    const BEA_ID: &str = "9e795003-0000-4000-8000-000000000003";

    async fn fixture() -> Db {
        let db = crate::create_database(":memory:").await.unwrap();
        for (id, name) in [
            (COMMON_ID, "Common"),
            (ALICE_ID, "Alice only"),
            (BEA_ID, "Bea only"),
        ] {
            create_record(
                &db,
                json!({
                    "id": id, "type": "Document", "kind": "note", "name": name,
                    "home_id": crate::schema::ROOT_RECORD_ID
                }),
            )
            .await
            .unwrap();
        }
        replace_explicit_policy(
            &db,
            "test:policy",
            COMMON_ID,
            vec![
                AllowEntry::account("alice", Capability::View),
                AllowEntry::account("bea", Capability::View),
            ],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            ALICE_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            BEA_ID,
            vec![AllowEntry::account("bea", Capability::View)],
        )
        .await
        .unwrap();
        db
    }

    async fn call(db: &Db, caller: Caller, args: Value) -> Value {
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        registry
            .call(db.clone(), caller, "get_workspace_snapshot", args)
            .await
            .unwrap()
    }

    fn record_ids(page: &Value) -> Vec<String> {
        page["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[tokio::test]
    async fn tool_serves_two_principals_their_own_rows() {
        let db = fixture().await;
        let alice = Caller::authenticated("alice");
        let bea = Caller::authenticated("bea");
        let alice_open = call(&db, alice.clone(), json!({ "action": "open" })).await;
        let alice_token = alice_open["snapshot_token"].as_str().unwrap();
        let page = call(
            &db,
            alice.clone(),
            json!({ "action": "page", "snapshot_token": alice_token, "section": "records" }),
        )
        .await;
        let ids = record_ids(&page);
        assert!(ids.contains(&COMMON_ID.to_string()));
        assert!(ids.contains(&ALICE_ID.to_string()));
        assert!(!ids.contains(&BEA_ID.to_string()));
        // Wire keys match the governed columns, not Rust field names.
        for row in page["rows"].as_array().unwrap() {
            assert!(row.get("type").is_some());
            assert!(row.get("record_type").is_none());
        }
        let bea_open = call(&db, bea.clone(), json!({ "action": "open" })).await;
        let bea_page = call(
            &db,
            bea.clone(),
            json!({
                "action": "page",
                "snapshot_token": bea_open["snapshot_token"].as_str().unwrap(),
                "section": "records",
            }),
        )
        .await;
        let bea_ids = record_ids(&bea_page);
        assert!(bea_ids.contains(&COMMON_ID.to_string()));
        assert!(bea_ids.contains(&BEA_ID.to_string()));
        assert!(!bea_ids.contains(&ALICE_ID.to_string()));
    }

    #[tokio::test]
    async fn tool_restarts_revoked_pin_with_no_rows() {
        let db = fixture().await;
        let bea = Caller::authenticated("bea");
        let opened = call(&db, bea.clone(), json!({ "action": "open" })).await;
        let token = opened["snapshot_token"].as_str().unwrap().to_string();
        replace_explicit_policy(
            &db,
            "test:narrow",
            COMMON_ID,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let caught = call(
            &db,
            bea.clone(),
            json!({ "action": "catch_up", "snapshot_token": &token }),
        )
        .await;
        assert_eq!(caught["restart_required"], true);
        assert!(caught.get("upsert_records").is_none());
        let paged = call(
            &db,
            bea.clone(),
            json!({ "action": "page", "snapshot_token": &token, "section": "records" }),
        )
        .await;
        assert_eq!(paged["restart_required"], true);
        assert!(paged.get("rows").is_none());
    }

    #[tokio::test]
    async fn tool_catch_up_opt_in_returns_fence_moved_delta() {
        let db = fixture().await;
        let alice = Caller::authenticated("alice");
        let opened = call(&db, alice.clone(), json!({ "action": "open" })).await;
        let token = opened["snapshot_token"].as_str().unwrap().to_string();
        // A record INSERT moves the authorization epoch by schema trigger.
        let newcomer = "9e795003-0000-4000-8000-000000000041";
        create_record(
            &db,
            json!({
                "id": newcomer, "type": "Document", "kind": "note", "name": "Newcomer",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            newcomer,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        // Default (flag absent) still restarts on the moved fence.
        let restarted = call(
            &db,
            alice.clone(),
            json!({ "action": "catch_up", "snapshot_token": &token }),
        )
        .await;
        assert_eq!(restarted["restart_required"], true);
        assert!(restarted.get("upsert_records").is_none());
        // Opt-in returns the exact diff flagged fence_moved:true.
        let delta = call(
            &db,
            alice.clone(),
            json!({ "action": "catch_up", "snapshot_token": &token, "accept_fence_moved": true }),
        )
        .await;
        assert_eq!(delta["fence_moved"], true);
        let upserted: Vec<&str> = delta["upsert_records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert!(upserted.contains(&newcomer));
        assert!(delta["delete_record_ids"].as_array().unwrap().is_empty());
        // With the flag passed and fences steady, the key is present as false.
        let steady = call(
            &db,
            alice.clone(),
            json!({ "action": "catch_up", "snapshot_token": delta["snapshot_token"], "accept_fence_moved": true }),
        )
        .await;
        assert_eq!(steady["fence_moved"], false);
    }

    #[tokio::test]
    async fn tool_catch_up_opt_out_omits_fence_moved() {
        // Byte-identical contract: without the flag the delta carries
        // exactly the keys main has — no `fence_moved` member at all.
        let db = fixture().await;
        let alice = Caller::authenticated("alice");
        let opened = call(&db, alice.clone(), json!({ "action": "open" })).await;
        let token = opened["snapshot_token"].as_str().unwrap().to_string();
        // A rename moves no fence, so the default path diffs.
        update_record(&db, ALICE_ID, json!({ "name": "Alice renamed" }))
            .await
            .unwrap();
        let delta = call(
            &db,
            alice.clone(),
            json!({ "action": "catch_up", "snapshot_token": &token }),
        )
        .await;
        assert!(delta.get("restart_required").is_none());
        assert!(delta.get("fence_moved").is_none());
        let mut keys: Vec<&str> = delta
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "authorization_epoch",
                "content_events",
                "content_seq",
                "delete_facet_ids",
                "delete_facet_keys",
                "delete_link_ids",
                "delete_link_keys",
                "delete_record_ids",
                "relationship_seq",
                "run_context",
                "snapshot_token",
                "upsert_facets",
                "upsert_links",
                "upsert_records",
            ],
            "opt-out delta carries exactly the keys main has"
        );
        let upserted: Vec<&str> = delta["upsert_records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect();
        assert!(upserted.contains(&ALICE_ID));
    }

    #[tokio::test]
    async fn tool_rejects_malformed_calls() {
        let db = fixture().await;
        let alice = Caller::authenticated("alice");
        let mut registry = ToolRegistry::new();
        register_surface_tools(&mut registry).unwrap();
        assert!(registry
            .call(
                db.clone(),
                alice.clone(),
                "get_workspace_snapshot",
                json!({ "action": "dance" })
            )
            .await
            .is_err());
        assert!(registry
            .call(
                db.clone(),
                alice.clone(),
                "get_workspace_snapshot",
                json!({ "action": "page", "section": "records" })
            )
            .await
            .is_err());
        // Over-cap reads are unavailable, never empty.
        let id = "9e795003-0000-4000-8000-000000000009";
        create_record(
            &db,
            json!({
                "id": id, "type": "Document", "kind": "note", "name": "large",
                "home_id": crate::schema::ROOT_RECORD_ID
            }),
        )
        .await
        .unwrap();
        replace_explicit_policy(
            &db,
            "test:policy",
            id,
            vec![AllowEntry::account("alice", Capability::View)],
        )
        .await
        .unwrap();
        let large = "x".repeat(25 * 1024 * 1024);
        sqlx::query("UPDATE records SET summary = ? WHERE id = ?")
            .bind(large)
            .bind(id)
            .execute(db.write_pool())
            .await
            .unwrap();
        let denied = call(&db, alice.clone(), json!({ "action": "open" })).await;
        assert_eq!(denied["unavailable"], true);
        assert!(denied.get("snapshot_token").is_none());
    }
}
