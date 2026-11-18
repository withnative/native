//! Broker wire contract: tool names, outbound allowlist, and the
//! consumer-neutral projection (SessionSummary / timeline items).
//!
//! Shapes follow Desktop's broker semantics (`registry.ts` hostEpoch, `daemon.ts`
//! list/follow, `contract.ts` SessionSummary/HostSummary) and the app-side
//! shapes in `core.d.ts` — mapped here onto daemon agent snapshots and the
//! projected timeline, never invented.

use serde_json::{json, Value};

/// Tool names intercepted in `route_message` like `node_status`, never
/// forwarded upstream.
pub const TOOL_CAPABILITIES: &str = "node_agent_sessions_capabilities";
pub const TOOL_LIST: &str = "node_agent_sessions_list";
pub const TOOL_HISTORY: &str = "node_agent_sessions_history";
pub const TOOL_FOLLOW: &str = "node_agent_sessions_follow";
pub const TOOL_UNFOLLOW: &str = "node_agent_sessions_unfollow";

/// Operations advertised in the capabilities reply when configured.
pub const OPERATIONS: &[&str] = &["list", "history", "follow"];

/// Push notification method sent on the connection that followed.
pub const EVENT_NOTIFICATION: &str = "notifications/node_agent_sessions/event";

/// Max follows per connection (mirrors Desktop's `MAX_FOLLOWS = 4`).
pub const MAX_FOLLOWS_PER_CONNECTION: usize = 4;
/// Follow tail page size (mirrors Desktop's 1 s tail poll with limit 50).
pub const FOLLOW_PAGE_LIMIT: u64 = 50;
/// History default/cap (Desktop reads up to 100 for an explicit page).
pub const HISTORY_DEFAULT_LIMIT: u64 = 50;
pub const HISTORY_MAX_LIMIT: u64 = 100;
/// List page size for fetch-all.
pub const LIST_PAGE_LIMIT: u64 = 200;

/// Session id shape (Desktop `contract.ts`: 1..128 of `[A-Za-z0-9:_-]`).
fn is_valid_session_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'_' || b == b'-')
}

/// Permitted outbound daemon message types for the broker. No label writes,
/// no sends, no creates, no permission traffic.
fn allowed_keys(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "fetch_agents_request" => Some(&[
            "type",
            "requestId",
            "scope",
            "filter",
            "sort",
            "page",
            "subscribe",
            "sync",
        ]),
        "fetch_agent_timeline_request" => Some(&[
            "type",
            "agentId",
            "requestId",
            "direction",
            "cursor",
            "limit",
            "projection",
            "mergeWindow",
        ]),
        "agent.timeline.set_subscription.request" => Some(&["type", "agentIds", "requestId"]),
        "ping" => Some(&["type"]),
        _ => None,
    }
}

/// Allowlist gate for broker outbound daemon traffic. Each permitted read must
/// carry only its protocol fields. Everything else is refused — in particular
/// any agent send, agent creation, label write, or permission traffic.
pub fn check_broker_outbound_allowed(message: &Value) -> std::result::Result<(), String> {
    let Some(kind) = message.get("type").and_then(Value::as_str) else {
        return Err("daemon message has no type".into());
    };
    let Some(keys) = allowed_keys(kind) else {
        return Err(format!("daemon call not permitted for the broker: {kind}"));
    };
    let Some(map) = message.as_object() else {
        return Err("daemon message is not an object".into());
    };
    for key in map.keys() {
        if !keys.contains(&key.as_str()) {
            return Err(format!("field not permitted on {kind}: {key}"));
        }
    }
    Ok(())
}

/// `fetch_agents_request` (fetch-all, no label subscription; the broker owns
/// no daemon subscriptions in slice 1 — follow uses tail polling).
pub fn fetch_agents_message(request_id: &str, cursor: Option<&str>) -> Value {
    let mut message = json!({
        "type": "fetch_agents_request",
        "requestId": request_id,
        "page": {"limit": LIST_PAGE_LIMIT},
    });
    if let Some(cursor) = cursor {
        message["page"]["cursor"] = cursor.into();
    }
    message
}

/// Projected timeline page fetch: tail for a snapshot, `after` + cursor for
/// history paging.
pub fn fetch_timeline_message(
    agent_id: &str,
    request_id: &str,
    direction: &str,
    cursor: Option<&Value>,
    limit: u64,
) -> Value {
    let mut message = json!({
        "type": "fetch_agent_timeline_request",
        "agentId": agent_id,
        "requestId": request_id,
        "direction": direction,
        "projection": "projected",
        "limit": limit,
    });
    if let Some(cursor) = cursor {
        message["cursor"] = cursor.clone();
    }
    message
}

/// Map one daemon agent snapshot (+ project row) to a consumer-neutral
/// `SessionSummary` value. Returns `None` for archived agents or snapshots
/// without an id. Mirrors Desktop's `summarizeSession` (projection.ts):
/// truncations apply to display strings only, never to ids.
pub fn summarize_agent(
    agent: &Value,
    project: Option<&Value>,
    host_id: &str,
    host_label: &str,
    host_epoch: &str,
) -> Option<Value> {
    if agent.get("archivedAt").is_some_and(|v| !v.is_null()) {
        return None;
    }
    let id = agent.get("id")?.as_str()?;
    if !is_valid_session_id(id) {
        return None;
    }
    let clip = |value: Option<&str>, max: usize| {
        value.map(|s| {
            if s.len() > max {
                s[..max].to_owned()
            } else {
                s.to_owned()
            }
        })
    };
    let labels = agent.get("labels").and_then(Value::as_object);
    let label_str = |key: &str| {
        labels
            .and_then(|m| m.get(key))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let mut summary = json!({
        "id": id,
        "hostId": host_id,
        "hostLabel": host_label,
        "hostEpoch": host_epoch,
        "title": agent.get("title").and_then(Value::as_str).map(|t| t.chars().take(500).collect::<String>()),
        "provider": agent.get("provider").and_then(Value::as_str).unwrap_or("").chars().take(128).collect::<String>(),
        "model": agent.get("model").and_then(Value::as_str).map(|m| m.chars().take(256).collect::<String>()),
        "status": agent.get("status").and_then(Value::as_str).unwrap_or(""),
        "lastActivity": agent.get("updatedAt").and_then(Value::as_str).unwrap_or(""),
        "workspace": {
            "id": agent.get("workspaceId").and_then(Value::as_str),
            "name": project.and_then(|p| p.get("workspaceName")).and_then(Value::as_str).map(|n| n.chars().take(500).collect::<String>()),
        },
    });
    if summary["title"].is_null() {
        summary["title"] = Value::Null;
    }
    if summary["model"].is_null() {
        summary["model"] = Value::Null;
    }
    if let Some(created) = clip(agent.get("createdAt").and_then(Value::as_str), 128) {
        summary["createdAt"] = created.into();
    }
    if let Some(parent) = label_str("paseo.parent-agent-id") {
        if is_valid_session_id(parent) {
            summary["parentId"] = parent.into();
        }
    }
    if let Some(started) = label_str("paseo.started-by") {
        if matches!(started, "user" | "agent" | "schedule") {
            summary["startedBy"] = started.into();
        }
    }
    if let Some(unread) = agent.get("requiresAttention") {
        if unread.is_boolean() {
            summary["unread"] = unread.clone();
        }
    }
    match agent.get("attentionRequest") {
        Some(Value::Null) => {
            summary["attentionRequest"] = Value::Null;
        }
        Some(req) if req.is_object() => {
            let kind = req.get("kind").and_then(Value::as_str).unwrap_or("");
            let message = req.get("message").and_then(Value::as_str).unwrap_or("");
            if !kind.is_empty() {
                summary["attentionRequest"] = json!({
                    "kind": kind,
                    "message": message.chars().take(500).collect::<String>(),
                });
            }
        }
        _ => {}
    }
    match agent.get("pendingPermissions") {
        Some(Value::Null) => {}
        Some(Value::Array(items)) => {
            if items.is_empty() {
                summary["pendingPermission"] = Value::Null;
            } else if let Some(first) = items.first() {
                let rid = first.get("id").and_then(Value::as_str).unwrap_or("");
                if !rid.is_empty() && rid.len() <= 128 {
                    let mut perm = json!({
                        "requestId": rid,
                        "kind": first.get("kind").and_then(Value::as_str).unwrap_or("other"),
                    });
                    if let Some(title) = first.get("title").and_then(Value::as_str) {
                        perm["title"] = title.chars().take(256).collect::<String>().into();
                    }
                    summary["pendingPermission"] = perm;
                }
            }
        }
        _ => {}
    }
    Some(summary)
}

/// Collapse whitespace and clip a typed tool input to a one-line detail.
/// Only typed input fields cross the boundary; display fallbacks (which can
/// carry outputs) never do.
pub fn summarize_tool_detail(detail: &Value) -> Option<String> {
    let input = match detail.get("type").and_then(Value::as_str)? {
        "shell" => detail.get("command")?.as_str()?,
        "read" | "edit" | "write" => detail.get("filePath")?.as_str()?,
        "search" => detail.get("query")?.as_str()?,
        _ => return None,
    };
    let line: String = input.split_whitespace().collect::<Vec<_>>().join(" ");
    let line = line.trim().to_owned();
    if line.is_empty() {
        return None;
    }
    Some(line.chars().take(256).collect())
}

/// Excerpt a message to the 16 KiB budget without splitting a surrogate pair.
pub fn excerpt_message_text(text: &str) -> (String, bool) {
    const MAX_MESSAGE_CHARS: usize = 16384;
    let len = text.chars().count();
    if len <= MAX_MESSAGE_CHARS {
        return (text.to_owned(), false);
    }
    // Char-boundary safe: take MAX chars, then back off one if we split a
    // surrogate pair at the UTF-16 level.
    let mut end: usize = text
        .char_indices()
        .nth(MAX_MESSAGE_CHARS)
        .map(|(i, _)| i)
        .unwrap_or(text.len());
    let prefix = &text[..end];
    let utf16: Vec<u16> = prefix.encode_utf16().collect();
    if let Some(&high) = utf16.last() {
        if (0xd800..0xdc00).contains(&high) {
            let char_count = prefix.chars().count();
            end = prefix
                .char_indices()
                .nth(char_count.saturating_sub(1))
                .map(|(i, _)| i)
                .unwrap_or(0);
        }
    }
    (text[..end].to_owned(), true)
}

/// Project daemon timeline entries to consumer-neutral items. Windows to the
/// last 50 entries, appends a `status` item for a live agent, and enforces
/// the ~240 KiB projection budget by dropping the oldest content first.
pub fn project_timeline(page_entries: &[Value], epoch: &str, agent_status: Option<&str>) -> Value {
    const PROJECTION_BUDGET_BYTES: usize = 245_760;
    // The window keeps the last 50 entries, but truncation is measured against
    // the full page: a page larger than the window is already truncated.
    let projectable_total = page_entries
        .iter()
        .filter(|entry| {
            let item = entry.get("item").unwrap_or(entry);
            matches!(
                item.get("type").and_then(Value::as_str),
                Some("user_message" | "assistant_message" | "tool_call")
            )
        })
        .count();
    let windowed: Vec<&Value> = page_entries
        .iter()
        .rev()
        .take(50)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let mut items: Vec<Value> = Vec::new();
    for entry in &windowed {
        let item = entry.get("item").unwrap_or(entry);
        let seq = entry.get("seqStart");
        let seq_str = seq.map(|s| s.to_string()).unwrap_or_default();
        let id = format!("{epoch}:{seq_str}");
        match item.get("type").and_then(Value::as_str) {
            Some("user_message" | "assistant_message") => {
                let role = if item.get("type").and_then(Value::as_str) == Some("user_message") {
                    "user"
                } else {
                    "assistant"
                };
                let text = item.get("text").and_then(Value::as_str).unwrap_or("");
                let (text, truncated) = excerpt_message_text(text);
                let mut row = json!({"id": id, "kind": "message", "role": role, "text": text});
                if truncated {
                    row["truncated"] = true.into();
                }
                items.push(row);
            }
            Some("tool_call") => {
                let mut row = json!({
                    "id": id,
                    "kind": "tool",
                    "title": item.get("name").and_then(Value::as_str).unwrap_or("").chars().take(256).collect::<String>(),
                    "status": item.get("status").and_then(Value::as_str).unwrap_or(""),
                });
                if let Some(detail) = item.get("detail").and_then(summarize_tool_detail) {
                    row["detail"] = detail.into();
                }
                items.push(row);
            }
            _ => {}
        }
    }
    if let Some(status) = agent_status {
        items.push(json!({"id": "status", "kind": "status", "status": status}));
    }
    let projectable_kept = items
        .iter()
        .filter(|i| i.get("kind").and_then(Value::as_str) != Some("status"))
        .count();
    let mut history_truncated = projectable_total > projectable_kept;
    // Byte budget: {"items":[]} is 12 overhead bytes, ,"historyTruncated":true
    // adds 24 more; items joined by one comma each.
    let envelope = |bytes_total: usize, count: usize, truncated: bool| {
        (if truncated { 36 } else { 12 }) + bytes_total + count.saturating_sub(1)
    };
    let sizes: Vec<usize> = items
        .iter()
        .map(|i| serde_json::to_string(i).map(|s| s.len()).unwrap_or(0))
        .collect();
    let mut bytes_total: usize = sizes.iter().sum();
    let mut content_count = projectable_kept;
    let mut drop = 0usize;
    while envelope(
        bytes_total,
        items.len().saturating_sub(drop),
        history_truncated,
    ) > PROJECTION_BUDGET_BYTES
        && content_count > 1
    {
        bytes_total = bytes_total.saturating_sub(sizes[drop]);
        drop += 1;
        content_count = content_count.saturating_sub(1);
        history_truncated = true;
    }
    if drop > 0 {
        items.drain(..drop);
    }
    let mut out = json!({"items": items});
    if history_truncated {
        out["historyTruncated"] = true.into();
    }
    out
}

/// Build a successful tool result envelope (content + structuredContent),
/// mirroring `node_status_reply`'s era handling at the call site.
pub fn tool_result(payload: Value) -> Value {
    let text = serde_json::to_string_pretty(&payload).unwrap_or_default();
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": false,
    })
}

/// Build a structured refusal envelope (`isError: true` with a `code`).
pub fn tool_refusal(code: &str, message: &str, extra: Value) -> Value {
    let mut payload = json!({"code": code, "message": message});
    if let Value::Object(map) = extra {
        for (k, v) in map {
            payload[k] = v;
        }
    }
    let text = serde_json::to_string_pretty(&payload).unwrap_or_default();
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn broker_allowlist_rejects_sends_creates_and_extra_fields() {
        assert!(check_broker_outbound_allowed(&fetch_agents_message("r", None)).is_ok());
        assert!(
            check_broker_outbound_allowed(&fetch_timeline_message("a", "r", "tail", None, 50))
                .is_ok()
        );
        assert!(check_broker_outbound_allowed(&json!({"type": "ping"})).is_ok());
        assert!(
            check_broker_outbound_allowed(
                &json!({"type": "agent.timeline.set_subscription.request", "agentIds": [], "requestId": "r"})
            )
            .is_ok()
        );
        for blocked in [
            json!({"type": "send_agent_message_request", "agentId": "a", "requestId": "r", "text": "hi"}),
            json!({"type": "create_agent_request", "requestId": "r"}),
            json!({"type": "update_agent_request", "agentId": "a", "requestId": "r",
                   "labels": {"native.save.status": "ok:1"}}),
            json!({"type": "get_agent_permission_form_request", "agentId": "a", "requestId": "r"}),
            json!({"type": "respond_to_permission_request", "agentId": "a", "requestId": "r"}),
            json!({"type": "agent_update"}),
        ] {
            assert!(
                check_broker_outbound_allowed(&blocked).is_err(),
                "{blocked}"
            );
        }
        for smuggled in [
            json!({"type": "fetch_agents_request", "requestId": "r", "labels": {"x": "y"}}),
            json!({"type": "fetch_agent_timeline_request", "agentId": "a", "requestId": "r",
                   "direction": "tail", "projection": "projected", "limit": 50, "text": "prompt"}),
            json!({"type": "ping", "extra": 1}),
        ] {
            assert!(
                check_broker_outbound_allowed(&smuggled).is_err(),
                "{smuggled}"
            );
        }
    }

    #[test]
    fn summarize_agent_maps_shapes_and_drops_archived() {
        let agent = json!({
            "id": "a1",
            "provider": "claude",
            "model": "m",
            "status": "idle",
            "title": "hello",
            "updatedAt": "2026-11-04T00:00:00.000Z",
            "createdAt": "2026-11-03T00:00:00.000Z",
            "workspaceId": "w1",
            "labels": {"paseo.parent-agent-id": "p0", "paseo.started-by": "user"},
            "requiresAttention": true,
        });
        let project = json!({"workspaceName": "proj"});
        let row = summarize_agent(&agent, Some(&project), "srv", "label", "epoch").unwrap();
        assert_eq!(row["id"], "a1");
        assert_eq!(row["hostId"], "srv");
        assert_eq!(row["hostEpoch"], "epoch");
        assert_eq!(row["parentId"], "p0");
        assert_eq!(row["startedBy"], "user");
        assert_eq!(row["workspace"]["name"], "proj");
        let archived = json!({"id": "a1", "archivedAt": "2026-11-04T00:00:00Z"});
        assert!(summarize_agent(&archived, None, "srv", "l", "e").is_none());
        // Unknown started-by values are dropped, never passed through.
        let weird = json!({"id": "a1", "labels": {"paseo.started-by": "daemon"}});
        let row = summarize_agent(&weird, None, "srv", "l", "e").unwrap();
        assert!(row.get("startedBy").is_none());
    }

    #[test]
    fn project_timeline_windows_truncates_and_budgets() {
        let entries: Vec<Value> = (0..60)
            .map(|i| json!({"seqStart": i, "item": {"type": "user_message", "text": "hi"}}))
            .collect();
        let out = project_timeline(&entries, "e", Some("idle"));
        let items = out["items"].as_array().unwrap();
        // Last 50 content items + the status item.
        assert_eq!(items.len(), 51);
        assert!(out.get("historyTruncated").is_some());
        assert_eq!(items.last().unwrap()["kind"], "status");
    }
}
