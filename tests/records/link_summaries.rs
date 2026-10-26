//! `get_record` link rows carry a compact summary of the record at the far end
//! (`other`): name, type, kind, lifecycle, a supersession flag and a short
//! reference.
//!
//! The boundary these tests pin is visibility. A link to a record the caller
//! cannot see is dropped from the window and the count today; it must stay
//! dropped, and nothing about it — name, type, kind, lifecycle or succession —
//! may reach the response, the text rendering included.

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::mcp::render;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};

async fn db() -> Db {
    create_database(":memory:").await.unwrap()
}

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    registry
}

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, args: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, args)
        .await
        .unwrap()
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    args: Value,
) -> Value {
    registry.call(db.clone(), caller, tool, args).await.unwrap()
}

fn bea() -> Caller {
    Caller::authenticated("acct:bea")
        .with_hosting_context("host:bea", "db:test")
        .with_hosting_owner(false)
}

async fn create(registry: &ToolRegistry, db: &Db, mut args: Value) -> String {
    if let Some(object) = args.as_object_mut() {
        object
            .entry("reason")
            .or_insert_with(|| json!("link summary test fixture"));
    }
    call(registry, db, "create_record", args).await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn note(registry: &ToolRegistry, db: &Db, name: &str) -> String {
    create(
        registry,
        db,
        json!({ "type": "Document", "kind": "note", "name": name }),
    )
    .await
}

async fn link(registry: &ToolRegistry, db: &Db, source: &str, target: &str, relationship: &str) {
    call(
        registry,
        db,
        "manage_links",
        json!({
            "action": "add",
            "source_id": source,
            "target_id": target,
            "relationship": relationship,
            "note": format!("{relationship} note"),
        }),
    )
    .await;
}

/// Make `id` invisible to `bea` (visible only to `acct:alice`).
async fn hide_from_bea(db: &Db, id: &str) {
    replace_explicit_policy(
        db,
        "test:policy",
        id,
        vec![AllowEntry::account("acct:alice", Capability::View)],
    )
    .await
    .unwrap();
}

async fn get_as(registry: &ToolRegistry, db: &Db, caller: Caller, id: &str) -> Value {
    call_as(registry, db, caller, "get_record", json!({ "ids": [id] })).await
}

fn only_link<'a>(record: &'a Value, direction: &str) -> &'a Value {
    let links = record[direction].as_array().unwrap();
    assert_eq!(links.len(), 1, "{direction}: {record:#}");
    &links[0]
}

#[tokio::test]
async fn links_out_and_in_name_the_record_at_the_far_end() {
    let db = db().await;
    let registry = registry();
    let task = create(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Ship the thing",
            "lifecycle": "in_progress",
            "body": "a long body that must not travel with the link",
            "summary": "a summary that must not travel with the link",
        }),
    )
    .await;
    let hub = note(&registry, &db, "Hub note").await;
    let upstream = note(&registry, &db, "Upstream note").await;
    link(&registry, &db, &hub, &task, "relates_to").await;
    link(&registry, &db, &upstream, &hub, "informs").await;

    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let record = &payload["records"][0];

    // Outgoing: the far end is the target.
    let out = only_link(record, "links_out");
    assert_eq!(out["target_id"], json!(task));
    let other = &out["other"];
    assert_eq!(other["id"], json!(task));
    assert_eq!(other["name"], "Ship the thing");
    assert_eq!(other["type"], "WorkItem");
    assert_eq!(other["kind"], "task");
    assert_eq!(other["lifecycle"]["status"], "governed");
    assert_eq!(other["lifecycle"]["value"], "in_progress");
    assert_eq!(other["lifecycle"]["terminality"], "open");
    assert!(
        other["display_reference"].as_str().is_some(),
        "short reference: {other:#}"
    );
    // Compact: no body or summary of the other record.
    let keys: Vec<&str> = other
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert!(
        keys.iter().all(|key| [
            "id",
            "name",
            "type",
            "kind",
            "lifecycle",
            "superseded",
            "display_reference"
        ]
        .contains(key)),
        "unexpected keys {keys:?}"
    );
    // Not superseded: the flag is absent, never false.
    assert!(other.get("superseded").is_none(), "{other:#}");

    // Existing row fields are untouched.
    assert_eq!(out["source_id"], json!(hub));
    assert_eq!(out["relationship"], "relates_to");
    assert_eq!(out["note"], "relates_to note");
    assert!(out["id"].as_str().is_some() && out["created_at"].as_str().is_some());

    // Incoming: the far end is the source.
    let incoming = only_link(record, "links_in");
    assert_eq!(incoming["source_id"], json!(upstream));
    assert_eq!(incoming["other"]["id"], json!(upstream));
    assert_eq!(incoming["other"]["name"], "Upstream note");
    assert_eq!(incoming["other"]["type"], "Document");
    assert_eq!(incoming["other"]["kind"], "note");
    assert!(incoming["other"].get("lifecycle").is_none());
    db.close().await;
}

#[tokio::test]
async fn superseded_far_end_is_flagged_and_a_live_one_is_not() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let old = note(&registry, &db, "Old charter").await;
    let live = note(&registry, &db, "Live charter").await;
    let newer = note(&registry, &db, "New charter").await;
    link(&registry, &db, &hub, &old, "relates_to").await;
    link(&registry, &db, &hub, &live, "relates_to").await;
    link(&registry, &db, &newer, &old, "supersedes").await;

    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let links = payload["records"][0]["links_out"].as_array().unwrap();
    let other_for = |id: &str| {
        links
            .iter()
            .find(|link| link["target_id"] == json!(id))
            .unwrap()["other"]
            .clone()
    };
    assert_eq!(other_for(&old)["superseded"], json!(true));
    assert!(other_for(&live).get("superseded").is_none());

    // The flag is the incoming-supersedes signal `get_record` already gives
    // for the record itself — the two cannot disagree.
    let direct = get_as(&registry, &db, Caller::local(), &old).await;
    assert_eq!(direct["records"][0]["superseded_by"]["total_count"], 1);

    // A superseding link seen from the successor: the superseded record is the
    // far end of a `supersedes` row and is flagged as such.
    let from_successor = get_as(&registry, &db, Caller::local(), &newer).await;
    let supersedes = only_link(&from_successor["records"][0], "links_out");
    assert_eq!(supersedes["relationship"], "supersedes");
    assert_eq!(supersedes["other"]["superseded"], json!(true));

    // A withdrawn successor stops counting, as it does for `superseded_by`.
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": newer, "reason": "withdraw the replacement" }),
    )
    .await;
    let after = get_as(&registry, &db, Caller::local(), &hub).await;
    let still_flagged = after["records"][0]["links_out"]
        .as_array()
        .unwrap()
        .iter()
        .any(|link| link["other"].get("superseded").is_some());
    assert!(!still_flagged, "{after:#}");
    db.close().await;
}

#[tokio::test]
async fn links_to_hidden_records_stay_dropped_and_leak_nothing() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let visible_out = note(&registry, &db, "Visible target").await;
    let hidden_out = create(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Sealed target secret",
            "lifecycle": "in_progress",
        }),
    )
    .await;
    let visible_in = note(&registry, &db, "Visible source").await;
    let hidden_in = note(&registry, &db, "Sealed source secret").await;
    link(&registry, &db, &hub, &visible_out, "relates_to").await;
    link(&registry, &db, &hub, &hidden_out, "relates_to").await;
    link(&registry, &db, &visible_in, &hub, "relates_to").await;
    link(&registry, &db, &hidden_in, &hub, "relates_to").await;
    hide_from_bea(&db, &hidden_out).await;
    hide_from_bea(&db, &hidden_in).await;

    let payload = get_as(&registry, &db, bea(), &hub).await;
    let record = &payload["records"][0];

    // Same behaviour as before summaries existed: hidden rows are not in the
    // window and not in the count.
    assert_eq!(record["links_out_count"], 1, "{record:#}");
    assert_eq!(record["links_in_count"], 1, "{record:#}");
    assert_eq!(
        only_link(record, "links_out")["other"]["name"],
        "Visible target"
    );
    assert_eq!(
        only_link(record, "links_in")["other"]["name"],
        "Visible source"
    );

    // Nothing about a hidden record appears anywhere in the payload or text.
    let json_text = payload.to_string();
    let text = render::render("get_record", &payload).unwrap();
    for haystack in [json_text, text] {
        for needle in [
            hidden_out.as_str(),
            hidden_in.as_str(),
            "Sealed target secret",
            "Sealed source secret",
        ] {
            assert!(!haystack.contains(needle), "leaked {needle:?}: {haystack}");
        }
    }
    db.close().await;
}

#[tokio::test]
async fn hidden_far_end_supersession_is_not_disclosed() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let hidden_old = note(&registry, &db, "Sealed superseded record").await;
    let successor = note(&registry, &db, "Visible successor").await;
    link(&registry, &db, &hub, &hidden_old, "relates_to").await;
    link(&registry, &db, &successor, &hidden_old, "supersedes").await;
    hide_from_bea(&db, &hidden_old).await;

    let payload = get_as(&registry, &db, bea(), &hub).await;
    let record = &payload["records"][0];
    assert_eq!(record["links_out_count"], 0, "{record:#}");
    assert_eq!(record["links_out"], json!([]));
    let haystack = format!(
        "{}{}",
        payload,
        render::render("get_record", &payload).unwrap()
    );
    assert!(!haystack.contains("Sealed superseded record"), "{haystack}");
    assert!(!haystack.contains(&hidden_old), "{haystack}");
    db.close().await;
}

#[tokio::test]
async fn hidden_successor_is_counted_never_named() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let old = note(&registry, &db, "Old charter").await;
    let hidden_new = note(&registry, &db, "Sealed replacement secret").await;
    link(&registry, &db, &hub, &old, "relates_to").await;
    link(&registry, &db, &hidden_new, &old, "supersedes").await;
    hide_from_bea(&db, &hidden_new).await;

    let payload = get_as(&registry, &db, bea(), &hub).await;
    let record = &payload["records"][0];
    let out = only_link(record, "links_out");
    // The far end is visible, so it is summarised. Its supersession is the same
    // count-without-name the record's own `superseded_by` gives this caller.
    assert_eq!(out["other"]["name"], "Old charter");
    assert_eq!(out["other"]["superseded"], json!(true), "{out:#}");
    let direct = get_as(&registry, &db, bea(), &old).await;
    assert_eq!(direct["records"][0]["superseded_by"]["total_count"], 1);
    assert_eq!(direct["records"][0]["superseded_by"]["items"], json!([]));

    // Nothing identifies the hidden successor.
    let haystack = format!(
        "{}{}",
        payload,
        render::render("get_record", &payload).unwrap()
    );
    assert!(
        !haystack.contains("Sealed replacement secret"),
        "{haystack}"
    );
    assert!(!haystack.contains(&hidden_new), "{haystack}");
    db.close().await;
}

#[tokio::test]
async fn windowed_links_keep_their_own_summaries_across_pages() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let mut names = Vec::new();
    for index in 0..5 {
        let name = format!("Peer {index}");
        let id = note(&registry, &db, &name).await;
        link(&registry, &db, &hub, &id, "relates_to").await;
        names.push((id, name));
    }
    let mut seen = Vec::new();
    for offset in 0..5 {
        let payload = call(
            &registry,
            &db,
            "get_record",
            json!({ "ids": [hub], "links_limit": 1, "links_offset": offset }),
        )
        .await;
        let record = &payload["records"][0];
        assert_eq!(record["links_out_count"], 5);
        let row = only_link(record, "links_out");
        let id = row["target_id"].as_str().unwrap().to_string();
        let expected = &names.iter().find(|(peer, _)| *peer == id).unwrap().1;
        assert_eq!(row["other"]["id"], json!(id));
        assert_eq!(row["other"]["name"], json!(expected));
        seen.push(id);
    }
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len(), 5);
    db.close().await;
}

#[tokio::test]
async fn text_rendering_reads_each_link_as_title_and_reference() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let old = note(&registry, &db, "Old charter").await;
    let task = create(
        &registry,
        &db,
        json!({
            "type": "WorkItem", "kind": "task", "name": "Ship the thing",
            "lifecycle": "in_progress",
        }),
    )
    .await;
    let newer = note(&registry, &db, "New charter").await;
    link(&registry, &db, &hub, &old, "relates_to").await;
    link(&registry, &db, &task, &hub, "blocks").await;
    link(&registry, &db, &newer, &old, "supersedes").await;

    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let record = &payload["records"][0];
    let old_ref = only_link(record, "links_out")["other"]["display_reference"]
        .as_str()
        .unwrap()
        .to_string();
    let task_ref = only_link(record, "links_in")["other"]["display_reference"]
        .as_str()
        .unwrap()
        .to_string();
    let text = render::render("get_record", &payload).unwrap();

    let out_line = text
        .lines()
        .find(|line| line.contains("→ relates_to"))
        .unwrap_or_else(|| panic!("no outgoing link line: {text}"));
    assert!(
        out_line.contains(&format!("Old charter ({old_ref} · {old})")),
        "{out_line}"
    );
    assert!(out_line.contains("Document/note"), "{out_line}");
    assert!(out_line.contains("superseded"), "{out_line}");
    assert!(out_line.contains("note: relates_to note"), "{out_line}");
    // A readable line, not the raw row.
    assert!(!out_line.contains("source_id"), "{out_line}");

    let in_line = text
        .lines()
        .find(|line| line.contains("← blocks"))
        .unwrap_or_else(|| panic!("no incoming link line: {text}"));
    assert!(
        in_line.contains(&format!("Ship the thing ({task_ref} · {task})")),
        "{in_line}"
    );
    assert!(in_line.contains("WorkItem/task · in_progress"), "{in_line}");
    assert!(!in_line.contains("superseded"), "{in_line}");
    db.close().await;
}

#[tokio::test]
async fn tombstoned_far_end_carries_no_unfollowable_short_reference() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let gone = note(&registry, &db, "Withdrawn peer").await;
    let live = note(&registry, &db, "Live peer").await;
    link(&registry, &db, &hub, &gone, "relates_to").await;
    link(&registry, &db, &hub, &live, "relates_to").await;
    call(
        &registry,
        &db,
        "delete_record",
        json!({ "id": gone, "reason": "withdraw the peer" }),
    )
    .await;

    // A trusted local caller still sees the link to the tombstone.
    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let links = payload["records"][0]["links_out"].as_array().unwrap();
    let other_for = |id: &str| {
        links
            .iter()
            .find(|link| link["target_id"] == json!(id))
            .unwrap_or_else(|| panic!("no link to {id}: {payload:#}"))["other"]
            .clone()
    };
    let tombstone = other_for(&gone);
    assert_eq!(tombstone["id"], json!(gone));
    // Prefix resolution excludes tombstones, so no short reference is offered.
    assert!(
        tombstone.get("display_reference").is_none(),
        "{tombstone:#}"
    );
    assert!(other_for(&live)["display_reference"].as_str().is_some());

    // The text falls back to the full id, which always opens.
    let text = render::render("get_record", &payload).unwrap();
    let line = text
        .lines()
        .find(|line| line.contains("Withdrawn peer"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(line.contains(&format!("({gone})")), "{line}");
    db.close().await;
}

/// Links written as `link.added` content events (spine `mentions`) replay under
/// `as_of`, which the `manage_links` tool's relationship assertions do not;
/// this is how a historical link window is built.
async fn add_content_link(db: &Db, source: &str, target: &str) {
    native_ce::store::add_link(
        db,
        native_ce::events::LinkAddedPayload {
            id: None,
            source_id: source.into(),
            target_id: target.into(),
            relationship: "mentions".into(),
            note: None,
        },
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn historical_read_keeps_a_hidden_far_end_hidden() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let peer = note(&registry, &db, "Sealed later peer").await;
    add_content_link(&db, &hub, &peer).await;
    let seq: i64 = sqlx::query_scalar("SELECT MAX(seq) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let as_of = json!({ "ids": [hub], "as_of": { "content_seq": seq } });

    // While the peer is visible, the historical window summarises it — for a
    // restricted caller and for the trusted local one alike.
    for caller in [bea(), Caller::local()] {
        let historical = call_as(&registry, &db, caller, "get_record", as_of.clone()).await;
        let row = only_link(&historical["records"][0], "links_out");
        assert_eq!(row["other"]["name"], "Sealed later peer", "{historical:#}");
    }

    // Visibility changes after the as_of point. Live authorization governs a
    // historical read, so the far end disappears for the caller who lost it.
    hide_from_bea(&db, &peer).await;
    let hidden = call_as(&registry, &db, bea(), "get_record", as_of.clone()).await;
    let record = &hidden["records"][0];
    assert_eq!(record["links_out"], json!([]), "{hidden:#}");
    assert_eq!(record["links_out_count"], 0);
    let haystack = format!("{hidden}{}", render::render("get_record", &hidden).unwrap());
    assert!(!haystack.contains("Sealed later peer"), "{haystack}");
    assert!(!haystack.contains(&peer), "{haystack}");

    // The caller who can still see it keeps the summary.
    let local = call(&registry, &db, "get_record", as_of).await;
    assert_eq!(
        only_link(&local["records"][0], "links_out")["other"]["name"],
        "Sealed later peer"
    );
    db.close().await;
}

#[tokio::test]
async fn hidden_rows_interleaved_with_paging_never_shift_or_leak() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let mut visible = Vec::new();
    let mut hidden = Vec::new();
    for index in 0..8 {
        let secret = index % 2 == 1;
        let name = if secret {
            format!("Sealed peer {index}")
        } else {
            format!("Open peer {index}")
        };
        let id = note(&registry, &db, &name).await;
        link(&registry, &db, &hub, &id, "relates_to").await;
        if secret {
            hide_from_bea(&db, &id).await;
            hidden.push((id, name));
        } else {
            visible.push((id, name));
        }
    }
    let mut seen = Vec::new();
    for offset in [0, 2] {
        let payload = call_as(
            &registry,
            &db,
            bea(),
            "get_record",
            json!({ "ids": [hub], "links_limit": 2, "links_offset": offset }),
        )
        .await;
        let record = &payload["records"][0];
        // Counts and offsets are caller-relative: hidden rows never take a slot.
        assert_eq!(record["links_out_count"], 4, "{record:#}");
        let rows = record["links_out"].as_array().unwrap();
        assert_eq!(rows.len(), 2, "offset {offset}: {record:#}");
        for row in rows {
            assert_eq!(row["other"]["id"], row["target_id"]);
            seen.push(row["target_id"].as_str().unwrap().to_string());
        }
        let haystack = format!(
            "{payload}{}",
            render::render("get_record", &payload).unwrap()
        );
        for (id, name) in &hidden {
            assert!(!haystack.contains(id.as_str()) && !haystack.contains(name.as_str()));
        }
    }
    seen.sort();
    let mut expected: Vec<String> = visible.iter().map(|(id, _)| id.clone()).collect();
    expected.sort();
    assert_eq!(seen, expected);
    db.close().await;
}

#[tokio::test]
async fn archived_far_end_is_still_summarised() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let shelved = note(&registry, &db, "Shelved peer").await;
    link(&registry, &db, &hub, &shelved, "relates_to").await;
    call(
        &registry,
        &db,
        "archive_record",
        json!({ "id": shelved, "reason": "shelve the peer" }),
    )
    .await;

    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let other = &only_link(&payload["records"][0], "links_out")["other"];
    assert_eq!(other["id"], json!(shelved));
    assert_eq!(other["name"], "Shelved peer");
    assert!(other["display_reference"].as_str().is_some(), "{other:#}");
    db.close().await;
}

#[tokio::test]
async fn self_link_summarises_the_record_on_both_sides() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Loop note").await;
    add_content_link(&db, &hub, &hub).await;

    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let record = &payload["records"][0];
    for direction in ["links_out", "links_in"] {
        let row = only_link(record, direction);
        assert_eq!(row["source_id"], json!(hub));
        assert_eq!(row["target_id"], json!(hub));
        assert_eq!(row["other"]["id"], json!(hub), "{direction}: {row:#}");
        assert_eq!(row["other"]["name"], "Loop note");
    }
    db.close().await;
}

#[tokio::test]
async fn unclassified_lifecycle_is_reported_as_such() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    // The tool refuses a lifecycle no vocabulary governs; a stored token like
    // this still arrives through import and raw writes, and must read honestly.
    let odd = native_ce::store::create_record(
        &db,
        json!({
            "type": "Document", "kind": "note", "name": "Odd lifecycle",
            "lifecycle": "mothballed",
        }),
    )
    .await
    .unwrap();
    link(&registry, &db, &hub, &odd, "relates_to").await;

    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let other = &only_link(&payload["records"][0], "links_out")["other"];
    assert_eq!(other["lifecycle"]["status"], "unclassified", "{other:#}");
    assert_eq!(other["lifecycle"]["value"], "mothballed");
    assert!(other["lifecycle"].get("terminality").is_none());
    let text = render::render("get_record", &payload).unwrap();
    let line = text
        .lines()
        .find(|line| line.contains("Odd lifecycle"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(line.contains("mothballed (unclassified)"), "{line}");
    db.close().await;
}

#[tokio::test]
async fn many_successors_flag_the_far_end_once() {
    let db = db().await;
    let registry = registry();
    let hub = note(&registry, &db, "Hub").await;
    let old = note(&registry, &db, "Old charter").await;
    link(&registry, &db, &hub, &old, "relates_to").await;
    for index in 0..5 {
        let newer = note(&registry, &db, &format!("Revision {index}")).await;
        link(&registry, &db, &newer, &old, "supersedes").await;
    }
    let payload = get_as(&registry, &db, Caller::local(), &hub).await;
    let row = only_link(&payload["records"][0], "links_out");
    assert_eq!(row["other"]["superseded"], json!(true));
    // The record's own disclosure agrees, with the full successor count.
    let direct = get_as(&registry, &db, Caller::local(), &old).await;
    assert_eq!(direct["records"][0]["superseded_by"]["total_count"], 5);
    db.close().await;
}
