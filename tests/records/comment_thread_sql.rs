//! `thread.items` snapshot proof for the proposed comment-thread SQL.
//!
//! ONE real public-registry `manage_alpha_tabs` snapshot `live_read` over the
//! CORRECTED proposed package SQL, installed as a second exact consented
//! install on the genuine `comment_public_setup` fixture (a folder filing home
//! plus a separate Collection kind:query v0.2 cohort). This is a
//! registry-level proof, NOT hosted acceptance: the comment viewer is the
//! fixture's explicitly labelled canonical identity seed, and no OTP or host
//! path runs.
//!
//! Root concern proved here: `links` is UNIQUE(source_id, target_id,
//! relationship), and the exactly-one `part_of` rule covers only
//! Annotation/comment. An ordinary governed Document/note may therefore carry
//! two explicit `part_of` links, and the naive join returns that note twice.
//! The corrected package join restricts the parent join to Annotation/comment
//! in its `ON` clause, so the note projects once with null part_of/parent
//! fields while the root and reply project their actual canonical parents.

use std::collections::HashSet;

use native_ce::authorization::{replace_explicit_policy, AllowEntry, Capability};
use native_ce::Db;
use serde_json::{json, Value};

use super::{
    alpha_guard_verified_install, call_as, comment_public_declaration, comment_public_mdx_source,
    comment_public_setup, html_interaction_source, ALPHA_GUARD_ACCOUNT, COLLECTION, INSIDE,
};

const PROPOSED_PACKAGE: &str = "agent.thread-items-proof";
const NOTE_TWO_PARENTS: &str = "0a5e0000-0000-4000-8000-000000000021";
const ROOT_COMMENT: &str = "0a5e0000-0000-4000-8000-000000000022";
const FLAT_REPLY: &str = "0a5e0000-0000-4000-8000-000000000023";

/// The PROPOSED package SQL exactly as authored, before the parent-join fix.
fn thread_items_sql_uncorrected() -> String {
    r#"SELECT r.id, r.type, r.kind, r.name, r.body, r.home_id, r.lifecycle,
              l.target_id AS part_of, p.type AS parent_type, p.kind AS parent_kind
         FROM records r
         LEFT JOIN links l ON l.source_id = r.id AND l.relationship = 'part_of'
         LEFT JOIN records p ON p.id = l.target_id
        WHERE r.deleted_at IS NULL
          AND ((r.type = 'Document' AND r.kind = 'note')
               OR (r.type = 'Annotation' AND r.kind = 'comment'))
        ORDER BY r.id ASC LIMIT 200"#
        .into()
}

/// The CORRECTED proposed SQL: the parent join is restricted to
/// Annotation/comment in the `LEFT JOIN` `ON` clause, so ordinary notes never
/// join a parent and cannot duplicate on multiple `part_of` links.
fn thread_items_sql() -> String {
    r#"SELECT r.id, r.type, r.kind, r.name, r.body, r.home_id, r.lifecycle,
              l.target_id AS part_of, p.type AS parent_type, p.kind AS parent_kind
         FROM records r
         LEFT JOIN links l ON l.source_id = r.id AND l.relationship = 'part_of'
           AND r.type = 'Annotation' AND r.kind = 'comment'
         LEFT JOIN records p ON p.id = l.target_id
        WHERE r.deleted_at IS NULL
          AND ((r.type = 'Document' AND r.kind = 'note')
               OR (r.type = 'Annotation' AND r.kind = 'comment'))
        ORDER BY r.id ASC LIMIT 200"#
        .into()
}

/// The fixture declaration reused verbatim, with only the `thread.items` SQL
/// swapped for the corrected proposed statement. The `comment.create.v1`
/// effect bounds and the `attention.query.v1` need are unchanged, so this is a
/// second exact consented install of the same artifact body.
fn proposed_thread_declaration() -> Value {
    let mut declaration = comment_public_declaration();
    let needs = declaration["needs"]
        .as_array_mut()
        .expect("comment_public_declaration carries needs");
    let need = needs
        .iter_mut()
        .find(|entry| entry.get("key").and_then(Value::as_str) == Some("thread.items"))
        .expect("comment_public_declaration carries the thread.items sql need");
    need["sql"] = json!(thread_items_sql());
    declaration
}

async fn grant_view(db: &Db, id: &str) {
    replace_explicit_policy(
        db,
        "test:policy",
        id,
        vec![AllowEntry::account(ALPHA_GUARD_ACCOUNT, Capability::View)],
    )
    .await
    .unwrap();
}

fn row_for<'a>(rows: &'a [Value], id: &str) -> &'a Value {
    rows.iter()
        .find(|row| row["id"].as_str() == Some(id))
        .unwrap_or_else(|| panic!("thread.items omitted {id}"))
}

#[tokio::test]
async fn thread_items_snapshot_joins_canonical_comment_parents_once() {
    let setup = comment_public_setup().await;

    let html = html_interaction_source(&comment_public_mdx_source());
    let (verified, _revision, _digest, _declaration_digest) = alpha_guard_verified_install(
        &setup.db,
        &setup.registry,
        ALPHA_GUARD_ACCOUNT,
        PROPOSED_PACKAGE,
        &html,
        proposed_thread_declaration(),
    )
    .await;

    // Ordinary governed note with TWO explicit outgoing part_of links to two
    // distinct live visible records. The exactly-one rule covers only
    // Annotation/comment, so this is admissible; both targets are viewable.
    let note = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "create_record",
        json!({
            "id": NOTE_TWO_PARENTS,
            "type": "Document",
            "kind": "note",
            "name": "Filed note with two parents",
            "body": "Note body visible to the thread query.",
            "home_id": COLLECTION,
            "links": [
                {"target_id": COLLECTION, "relationship": "part_of"},
                {"target_id": INSIDE, "relationship": "part_of"},
            ],
            "reason": "Ordinary governed note carrying two explicit part_of links."
        }),
    )
    .await
    .unwrap();
    assert_eq!(note["id"], NOTE_TWO_PARENTS, "{note:#}");
    grant_view(&setup.db, NOTE_TWO_PARENTS).await;

    // Ordinary governed root comment on the filed note. `informational` is the
    // named form of the null root lifecycle. `name` is the artifact default
    // label supplied explicitly; no ordinary default naming is claimed.
    let root = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "create_record",
        json!({
            "id": ROOT_COMMENT,
            "type": "Annotation",
            "kind": "comment",
            "name": "Comment",
            "body": "Root comment body.",
            "lifecycle": "informational",
            "home_id": COLLECTION,
            "links": [{"target_id": INSIDE, "relationship": "part_of"}],
            "reason": "Ordinary governed root comment on the filed note."
        }),
    )
    .await
    .unwrap();
    assert_eq!(root["id"], ROOT_COMMENT, "{root:#}");
    grant_view(&setup.db, ROOT_COMMENT).await;

    // Ordinary governed flat reply; omitting lifecycle leaves the reply null,
    // because thread state lives on the root.
    let reply = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "create_record",
        json!({
            "id": FLAT_REPLY,
            "type": "Annotation",
            "kind": "comment",
            "name": "Comment",
            "body": "Flat reply body.",
            "home_id": COLLECTION,
            "links": [{"target_id": ROOT_COMMENT, "relationship": "part_of"}],
            "reason": "Ordinary governed flat reply on the root comment."
        }),
    )
    .await
    .unwrap();
    assert_eq!(reply["id"], FLAT_REPLY, "{reply:#}");
    grant_view(&setup.db, FLAT_REPLY).await;

    // Contrast leg: the PROPOSED SQL as authored duplicates the two-parent
    // note on the ordinary query path, proving the ON-clause fix is needed.
    let uncorrected = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "query_sql",
        json!({"sql": thread_items_sql_uncorrected()}),
    )
    .await
    .unwrap();
    let uncorrected_rows = uncorrected["rows"].as_array().expect("query_sql rows");
    let note_parents: HashSet<&str> = uncorrected_rows
        .iter()
        .filter(|row| row["id"].as_str() == Some(NOTE_TWO_PARENTS))
        .map(|row| row["part_of"].as_str().expect("uncorrected note parent"))
        .collect();
    assert_eq!(
        note_parents,
        HashSet::from([COLLECTION, INSIDE]),
        "{uncorrected:#}"
    );

    // The real public-registry snapshot read: the same SQL as consented at
    // install, executed by `manage_alpha_tabs` over the viewer's authority.
    let read = call_as(
        &setup.registry,
        &setup.db,
        setup.alice.clone(),
        "manage_alpha_tabs",
        json!({
            "action": "live_read",
            "package": PROPOSED_PACKAGE,
            "expected_install_event_id": verified,
        }),
    )
    .await
    .unwrap();
    assert_eq!(read["live_reads"], true, "{read:#}");
    let thread = &read["input"]["sql"]["thread.items"];
    assert_eq!(thread["label"], "Thread", "{read:#}");
    assert_eq!(thread["truncated"], false, "{read:#}");
    let rows = thread["rows"].as_array().expect("thread.items rows");

    // No duplicate projected identity, and every expected thread row present.
    let ids: Vec<&str> = rows.iter().map(|row| row["id"].as_str().unwrap()).collect();
    let unique: HashSet<&str> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate ids: {read:#}");
    for id in [INSIDE, NOTE_TWO_PARENTS, ROOT_COMMENT, FLAT_REPLY] {
        assert!(ids.contains(&id), "missing {id}: {read:#}");
    }

    // The two-parent note projects exactly once, with null parent fields.
    let note_row = row_for(rows, NOTE_TWO_PARENTS);
    assert_eq!(note_row["type"], "Document", "{note_row:#}");
    assert_eq!(note_row["kind"], "note", "{note_row:#}");
    assert_eq!(
        note_row["name"], "Filed note with two parents",
        "{note_row:#}"
    );
    assert_eq!(
        note_row["body"], "Note body visible to the thread query.",
        "{note_row:#}"
    );
    assert_eq!(note_row["home_id"], COLLECTION, "{note_row:#}");
    assert!(note_row["lifecycle"].is_null(), "{note_row:#}");
    assert!(note_row["part_of"].is_null(), "{note_row:#}");
    assert!(note_row["parent_type"].is_null(), "{note_row:#}");
    assert!(note_row["parent_kind"].is_null(), "{note_row:#}");

    // The root comment projects its canonical note parent.
    let root_row = row_for(rows, ROOT_COMMENT);
    assert_eq!(root_row["type"], "Annotation", "{root_row:#}");
    assert_eq!(root_row["kind"], "comment", "{root_row:#}");
    assert_eq!(root_row["name"], "Comment", "{root_row:#}");
    assert_eq!(root_row["body"], "Root comment body.", "{root_row:#}");
    assert_eq!(root_row["home_id"], COLLECTION, "{root_row:#}");
    assert_eq!(root_row["lifecycle"], "informational", "{root_row:#}");
    assert_eq!(root_row["part_of"], INSIDE, "{root_row:#}");
    assert_eq!(root_row["parent_type"], "Document", "{root_row:#}");
    assert_eq!(root_row["parent_kind"], "note", "{root_row:#}");

    // The flat reply projects its canonical root-comment parent and stays
    // null-lifecycle.
    let reply_row = row_for(rows, FLAT_REPLY);
    assert_eq!(reply_row["type"], "Annotation", "{reply_row:#}");
    assert_eq!(reply_row["kind"], "comment", "{reply_row:#}");
    assert_eq!(reply_row["name"], "Comment", "{reply_row:#}");
    assert_eq!(reply_row["body"], "Flat reply body.", "{reply_row:#}");
    assert_eq!(reply_row["home_id"], COLLECTION, "{reply_row:#}");
    assert!(reply_row["lifecycle"].is_null(), "{reply_row:#}");
    assert_eq!(reply_row["part_of"], ROOT_COMMENT, "{reply_row:#}");
    assert_eq!(reply_row["parent_type"], "Annotation", "{reply_row:#}");
    assert_eq!(reply_row["parent_kind"], "comment", "{reply_row:#}");

    // The plain note's only thread projection is itself: one row, null parent.
    let inside_row = row_for(rows, INSIDE);
    assert!(inside_row["part_of"].is_null(), "{inside_row:#}");
    assert!(inside_row["parent_type"].is_null(), "{inside_row:#}");
    assert!(inside_row["parent_kind"].is_null(), "{inside_row:#}");
}
