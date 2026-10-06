//! Deterministic fixture worlds for member-offline closure tests (slice F-C).
//!
//! Test support only. Builders create engine databases through the engine's
//! real write paths — the same helpers existing tests use (`store::`
//! record/link/facet writes, `authorization::replace_explicit_policy`,
//! `blob::insert_blob`, `meta::schema_config` writes, person + binding
//! member setup). No member-offline production code lives here and no
//! filtering is implemented: each world only *creates* records and exposes,
//! for every hidden artefact, a named handle plus the EXPECTED visible id
//! set E(m) computed with the engine's existing online authorization
//! evaluator (`query::sql::workspace_visible_set`), never a hand-written
//! visibility list. The per-world `visible_to_*` / `hidden_from_*` lists are
//! consistency checks *against* that engine-computed E(m), which remains the
//! actual E(m); see also `assert_evaluator_agreement`.
//!
//! Contract: Native record c323277 revision 5, §0 (disclosure principle,
//! E(m)), §7.2 fixtures 1–3 and 8, §2.6 omitted fields, §3.3 closure rules.

use std::collections::HashSet;

use serde_json::{json, Value};
use sqlx::Row;

use crate::authorization::{
    effective_capability, replace_explicit_policy, AllowEntry, Capability, Principal,
};
use crate::db::{create_database, open_database, Db};
use crate::events::{FacetSetPayload, LinkAddedPayload};
use crate::meta::schema_config::{write_user_schema_config, SchemaConfigOptions};
use crate::query::sql::query_sql;
use crate::query::{sql::workspace_visible_set, QueryPrincipal};
use crate::schema::ROOT_RECORD_ID;
use crate::store::{add_link, create_record, set_facet, update_record};

/// Test accounts. Member A is `ACCT_A`, member B is `ACCT_B`; both present
/// with `is_member = true` footing unless a world says otherwise.
pub(crate) const ACCT_A: &str = "acct_a";
pub(crate) const ACCT_B: &str = "acct_b";

/// E(m): the online evaluator's visible id set for `account`.
pub(crate) async fn online_visible_ids(db: &Db, account: &str) -> HashSet<String> {
    let principal = QueryPrincipal::authenticated(account, true);
    workspace_visible_set(db, principal)
        .await
        .unwrap()
        .ids
        .as_ref()
        .clone()
}

/// Pins a world's `authored_disclosed_ids()` list (§7.2 item 1(a)'s
/// permitted exception): each id is outside E(m) for `account`, yet its
/// full text appears in the name or body of a record inside E(m). A stale
/// list therefore fails here instead of silently widening a raw-scan
/// allowance.
pub(crate) async fn assert_authored_disclosures(db: &Db, account: &str, ids: &[&str]) {
    let visible = online_visible_ids(db, account).await;
    for id in ids {
        assert!(!visible.contains(*id), "{id} must be hidden from {account}");
        let carriers: Vec<String> = sqlx::query_scalar(
            "SELECT id FROM records WHERE instr(name, ?1) > 0 OR instr(body, ?1) > 0",
        )
        .bind(id)
        .fetch_all(db.write_pool())
        .await
        .unwrap();
        assert!(
            carriers.iter().any(|carrier| visible.contains(carrier)),
            "{id} must appear in visible authored text for {account}"
        );
    }
}

/// Person record + canonical account binding, as `authorization.rs` tests do.
pub(crate) async fn create_member(db: &Db, person_id: &str, account: &str) {
    create_record(
        db,
        json!({
            "id": person_id,
            "type": "Entity",
            "kind": "person",
            "name": person_id,
            "home_id": ROOT_RECORD_ID,
        }),
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical)
         VALUES (?, 'account', ?, 1)",
    )
    .bind(person_id)
    .bind(account)
    .execute(db.write_pool())
    .await
    .unwrap();
}

/// Plain note document.
pub(crate) async fn mk_doc(db: &Db, id: &str, home: &str, body: Option<&str>, owner: Option<&str>) {
    let mut fields = json!({
        "id": id,
        "type": "Document",
        "kind": "note",
        "name": id,
        "home_id": home,
    });
    if let Some(body) = body {
        fields["body"] = json!(body);
    }
    if let Some(owner) = owner {
        fields["owner_id"] = json!(owner);
    }
    create_record(db, fields).await.unwrap();
}

/// Collection (folder) that can bear children.
pub(crate) async fn mk_collection(db: &Db, id: &str, home: &str) {
    create_record(
        db,
        json!({
            "id": id,
            "type": "Collection",
            "kind": "folder",
            "name": id,
            "home_id": home,
        }),
    )
    .await
    .unwrap();
}

/// Explicit policy boundary (each record becomes its own anchor).
pub(crate) async fn grant(db: &Db, id: &str, entries: Vec<AllowEntry>) {
    replace_explicit_policy(db, "test:member-offline-fixtures", id, entries)
        .await
        .unwrap();
}
pub(crate) async fn link(db: &Db, id: &str, source: &str, target: &str, rel: &str) {
    add_link(
        db,
        LinkAddedPayload {
            id: Some(id.into()),
            source_id: source.into(),
            target_id: target.into(),
            relationship: rel.into(),
            note: None,
        },
    )
    .await
    .unwrap();
}

/// Attachment with inline bytes on exactly one `part_of` bearer edge, as
/// `query::sql` tests do. Returns the blob id.
pub(crate) async fn attach_inline(
    db: &Db,
    attachment_id: &str,
    bearer_id: &str,
    grants: Vec<AllowEntry>,
    bytes: &[u8],
) -> String {
    create_record(
        db,
        json!({
            "id": attachment_id,
            "type": "Document",
            "kind": "attachment",
            "name": format!("{attachment_id}.txt"),
            "home_id": ROOT_RECORD_ID,
        }),
    )
    .await
    .unwrap();
    grant(db, attachment_id, grants).await;
    let blob = crate::blob::insert_blob(
        db,
        bytes,
        Some("text/plain"),
        Some(&format!("{attachment_id}.txt")),
    )
    .await
    .unwrap();
    set_facet(
        db,
        attachment_id,
        FacetSetPayload {
            key: "blob_ref".into(),
            value: Some(blob.id.clone()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    link(
        db,
        &format!("bearer-{attachment_id}"),
        attachment_id,
        bearer_id,
        "part_of",
    )
    .await;
    blob.id
}
/// Attachment whose blob row is external-tier with the given `external_ref`,
/// inserted the way `query::sql` external-blob tests do (raw blob row with
/// `bytes IS NULL` plus the ordinary attachment write path around it).
pub(crate) async fn attach_external(
    db: &Db,
    attachment_id: &str,
    bearer_id: &str,
    grants: Vec<AllowEntry>,
    blob_id: &str,
    external_ref: &str,
) {
    create_record(
        db,
        json!({
            "id": attachment_id,
            "type": "Document",
            "kind": "attachment",
            "name": "external.bin",
            "home_id": ROOT_RECORD_ID,
        }),
    )
    .await
    .unwrap();
    grant(db, attachment_id, grants).await;
    sqlx::query(
        "INSERT INTO blobs
           (id, bytes, mime, size_bytes, sha256, original_filename,
            storage_tier, external_ref)
         VALUES (?, NULL, 'application/octet-stream', ?, '00',
                 'external.bin', 'external', ?)",
    )
    .bind(blob_id)
    .bind(1_000_000_i64)
    .bind(external_ref)
    .execute(db.write_pool())
    .await
    .unwrap();
    set_facet(
        db,
        attachment_id,
        FacetSetPayload {
            key: "blob_ref".into(),
            value: Some(blob_id.into()),
            vocab_ref: None,
            as_of: None,
            observation_only: false,
        },
    )
    .await
    .unwrap();
    link(
        db,
        &format!("bearer-{attachment_id}"),
        attachment_id,
        bearer_id,
        "part_of",
    )
    .await;
}

/// User-layer `schema_config` row through the real write path.
pub(crate) async fn schema_row(db: &Db, id: &str, data: Value, collection: Option<&str>) {
    write_user_schema_config(
        db,
        data,
        SchemaConfigOptions {
            id: Some(id.into()),
            version_lineage: None,
            applies_to_collection_id: collection.map(str::to_string),
        },
    )
    .await
    .unwrap();
}

/// Message record with addressed-to audience rows, as
/// `message_expectation.rs` tests do (record write path + audience rows).
pub(crate) async fn message_to(db: &Db, id: &str, grants: Vec<AllowEntry>, principals: &[&str]) {
    create_record(
        db,
        json!({ "id": id, "type": "Message", "kind": "text", "name": id }),
    )
    .await
    .unwrap();
    grant(db, id, grants).await;
    for principal in principals {
        sqlx::query(
            "INSERT INTO message_audiences
               (message_id, principal_id, source, grant_id, event_seq, created_at)
             VALUES (?, ?, 'addressed_to', 'test-grant', 1,
                     '2026-01-01T00:00:00Z')",
        )
        .bind(id)
        .bind(*principal)
        .execute(db.write_pool())
        .await
        .unwrap();
    }
}

/// Account-scope instruction binding for `account` to `source`, written the
/// way the production writer does (raw projection row; `created_by` is the
/// account). Decision #4: the producer ships it only when `source` ∈ E(m).
pub(crate) async fn insert_instruction_binding(
    db: &Db,
    id: &str,
    account: &str,
    source: &str,
    position: i64,
) {
    sqlx::query(
        "INSERT INTO instruction_bindings
           (id, scope_kind, scope_id, source_record_id, position, enabled,
            created_by, created_at, updated_at)
         VALUES (?, 'account', ?, ?, ?, 1, ?,
                 '2026-09-29T00:00:00.000Z', '2026-09-29T00:00:00.000Z')",
    )
    .bind(id)
    .bind(account)
    .bind(source)
    .bind(position)
    .bind(account)
    .execute(db.write_pool())
    .await
    .unwrap();
}

/// Read back the policy anchor of a record (to pin anchor-sharing claims).
pub(crate) async fn anchor_of(db: &Db, id: &str) -> String {
    sqlx::query("SELECT policy_anchor_id FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(db.write_pool())
        .await
        .unwrap()
        .try_get("policy_anchor_id")
        .unwrap()
}

/// Raw-presence pins: every handle must exist in the owning world before any
/// E(m) absence assertion, so a silently dropped artefact cannot leave the
/// tests green while later raw-byte scans have nothing to find.
pub(crate) async fn assert_record_present(db: &Db, id: &str) {
    let found: Option<String> = sqlx::query_scalar("SELECT id FROM records WHERE id = ?")
        .bind(id)
        .fetch_optional(db.write_pool())
        .await
        .unwrap();
    assert_eq!(found.as_deref(), Some(id), "record {id} must exist");
}

pub(crate) async fn assert_link_present(db: &Db, id: &str) {
    let found: Option<String> = sqlx::query_scalar("SELECT id FROM links WHERE id = ?")
        .bind(id)
        .fetch_optional(db.write_pool())
        .await
        .unwrap();
    assert_eq!(found.as_deref(), Some(id), "link {id} must exist");
}

pub(crate) async fn assert_schema_row_present(db: &Db, id: &str) {
    let found: Option<String> = sqlx::query_scalar("SELECT id FROM schema_config WHERE id = ?")
        .bind(id)
        .fetch_optional(db.write_pool())
        .await
        .unwrap();
    assert_eq!(
        found.as_deref(),
        Some(id),
        "schema_config row {id} must exist"
    );
}

pub(crate) async fn assert_blob_present(db: &Db, id: &str) {
    let found: Option<String> = sqlx::query_scalar("SELECT id FROM blobs WHERE id = ?")
        .bind(id)
        .fetch_optional(db.write_pool())
        .await
        .unwrap();
    assert_eq!(found.as_deref(), Some(id), "blob {id} must exist");
}

pub(crate) async fn assert_audience_present(db: &Db, message_id: &str, principal: &str) {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT message_id FROM message_audiences WHERE message_id = ? AND principal_id = ?",
    )
    .bind(message_id)
    .bind(principal)
    .fetch_optional(db.write_pool())
    .await
    .unwrap();
    assert_eq!(
        found.as_deref(),
        Some(message_id),
        "audience for {message_id} to {principal} must exist"
    );
}

/// Differential provenance for E(m): `workspace_visible_set` (the governed
/// query_sql view) must agree with the `authorization.rs` evaluator
/// (owner floor + bearer minimum, contract §3.2) on every live record id.
///
/// Annotation records and Unit-borne records are skipped, not compared:
/// E(m) subtracts attribution/acknowledgement annotations, semantic Units
/// and anything they bear (`query::sql` views; contract §3.2 records row
/// rule), while `effective_capability` evaluates the bearer chain without
/// that generic-surface subtraction, so the two would spuriously disagree
/// there. At least one record must be compared, so an all-skipped call
/// cannot pass vacuously.
pub(crate) async fn assert_evaluator_agreement(db: &Db, account: &str, ids: &[&str]) {
    let set = online_visible_ids(db, account).await;
    let mut compared = 0_usize;
    for id in ids {
        assert_record_present(db, id).await;
        let row = sqlx::query("SELECT type, kind FROM records WHERE id = ?")
            .bind(id)
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        let record_type: String = row.try_get("type").unwrap();
        let kind: Option<String> = row.try_get("kind").unwrap();
        let unit_borne: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM semantic_units WHERE unit_id = ?)")
                .bind(id)
                .fetch_one(db.write_pool())
                .await
                .unwrap();
        if record_type == "Annotation" || kind.as_deref() == Some("semantic-unit") || unit_borne {
            continue;
        }
        let capability = effective_capability(db, Principal::bound(account, true), id)
            .await
            .unwrap();
        assert_eq!(
            set.contains(*id),
            capability.allows(Capability::View),
            "evaluators disagree on {id} for {account}"
        );
        compared += 1;
    }
    assert!(compared > 0, "assert_evaluator_agreement compared nothing");
}

/// Column order for [`record_row_cells`]: every column of the live `records`
/// table, verified by `PRAGMA table_info(records)` on a fixture-built
/// database (20 columns, cid 0–19, ending in integer `archived`).
pub(crate) const RECORD_ROW_COLUMNS: &[&str] = &[
    "id",
    "type",
    "kind",
    "name",
    "body",
    "home_id",
    "lifecycle",
    "owner_id",
    "claimed_by_account",
    "claimed_run_key",
    "claimed_at",
    "policy_anchor_id",
    "persistence",
    "maturity",
    "summary",
    "last_activity_at",
    "created_at",
    "updated_at",
    "deleted_at",
    "archived",
];

/// Full raw `records` row as ordered strings ([`RECORD_ROW_COLUMNS` order;
/// every live column of the table).
pub(crate) async fn record_row_cells(db: &Db, id: &str) -> Vec<String> {
    let sql = format!(
        "SELECT {} FROM records WHERE id = ?",
        RECORD_ROW_COLUMNS.join(", ")
    );
    let row = sqlx::query(&sql)
        .bind(id)
        .fetch_one(db.write_pool())
        .await
        .unwrap();
    let mut cells: Vec<String> = Vec::new();
    for column in RECORD_ROW_COLUMNS {
        // `archived` is the table's only INTEGER column; the rest are TEXT.
        if *column == "archived" {
            let value: Option<i64> = row.try_get(*column).unwrap();
            cells.push(
                value
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "<null>".into()),
            );
        } else {
            cells.push(
                row.try_get::<Option<String>, _>(*column)
                    .unwrap()
                    .unwrap_or_else(|| "<null>".into()),
            );
        }
    }
    cells
}
/// §7.2 item 3 (`two_caller_world`): members A and B share one anchor set
/// (a `members`-granted collection with an inheriting child); A owns a
/// record through the owner floor; an attachment with an A-only bearer; a
/// hidden parent with a visible child; a visible->hidden link; a hidden
/// record mentioned in a visible body; an invisible successor; an external
/// blob whose `external_ref` embeds a hidden UUID; a collection-scoped
/// schema row on a hidden collection; a collection-scoped schema row that
/// embeds a hidden id (gate-failing row); a message addressed only to A.
pub(crate) mod two_caller {
    use super::*;

    pub(crate) const PERSON_A: &str = "f1000000-0000-4000-8000-0000000000a1";
    pub(crate) const PERSON_B: &str = "f1000000-0000-4000-8000-0000000000b1";
    pub(crate) const SHARED: &str = "f1000000-0000-4000-8000-000000000001";
    pub(crate) const SHARED_CHILD: &str = "f1000000-0000-4000-8000-000000000002";
    pub(crate) const A_OWNED: &str = "f1000000-0000-4000-8000-000000000003";
    pub(crate) const BEARER_A: &str = "f1000000-0000-4000-8000-000000000004";
    pub(crate) const ATT_A: &str = "f1000000-0000-4000-8000-000000000005";
    pub(crate) const HIDDEN_PARENT: &str = "f1000000-0000-4000-8000-000000000006";
    pub(crate) const VISIBLE_CHILD: &str = "f1000000-0000-4000-8000-000000000007";
    pub(crate) const HIDDEN_MENTIONED: &str = "f1000000-0000-4000-8000-000000000008";
    pub(crate) const OLD_RECORD: &str = "f1000000-0000-4000-8000-000000000009";
    pub(crate) const NEWER_HIDDEN: &str = "f1000000-0000-4000-8000-000000000010";
    pub(crate) const MSG_A: &str = "f1000000-0000-4000-8000-000000000011";
    pub(crate) const EXT_ATTACH: &str = "f1000000-0000-4000-8000-000000000012";
    pub(crate) const EXT_BLOB: &str = "f1000000-0000-4000-8000-00000000b012";
    pub(crate) const HIDDEN_COLLECTION: &str = "f1000000-0000-4000-8000-000000000013";
    /// Visible to B only: the record hidden from A.
    pub(crate) const B_ONLY: &str = "f1000000-0000-4000-8000-000000000014";
    pub(crate) const HIDDEN_COLL_SCHEMA: &str = "two-caller-hidden-coll-schema";
    pub(crate) const GATED_COLL_SCHEMA: &str = "two-caller-gated-coll-schema";
    /// A's account-scope instruction binding whose source (B_ONLY) is hidden
    /// from A: decision #4 says it must not ship.
    pub(crate) const BINDING_HIDDEN_SOURCE: &str = "two-caller-binding-hidden";
    /// A's account-scope instruction binding whose source (SHARED_CHILD) is
    /// visible to A: the twin that proves the rule is about the source.
    pub(crate) const BINDING_VISIBLE_SOURCE: &str = "two-caller-binding-visible";
    /// Facet value on HIDDEN_PARENT (hidden from B): §7.2 item 1(a) requires a
    /// raw scan to find no hidden facet value.
    pub(crate) const HIDDEN_PARENT_FACET: &str = "two-caller-hidden-parent-facet";
    /// Facet value on B_ONLY (hidden from A).
    pub(crate) const B_ONLY_FACET: &str = "two-caller-b-only-facet";

    // Hidden artefact *values* (handles for later raw-byte scans; record
    // names already equal their ids, so ids cover names).
    pub(crate) const ATT_A_BYTES: &[u8] = b"a-only bytes";
    pub(crate) const LINK_VIS_HIDDEN: &str = "two-caller-vis-hidden";
    pub(crate) const LINK_SUPERSEDES: &str = "two-caller-supersedes";
    /// `external_ref` embeds B_ONLY in full: for A the row ships (bearer and
    /// attachment are members-visible) while the future exact-id gate (§3.3
    /// rule 6) withholds the value; for B the gate passes.
    pub(crate) fn ext_ref_value() -> String {
        format!("external://vault/{B_ONLY}")
    }
    /// Ids a raw scan must permit because they appear in visible authored
    /// text: the visible SHARED_CHILD body cites HIDDEN_MENTIONED's full
    /// UUID, which ships verbatim under §3.3 rule 4 (online parity).
    pub(crate) fn authored_disclosed_ids() -> Vec<&'static str> {
        vec![HIDDEN_MENTIONED]
    }

    pub(crate) struct World {
        pub db: Db,
    }

    /// Ids E(A) must contain.
    pub(crate) fn visible_to_a() -> Vec<&'static str> {
        vec![
            PERSON_A,
            PERSON_B,
            SHARED,
            SHARED_CHILD,
            A_OWNED,
            BEARER_A,
            ATT_A,
            HIDDEN_PARENT,
            VISIBLE_CHILD,
            HIDDEN_MENTIONED,
            OLD_RECORD,
            NEWER_HIDDEN,
            MSG_A,
            EXT_ATTACH,
            HIDDEN_COLLECTION,
        ]
    }

    /// Ids E(B) must contain.
    pub(crate) fn visible_to_b() -> Vec<&'static str> {
        vec![
            PERSON_A,
            PERSON_B,
            SHARED,
            SHARED_CHILD,
            VISIBLE_CHILD,
            OLD_RECORD,
            EXT_ATTACH,
            B_ONLY,
        ]
    }

    /// Record ids E(B) must exclude (every handle hidden from B).
    pub(crate) fn hidden_from_b() -> Vec<&'static str> {
        vec![
            A_OWNED,
            BEARER_A,
            ATT_A,
            HIDDEN_PARENT,
            HIDDEN_MENTIONED,
            NEWER_HIDDEN,
            MSG_A,
            HIDDEN_COLLECTION,
        ]
    }

    /// Record ids E(A) must exclude (every handle hidden from A).
    pub(crate) fn hidden_from_a() -> Vec<&'static str> {
        vec![B_ONLY]
    }

    pub(crate) async fn build() -> World {
        let db = create_database(":memory:").await.unwrap();
        create_member(&db, PERSON_A, ACCT_A).await;
        create_member(&db, PERSON_B, ACCT_B).await;
        grant(&db, PERSON_A, vec![AllowEntry::members(Capability::View)]).await;
        grant(&db, PERSON_B, vec![AllowEntry::members(Capability::View)]).await;

        // Shared anchor set: members-granted collection, child inherits.
        mk_collection(&db, SHARED, ROOT_RECORD_ID).await;
        grant(&db, SHARED, vec![AllowEntry::members(Capability::View)]).await;
        mk_doc(&db, SHARED_CHILD, SHARED, None, None).await;

        // Owner floor: A owns it, nobody is granted it.
        mk_doc(&db, A_OWNED, SHARED, None, Some(PERSON_A)).await;
        grant(&db, A_OWNED, vec![]).await;

        // Bearer-restricted attachment: bearer visible to A only. The
        // attachment's own grant is irrelevant (attachments authorize via
        // the bearer walk), so it carries an A-only grant for honesty.
        mk_doc(&db, BEARER_A, ROOT_RECORD_ID, None, None).await;
        grant(
            &db,
            BEARER_A,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        attach_inline(
            &db,
            ATT_A,
            BEARER_A,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
            ATT_A_BYTES,
        )
        .await;
        // Hidden parent (A only) with a child visible to both.
        mk_collection(&db, HIDDEN_PARENT, ROOT_RECORD_ID).await;
        grant(
            &db,
            HIDDEN_PARENT,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        // Hidden facet value on the hidden parent.
        set_facet(
            &db,
            HIDDEN_PARENT,
            FacetSetPayload {
                key: "note".into(),
                value: Some(HIDDEN_PARENT_FACET.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        mk_doc(&db, VISIBLE_CHILD, HIDDEN_PARENT, None, None).await;
        grant(
            &db,
            VISIBLE_CHILD,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;

        // Hidden record mentioned (URL form) in a visible body.
        mk_doc(&db, HIDDEN_MENTIONED, ROOT_RECORD_ID, None, None).await;
        grant(
            &db,
            HIDDEN_MENTIONED,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        update_record(
            &db,
            SHARED_CHILD,
            json!({ "body": format!("see n8v.to/{HIDDEN_MENTIONED} for details") }),
        )
        .await
        .unwrap();

        // Visible -> hidden link ("mentions" is content-owned, so the edge
        // lands in the links table; "relates_to" would be relationship-owned
        // and never projected there).
        link(
            &db,
            LINK_VIS_HIDDEN,
            SHARED_CHILD,
            HIDDEN_PARENT,
            "mentions",
        )
        .await;

        // Invisible successor: hidden newer record supersedes a visible one.
        mk_doc(&db, OLD_RECORD, ROOT_RECORD_ID, None, None).await;
        grant(&db, OLD_RECORD, vec![AllowEntry::members(Capability::View)]).await;
        mk_doc(&db, NEWER_HIDDEN, ROOT_RECORD_ID, None, None).await;
        grant(
            &db,
            NEWER_HIDDEN,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        link(&db, LINK_SUPERSEDES, NEWER_HIDDEN, OLD_RECORD, "supersedes").await;

        // B-only record: hidden from A, visible to B.
        mk_doc(&db, B_ONLY, ROOT_RECORD_ID, Some("b-only note"), None).await;
        grant(
            &db,
            B_ONLY,
            vec![AllowEntry::account(ACCT_B, Capability::View)],
        )
        .await;
        // Hidden facet value on the B-only record (hidden from A).
        set_facet(
            &db,
            B_ONLY,
            FacetSetPayload {
                key: "note".into(),
                value: Some(B_ONLY_FACET.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();

        // Decision #4 instruction bindings are deliberately NOT seeded in the
        // shared world: an account-scope binding to a hidden source makes
        // `resolve_for_account` return `invalid`, which would break the
        // qualification suite that builds on this world. The producer test
        // seeds `BINDING_VISIBLE_SOURCE`/`BINDING_HIDDEN_SOURCE` on its own
        // copy of this database instead.

        // External blob on a both-visible bearer (OLD_RECORD) whose
        // external_ref embeds B_ONLY in full: the row ships to A while the
        // value is outside E(A) (future gate withholds it); B sees both.
        attach_external(
            &db,
            EXT_ATTACH,
            OLD_RECORD,
            vec![AllowEntry::members(Capability::View)],
            EXT_BLOB,
            &ext_ref_value(),
        )
        .await;

        // Hidden collection + its collection-scoped schema row.
        mk_collection(&db, HIDDEN_COLLECTION, ROOT_RECORD_ID).await;
        grant(
            &db,
            HIDDEN_COLLECTION,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        schema_row(
            &db,
            HIDDEN_COLL_SCHEMA,
            json!({"shapes": {}}),
            Some(HIDDEN_COLLECTION),
        )
        .await;

        // Collection-scoped schema row on the visible collection that embeds
        // a hidden id in full (future gate-failing row).
        schema_row(
            &db,
            GATED_COLL_SCHEMA,
            json!({"shapes": {}, "note": HIDDEN_MENTIONED}),
            Some(SHARED),
        )
        .await;

        // Message addressed only to A.
        message_to(
            &db,
            MSG_A,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
            &[ACCT_A],
        )
        .await;

        World { db }
    }

    #[tokio::test]
    async fn world_is_what_it_claims() {
        let world = build().await;
        // A and B share one anchor set: the child inherits the grant.
        assert_eq!(anchor_of(&world.db, SHARED_CHILD).await, SHARED);
        // Raw presence first: every handle exists before any E(m) claim.
        for id in visible_to_a().iter().chain(visible_to_b().iter()) {
            assert_record_present(&world.db, id).await;
        }
        for id in hidden_from_a().iter().chain(hidden_from_b().iter()) {
            assert_record_present(&world.db, id).await;
        }
        assert_link_present(&world.db, LINK_VIS_HIDDEN).await;
        assert_link_present(&world.db, LINK_SUPERSEDES).await;
        assert_blob_present(&world.db, EXT_BLOB).await;
        assert_schema_row_present(&world.db, HIDDEN_COLL_SCHEMA).await;
        assert_schema_row_present(&world.db, GATED_COLL_SCHEMA).await;
        assert_audience_present(&world.db, MSG_A, ACCT_A).await;
        // The external_ref value embeds B_ONLY in full.
        let ext_ref: String = sqlx::query_scalar("SELECT external_ref FROM blobs WHERE id = ?")
            .bind(EXT_BLOB)
            .fetch_one(world.db.write_pool())
            .await
            .unwrap();
        assert_eq!(ext_ref, ext_ref_value());
        let ea = online_visible_ids(&world.db, ACCT_A).await;
        let eb = online_visible_ids(&world.db, ACCT_B).await;
        for id in visible_to_a() {
            assert!(ea.contains(id), "E(A) must contain {id}");
        }
        for id in visible_to_b() {
            assert!(eb.contains(id), "E(B) must contain {id}");
        }
        for id in hidden_from_b() {
            assert!(!eb.contains(id), "E(B) must exclude hidden {id}");
        }
        for id in hidden_from_a() {
            assert!(!ea.contains(id), "E(A) must exclude hidden {id}");
        }
        // Owner floor: A sees its owned record although nobody is granted it.
        assert!(ea.contains(A_OWNED));
        // §3.3 rule 1: the raw home still points at the hidden parent ...
        let home: Option<String> = sqlx::query("SELECT home_id FROM records WHERE id = ?")
            .bind(VISIBLE_CHILD)
            .fetch_one(world.db.write_pool())
            .await
            .unwrap()
            .try_get("home_id")
            .unwrap();
        assert_eq!(home.as_deref(), Some(HIDDEN_PARENT));
        // ... while the governed view NULLs it for B.
        let governed = query_sql(
            &world.db,
            QueryPrincipal::authenticated(ACCT_B, true),
            &format!("SELECT home_id FROM records WHERE id = '{VISIBLE_CHILD}'"),
        )
        .await
        .unwrap();
        assert_eq!(governed.rows, vec![json!({"home_id": Value::Null})]);
        assert_authored_disclosures(&world.db, ACCT_B, &authored_disclosed_ids()).await;
        // Both evaluators agree on every record id in the world.
        let mut all: Vec<&str> = visible_to_a();
        all.extend(visible_to_b());
        all.extend(hidden_from_a());
        all.extend(hidden_from_b());
        all.sort();
        all.dedup();
        assert_evaluator_agreement(&world.db, ACCT_A, &all).await;
        assert_evaluator_agreement(&world.db, ACCT_B, &all).await;
    }
}
/// §7.2 item 1 (`hidden_change_worlds`): World B = World A plus exactly the
/// hidden-only changes listed in item 1. Member of interest is B, from whom
/// every delta is hidden.
///
/// The listed "hidden Unit-bearer change" is deliberately not built: Units
/// and anything they bear are excluded from member v1 (contract §3.2
/// `records` row rule — generic surfaces subtract Units and Unit-borne
/// records — and the §4.1 trigger-coverage exemption owned by 766ede6), so
/// such a change cannot move E(m) for a member copy. TODO(producer): revisit
/// if Units ever enter the member profile.
pub(crate) mod hidden_change {
    use super::*;

    pub(crate) const PERSON_A: &str = "b2000000-0000-4000-8000-0000000000a1";
    pub(crate) const PERSON_B: &str = "b2000000-0000-4000-8000-0000000000b1";
    pub(crate) const SHARED_H: &str = "b2000001-0000-4000-8000-000000000001";
    pub(crate) const VIS_H: &str = "b2000000-0000-4000-8000-000000000001";
    pub(crate) const HIDDEN_H: &str = "b2000002-0000-4000-8000-000000000001";
    pub(crate) const HIDDEN_NEW: &str = "b2000002-0000-4000-8000-000000000002";
    /// Shares an 8-hex prefix ("b2000000", exceeding the 7+ requirement)
    /// with the visible VIS_H record.
    pub(crate) const HIDDEN_PREFIX_SIBLING: &str = "b2000000-0000-4000-8000-000000000002";
    pub(crate) const NEWER_H: &str = "b2000002-0000-4000-8000-000000000003";
    pub(crate) const GLOBAL_SCHEMA: &str = "hidden-change-global-schema";

    // Hidden artefact *values* (handles for later raw-byte scans).
    pub(crate) const VIS_BODY_BASE: &str = "visible base";
    pub(crate) const HIDDEN_BODY_BASE: &str = "hidden base";
    pub(crate) const HIDDEN_BODY_EDITED: &str = "hidden edited";
    pub(crate) const HIDDEN_BODY_NEW: &str = "hidden new";
    pub(crate) const HIDDEN_BODY_PREFIX: &str = "hidden prefix sibling";
    pub(crate) const HIDDEN_BODY_NEWER: &str = "hidden newer";
    pub(crate) const LINK_VIS_HIDDEN: &str = "hidden-change-vis-hidden";
    pub(crate) const LINK_SUPERSEDES: &str = "hidden-change-supersedes";
    /// A facet value on the hidden HIDDEN_H record: §7.2 item 1(a) requires a
    /// raw scan to find no hidden facet value either.
    pub(crate) const HIDDEN_FACET_KEY: &str = "hidden-change-note";
    pub(crate) const HIDDEN_FACET_VALUE: &str = "hidden-change-facet-value";
    /// No visible authored text embeds a hidden full id in this world, so a
    /// raw scan must permit nothing beyond the shipped visible values.
    pub(crate) fn authored_disclosed_ids() -> Vec<&'static str> {
        vec![]
    }

    pub(crate) struct Worlds {
        pub a: Db,
        pub b: Db,
        /// Owns the database files (both worlds are file-backed so B can
        /// start as a byte-level clone of A).
        _dir: tempfile::TempDir,
    }

    pub(crate) fn visible_to_b() -> Vec<&'static str> {
        vec![PERSON_A, PERSON_B, SHARED_H, VIS_H]
    }

    pub(crate) fn hidden_from_b() -> Vec<&'static str> {
        vec![HIDDEN_H, HIDDEN_NEW, HIDDEN_PREFIX_SIBLING, NEWER_H]
    }

    async fn build_base(db: &Db) {
        create_member(db, PERSON_A, ACCT_A).await;
        create_member(db, PERSON_B, ACCT_B).await;
        grant(db, PERSON_A, vec![AllowEntry::members(Capability::View)]).await;
        grant(db, PERSON_B, vec![AllowEntry::members(Capability::View)]).await;
        mk_collection(db, SHARED_H, ROOT_RECORD_ID).await;
        grant(db, SHARED_H, vec![AllowEntry::members(Capability::View)]).await;
        mk_doc(db, VIS_H, ROOT_RECORD_ID, Some(VIS_BODY_BASE), None).await;
        grant(db, VIS_H, vec![AllowEntry::members(Capability::View)]).await;
        mk_doc(db, HIDDEN_H, ROOT_RECORD_ID, Some(HIDDEN_BODY_BASE), None).await;
        grant(
            db,
            HIDDEN_H,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
    }

    async fn apply_hidden_deltas(db: &Db) {
        // Hidden record creation, incl. the prefix-colliding one.
        mk_doc(db, HIDDEN_NEW, ROOT_RECORD_ID, Some(HIDDEN_BODY_NEW), None).await;
        grant(
            db,
            HIDDEN_NEW,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        mk_doc(
            db,
            HIDDEN_PREFIX_SIBLING,
            ROOT_RECORD_ID,
            Some(HIDDEN_BODY_PREFIX),
            None,
        )
        .await;
        grant(
            db,
            HIDDEN_PREFIX_SIBLING,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        // Hidden edit.
        update_record(db, HIDDEN_H, json!({ "body": HIDDEN_BODY_EDITED }))
            .await
            .unwrap();
        // Hidden policy change (still A-only: View -> Edit).
        grant(
            db,
            HIDDEN_H,
            vec![AllowEntry::account(ACCT_A, Capability::Edit)],
        )
        .await;
        // Link from a visible record to a hidden record (content-owned).
        link(db, LINK_VIS_HIDDEN, VIS_H, HIDDEN_H, "mentions").await;
        // Hidden invisible successor of a visible record.
        mk_doc(db, NEWER_H, ROOT_RECORD_ID, Some(HIDDEN_BODY_NEWER), None).await;
        grant(
            db,
            NEWER_H,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        link(db, LINK_SUPERSEDES, NEWER_H, VIS_H, "supersedes").await;
        // Hidden facet value on a hidden record.
        set_facet(
            db,
            HIDDEN_H,
            FacetSetPayload {
                key: HIDDEN_FACET_KEY.into(),
                value: Some(HIDDEN_FACET_VALUE.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
        // Hidden id embedded in full in a global schema_config.data.
        schema_row(
            db,
            GLOBAL_SCHEMA,
            json!({"shapes": {}, "note": HIDDEN_H}),
            None,
        )
        .await;
    }

    pub(crate) async fn build() -> Worlds {
        // No test clock exists: record timestamps come from the wall clock
        // (`store::now_iso`), so two write passes can never agree. Instead B
        // starts as a file clone of A (`VACUUM INTO`) and only the hidden
        // deltas run after the fork. Untouched rows — including every
        // shipped timestamp — are therefore identical in A and B.
        let dir = tempfile::tempdir().unwrap();
        let a_path = dir.path().join("a.db");
        let a = create_database(a_path.to_str().unwrap()).await.unwrap();
        build_base(&a).await;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(a.write_pool())
            .await
            .unwrap();
        let b_path = dir.path().join("b.db");
        let into = format!(
            "VACUUM INTO '{}'",
            b_path.to_string_lossy().replace('\'', "''")
        );
        sqlx::query(&into).execute(a.write_pool()).await.unwrap();
        let b = open_database(b_path.to_str().unwrap()).await.unwrap();
        apply_hidden_deltas(&b).await;
        Worlds { a, b, _dir: dir }
    }

    #[tokio::test]
    async fn hidden_only_changes_move_nothing_for_b() {
        let worlds = build().await;
        assert_authored_disclosures(&worlds.b, ACCT_B, &authored_disclosed_ids()).await;
        // Raw presence: base handles exist in both worlds, delta handles in
        // B only, before any E(m) claim.
        for id in visible_to_b() {
            assert_record_present(&worlds.a, id).await;
            assert_record_present(&worlds.b, id).await;
        }
        assert_record_present(&worlds.a, HIDDEN_H).await;
        for id in hidden_from_b() {
            assert_record_present(&worlds.b, id).await;
        }
        assert_link_present(&worlds.b, LINK_VIS_HIDDEN).await;
        assert_link_present(&worlds.b, LINK_SUPERSEDES).await;
        assert_schema_row_present(&worlds.b, GLOBAL_SCHEMA).await;
        // The hidden edit landed in B only.
        let body_a: String = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
            .bind(HIDDEN_H)
            .fetch_one(worlds.a.write_pool())
            .await
            .unwrap();
        let body_b: String = sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
            .bind(HIDDEN_H)
            .fetch_one(worlds.b.write_pool())
            .await
            .unwrap();
        assert_eq!(body_a, HIDDEN_BODY_BASE);
        assert_eq!(body_b, HIDDEN_BODY_EDITED);
        let ea = online_visible_ids(&worlds.a, ACCT_B).await;
        let eb = online_visible_ids(&worlds.b, ACCT_B).await;
        for id in visible_to_b() {
            assert!(ea.contains(id), "E_A(B) must contain {id}");
            assert!(eb.contains(id), "E_B(B) must contain {id}");
        }
        for id in hidden_from_b() {
            assert!(!ea.contains(id), "E_A(B) must exclude hidden {id}");
            assert!(!eb.contains(id), "E_B(B) must exclude hidden {id}");
        }
        // Hidden-only deltas add/remove no record for B.
        assert_eq!(ea, eb);
        // §7.2 item 1(c) attribution: every visible record's raw row is
        // identical in A and B except VIS_H, whose updated_at and
        // last_activity_at legitimately move — the hidden delta adds a link
        // FROM it, and link writes touch the source record whatever the
        // target (contract §2.4 item 3). Those two columns are the only
        // allowed difference, and they must actually differ.
        let laa = RECORD_ROW_COLUMNS
            .iter()
            .position(|c| *c == "last_activity_at")
            .unwrap();
        let uaa = RECORD_ROW_COLUMNS
            .iter()
            .position(|c| *c == "updated_at")
            .unwrap();
        for id in visible_to_b() {
            let ra = record_row_cells(&worlds.a, id).await;
            let rb = record_row_cells(&worlds.b, id).await;
            assert_eq!(ra.len(), rb.len());
            for (ix, (ca, cb)) in ra.iter().zip(rb.iter()).enumerate() {
                if id == VIS_H && (ix == laa || ix == uaa) {
                    continue;
                }
                assert_eq!(
                    ca, cb,
                    "column {} of visible {id} differs between A and B",
                    RECORD_ROW_COLUMNS[ix]
                );
            }
            if id == VIS_H {
                assert_ne!(
                    (&ra[laa], &ra[uaa]),
                    (&rb[laa], &rb[uaa]),
                    "VIS_H timestamps must move in B (link-touch)"
                );
            }
        }
        // Both evaluators agree on every record id in world B.
        let mut all: Vec<&str> = visible_to_b();
        all.extend(hidden_from_b());
        assert_evaluator_agreement(&worlds.b, ACCT_B, &all).await;
        assert_evaluator_agreement(&worlds.b, ACCT_A, &all).await;
    }
}
/// §7.2 item 2 (`prefix_gate_worlds`): a global `schema_config.data` value
/// contains the short reference `abc1234`. World `without` has no record
/// with that prefix; world `with` adds a hidden record whose id starts
/// `abc1234`. The value must ship verbatim in both worlds and E(B) must be
/// identical: the gate never resolves short references.
pub(crate) mod prefix_gate {
    use super::*;

    pub(crate) const PERSON_A: &str = "c3000000-0000-4000-8000-0000000000a1";
    pub(crate) const PERSON_B: &str = "c3000000-0000-4000-8000-0000000000b1";
    pub(crate) const VIS_P: &str = "c3000000-0000-4000-8000-000000000001";
    pub(crate) const HIDDEN_PREFIX: &str = "abc12340-0000-4000-8000-000000000001";
    pub(crate) const PREFIX_SCHEMA: &str = "prefix-gate-schema";

    pub(crate) const SHORT_REF_DATA: &str = "see abc1234 for context";

    /// Nothing here is a full hidden id: the schema note holds only the
    /// short reference `abc1234`, which the exact-id gate never resolves.
    pub(crate) fn authored_disclosed_ids() -> Vec<&'static str> {
        vec![]
    }

    pub(crate) struct Worlds {
        pub without: Db,
        pub with: Db,
        /// Owns the database files (`with` starts as a byte-level clone of
        /// `without`, so the two artifacts are identical apart from the
        /// hidden prefix record).
        _dir: tempfile::TempDir,
    }

    async fn build_base(db: &Db) {
        create_member(db, PERSON_A, ACCT_A).await;
        create_member(db, PERSON_B, ACCT_B).await;
        grant(db, PERSON_A, vec![AllowEntry::members(Capability::View)]).await;
        grant(db, PERSON_B, vec![AllowEntry::members(Capability::View)]).await;
        mk_doc(db, VIS_P, ROOT_RECORD_ID, Some("visible"), None).await;
        grant(db, VIS_P, vec![AllowEntry::members(Capability::View)]).await;
        schema_row(
            db,
            PREFIX_SCHEMA,
            json!({"shapes": {}, "note": SHORT_REF_DATA}),
            None,
        )
        .await;
    }

    pub(crate) async fn build() -> Worlds {
        // Same determinism rule as hidden_change: no test clock exists, so
        // `with` starts as a file clone of `without` and only the hidden
        // prefix record is added after the fork. Untouched rows — including
        // every shipped timestamp — are therefore identical, as §7.2 item 2
        // requires ("the artifact ... must be identical").
        let dir = tempfile::tempdir().unwrap();
        let without_path = dir.path().join("without.db");
        let without = create_database(without_path.to_str().unwrap())
            .await
            .unwrap();
        build_base(&without).await;
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(without.write_pool())
            .await
            .unwrap();
        let with_path = dir.path().join("with.db");
        let into = format!(
            "VACUUM INTO '{}'",
            with_path.to_string_lossy().replace('\'', "''")
        );
        sqlx::query(&into)
            .execute(without.write_pool())
            .await
            .unwrap();
        let with = open_database(with_path.to_str().unwrap()).await.unwrap();
        mk_doc(
            &with,
            HIDDEN_PREFIX,
            ROOT_RECORD_ID,
            Some("hidden prefix holder"),
            None,
        )
        .await;
        grant(
            &with,
            HIDDEN_PREFIX,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        Worlds {
            without,
            with,
            _dir: dir,
        }
    }

    async fn schema_note(db: &Db) -> String {
        sqlx::query("SELECT data FROM schema_config WHERE id = ?")
            .bind(PREFIX_SCHEMA)
            .fetch_one(db.write_pool())
            .await
            .unwrap()
            .try_get("data")
            .unwrap()
    }

    #[tokio::test]
    async fn short_reference_ships_verbatim_in_both_worlds() {
        assert!(HIDDEN_PREFIX.starts_with("abc1234"));
        let worlds = build().await;
        assert_authored_disclosures(&worlds.with, ACCT_B, &authored_disclosed_ids()).await;
        // Raw presence: the hidden prefix record exists in `with`.
        assert_record_present(&worlds.with, HIDDEN_PREFIX).await;
        assert_record_present(&worlds.with, VIS_P).await;
        assert_record_present(&worlds.without, VIS_P).await;
        assert_schema_row_present(&worlds.with, PREFIX_SCHEMA).await;
        assert_schema_row_present(&worlds.without, PREFIX_SCHEMA).await;
        // The short reference is opaque text: identical row in both worlds.
        assert_eq!(
            schema_note(&worlds.without).await,
            schema_note(&worlds.with).await
        );
        assert!(schema_note(&worlds.with).await.contains("abc1234"));
        // E(B) is identical whether or not the hidden prefix record exists.
        let e_without = online_visible_ids(&worlds.without, ACCT_B).await;
        let e_with = online_visible_ids(&worlds.with, ACCT_B).await;
        assert_eq!(e_without, e_with);
        assert!(e_with.contains(VIS_P));
        assert!(!e_with.contains(HIDDEN_PREFIX));
        // The hidden prefix record touches no visible row: every visible
        // records row (all columns) is identical in both worlds, with no
        // exceptions.
        for id in [PERSON_A, PERSON_B, VIS_P] {
            assert_eq!(
                record_row_cells(&worlds.without, id).await,
                record_row_cells(&worlds.with, id).await,
                "visible row {id} differs between the prefix_gate worlds"
            );
        }
        assert_evaluator_agreement(&worlds.with, ACCT_B, &[VIS_P, HIDDEN_PREFIX]).await;
        assert_evaluator_agreement(&worlds.without, ACCT_B, &[VIS_P]).await;
    }
}

/// §7.2 item 8 (§2.6, R5): walk any JSON value recursively and fail if a
/// workspace-wide counter-bearing *metadata* field appears. `context` names
/// the response under test; failures carry the JSON path (`$.a[0].act`).
///
/// Banned metadata: keys `act`, `head_act`, `frontier`; any key equal to `seq`
/// or ending in `_seq` (covers `as_of_seq`, `content_head_seq`,
/// `previous_seq`, `local_seq`, `event_seq`, `content_seq` in any position,
/// and the dropped `source_event_seq` / `meta_event_seq` /
/// `declaration_event_seq` / `creation_event_seq` columns of §3.2); any key
/// starting `authorization_revision`; key `acts` with a non-null value
/// (`acts: null` is the member replacement and is allowed); any string
/// value matching `^rec:\d+$` or `^obs:\d+$`. Allowed and exercised by the
/// clean test: `acts: null`, scoped `ordering.ordinal`,
/// `caller_write_ordinal`, and opaque `revision_digest` strings.
///
/// **Caller-authored payload is exempt.** Body, name, summary, snippets,
/// facet values and other authored JSON ship verbatim (§3.3 rule 4; §2.3
/// parity), so a user value may read `rec:123`/`obs:456` and authored JSON may
/// carry keys like `seq`. The scan never looks inside [`USER_PAYLOAD_KEYS`];
/// that is the only exemption, and it is by position, never by reinterpreting
/// a metadata field. `rows`/`columns` cover `query_sql` result sets, whose
/// column aliases are user-authored.
const USER_PAYLOAD_KEYS: &[&str] = &[
    "name",
    "body",
    "summary",
    "snippet",
    "markdown",
    "excerpt",
    "title",
    // user-authored JSON containers
    "value",
    "data",
    "metadata",
    "external_ref",
    "selectors",
    // query_sql result sets (aliases authored by the caller)
    "rows",
    "columns",
];

pub(crate) fn assert_no_counter_fields(value: &Value, context: &str) {
    const BANNED_KEYS: &[&str] = &["act", "head_act", "frontier"];

    fn is_counter_seq_key(key: &str) -> bool {
        key == "seq" || key.ends_with("_seq")
    }

    fn is_version_token(s: &str) -> bool {
        let rest = s.strip_prefix("rec:").or_else(|| s.strip_prefix("obs:"));
        rest.is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
    }

    fn walk(value: &Value, path: &str, context: &str) {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let child_path = format!("{path}.{key}");
                    if USER_PAYLOAD_KEYS.contains(&key.as_str()) {
                        // Authored payload: shipped verbatim, not a counter.
                        continue;
                    }
                    let banned = BANNED_KEYS.contains(&key.as_str())
                        || is_counter_seq_key(key)
                        || key.starts_with("authorization_revision")
                        || (key == "acts" && !child.is_null());
                    assert!(!banned, "{context}: counter-bearing field at {child_path}");
                    walk(child, &child_path, context);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    walk(child, &format!("{path}[{index}]"), context);
                }
            }
            Value::String(s) => {
                assert!(
                    !is_version_token(s),
                    "{context}: counter-bearing version token at {path}: {s}"
                );
            }
            _ => {}
        }
    }

    walk(value, "$", context);
}

/// §7.2 item 8 helper tests: one positive case per rule plus a clean
/// member-shaped example. Positive cases assert the exact JSON path.
#[cfg(test)]
mod counter_scan_tests {
    use super::*;
    use serde_json::json;

    #[test]
    #[should_panic(expected = "$.act")]
    fn rejects_act() {
        assert_no_counter_fields(&json!({"act": 5}), "t");
    }

    #[test]
    #[should_panic(expected = "$.head_act")]
    fn rejects_head_act() {
        assert_no_counter_fields(&json!({"head_act": 7}), "t");
    }

    #[test]
    #[should_panic(expected = "$.frontier")]
    fn rejects_frontier() {
        assert_no_counter_fields(&json!({"frontier": {"a": 1}}), "t");
    }

    #[test]
    #[should_panic(expected = "$.as_of_seq")]
    fn rejects_as_of_seq() {
        assert_no_counter_fields(&json!({"as_of_seq": 9}), "t");
    }

    #[test]
    #[should_panic(expected = "$.content_head_seq")]
    fn rejects_content_head_seq() {
        assert_no_counter_fields(&json!({"content_head_seq": 9}), "t");
    }

    #[test]
    #[should_panic(expected = "$.previous_seq")]
    fn rejects_previous_seq() {
        assert_no_counter_fields(&json!({"previous_seq": 9}), "t");
    }

    #[test]
    #[should_panic(expected = "$.a[0].local_seq")]
    fn rejects_local_seq_nested() {
        assert_no_counter_fields(&json!({"a": [{"local_seq": 1}]}), "t");
    }

    #[test]
    #[should_panic(expected = "$.event_seq")]
    fn rejects_event_seq() {
        assert_no_counter_fields(&json!({"event_seq": 4}), "t");
    }

    #[test]
    #[should_panic(expected = "$.authorization_revision_epoch")]
    fn rejects_authorization_revision_prefix() {
        assert_no_counter_fields(&json!({"authorization_revision_epoch": 3}), "t");
    }

    #[test]
    #[should_panic(expected = "$.acts")]
    fn rejects_non_null_acts() {
        assert_no_counter_fields(&json!({"acts": []}), "t");
    }

    #[test]
    #[should_panic(expected = "$.as_of.content_seq")]
    fn rejects_content_seq_under_as_of() {
        assert_no_counter_fields(&json!({"as_of": {"content_seq": 9}}), "t");
    }

    #[test]
    #[should_panic(expected = "$.version")]
    fn rejects_rec_token() {
        assert_no_counter_fields(&json!({"version": "rec:123"}), "t");
    }

    #[test]
    #[should_panic(expected = "$.facets[0].version")]
    fn rejects_obs_token_nested() {
        assert_no_counter_fields(&json!({"facets": [{"version": "obs:456"}]}), "t");
    }

    #[test]
    fn accepts_clean_member_shape() {
        assert_no_counter_fields(
            &json!({
                "acts": null,
                "ordering": {"kind": "scoped", "ordinal": 3},
                "caller_write_ordinal": 12,
                "revision_digest": "sha256:9f2c",
                "as_of": {"page_digest": "opaque"},
                "records": [
                    {"id": "b2000000-0000-4000-8000-000000000001",
                     "display_reference": "b2000000"}
                ]
            }),
            "clean",
        );
    }

    #[test]
    fn accepts_authored_counter_like_text_and_keys() {
        // Authored payload ships verbatim: counter-like text in name/body/
        // summary/facet values and authored JSON keys inside facet values (and
        // query_sql rows/aliases) are not metadata.
        assert_no_counter_fields(
            &json!({
                "records": [{
                    "name": "rec:123",
                    "body": "obs:456",
                    "summary": "rec:7",
                    "facets": [
                        {"key": "plain", "value": "obs:456"},
                        {"key": "payload", "value": {"seq": 1, "my_seq": 2}}
                    ]
                }],
                "rows": [{"seq": 3, "note": "rec:9"}],
                "columns": ["seq"]
            }),
            "authored payload",
        );
    }

    #[test]
    #[should_panic(expected = "$.source_event_seq")]
    fn rejects_dropped_seq_columns() {
        assert_no_counter_fields(&json!({"source_event_seq": 5}), "t");
    }

    #[test]
    #[should_panic(expected = "$.seq")]
    fn rejects_bare_seq() {
        assert_no_counter_fields(&json!({"seq": 1}), "t");
    }

    #[test]
    #[should_panic(expected = "$.error.details.previous_seq")]
    fn rejects_counter_in_refusal_payload() {
        assert_no_counter_fields(
            &json!({"error": {
                "code": "unavailable_offline",
                "surface": "get_history",
                "retry": "when_online",
                "details": {"previous_seq": 3}
            }}),
            "refusal",
        );
    }
}
