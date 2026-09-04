//! Observable engine scenarios shared by every storage backend.
//!
//! Keep this module above the physical storage boundary: no backend handle,
//! inspection SQL, filesystem path, or backend row type belongs here.

use native_ce::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Duration;

use super::{ContractHarness, DeliveredMessageFixture, TestCaller};

const REASON: &str = "Exercise the backend-neutral engine contract.";
const ROOT_ID: &str = "native:root";
const UNFILED_ID: &str = "native:unfiled";

const PREFIX_UNIQUE: &str = "1a2b3c4d-0000-4000-8000-00000000ffff";
const PREFIX_TWIN_A: &str = "dede01aa-0000-4000-8000-000000000001";
const PREFIX_TWIN_B: &str = "dede01bb-0000-4000-8000-000000000002";
const PREFIX_HIDDEN: &str = "c0ffee11-0000-4000-8000-000000000003";
const PREFIX_SHADOWED: &str = "abc1234a-0000-4000-8000-000000000004";
/// Caller-chosen ids from before record ids had to be canonical UUIDs. They
/// are seeded as history (see `create_historical_record_for_test`), never
/// through `create_record`. `PREFIX_EXACT` is deliberately a strict prefix of
/// [`PREFIX_SHADOWED`]; the ordered pair deliberately share a non-hex prefix.
const PREFIX_EXACT: &str = "abc123";
const PREFIX_ORDER_ONE: &str = "order-one";
const PREFIX_ORDER_TWO: &str = "order-two";
/// Asserted by `create_record.id`: a canonical UUID adjacent to
/// [`PREFIX_SHADOWED`], so it stays next to what a prefix scan might reach.
const PREFIX_ASSERTED: &str = "abc1240a-0000-4000-8000-000000000006";
/// Homed through a prefix; a plain canonical id, nothing about its spelling is
/// under test.
const PREFIX_HOMED: &str = "c07a0000-0000-4000-8000-000000000013";
const PREFIX_ALICE: &str = "a11ce000-0000-4000-8000-000000000014";
const PREFIX_BEA: &str = "bea00000-0000-4000-8000-000000000015";
const PREFIX_FOLDER: &str = "f01de400-0000-4000-8000-000000000005";
const PREFIX_ATTRIBUTION: &str = "a7700011-0000-4000-8000-000000000006";

pub const DESCRIBE_SCHEMA_KIND_ID: &str = "vv:voc:kind:Document:review_note";
pub const DESCRIBE_SCHEMA_KIND_TOKEN: &str = "review_note";
pub const DESCRIBE_SCHEMA_GLOBAL_CONFIG_ID: &str = "contract:schema:global";
pub const DESCRIBE_SCHEMA_HIDDEN_CONFIG_ID: &str = "contract:schema:hidden";
pub const DESCRIBE_SCHEMA_HIDDEN_COLLECTION_ID: &str = "c07a0000-0000-4000-8000-000000000012";

pub fn describe_schema_kind_metadata() -> Value {
    json!({
        "schema_version": 1,
        "provenance_ref": "rec:contract-schema-governance",
        "definition": "A governed Document kind installed by the describe-schema contract.",
        "identity": {
            "criterion": "The record is an independently identified review note.",
            "dedup": { "mode": "manual", "keys": [] }
        },
        "declared_capabilities": ["contract.describe_schema"]
    })
}

pub fn describe_schema_kind_payload() -> Value {
    json!({
        "vocabulary_id": "voc:kind:Document",
        "value": DESCRIBE_SCHEMA_KIND_TOKEN,
        "gloss": "Review note",
        "status": "active",
        "ordinal": 99.0,
        "terminality": "open",
        "metadata": describe_schema_kind_metadata()
    })
}

pub fn describe_schema_global_config_data() -> String {
    json!({
        "shapes": {
            "Document:review_note": {
                "facets": { "review_marker": { "required": true } }
            }
        }
    })
    .to_string()
}

pub fn describe_schema_hidden_config_data() -> String {
    json!({
        "shapes": {
            "Document:review_note": {
                "facets": { "hidden_marker": { "required": true } }
            }
        }
    })
    .to_string()
}

/// Shared assertion over the same semantic columns and governed mutations on
/// both physical adapters. This deliberately ignores driver carrier spelling.
pub fn assert_describe_schema_shared_contract(owner: &Value, member: &Value) {
    for (table_name, column_name, logical_type) in [
        ("content_events", "payload", "JSON"),
        ("content_events", "created_at", "TIMESTAMP"),
        ("facet_values", "value", "JSON"),
        ("bindings", "is_canonical", "BOOLEAN"),
        ("blobs", "bytes", "BLOB"),
        ("blobs", "size_bytes", "INTEGER"),
        ("vocabulary_values", "ordinal", "REAL"),
        ("vocabulary_values", "metadata", "JSON"),
        ("schema_config", "data", "JSON"),
        ("policy_events", "payload", "JSON"),
        ("storage_portability_policy", "targets", "JSON"),
        ("run_contexts", "updated_at", "TIMESTAMP"),
    ] {
        let table = owner["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["name"] == table_name)
            .unwrap_or_else(|| panic!("missing shared table {table_name}"));
        let column = table["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|column| column["name"] == column_name)
            .unwrap_or_else(|| panic!("missing shared column {table_name}.{column_name}"));
        assert_eq!(column["type"], logical_type, "{table_name}.{column_name}");
    }

    for (table_name, column_name, semantic_role, portability) in [
        (
            "content_events",
            "seq",
            "database_local_replay_position",
            "non_portable",
        ),
        (
            "content_events",
            "id",
            "portable_event_identity",
            "portable",
        ),
        (
            "content_event_sources",
            "source_seq",
            "origin_replay_position",
            "portable_with_origin_database_id",
        ),
    ] {
        let table = owner["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|table| table["name"] == table_name)
            .unwrap_or_else(|| panic!("missing semantic table {table_name}"));
        let column = table["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|column| column["name"] == column_name)
            .unwrap_or_else(|| panic!("missing semantic column {table_name}.{column_name}"));
        assert_eq!(column["semantic_role"], semantic_role);
        assert_eq!(column["portability"], portability);
    }

    let governed_kind = owner["kind_registry"]["Document"]
        .as_array()
        .unwrap()
        .iter()
        .find(|kind| kind["token"] == DESCRIBE_SCHEMA_KIND_TOKEN)
        .expect("governed kind mutation must be visible");
    assert_eq!(governed_kind["value_id"], DESCRIBE_SCHEMA_KIND_ID);
    assert_eq!(governed_kind["metadata"], describe_schema_kind_metadata());
    assert_eq!(
        owner["resolved_schema_config"]["shapes"]["Document:review_note"]["facets"]
            ["review_marker"]["required"],
        true
    );
    assert!(!owner["resolved_schema_config"]
        .to_string()
        .contains("hidden_marker"));
    assert_eq!(
        member["resolved_schema_config"],
        owner["resolved_schema_config"]
    );
    assert_eq!(member["kind_registry"], owner["kind_registry"]);
    assert_eq!(
        member["engine"]["ddl_fingerprint"],
        owner["engine"]["ddl_fingerprint"]
    );
}

async fn call<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
    tool: &str,
    arguments: Value,
) -> Result<Value> {
    harness
        .call(database, TestCaller::Local, tool, arguments)
        .await
}

async fn create<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
    arguments: Value,
) -> Result<Value> {
    call(harness, database, "create_record", arguments).await
}

/// Backend-neutral boundary contract for abbreviated record references.
///
/// These calls deliberately enter through real MCP dispatch. The scenario
/// therefore proves that resolution happens before both read and write
/// handlers without prescribing a database driver or inspecting physical
/// state.
pub async fn record_reference_resolution<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<()> {
    for (id, name) in [
        (PREFIX_UNIQUE, "Unique"),
        (PREFIX_TWIN_A, "Twin A"),
        (PREFIX_TWIN_B, "Twin B"),
        (PREFIX_HIDDEN, "Hidden"),
        (PREFIX_SHADOWED, "Shadowed"),
    ] {
        create(
            harness,
            database,
            json!({
                "id": id, "type": "Document", "kind": "note", "name": name,
                "reason": "Create the portable record-reference fixture."
            }),
        )
        .await?;
    }
    // Caller-chosen ids, seeded the way history arrives rather than through
    // `create_record`: a record id admitted today must be a canonical UUID, so
    // no caller can mint these any more. Databases written before that rule
    // still hold them, and resolution has to keep answering for them. Their
    // *shapes* are load-bearing and must not be canonicalised: PREFIX_EXACT is
    // a strict prefix of PREFIX_SHADOWED (`abc1234a-…`), which is what makes
    // exact-before-prefix observable at all, and it cannot be expressed with
    // two UUIDs because every canonical UUID is the same 36 characters long.
    // PREFIX_ORDER_ONE and PREFIX_ORDER_TWO share the non-hex human prefix
    // `order`, which is why a human-chosen abbreviation resolves to nothing.
    for (id, name) in [
        (PREFIX_ORDER_ONE, "Order one"),
        (PREFIX_ORDER_TWO, "Order two"),
        (PREFIX_EXACT, "Exactly abc123"),
    ] {
        harness
            .create_historical_record_for_test(database, id, name)
            .await?;
    }
    create(
        harness,
        database,
        json!({
            "id": PREFIX_FOLDER, "type": "Collection", "kind": "folder",
            "name": "Folder", "persistence": "enduring",
            "reason": "Create the portable record-reference folder fixture."
        }),
    )
    .await?;
    harness
        .create_attribution_record_for_test(database, PREFIX_ATTRIBUTION)
        .await?;

    let attribution = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["a77000"] }),
    )
    .await?;
    assert_eq!(attribution["records"][0]["status"], "not_found");
    assert_eq!(attribution["records"][0]["id"], "a77000");

    let read = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["1a2b3c"] }),
    )
    .await?;
    assert_eq!(read["records"][0]["id"], PREFIX_UNIQUE);

    for abbreviation in ["1a2b3c4d0", "1a2b3c4d-0", "1a2b3c4d-00"] {
        let read = call(
            harness,
            database,
            "get_record",
            json!({ "ids": [abbreviation] }),
        )
        .await?;
        assert_eq!(read["records"][0]["id"], PREFIX_UNIQUE, "{abbreviation}");
    }

    let updated = call(
        harness,
        database,
        "update_record",
        json!({
            "id": "1a2b3c4d", "name": "Renamed through a portable prefix",
            "reason": "Prove writes resolve record references."
        }),
    )
    .await?;
    assert_eq!(updated["id"], PREFIX_UNIQUE);
    let homed = create(
        harness,
        database,
        json!({
            "id": PREFIX_HOMED, "type": "Document", "kind": "note",
            "name": "Homed through a portable prefix", "home_id": "f01de4",
            "reason": "Prove nested identifier fields resolve."
        }),
    )
    .await?;
    assert_eq!(homed["home_id"], PREFIX_FOLDER);

    let exact = call(
        harness,
        database,
        "get_record",
        json!({ "ids": [PREFIX_EXACT] }),
    )
    .await?;
    assert_eq!(exact["records"][0]["id"], PREFIX_EXACT);
    assert_eq!(exact["records"][0]["name"], "Exactly abc123");

    for unresolved in ["order", "order-", "1a2b3"] {
        let read = call(
            harness,
            database,
            "get_record",
            json!({ "ids": [unresolved] }),
        )
        .await?;
        assert_eq!(read["records"][0]["status"], "not_found");
        assert_eq!(read["records"][0]["id"], unresolved);
    }

    let ambiguous = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["dede01"] }),
    )
    .await
    .expect_err("the six-character twin prefix must remain ambiguous")
    .to_string();
    assert!(ambiguous.contains("ambiguous"), "{ambiguous}");
    assert!(ambiguous.contains(PREFIX_TWIN_A), "{ambiguous}");
    assert!(ambiguous.contains(PREFIX_TWIN_B), "{ambiguous}");
    let disambiguated = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["dede01a"] }),
    )
    .await?;
    assert_eq!(disambiguated["records"][0]["id"], PREFIX_TWIN_A);

    for (id, name, account, principal) in [
        (
            PREFIX_ALICE,
            "Prefix Alice",
            "acct:prefix-alice",
            "native/prefix-alice",
        ),
        (
            PREFIX_BEA,
            "Prefix Bea",
            "acct:prefix-bea",
            "native/prefix-bea",
        ),
    ] {
        create(
            harness,
            database,
            json!({
                "id": id, "type": "Entity", "kind": "person", "name": name,
                "reason": "Create a portable record-reference principal."
            }),
        )
        .await?;
        harness
            .provision_member(database, id, account, principal)
            .await?;
    }
    harness
        .restrict_record_to_account_for_test(database, PREFIX_HIDDEN, "acct:prefix-alice")
        .await?;
    let unseen = harness
        .call(
            database,
            TestCaller::member("acct:prefix-bea"),
            "get_record",
            json!({ "ids": ["c0ffee", "bbbbbb"] }),
        )
        .await?;
    for (index, input) in ["c0ffee", "bbbbbb"].into_iter().enumerate() {
        assert_eq!(unseen["records"][index]["status"], "not_found");
        assert_eq!(unseen["records"][index]["id"], input);
    }
    let seen = harness
        .call(
            database,
            TestCaller::member("acct:prefix-alice"),
            "get_record",
            json!({ "ids": ["c0ffee"] }),
        )
        .await?;
    assert_eq!(seen["records"][0]["id"], PREFIX_HIDDEN);

    harness
        .restrict_record_to_account_for_test(database, PREFIX_TWIN_B, "acct:prefix-alice")
        .await?;
    let straddled = harness
        .call(
            database,
            TestCaller::member("acct:prefix-bea"),
            "get_record",
            json!({ "ids": ["dede01"] }),
        )
        .await?;
    assert_eq!(straddled["records"][0]["id"], PREFIX_TWIN_A);
    let scoped_ambiguity = harness
        .call(
            database,
            TestCaller::member("acct:prefix-alice"),
            "get_record",
            json!({ "ids": ["dede01"] }),
        )
        .await
        .expect_err("a caller who sees both twins must still receive ambiguity")
        .to_string();
    assert!(scoped_ambiguity.contains(PREFIX_TWIN_A));
    assert!(scoped_ambiguity.contains(PREFIX_TWIN_B));

    let asserted = create(
        harness,
        database,
        json!({
            "id": PREFIX_ASSERTED, "type": "Document", "kind": "note", "name": "Asserted",
            "reason": "Prove create_record.id remains an assertion."
        }),
    )
    .await?;
    assert_eq!(asserted["id"], PREFIX_ASSERTED);
    Ok(())
}

pub async fn record_lifecycle<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<()> {
    // Genesis names the workspace neutrally on every backend. The root record
    // IS the workspace, so no genesis path may brand it, and only the hosted
    // per-account provisioner (which has an email in hand) names it otherwise.
    let root = call(harness, database, "get_record", json!({ "ids": [ROOT_ID] })).await?;
    assert_eq!(root["records"][0]["name"], "Workspace");

    let created = create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000008",
            "type": "WorkItem",
            "kind": "task",
            "name": "Portable lifecycle",
            "body": "created",
            "lifecycle": "open",
            "reason": REASON
        }),
    )
    .await?;
    assert_eq!(created["id"], "c07a0000-0000-4000-8000-000000000008");

    let fetched = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-000000000008"] }),
    )
    .await?;
    assert_eq!(fetched["records"][0]["status"], "found");
    assert_eq!(fetched["records"][0]["body"], "created");

    let default_epic_id = "c07a0000-0000-4000-8000-000000000009";
    create(
        harness,
        database,
        json!({
            "id": default_epic_id,
            "type": "WorkItem",
            "kind": "epic",
            "name": "Portable default epic lifecycle",
            "reason": REASON
        }),
    )
    .await?;
    let default_epic = call(
        harness,
        database,
        "get_record",
        json!({ "ids": [default_epic_id] }),
    )
    .await?;
    assert_eq!(
        default_epic["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );

    let explicit_epic_id = "c07a0000-0000-4000-8000-000000000010";
    create(
        harness,
        database,
        json!({
            "id": explicit_epic_id,
            "type": "WorkItem",
            "kind": "epic",
            "name": "Portable explicit epic lifecycle",
            "lifecycle": "in_progress",
            "reason": REASON
        }),
    )
    .await?;
    let explicit_epic = call(
        harness,
        database,
        "get_record",
        json!({ "ids": [explicit_epic_id] }),
    )
    .await?;
    assert_eq!(
        explicit_epic["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "in_progress"
    );

    call(
        harness,
        database,
        "update_record",
        json!({ "id": explicit_epic_id, "lifecycle": "completed", "reason": REASON }),
    )
    .await?;
    let invalid_epic_update = call(
        harness,
        database,
        "update_record",
        json!({ "id": explicit_epic_id, "lifecycle": "bespoke", "reason": REASON }),
    )
    .await
    .expect_err("an epic lifecycle must be an active member of its governing vocabulary")
    .to_string();
    assert!(
        invalid_epic_update.contains("not an active member"),
        "{invalid_epic_update}"
    );
    let explicit_epic = call(
        harness,
        database,
        "get_record",
        json!({ "ids": [explicit_epic_id] }),
    )
    .await?;
    assert_eq!(
        explicit_epic["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );
    let clear_required_epic = call(
        harness,
        database,
        "update_record",
        json!({ "id": explicit_epic_id, "lifecycle": null, "reason": REASON }),
    )
    .await
    .expect_err("clearing an epic's required lifecycle must be rejected")
    .to_string();
    assert!(
        clear_required_epic.contains("required-facet conformance"),
        "{clear_required_epic}"
    );
    let explicit_epic = call(
        harness,
        database,
        "get_record",
        json!({ "ids": [explicit_epic_id] }),
    )
    .await?;
    assert_eq!(
        explicit_epic["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "completed"
    );

    let invalid_epic_create = create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000011",
            "type": "WorkItem",
            "kind": "epic",
            "name": "Invalid explicit epic lifecycle",
            "lifecycle": "bespoke",
            "reason": REASON
        }),
    )
    .await
    .expect_err("an invalid explicit epic lifecycle must be rejected")
    .to_string();
    assert!(
        invalid_epic_create.contains("not an active member"),
        "{invalid_epic_create}"
    );

    let future_kind_id = "c07a0000-0000-4000-8000-000000000012";
    create(
        harness,
        database,
        json!({
            "id": future_kind_id,
            "type": "WorkItem",
            "kind": "future_contract_kind",
            "name": "Portable unbound future work kind",
            "reason": REASON
        }),
    )
    .await?;
    let future_kind = call(
        harness,
        database,
        "get_record",
        json!({ "ids": [future_kind_id] }),
    )
    .await?;
    assert_eq!(
        future_kind["records"][0]["lifecycle_interpretation"]["status"],
        "absent"
    );
    let future_kind_update = call(
        harness,
        database,
        "update_record",
        json!({ "id": future_kind_id, "lifecycle": "open", "reason": REASON }),
    )
    .await
    .expect_err("an unbound future WorkItem kind must reject a non-null lifecycle")
    .to_string();
    assert!(
        future_kind_update.contains("lifecycle is not governed"),
        "{future_kind_update}"
    );
    let future_kind_create = create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000013",
            "type": "WorkItem",
            "kind": "another_future_contract_kind",
            "name": "Invalid explicit future lifecycle",
            "lifecycle": "open",
            "reason": REASON
        }),
    )
    .await
    .expect_err("create must reject lifecycle on an unbound future WorkItem kind")
    .to_string();
    assert!(
        future_kind_create.contains("lifecycle is not governed"),
        "{future_kind_create}"
    );

    let updated = call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-000000000008",
            "name": "Portable lifecycle updated",
            "summary": "same tool contract, different storage",
            "facets": { "priority": "high" },
            "reason": REASON
        }),
    )
    .await?;
    assert_eq!(updated["name"], "Portable lifecycle updated");
    assert_eq!(updated["summary"], "same tool contract, different storage");
    assert_eq!(updated["facets"][0]["key"], "priority");
    assert_eq!(updated["facets"][0]["value"], "high");

    let archived = call(
        harness,
        database,
        "archive_record",
        json!({ "id": "c07a0000-0000-4000-8000-000000000008", "reason": REASON }),
    )
    .await?;
    assert_eq!(archived["changed"], true);

    let fetched = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-000000000008"] }),
    )
    .await?;
    assert_eq!(fetched["records"][0]["archived"], true);
    assert_eq!(
        fetched["records"][0]["lifecycle_interpretation"]["value"]["canonical"],
        "open"
    );
    assert!(fetched["records"][0].get("lifecycle").is_none());
    assert_eq!(fetched["records"][0]["facets"][0]["value"], "high");
    Ok(())
}

/// One backend-neutral attachment chain. Dynamic identifiers and timestamps
/// are deliberately normalized out of the returned receipt so Postgres and
/// Turso-local are held to byte-identical observable meaning.
pub async fn attachment_lifecycle<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<Value> {
    create(
        harness,
        database,
        json!({
            "id":"c07a0000-0000-4000-8000-000000000002",
            "type":"Document",
            "kind":"note",
            "name":"Attachment bearer",
            "home_id":UNFILED_ID,
            "reason":REASON
        }),
    )
    .await?;
    let created = call(
        harness,
        database,
        "attach_text",
        json!({
            "record_id":"c07a0000-0000-4000-8000-000000000002",
            "text":"portable attachment bytes",
            "filename":"portable.txt",
            "mime":"text/plain"
        }),
    )
    .await?;
    let attachment_id = created["attachment_id"]
        .as_str()
        .expect("attachment id")
        .to_string();
    let ranged = call(
        harness,
        database,
        "read_attachment",
        json!({"attachment_id":attachment_id,"offset":9,"length":10}),
    )
    .await?;
    let listed = call(
        harness,
        database,
        "manage_attachments",
        json!({"action":"list","record_id":"c07a0000-0000-4000-8000-000000000002"}),
    )
    .await?;
    let inspected = call(
        harness,
        database,
        "manage_attachments",
        json!({"action":"inspect","attachment_id":attachment_id}),
    )
    .await?;
    let history = call(
        harness,
        database,
        "get_history",
        json!({"record_id":attachment_id}),
    )
    .await?;
    let content_seq = history["events"]
        .as_array()
        .expect("attachment history")
        .iter()
        .filter_map(|event| event["local_seq"].as_i64())
        .max()
        .expect("attachment content sequence");
    let detached = call(
        harness,
        database,
        "manage_attachments",
        json!({
            "action":"detach",
            "attachment_id":attachment_id,
            "if_content_seq":content_seq
        }),
    )
    .await?;
    let after = call(
        harness,
        database,
        "manage_attachments",
        json!({"action":"list","record_id":"c07a0000-0000-4000-8000-000000000002"}),
    )
    .await?;
    let read_after_detach = harness
        .call(
            database,
            TestCaller::Local,
            "read_attachment",
            json!({"attachment_id":attachment_id}),
        )
        .await
        .expect_err("detached attachment must not remain readable")
        .to_string();
    harness.assert_replay_equivalent(database).await?;

    Ok(json!({
        "create": {
            "name": created["name"],
            "mime": created["blob"]["mime"],
            "size_bytes": created["blob"]["size_bytes"],
            "sha256": created["blob"]["sha256"],
        },
        "range": {
            "content": ranged["content"],
            "encoding": ranged["content_encoding"],
            "length": ranged["length"],
            "eof": ranged["eof"],
        },
        "listed": listed["attachments"].as_array().map_or(0, Vec::len),
        "inspected_detached": inspected["detached"],
        "detach": {
            "detached": detached["detached"],
            "blob_retained": detached["blob_retained"],
        },
        "listed_after_detach": after["attachments"].as_array().map_or(0, Vec::len),
        "read_after_detach_missing": read_after_detach.contains("does not exist"),
    }))
}

pub async fn link_mutation<H: ContractHarness>(harness: &H, database: &H::Database) -> Result<()> {
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000009", "type": "WorkItem", "kind": "task",
            "name": "Source", "reason": REASON
        }),
    )
    .await?;
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000a", "type": "Outcome", "kind": "target",
            "name": "Target", "reason": REASON
        }),
    )
    .await?;
    let added = call(
        harness,
        database,
        "manage_links",
        json!({
            "action": "add", "source_id": "c07a0000-0000-4000-8000-000000000009",
            "target_id": "c07a0000-0000-4000-8000-00000000000a", "relationship": "implements",
            "note": "portable edge"
        }),
    )
    .await?;
    assert_eq!(added["status"], "added");

    let listed = call(
        harness,
        database,
        "manage_links",
        json!({ "action": "list", "record_id": "c07a0000-0000-4000-8000-000000000009" }),
    )
    .await?;
    assert_eq!(listed["links_out"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        listed["links_out"][0]["target_id"],
        "c07a0000-0000-4000-8000-00000000000a"
    );
    assert_eq!(listed["links_out"][0]["relationship"], "implements");
    assert_eq!(listed["links_out"][0]["note"], "portable edge");
    Ok(())
}

pub async fn visibility<H: ContractHarness>(harness: &H, database: &H::Database) -> Result<()> {
    for (id, name, account, principal) in [
        (
            "c07a0000-0000-4000-8000-000000000001",
            "Alice",
            "acct:alice",
            "native/alice",
        ),
        (
            "c07a0000-0000-4000-8000-000000000003",
            "Bea",
            "acct:bea",
            "native/bea",
        ),
        (
            "c07a0000-0000-4000-8000-000000000004",
            "Cara",
            "acct:cara",
            "native/cara",
        ),
    ] {
        create(
            harness,
            database,
            json!({ "id": id, "type": "Entity", "kind": "person", "name": name, "reason": REASON }),
        )
        .await?;
        harness
            .provision_member(database, id, account, principal)
            .await?;
    }

    harness
        .deliver_message_fixture(
            database,
            TestCaller::member("acct:alice"),
            DeliveredMessageFixture {
                id: "c07a0000-0000-4000-8000-00000000000d",
                name: "For Bea",
                body: "visible only to the declared audience",
                addressed_to: &["c07a0000-0000-4000-8000-000000000003"],
                idempotency_key: "contract:visibility:send",
            },
        )
        .await?;

    let for_bea = harness
        .call(
            database,
            TestCaller::member("acct:bea"),
            "get_record",
            json!({ "ids": ["c07a0000-0000-4000-8000-00000000000d"] }),
        )
        .await?;
    assert_eq!(for_bea["records"][0]["status"], "found");
    assert_eq!(
        for_bea["records"][0]["body"],
        "visible only to the declared audience"
    );
    let history_for_bea = harness
        .call(
            database,
            TestCaller::member("acct:bea"),
            "get_history",
            json!({ "record_id": "c07a0000-0000-4000-8000-00000000000d", "detail": "full" }),
        )
        .await?;
    let repeated_history_for_bea = harness
        .call(
            database,
            TestCaller::member("acct:bea"),
            "get_history",
            json!({ "record_id": "c07a0000-0000-4000-8000-00000000000d", "detail": "full" }),
        )
        .await?;
    assert_eq!(
        repeated_history_for_bea, history_for_bea,
        "authorized history reads are idempotent"
    );
    let created = history_for_bea["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|event| event["type"] == "record.created")
        .expect("an authorized recipient sees the creation event");
    assert_eq!(
        created["payload"]["body"],
        "visible only to the declared audience"
    );
    assert!(
        created["payload"]["owner_id"].is_null(),
        "a recipient history read must not disclose the sender identity"
    );
    let metadata_history_for_bea = harness
        .call(
            database,
            TestCaller::member("acct:bea"),
            "get_history",
            json!({ "record_id": "c07a0000-0000-4000-8000-00000000000d" }),
        )
        .await?;
    let metadata_created = metadata_history_for_bea["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|event| event["type"] == "record.created")
        .expect("metadata retains the authorized creation envelope");
    assert!(metadata_created.get("payload").is_none());
    assert_eq!(metadata_created["payload_omitted"], true);
    assert_eq!(
        metadata_created["payload_json_utf8_bytes"],
        serde_json::to_vec(&created["payload"]).unwrap().len(),
        "payload size is derived from the caller-visible post-redaction value"
    );
    assert!(metadata_created["changed_fields"]
        .as_array()
        .is_some_and(|fields| fields.contains(&json!("owner_id"))));
    assert_eq!(
        metadata_history_for_bea["representation"]["full_detail"],
        json!({ "detail": "full" })
    );
    // Identity is disclosed on the same terms as any other record: by `View` on
    // the person. Bea can read Alice's person record here, so the byline
    // resolves and the run travels with it — attribution to a hidden actor is
    // attribution nobody can act on. The sender's identity inside the payload is
    // a separate boundary and stays closed, as asserted above.
    assert_eq!(
        created["actor"], "acct:alice",
        "a recipient who can view the sender's person record sees the actor"
    );
    // Only the disclosure rule is contracted across engines. Resolving the
    // account to a display name is a richer surface that not every engine's
    // history reader offers, and it is asserted where it exists rather than
    // required of every backend by this scenario.

    // The same read, with only `View` of the person withdrawn. Attribution has
    // to disappear with it, or the person's policy is not what governs it.
    harness
        .restrict_record_to_account_for_test(
            database,
            "c07a0000-0000-4000-8000-000000000001",
            "acct:alice",
        )
        .await?;
    let history_without_person = harness
        .call(
            database,
            TestCaller::member("acct:bea"),
            "get_history",
            json!({ "record_id": "c07a0000-0000-4000-8000-00000000000d" }),
        )
        .await?;
    let created_without_person = history_without_person["events"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|event| event["type"] == "record.created")
        .expect("the event itself stays visible to the audience");
    assert!(
        created_without_person["actor"].is_null(),
        "a recipient who cannot view the sender's person record sees no actor"
    );
    assert!(
        created_without_person["run_key"].is_null(),
        "the run does not outlive the name it travelled with"
    );

    let for_cara = harness
        .call(
            database,
            TestCaller::member("acct:cara"),
            "get_record",
            json!({ "ids": ["c07a0000-0000-4000-8000-00000000000d"] }),
        )
        .await?;
    assert_eq!(for_cara["records"][0]["status"], "not_found");
    assert!(for_cara["records"][0].get("body").is_none());
    Ok(())
}

/// Shared production-route contract for governed external bindings.
///
/// This deliberately excludes `manage_bindings.observations`: observation
/// provenance remains a separately classified residual on non-SQLite engines.
pub async fn identity_bindings<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<()> {
    for (id, name, account, principal) in [
        (
            "1de70000-0000-4000-8000-000000000001",
            "Alpha",
            "acct:identity-alpha",
            "native/identity-alpha",
        ),
        (
            "1de70000-0000-4000-8000-000000000002",
            "Beta",
            "acct:identity-beta",
            "native/identity-beta",
        ),
    ] {
        harness
            .call(
                database,
                TestCaller::Local,
                "create_record",
                json!({
                    "id":id,"type":"Entity","kind":"person","name":name,
                    "reason":"Create an identity contract member."
                }),
            )
            .await?;
        harness
            .provision_member(database, id, account, principal)
            .await?;
    }

    let alpha = TestCaller::member("acct:identity-alpha");
    let empty = harness
        .call(
            database,
            alpha.clone(),
            "resolve_external",
            json!({"bindings":[],"reason":"Exercise the stable empty-claim error."}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        empty,
        "resolve_external requires at least one binding claim"
    );
    let blank_reason = harness
        .call(
            database,
            alpha.clone(),
            "resolve_external",
            json!({
                "bindings":[{"system":"native-principal","identifier":"native/invalid-reason"}],
                "reason":"   "
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        blank_reason,
        "resolve_external: 'reason' must contain non-whitespace reasoning"
    );
    let primary = json!({"system":"native-principal","identifier":"native/resolved-alpha"});
    let created = harness
        .call(
            database,
            alpha.clone(),
            "resolve_external",
            json!({
                "bindings":[primary.clone()],"reason":"Resolve a governed external identity."
            }),
        )
        .await?;
    assert_eq!(created["status"], "created");
    assert_eq!(created["bindings_added"].as_array().map(Vec::len), Some(1));
    let record_id = created["record_id"].as_str().unwrap().to_string();

    let durable = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"remove","record_id":record_id,"binding":primary.clone(),
                "reason":"Prove the required durable identity guard."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        durable,
        "cannot remove the only required durable 'native-principal' identity"
    );
    let revision_precedence = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"add","record_id":record_id,
                "binding":{"system":"unknown-system","identifier":"unresolved"},
                "reason":"Prove the portable revision rejection remains first.",
                "if_binding_state_revision":"unsupported"
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        revision_precedence,
        "manage_bindings: if_binding_state_revision is not yet qualified on this backend"
    );
    let visible_collision = harness
        .call(
            database,
            TestCaller::Local,
            "manage_bindings",
            json!({
                "action":"add","record_id":"1de70000-0000-4000-8000-000000000002",
                "binding":primary.clone(),"reason":"Prove a visible binding collision."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        visible_collision,
        "binding collision: external identity already belongs to another visible record"
    );

    let hit = harness
        .call(
            database,
            alpha.clone(),
            "resolve_external",
            json!({
                "bindings":[primary.clone()],
                "hints":{"name":"must not overwrite a hit"},
                "reason":"Retry the normalized identity resolution."
            }),
        )
        .await?;
    assert_eq!(hit["status"], "resolved");
    assert_eq!(hit["record_id"], record_id);
    assert_eq!(hit["bindings_added"].as_array().map(Vec::len), Some(0));

    let alias = json!({"system":"native-principal","identifier":"native/resolved-alias"});
    let added = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"add","record_id":record_id,"binding":alias.clone(),"canonical":false,
                "reason":"Add a non-canonical governed alias."
            }),
        )
        .await?;
    assert_eq!(added["status"], "added");
    let no_op = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"add","record_id":record_id,"binding":alias.clone(),"canonical":false,
                "reason":"Retry the governed alias addition."
            }),
        )
        .await?;
    assert_eq!(no_op["status"], "unchanged");

    let promoted = json!({"system":"native-principal","identifier":"native/resolved-promoted"});
    harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"add","record_id":record_id,"binding":promoted.clone(),
                "canonical":false,"reason":"Create a promotion candidate."
            }),
        )
        .await?;
    let promoted_on_add = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"add","record_id":record_id,"binding":promoted.clone(),
                "canonical":true,"reason":"Promote the existing binding through add."
            }),
        )
        .await?;
    assert_eq!(promoted_on_add["status"], "added");
    let already_canonical = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"canonicalize","record_id":record_id,"binding":promoted,
                "reason":"Prove an already-canonical binding is unchanged."
            }),
        )
        .await?;
    assert_eq!(already_canonical["status"], "unchanged");

    let canonicalized = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"canonicalize","record_id":record_id,"binding":alias.clone(),
                "reason":"Promote the governed alias."
            }),
        )
        .await?;
    assert_eq!(canonicalized["status"], "canonicalized");
    let missing_canonical = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"canonicalize","record_id":record_id,
                "binding":{"system":"native-principal","identifier":"native/missing-canonical"},
                "reason":"Prove the missing canonical target error."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        missing_canonical,
        "binding to canonicalize does not exist on record"
    );
    let listed = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"list","record_id":record_id
            }),
        )
        .await?;
    assert_eq!(listed["bindings"].as_array().map(Vec::len), Some(3));

    let temporary = json!({"system":"native-principal","identifier":"native/resolved-temporary"});
    harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"add","record_id":record_id,"binding":temporary.clone(),
                "reason":"Exercise a removable governed alias."
            }),
        )
        .await?;
    let removed = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"remove","record_id":record_id,"binding":temporary.clone(),
                "reason":"Remove the governed temporary alias."
            }),
        )
        .await?;
    assert_eq!(removed["status"], "removed");
    let removed_again = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"remove","record_id":record_id,"binding":temporary,
                "reason":"Retry the governed alias removal."
            }),
        )
        .await?;
    assert_eq!(removed_again["status"], "unchanged");

    let reconcile_claim = json!({
        "system":"native-record",
        "identifier":"ndb_00000000000000000000000000000000/c291cmNl"
    });
    let source = harness
        .call(
            database,
            alpha.clone(),
            "resolve_external",
            json!({
                "bindings":[reconcile_claim.clone()],
                "hints":{"record_type":"Entity","kind":"person","name":"Reconcile source"},
                "reason":"Create a visible binding-only reconciliation source."
            }),
        )
        .await?;
    let source_id = source["record_id"].as_str().unwrap().to_string();
    let preview = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"reconcile","target_record_id":record_id,
                "expected_source_record_id":source_id,"bindings":[reconcile_claim.clone()],
                "if_binding_state_revision":"ignored-for-preview"
            }),
        )
        .await?;
    assert_eq!(preview["status"], "preview");
    let stale = harness
        .call(
            database,
            TestCaller::Local,
            "manage_bindings",
            json!({
                "action":"reconcile","target_record_id":record_id,
                "expected_source_record_id":"1de70000-0000-4000-8000-000000000002",
                "bindings":[reconcile_claim.clone()]
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        stale,
        "stale expected owner for native-record:ndb_00000000000000000000000000000000/c291cmNl"
    );
    let reconciled = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"reconcile","target_record_id":record_id,
                "expected_source_record_id":source_id,"bindings":[reconcile_claim],"apply":true,
                "reason":"Apply the governed binding-only reconciliation."
            }),
        )
        .await?;
    assert_eq!(reconciled["status"], "reconciled");

    let colliding_claim = json!({
        "system":"native-record",
        "identifier":"ndb_00000000000000000000000000000000/Y29sbGlzaW9u"
    });
    let colliding_source = harness
        .call(
            database,
            alpha.clone(),
            "resolve_external",
            json!({
                "bindings":[colliding_claim.clone()],
                "hints":{"record_type":"Entity","kind":"person","name":"Canonical collision source"},
                "reason":"Create a second canonical transfer source."
            }),
        )
        .await?;
    let canonical_collision = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"reconcile","target_record_id":record_id,
                "expected_source_record_id":colliding_source["record_id"],
                "bindings":[colliding_claim],"apply":true,
                "reason":"Prove canonical transfer collision refusal."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        canonical_collision,
        "canonical binding collision while transferring system 'native-record'"
    );

    let hidden_claim = json!({"system":"native-principal","identifier":"native/hidden-beta"});
    let hidden = harness
        .call(
            database,
            TestCaller::member("acct:identity-beta"),
            "resolve_external",
            json!({
                "bindings":[hidden_claim.clone()],"reason":"Create the hidden identity owner."
            }),
        )
        .await?;
    let hidden_id = hidden["record_id"].as_str().unwrap().to_string();
    harness.assert_replay_equivalent(database).await?;
    harness
        .restrict_record_to_account_for_test(database, &hidden_id, "acct:identity-beta")
        .await?;
    let hidden_add = harness
        .call(
            database,
            alpha.clone(),
            "manage_bindings",
            json!({
                "action":"add","record_id":record_id,"binding":hidden_claim.clone(),
                "reason":"Probe a hidden binding owner through the adopted add planner."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(hidden_add.contains("binding_not_visible"), "{hidden_add}");
    assert!(!hidden_add.contains(&hidden_id), "{hidden_add}");
    assert!(!hidden_add.contains(&record_id), "{hidden_add}");
    let denied = harness
        .call(
            database,
            alpha.clone(),
            "resolve_external",
            json!({
                "bindings":[hidden_claim],"reason":"Probe an external identity without visibility."
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(denied.contains("binding_not_visible"), "{denied}");
    assert!(!denied.contains(&hidden_id), "{denied}");
    assert!(!denied.contains(&record_id), "{denied}");

    let observations = harness
        .call(
            database,
            alpha,
            "manage_bindings",
            json!({
                "action":"observations","record_id":record_id
            }),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(observations.contains("unsupported"), "{observations}");

    Ok(())
}

pub async fn replay<H: ContractHarness>(harness: &H, database: &H::Database) -> Result<()> {
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000010", "type": "Outcome", "kind": "target",
            "name": "Replay target", "reason": REASON
        }),
    )
    .await?;
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000f", "type": "WorkItem", "kind": "task",
            "name": "Replay source", "facets": { "effort": "small" },
            "links": [{ "target_id": "c07a0000-0000-4000-8000-000000000010", "relationship": "implements" }],
            "reason": REASON
        }),
    )
    .await?;
    call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000f", "name": "Replay source updated",
            "facets": { "effort": "medium" }, "reason": REASON
        }),
    )
    .await?;
    call(
        harness,
        database,
        "archive_record",
        json!({ "id": "c07a0000-0000-4000-8000-000000000010", "reason": REASON }),
    )
    .await?;

    harness.assert_replay_equivalent(database).await
}

pub async fn guarded_write_race<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<()> {
    let initial = "one guarded body";
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000e", "type": "Document", "kind": "note",
            "name": "Guarded race", "body": initial, "reason": REASON
        }),
    )
    .await?;
    let digest = hex::encode(Sha256::digest(initial.as_bytes()));

    // The read surface hands the caller the token it must send back. This is
    // the whole affordance: a safe rewrite is a copy from the read response
    // into the write request, never a hash the caller computes itself.
    let read = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000e"] }),
    )
    .await?;
    assert_eq!(
        read["records"][0]["body_digest"],
        json!(digest),
        "get_record returns the SHA-256 of the stored body"
    );

    // A whole-body replacement against existing content with neither
    // precondition is refused before any write.
    let unguarded = harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-00000000000e", "body": "must not land", "reason": REASON
            }),
        )
        .await
        .expect_err("an unguarded whole-body write must be refused")
        .to_string();
    assert!(
        unguarded.contains("unguarded whole-body write refused"),
        "{unguarded}"
    );
    assert!(unguarded.contains("Guarded race"), "{unguarded}");
    assert!(unguarded.contains(&digest), "{unguarded}");
    assert!(unguarded.contains("if_body_digest"), "{unguarded}");
    assert!(unguarded.contains("if_unmodified_since"), "{unguarded}");
    let after_refusal = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000e"] }),
    )
    .await?;
    assert_eq!(
        after_refusal["records"][0]["body"],
        json!(initial),
        "the refused write left the stored body untouched"
    );

    // Clearing a written body is a destructive replacement, not an exemption.
    let cleared = harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            json!({ "id": "c07a0000-0000-4000-8000-00000000000e", "body": null, "reason": REASON }),
        )
        .await
        .expect_err("clearing a non-empty body is a guarded replacement")
        .to_string();
    assert!(
        cleared.contains("unguarded whole-body write refused"),
        "{cleared}"
    );

    let alpha = harness.call(
        database,
        TestCaller::Local,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000e", "body": "alpha wins",
            "if_body_digest": digest, "reason": REASON
        }),
    );
    let bravo = harness.call(
        database,
        TestCaller::Local,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000e", "body": "bravo wins",
            "if_body_digest": digest, "reason": REASON
        }),
    );
    let (alpha, bravo) = tokio::join!(alpha, bravo);
    let results = [alpha, bravo];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    let error = results
        .iter()
        .find_map(|result| result.as_ref().err())
        .expect("one guarded update loses")
        .to_string();
    assert!(error.contains("body digest conflict"), "{error}");

    let fetched = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000e"] }),
    )
    .await?;
    let body = fetched["records"][0]["body"]
        .as_str()
        .expect("winning body is projected");
    assert!(matches!(body, "alpha wins" | "bravo wins"));

    let history = call(
        harness,
        database,
        "get_history",
        json!({ "record_id": "c07a0000-0000-4000-8000-00000000000e", "detail": "full" }),
    )
    .await?;
    let updates = history["events"]
        .as_array()
        .expect("history events")
        .iter()
        .filter(|event| event["type"] == "record.updated")
        .collect::<Vec<_>>();
    assert_eq!(updates.len(), 1, "the losing write appended no event");
    assert_eq!(updates[0]["payload"]["body"], body);

    // The PR 420 interleaving, end to end. Run A reads and holds digest A while
    // it thinks; run B writes under the then-current guard; run A's whole-body
    // write must lose without touching B's body, and must succeed once it has
    // reread and reconciled.
    let digest_a = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000e"] }),
    )
    .await?["records"][0]["body_digest"]
        .as_str()
        .expect("get_record exposes body_digest")
        .to_owned();

    let b_body = "run B reconciled the record";
    let b_written = call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000e", "body": b_body,
            "if_body_digest": digest_a, "reason": REASON
        }),
    )
    .await?;
    // The write response reports the new token, so run B can continue guarded
    // work without another read.
    let digest_b = b_written["body_digest"]
        .as_str()
        .expect("update_record reports the new body digest")
        .to_owned();
    assert_eq!(
        digest_b,
        hex::encode(Sha256::digest(b_body.as_bytes())),
        "the reported digest is the SHA-256 of the body just written"
    );

    let stale = harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-00000000000e", "body": "run A composed this from a stale base",
                "if_body_digest": digest_a, "reason": REASON
            }),
        )
        .await
        .expect_err("run A's digest is stale")
        .to_string();
    assert!(stale.contains("body digest conflict"), "{stale}");
    assert!(stale.contains(&digest_b), "{stale}");
    let preserved = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000e"] }),
    )
    .await?;
    assert_eq!(
        preserved["records"][0]["body"],
        json!(b_body),
        "run B's body is byte-for-byte unchanged"
    );
    assert_eq!(preserved["records"][0]["body_digest"], json!(digest_b));

    // Reread, reconcile, retry against the current token.
    let merged = call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000e", "body": "run A merged both edits",
            "if_body_digest": digest_b, "reason": REASON
        }),
    )
    .await?;
    assert_eq!(merged["body"], json!("run A merged both edits"));
    Ok(())
}

/// A record provisioned without a body stores no body at all. Every backend
/// must treat that absence as the empty string when checking `if_body_digest`,
/// so the first body a record ever receives can be written under a guard
/// instead of being rejected as a phantom conflict.
pub async fn null_body_digest_guard<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<()> {
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000b", "type": "Document", "kind": "note",
            "name": "Provisioned without a body", "reason": REASON
        }),
    )
    .await?;
    let fetched = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000b"] }),
    )
    .await?;
    assert_eq!(
        fetched["records"][0]["body"].as_str().unwrap_or(""),
        "",
        "a record created without a body carries no body content"
    );

    let empty_digest = hex::encode(Sha256::digest(b""));
    let stale_digest = hex::encode(Sha256::digest(b"a body this record never held"));

    // A genuinely stale digest still loses, and loses atomically.
    let error = harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-00000000000b", "body": "must not land",
                "if_body_digest": stale_digest, "reason": REASON
            }),
        )
        .await
        .expect_err("a stale digest against a bodyless record is a conflict")
        .to_string();
    assert!(error.contains("body digest conflict"), "{error}");
    let rejected = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000b"] }),
    )
    .await?;
    assert_eq!(
        rejected["records"][0]["body"].as_str().unwrap_or(""),
        "",
        "the stale guarded write left no body behind"
    );
    let history = call(
        harness,
        database,
        "get_history",
        json!({ "record_id": "c07a0000-0000-4000-8000-00000000000b" }),
    )
    .await?;
    assert_eq!(
        history["events"]
            .as_array()
            .expect("history events")
            .iter()
            .filter(|event| event["type"] == "record.updated")
            .count(),
        0,
        "the stale guarded write appended no event"
    );

    // The digest of the empty string matches the absent body, so the first
    // real body lands under the same guard the editor already sends.
    call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000b", "body": "the first body",
            "if_body_digest": empty_digest, "reason": REASON
        }),
    )
    .await?;
    let saved = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000b"] }),
    )
    .await?;
    assert_eq!(saved["records"][0]["body"], "the first body");

    // Clearing a written body is a destructive replacement, so it needs the
    // same guard the replacement did.
    let unguarded_clear = harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            json!({ "id": "c07a0000-0000-4000-8000-00000000000b", "body": "", "reason": REASON }),
        )
        .await
        .expect_err("emptying a written body is a guarded replacement")
        .to_string();
    assert!(
        unguarded_clear.contains("unguarded whole-body write refused"),
        "{unguarded_clear}"
    );
    let still_there = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000b"] }),
    )
    .await?;
    assert_eq!(still_there["records"][0]["body"], "the first body");

    // An empty stored body accepts the same digest, so clearing and rewriting
    // a body stays guardable rather than becoming a one-way door.
    call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000b", "body": "",
            "if_body_digest": hex::encode(Sha256::digest(b"the first body")),
            "reason": REASON
        }),
    )
    .await?;
    call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000b", "body": "rewritten after clearing",
            "if_body_digest": empty_digest, "reason": REASON
        }),
    )
    .await?;
    let rewritten = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000b"] }),
    )
    .await?;
    assert_eq!(rewritten["records"][0]["body"], "rewritten after clearing");

    // A bodyless record returns sha256("") rather than an absent field, so the
    // first body a record ever receives is guardable through the ordinary read.
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000c", "type": "Document", "kind": "note",
            "name": "First writer wins", "reason": REASON
        }),
    )
    .await?;
    let bodyless = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000c"] }),
    )
    .await?;
    assert_eq!(
        bodyless["records"][0]["body_digest"],
        json!(empty_digest),
        "a null stored body reports sha256(\"\"), never an absent field"
    );

    // Two unguarded writers against an initially empty body: the check runs
    // against current state inside the write transaction, so once the first has
    // established non-empty content the second is refused rather than silently
    // overwriting it.
    call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-00000000000c", "body": "first writer content",
            "reason": REASON
        }),
    )
    .await?;
    let second = harness
        .call(
            database,
            TestCaller::Local,
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-00000000000c", "body": "second writer content",
                "reason": REASON
            }),
        )
        .await
        .expect_err("the second unguarded initial writer must be refused")
        .to_string();
    assert!(
        second.contains("unguarded whole-body write refused"),
        "{second}"
    );
    let survivor = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-00000000000c"] }),
    )
    .await?;
    assert_eq!(survivor["records"][0]["body"], "first writer content");
    Ok(())
}

pub async fn timestamp_precondition<H: ContractHarness>(
    harness: &H,
    database: &H::Database,
) -> Result<()> {
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000014", "type": "Entity", "kind": "person",
            "name": "Timestamp owner", "reason": REASON
        }),
    )
    .await?;
    harness
        .provision_member(
            database,
            "c07a0000-0000-4000-8000-000000000014",
            "acct:timestamp-owner",
            "native/timestamp-owner",
        )
        .await?;
    create(
        harness,
        database,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000013", "type": "Document", "kind": "note",
            "name": "Timestamp guarded", "body": "alpha",
            "owner_id": "c07a0000-0000-4000-8000-000000000014", "reason": REASON
        }),
    )
    .await?;
    let fetched = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-000000000013"] }),
    )
    .await?;
    let original_updated_at = fetched["records"][0]["updated_at"]
        .as_str()
        .expect("get_record exposes updated_at")
        .to_owned();
    let parsed_original = chrono::DateTime::parse_from_rfc3339(&original_updated_at)
        .expect("get_record updated_at is RFC3339");
    let equivalent_offset = parsed_original
        .with_timezone(&chrono::FixedOffset::east_opt(3600).unwrap())
        .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, false);

    // SQLite projects millisecond event times. Ensure the successful write has
    // a distinct timestamp so the original value is genuinely stale on every
    // backend rather than relying on scheduler timing.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let body_digest = hex::encode(Sha256::digest(b"alpha"));
    let updated = harness
        .call(
            database,
            TestCaller::member("acct:timestamp-owner"),
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-000000000013", "name": "Timestamp matched", "body": "beta",
                "facets": { "priority": "high" },
                "if_body_digest": body_digest,
                "if_unmodified_since": equivalent_offset,
                "reason": REASON
            }),
        )
        .await?;
    assert_eq!(updated["name"], "Timestamp matched");
    assert_eq!(updated["body"], "beta");
    assert_eq!(updated["facets"][0]["value"], "high");
    let current_updated_at = updated["updated_at"]
        .as_str()
        .expect("updated record exposes updated_at")
        .to_owned();
    chrono::DateTime::parse_from_rfc3339(&current_updated_at)
        .expect("updated_at remains RFC3339 after write");

    harness
        .call(
            database,
            TestCaller::member("acct:timestamp-owner"),
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-000000000013", "facets": { "priority": "medium" },
                "reason": REASON
            }),
        )
        .await?;
    let after_facet = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-000000000013"] }),
    )
    .await?;
    let after_facet_updated_at = after_facet["records"][0]["updated_at"]
        .as_str()
        .expect("facet-only update exposes updated_at")
        .to_owned();
    assert_ne!(
        after_facet_updated_at, current_updated_at,
        "facet-only writes advance the record-wide token"
    );
    let accepted_history = call(
        harness,
        database,
        "get_history",
        json!({ "record_id": "c07a0000-0000-4000-8000-000000000013" }),
    )
    .await?;
    let accepted_update_count = accepted_history["events"]
        .as_array()
        .expect("history events")
        .iter()
        .filter(|event| event["type"] == "record.updated")
        .count();

    let stale = harness
        .call(
            database,
            TestCaller::member("acct:timestamp-owner"),
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-000000000013", "name": "must not land",
                "facets": { "priority": "urgent" },
                "if_unmodified_since": current_updated_at,
                "reason": REASON
            }),
        )
        .await
        .expect_err("the prior updated_at must be stale");
    assert!(matches!(stale, native_ce::Error::Conflict(_)), "{stale:?}");
    // `if_unmodified_since` is one of the two preconditions that admit a
    // guarded whole-body write, so its conflict owes the caller the same
    // legible content as the other two refusals.
    let stale = stale.to_string();
    assert!(stale.contains("stale write conflict"), "{stale}");
    assert!(stale.contains("Timestamp matched"), "{stale}");
    assert!(
        stale.contains(&hex::encode(Sha256::digest(b"beta"))),
        "{stale}"
    );
    assert!(stale.contains(&after_facet_updated_at), "{stale}");
    assert!(stale.contains("Reread the record"), "{stale}");

    let malformed = harness
        .call(
            database,
            TestCaller::member("acct:timestamp-owner"),
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-000000000013", "name": "must not land either",
                "if_unmodified_since": "not-a-timestamp", "reason": REASON
            }),
        )
        .await
        .expect_err("malformed timestamp must reject");
    assert!(malformed.to_string().contains("RFC3339"), "{malformed}");

    // Either precondition alone admits a whole-body replacement; supplying both
    // requires both to match, and a body change is a body change whichever one
    // is stale.
    let beta_digest = hex::encode(Sha256::digest(b"beta"));
    let both_stale_timestamp = harness
        .call(
            database,
            TestCaller::member("acct:timestamp-owner"),
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-000000000013", "body": "must not land",
                "if_body_digest": beta_digest,
                "if_unmodified_since": current_updated_at,
                "reason": REASON
            }),
        )
        .await
        .expect_err("a matching digest cannot rescue a stale timestamp");
    assert!(
        matches!(both_stale_timestamp, native_ce::Error::Conflict(_)),
        "{both_stale_timestamp:?}"
    );
    let both_stale_digest = harness
        .call(
            database,
            TestCaller::member("acct:timestamp-owner"),
            "update_record",
            json!({
                "id": "c07a0000-0000-4000-8000-000000000013", "body": "must not land",
                "if_body_digest": hex::encode(Sha256::digest(b"a body this record never held")),
                "if_unmodified_since": after_facet_updated_at,
                "reason": REASON
            }),
        )
        .await
        .expect_err("a matching timestamp cannot rescue a stale digest")
        .to_string();
    assert!(
        both_stale_digest.contains("body digest conflict"),
        "{both_stale_digest}"
    );
    let after = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-000000000013"] }),
    )
    .await?;
    assert_eq!(after["records"][0]["name"], "Timestamp matched");
    assert_eq!(after["records"][0]["body"], "beta");
    assert_eq!(after["records"][0]["facets"][0]["value"], "medium");
    assert_eq!(after["records"][0]["updated_at"], after_facet_updated_at);
    let history = call(
        harness,
        database,
        "get_history",
        json!({ "record_id": "c07a0000-0000-4000-8000-000000000013" }),
    )
    .await?;
    assert_eq!(
        history["events"]
            .as_array()
            .expect("history events")
            .iter()
            .filter(|event| event["type"] == "record.updated")
            .count(),
        accepted_update_count,
        "stale and malformed calls append no events"
    );

    // A record-wide timestamp is accepted on its own as the whole-body guard,
    // with no digest supplied at all.
    call(
        harness,
        database,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-000000000013", "body": "gamma",
            "if_unmodified_since": after_facet_updated_at, "reason": REASON
        }),
    )
    .await?;
    let gamma = call(
        harness,
        database,
        "get_record",
        json!({ "ids": ["c07a0000-0000-4000-8000-000000000013"] }),
    )
    .await?;
    assert_eq!(gamma["records"][0]["body"], "gamma");
    assert_eq!(
        gamma["records"][0]["body_digest"],
        json!(hex::encode(Sha256::digest(b"gamma")))
    );
    Ok(())
}

pub async fn logical_database_isolation<H: ContractHarness>(harness: &H) -> Result<()> {
    let first = harness.fresh_logical_database().await?;
    let second = harness.fresh_logical_database().await?;

    create(
        harness,
        &first,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000011", "type": "Document", "kind": "note",
            "name": "First database", "reason": REASON
        }),
    )
    .await?;
    create(
        harness,
        &second,
        json!({
            "id": "c07a0000-0000-4000-8000-000000000011", "type": "Document", "kind": "note",
            "name": "Second database", "reason": REASON
        }),
    )
    .await?;

    let ids = [ROOT_ID, UNFILED_ID, "c07a0000-0000-4000-8000-000000000011"];
    let first_before = harness
        .logical_snapshot(&first, TestCaller::Local, &ids)
        .await?;
    let second_before = harness
        .logical_snapshot(&second, TestCaller::Local, &ids)
        .await?;
    for fixed in [ROOT_ID, UNFILED_ID] {
        assert_eq!(first_before["records"][fixed]["status"], "found");
        assert_eq!(second_before["records"][fixed]["status"], "found");
        assert_eq!(
            first_before["records"][fixed],
            second_before["records"][fixed]
        );
    }
    assert_eq!(
        first_before["records"]["c07a0000-0000-4000-8000-000000000011"]["name"],
        "First database"
    );
    assert_eq!(
        second_before["records"]["c07a0000-0000-4000-8000-000000000011"]["name"],
        "Second database"
    );

    call(
        harness,
        &first,
        "update_record",
        json!({
            "id": "c07a0000-0000-4000-8000-000000000011", "body": "mutation stays in first",
            "facets": { "scope": "first-only" }, "reason": REASON
        }),
    )
    .await?;
    let first_after = harness
        .logical_snapshot(&first, TestCaller::Local, &ids)
        .await?;
    let second_after = harness
        .logical_snapshot(&second, TestCaller::Local, &ids)
        .await?;
    assert_eq!(
        first_after["records"]["c07a0000-0000-4000-8000-000000000011"]["body"],
        "mutation stays in first"
    );
    assert_eq!(
        first_after["records"]["c07a0000-0000-4000-8000-000000000011"]["facets"][0]["value"],
        "first-only"
    );
    assert_eq!(
        second_after, second_before,
        "the second logical database changed"
    );

    let first_history = call(
        harness,
        &first,
        "get_history",
        json!({ "record_id": "c07a0000-0000-4000-8000-000000000011", "detail": "full" }),
    )
    .await?;
    let second_history = call(
        harness,
        &second,
        "get_history",
        json!({ "record_id": "c07a0000-0000-4000-8000-000000000011", "detail": "full" }),
    )
    .await?;
    let first_events = first_history["events"].as_array().expect("first history");
    let second_events = second_history["events"].as_array().expect("second history");
    assert!(first_events
        .iter()
        .any(|event| event["type"] == "record.updated"));
    assert!(!second_events
        .iter()
        .any(|event| event["type"] == "record.updated"));
    assert_eq!(first_events[0]["payload"]["name"], "First database");
    assert_eq!(second_events[0]["payload"]["name"], "Second database");

    harness.assert_replay_equivalent(&first).await?;
    harness.assert_replay_equivalent(&second).await?;

    for database in [&first, &second] {
        for (id, name) in [
            ("c07a0000-0000-4000-8000-000000000007", "Isolation sender"),
            (
                "c07a0000-0000-4000-8000-000000000006",
                "Isolation recipient",
            ),
        ] {
            create(
                harness,
                database,
                json!({
                    "id": id, "type": "Entity", "kind": "person",
                    "name": name, "reason": REASON
                }),
            )
            .await?;
        }
    }
    harness
        .provision_member(
            &first,
            "c07a0000-0000-4000-8000-000000000007",
            "acct:first-database",
            "native/first-database",
        )
        .await?;
    harness
        .provision_member(
            &second,
            "c07a0000-0000-4000-8000-000000000007",
            "acct:second-database",
            "native/second-database",
        )
        .await?;
    harness
        .provision_member(
            &first,
            "c07a0000-0000-4000-8000-000000000006",
            "acct:first-recipient",
            "native/first-recipient",
        )
        .await?;
    harness
        .provision_member(
            &second,
            "c07a0000-0000-4000-8000-000000000006",
            "acct:second-recipient",
            "native/second-recipient",
        )
        .await?;

    for (database, account, body) in [
        (&first, "acct:first-database", "private to first"),
        (&second, "acct:second-database", "private to second"),
    ] {
        harness
            .deliver_message_fixture(
                database,
                TestCaller::member(account),
                DeliveredMessageFixture {
                    id: "c07a0000-0000-4000-8000-000000000005",
                    name: "Database-scoped authorization",
                    body,
                    addressed_to: &["c07a0000-0000-4000-8000-000000000006"],
                    idempotency_key: "contract:isolation:send",
                },
            )
            .await?;
    }

    for (database, allowed_account, denied_account, expected_body) in [
        (
            &first,
            "acct:first-database",
            "acct:second-database",
            "private to first",
        ),
        (
            &second,
            "acct:second-database",
            "acct:first-database",
            "private to second",
        ),
    ] {
        let allowed = harness
            .call(
                database,
                TestCaller::member(allowed_account),
                "get_record",
                json!({ "ids": ["c07a0000-0000-4000-8000-000000000005"] }),
            )
            .await?;
        assert_eq!(allowed["records"][0]["status"], "found");
        assert_eq!(allowed["records"][0]["body"], expected_body);

        let denied = harness
            .call(
                database,
                TestCaller::member(denied_account),
                "get_record",
                json!({ "ids": ["c07a0000-0000-4000-8000-000000000005"] }),
            )
            .await?;
        assert_eq!(
            denied["records"][0]["status"], "not_found",
            "authorization from the other logical database leaked"
        );
        assert!(denied["records"][0].get("body").is_none());
    }

    harness.assert_replay_equivalent(&first).await?;
    harness.assert_replay_equivalent(&second).await?;
    harness.close(&first).await;
    harness.close(&second).await;
    Ok(())
}

/// The shared logical corpus for the first portable views/history slice.
/// Generated times are asserted semantically rather than compared bytewise;
/// every stable field and the deterministic Markdown are identical across
/// adapters.
pub async fn portable_views<H: ContractHarness>(harness: &H) -> Result<()> {
    let database = harness.fresh_logical_database().await?;
    let parent = "11111111-1111-4111-8111-111111111111";
    let first = "22222222-2222-4222-8222-222222222222";
    let second = "33333333-3333-4333-8333-333333333333";
    let blocker = "44444444-4444-4444-8444-444444444444";
    let attribution = "55555555-5555-4555-8555-555555555555";
    let tombstone = "66666666-6666-4666-8666-666666666666";
    let linked_suggestion = "77777777-7777-4777-8777-777777777777";
    let deleted_suggestion = "88888888-8888-4888-8888-888888888888";
    let filed_suggestion = "99999999-9999-4999-8999-999999999999";
    let ordered_sibling = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    let grandchild = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    for arguments in [
        json!({"id":parent,"type":"Collection","kind":"folder","name":"Parent","home_id":UNFILED_ID,"reason":REASON}),
        json!({"id":"71e40000-0000-4000-8000-000000000001","type":"Entity","kind":"person","name":"Allowed viewer","reason":REASON}),
        json!({"id":"71e40000-0000-4000-8000-000000000002","type":"Entity","kind":"person","name":"Denied viewer","reason":REASON}),
        json!({"id":first,"type":"Document","kind":"note","name":"Alpha","body":"Portable body","summary":"Portable summary","home_id":parent,"owner_id":"71e40000-0000-4000-8000-000000000001","facets":{"priority":"high"},"reason":REASON}),
        json!({"id":second,"type":"WorkItem","kind":"task","name":"Beta","home_id":parent,"lifecycle":"open","reason":REASON}),
        json!({"id":ordered_sibling,"type":"Collection","kind":"folder","name":"Aardvark","home_id":parent,"reason":REASON}),
        json!({"id":grandchild,"type":"Document","kind":"note","name":"Boundary child","home_id":ordered_sibling,"reason":REASON}),
        json!({"id":tombstone,"type":"Document","kind":"note","name":"Private tombstone","home_id":parent,"reason":REASON}),
    ] {
        call(harness, &database, "create_record", arguments).await?;
    }
    harness
        .provision_member(
            &database,
            "71e40000-0000-4000-8000-000000000001",
            "acct:view-allowed",
            "principal:view-allowed",
        )
        .await?;
    harness
        .provision_member(
            &database,
            "71e40000-0000-4000-8000-000000000002",
            "acct:view-denied",
            "principal:view-denied",
        )
        .await?;
    harness
        .deliver_message_fixture(
            &database,
            TestCaller::member("acct:view-allowed"),
            DeliveredMessageFixture {
                id: blocker,
                name: "Blocker",
                body: "A caller-visible dependency fixture.",
                addressed_to: &["71e40000-0000-4000-8000-000000000001"],
                idempotency_key: "views:blocker-message",
            },
        )
        .await?;
    call(
        harness,
        &database,
        "manage_links",
        json!({"action":"add","source_id":second,"target_id":blocker,"relationship":"depends_on"}),
    )
    .await?;
    // Prove the authored records, audience and dependency projection rebuild
    // before installing the Postgres harness's deliberately projection-only
    // authorization fixtures below.
    harness.assert_replay_equivalent(&database).await?;
    harness
        .restrict_record_to_account_for_test(&database, first, "acct:view-allowed")
        .await?;
    harness
        .restrict_record_to_account_for_test(&database, tombstone, "acct:view-allowed")
        .await?;
    harness
        .tombstone_record_for_test(&database, tombstone)
        .await?;
    harness
        .create_attribution_record_for_test(&database, attribution)
        .await?;
    harness
        .create_suggestion_record_for_test(
            &database,
            linked_suggestion,
            Some(first),
            Some(UNFILED_ID),
            false,
        )
        .await?;
    harness
        .create_suggestion_record_for_test(
            &database,
            deleted_suggestion,
            Some(first),
            Some(UNFILED_ID),
            true,
        )
        .await?;
    harness
        .create_suggestion_record_for_test(&database, filed_suggestion, None, Some(parent), false)
        .await?;

    let structure = call(
        harness,
        &database,
        "get_structure",
        json!({"root_id":"11111111","max_depth":1,"max_children_per_node":2}),
    )
    .await?;
    assert_eq!(structure["root_id"], parent);
    assert_eq!(structure["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(structure["nodes"][0]["child_count"], 3);
    assert_eq!(structure["nodes"][1]["id"], ordered_sibling);
    assert_eq!(structure["nodes"][1]["child_count"], 1);
    assert_eq!(structure["nodes"][2]["id"], first);
    let depth_zero = call(
        harness,
        &database,
        "get_structure",
        json!({"root_id":parent,"max_depth":0}),
    )
    .await?;
    assert_eq!(depth_zero["nodes"].as_array().unwrap().len(), 1);
    assert_eq!(depth_zero["nodes"][0]["child_count"], 3);
    let again = call(
        harness,
        &database,
        "get_structure",
        json!({"root_id":parent,"max_depth":1,"max_children_per_node":2}),
    )
    .await?;
    assert_eq!(structure, again);
    let historical = call(
        harness,
        &database,
        "get_structure",
        json!({"root_id":parent,"as_of":{"content_seq":1}}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(historical.contains("get_structure historical projection"));

    let filtered = harness
        .call(
            &database,
            TestCaller::member("acct:view-denied"),
            "get_structure",
            json!({"root_id":parent,"max_depth":1}),
        )
        .await?;
    let filtered_ids = filtered["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|node| node["id"].as_str())
        .collect::<Vec<_>>();
    assert!(!filtered_ids.contains(&first));
    assert!(filtered_ids.contains(&second));
    let hidden_render = harness
        .call(
            &database,
            TestCaller::member("acct:view-denied"),
            "render_record",
            json!({"id":first}),
        )
        .await
        .unwrap_err()
        .to_string();
    let missing_id = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    let missing_render = harness
        .call(
            &database,
            TestCaller::member("acct:view-denied"),
            "render_record",
            json!({"id":missing_id}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(hidden_render, missing_render.replace(missing_id, first));
    for hidden_id in [attribution, tombstone] {
        for tool in ["get_structure", "render_record"] {
            let arguments = match tool {
                "get_structure" => json!({"root_id":hidden_id,"max_depth":0}),
                "render_record" => json!({"id":hidden_id}),
                _ => unreachable!(),
            };
            let hidden = harness
                .call(
                    &database,
                    TestCaller::member("acct:view-denied"),
                    tool,
                    arguments,
                )
                .await
                .unwrap_err()
                .to_string();
            let missing_arguments = match tool {
                "get_structure" => json!({"root_id":missing_id,"max_depth":0}),
                "render_record" => json!({"id":missing_id}),
                _ => unreachable!(),
            };
            let missing = harness
                .call(
                    &database,
                    TestCaller::member("acct:view-denied"),
                    tool,
                    missing_arguments,
                )
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(hidden, missing.replace(missing_id, hidden_id));
        }
    }

    let dashboard = call(
        harness,
        &database,
        "get_dashboard",
        json!({"scope":"11111111","limit":1}),
    )
    .await?;
    assert_eq!(dashboard["scope"], parent);
    assert_eq!(dashboard["limit"], 1);
    assert_eq!(dashboard["blocked_total"], 1);
    assert_eq!(dashboard["blocked"][0]["id"], second);
    assert_eq!(dashboard["blocked"][0]["waiting_on"][0]["id"], blocker);
    assert_eq!(dashboard["lifecycle_census"]["shape"], "counts");
    let mut dashboard_repeat = call(
        harness,
        &database,
        "get_dashboard",
        json!({"scope":parent,"limit":1}),
    )
    .await?;
    let mut dashboard_stable = dashboard.clone();
    dashboard_stable
        .as_object_mut()
        .unwrap()
        .remove("stale_cutoff");
    dashboard_repeat
        .as_object_mut()
        .unwrap()
        .remove("stale_cutoff");
    assert_eq!(dashboard_stable, dashboard_repeat);
    let filtered_dashboard = harness
        .call(
            &database,
            TestCaller::member("acct:view-denied"),
            "get_dashboard",
            json!({"scope":parent,"limit":1}),
        )
        .await?;
    assert_eq!(filtered_dashboard["blocked_total"], 0);

    let rendered = call(
        harness,
        &database,
        "render_record",
        json!({"id":"22222222"}),
    )
    .await?;
    let markdown = rendered["markdown"].as_str().unwrap();
    let expected = format!(
        "# Alpha\n\n**Document** / note — `{first}`\n\nPath: Workspace → Unfiled → Parent\n\npersistence: enduring · owner: 71e40000-0000-4000-8000-000000000001\n\n> Portable summary\n\nPortable body\n\n## Facets\n\n- priority: high\n\n## Links (incoming)\n\n- ← part_of — Contract suggestion (`{linked_suggestion}`)\n\n## Suggestions\n\n1 suggestion(s) hidden from ordinary children. Read with `get_record(include_suggestions:true)` or query `kind:suggestion`.\n"
    );
    assert_eq!(markdown, expected);
    assert_eq!(
        rendered,
        call(harness, &database, "render_record", json!({"id":first})).await?
    );
    let rendered_parent = call(harness, &database, "render_record", json!({"id":parent})).await?;
    let parent_markdown = rendered_parent["markdown"].as_str().unwrap();
    assert!(parent_markdown.contains(&format!(
        "- Aardvark (Collection / folder, `{ordered_sibling}`)"
    )));
    assert!(parent_markdown.contains(&format!("- Alpha (Document / note, `{first}`)")));
    assert!(parent_markdown.contains(&format!("- Beta (WorkItem / task, `{second}`)")));
    assert!(!parent_markdown.contains("## Suggestions"));
    let rendered_second = call(harness, &database, "render_record", json!({"id":second})).await?;
    assert!(rendered_second["markdown"]
        .as_str()
        .unwrap()
        .contains(&format!("- → depends_on — Blocker (`{blocker}`)")));

    let error = call(
        harness,
        &database,
        "get_structure",
        json!({"root_id":parent,"max_children_per_node":1001}),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("max_children_per_node must be between 0 and 1000"));
    let isolated = harness.fresh_logical_database().await?;
    for (tool, arguments) in [
        ("get_structure", json!({"root_id":parent,"max_depth":0})),
        ("render_record", json!({"id":first})),
        ("get_dashboard", json!({"scope":parent})),
    ] {
        assert!(harness
            .call(&isolated, TestCaller::Local, tool, arguments)
            .await
            .unwrap_err()
            .to_string()
            .contains("does not exist"));
    }
    harness.close(&isolated).await;
    harness
        .create_dashboard_link_overflow_for_test(&database, parent)
        .await?;
    let overflow = call(harness, &database, "get_dashboard", json!({"scope":parent}))
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        overflow,
        "portable record view link candidate set exceeds 10000 rows"
    );
    harness.close(&database).await;
    Ok(())
}

/// Shared live logical-query corpus. It enters through production MCP
/// dispatch and intentionally exercises logical, not backend-native, SQL.
pub async fn portable_logical_query<H: ContractHarness>(
    harness: &H,
    expect_partial_gaps: bool,
) -> Result<()> {
    let database = harness.fresh_logical_database().await?;
    let folder = "90e50000-0000-4000-8000-000000000005";
    let alpha = "90e50000-0000-4000-8000-000000000001";
    let beta = "90e50000-0000-4000-8000-000000000004";
    let owner = "90e50000-0000-4000-8000-00000000000b";
    let rollup = "90e50000-0000-4000-8000-00000000000c";
    let selector_rollup = "90e50000-0000-4000-8000-00000000000d";
    let archived_intermediate = "90e50000-0000-4000-8000-000000000002";
    let archived_leaf = "90e50000-0000-4000-8000-000000000003";
    let hidden_intermediate = "90e50000-0000-4000-8000-000000000006";
    let hidden_leaf = "90e50000-0000-4000-8000-000000000007";
    let missing_selector_id = "90e50000-0000-4000-8000-00000000000a";
    let rollup_recipe = json!({
        "v":"0.1",
        "outputs":{
            "total_amount":{
                "query":{"steps":[{"step":"filter","ancestor_id":folder,"types":["Document"]}]},
                "fold":{"op":"sum","facet_key":"amount"}
            }
        }
    })
    .to_string();
    let selector_rollup_recipe = json!({
        "v":"0.1",
        "outputs":{
            "hidden_owner_count":{
                "query":{"steps":[{"step":"filter","owner_id":owner}]},
                "fold":{"op":"count"}
            },
            "missing_owner_count":{
                "query":{"steps":[{"step":"filter","owner_id":missing_selector_id}]},
                "fold":{"op":"count"}
            }
        }
    })
    .to_string();
    for arguments in [
        json!({"id":folder,"type":"Collection","kind":"folder","name":"Query folder","home_id":UNFILED_ID,"reason":REASON}),
        json!({"id":owner,"type":"Entity","kind":"person","name":"Query owner","reason":REASON}),
        json!({"id":alpha,"type":"Document","kind":"note","name":"Alpha","home_id":folder,"owner_id":owner,"facets":{"amount":2,"token":"a","lane":"not-a-number"},"reason":REASON}),
        json!({"id":beta,"type":"Document","kind":"note","name":"Beta","home_id":folder,"facets":{"amount":10,"token":"b","lane":1},"reason":REASON}),
        json!({"id":rollup,"type":"Document","kind":"note","name":"Rollup bearer","facets":{"rollup":rollup_recipe},"reason":REASON}),
        json!({"id":selector_rollup,"type":"Document","kind":"note","name":"Selector rollup bearer","facets":{"rollup":selector_rollup_recipe},"reason":REASON}),
        json!({"id":archived_intermediate,"type":"Collection","kind":"folder","name":"Archived intermediate","home_id":folder,"reason":REASON}),
        json!({"id":archived_leaf,"type":"Document","kind":"note","name":"Archived branch leaf","home_id":archived_intermediate,"reason":REASON}),
        json!({"id":hidden_leaf,"type":"Document","kind":"note","name":"Hidden branch leaf","home_id":folder,"reason":REASON}),
    ] {
        call(harness, &database, "create_record", arguments).await?;
    }
    harness
        .provision_member(
            &database,
            owner,
            "acct:query-owner",
            "principal:query-owner",
        )
        .await?;
    call(
        harness,
        &database,
        "manage_links",
        json!({"action":"add","source_id":alpha,"target_id":beta,"relationship":"mentions"}),
    )
    .await?;
    harness.assert_replay_equivalent(&database).await?;
    harness
        .mark_record_archived_for_test(&database, archived_intermediate)
        .await?;
    harness
        .create_suggestion_record_for_test(
            &database,
            hidden_intermediate,
            None,
            Some(folder),
            false,
        )
        .await?;
    harness
        .rehome_record_for_test(&database, hidden_leaf, hidden_intermediate)
        .await?;
    harness
        .restrict_record_to_account_for_test(&database, alpha, "acct:query-owner")
        .await?;
    harness
        .restrict_record_to_account_for_test(&database, owner, "acct:query-owner")
        .await?;
    harness
        .restrict_record_to_account_for_test(&database, rollup, "acct:query-owner")
        .await?;

    let request = json!({
        "steps":[
            {"step":"filter","ancestor_id":folder,"facets":[{"key":"amount","gte":2}]}
        ],
        "facet_order":{"key":"amount","lane":"number","direction":"desc"},
        "limit":1,
        "offset":0
    });
    let first = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            request.clone(),
        )
        .await?;
    assert_eq!(first["shape"], "records");
    assert_eq!(first["total"], 2);
    assert_eq!(first["returned"], 1);
    assert_eq!(first["records"][0]["id"], beta);
    assert_eq!(first["records"][0]["name"], "Beta");
    let created_at = first["records"][0]["created_at"].as_str().unwrap();
    assert_eq!(created_at.len(), 24);
    assert!(created_at.ends_with('Z'));
    assert_eq!(first["has_more"], true);
    let again = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            request,
        )
        .await?;
    let mut first_stable = first.clone();
    let mut again_stable = again;
    if let Some(object) = first_stable.as_object_mut() {
        object.remove("observed_at");
    }
    if let Some(object) = again_stable.as_object_mut() {
        object.remove("observed_at");
    }
    assert_eq!(first_stable, again_stable);
    let second_page = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({
                "steps":[{"step":"filter","ancestor_id":folder,"facets":[{"key":"amount","gte":2}]}],
                "facet_order":{"key":"amount","lane":"number","direction":"desc"},
                "limit":1,
                "offset":1
            }),
        )
        .await?;
    assert_eq!(second_page["records"][0]["id"], alpha);
    assert_eq!(second_page["has_more"], false);

    let missing_last = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({
                "steps":[{"step":"filter","ancestor_id":folder}],
                "facet_order":{"key":"amount","lane":"number","direction":"desc"}
            }),
        )
        .await?;
    assert_eq!(missing_last["records"][0]["id"], beta);
    assert_eq!(missing_last["records"][1]["id"], alpha);
    assert_eq!(missing_last["records"][2]["id"], folder);
    assert_eq!(missing_last["total"], 3);
    assert!(!missing_last.to_string().contains(archived_leaf));
    assert!(!missing_last.to_string().contains(hidden_leaf));

    let archived_walk = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":folder,"include_archived":true}]}),
        )
        .await?;
    assert_eq!(archived_walk["total"], 5);
    assert!(archived_walk.to_string().contains(archived_intermediate));
    assert!(archived_walk.to_string().contains(archived_leaf));
    assert!(!archived_walk.to_string().contains(hidden_intermediate));
    assert!(!archived_walk.to_string().contains(hidden_leaf));
    for (root, include_archived, expected_total) in [
        (archived_intermediate, false, 0),
        (archived_intermediate, true, 2),
    ] {
        let scoped = harness
            .call(
                &database,
                TestCaller::member("acct:query-owner"),
                "query_record",
                json!({"steps":[{"step":"filter","ancestor_id":root,"include_archived":include_archived}]}),
            )
            .await?;
        assert_eq!(scoped["total"], expected_total, "root={root}");
    }
    assert!(harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":hidden_intermediate}]}),
        )
        .await
        .unwrap_err()
        .to_string()
        .contains(&format!("record {hidden_intermediate} does not exist")));

    let traversed = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({"steps":[{"step":"filter","ids":[alpha]},{"step":"traverse","target":"links","direction":"out","relationship":"mentions"}]}),
        )
        .await?;
    assert_eq!(traversed["records"][0]["id"], beta);

    let counted = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":folder}],"count_by":"type"}),
        )
        .await?;
    assert_eq!(counted["shape"], "counts");
    assert_eq!(counted["total"], 3);
    assert_eq!(counted["buckets"][0], json!({"key":"Document","count":2}));
    let null_count = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":folder,"types":["Document"]}],"count_by":"lifecycle"}),
        )
        .await?;
    assert_eq!(null_count["buckets"], json!([{"key":null,"count":2}]));

    let aggregate = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":folder,"types":["Document"]}],"aggregate":{"op":"sum","facet_key":"amount"}}),
        )
        .await?;
    assert_eq!(aggregate["shape"], "aggregate");
    assert_eq!(aggregate["value"], 12.0);
    assert_eq!(aggregate["contributing_values"], 2);

    let resolved = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "resolve_rollup",
            json!({"record_id":rollup,"rollup_name":"total_amount"}),
        )
        .await?;
    assert_eq!(resolved["value"], 12.0);
    assert_eq!(resolved["record_id"], rollup);
    assert_eq!(resolved["rollup_name"], "total_amount");
    assert_eq!(resolved["cache_hit"], false);
    assert_eq!(resolved["spec_digest"].as_str().unwrap().len(), 64);
    let resolved_again = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "resolve_rollup",
            json!({"record_id":rollup,"rollup_name":"total_amount"}),
        )
        .await?;
    assert_eq!(resolved_again["value"], resolved["value"]);
    assert_eq!(resolved_again["spec_digest"], resolved["spec_digest"]);
    assert_eq!(resolved_again["cache_hit"], !expect_partial_gaps);
    let hidden_rollup = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "resolve_rollup",
            json!({"record_id":rollup,"rollup_name":"total_amount"}),
        )
        .await
        .unwrap_err()
        .to_string();
    let missing_rollup = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "resolve_rollup",
            json!({"record_id":"90e50000-0000-4000-8000-000000000009","rollup_name":"total_amount"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        hidden_rollup,
        missing_rollup.replace("90e50000-0000-4000-8000-000000000009", rollup)
    );
    let hidden_rollup_selector = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "resolve_rollup",
            json!({"record_id":selector_rollup,"rollup_name":"hidden_owner_count"}),
        )
        .await
        .unwrap_err()
        .to_string();
    let missing_rollup_selector = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "resolve_rollup",
            json!({"record_id":selector_rollup,"rollup_name":"missing_owner_count"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert!(hidden_rollup_selector.starts_with("resolve_rollup: record "));
    assert_eq!(
        hidden_rollup_selector,
        missing_rollup_selector.replace(missing_selector_id, owner)
    );

    let scan = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "scan",
            json!({"scope":folder,"high_degree_min":1}),
        )
        .await?;
    assert_eq!(scan["corpus_size"], 3);
    assert_eq!(scan["census"]["by_type"]["total"], 3);
    assert_eq!(scan["axes"]["containers"]["count"], 1);
    assert_eq!(scan["axes"]["high_degree"]["count"], 2);
    assert!(scan["axes"].get("lexical").is_none());
    for hidden_root in [archived_intermediate, hidden_intermediate] {
        assert!(harness
            .call(
                &database,
                TestCaller::member("acct:query-owner"),
                "scan",
                json!({"scope":hidden_root}),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains(&format!("scope record {hidden_root} does not exist")));
    }

    let denied = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":folder,"types":["Document"]}]}),
        )
        .await?;
    assert_eq!(denied["total"], 1);
    assert_eq!(denied["records"][0]["id"], beta);
    assert!(!denied.to_string().contains(alpha));
    let denied_scan = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "scan",
            json!({"scope":folder,"high_degree_min":1}),
        )
        .await?;
    assert_eq!(denied_scan["corpus_size"], 2);
    assert_eq!(denied_scan["axes"]["high_degree"]["count"], 0);
    assert!(!denied_scan.to_string().contains(alpha));

    let hidden_lane_diagnostic = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":folder,"facets":[{"key":"lane","gte":10}]}]}),
        )
        .await?;
    assert_eq!(hidden_lane_diagnostic["total"], 0);
    assert!(hidden_lane_diagnostic.get("messages").is_none());
    let visible_lane_diagnostic = harness
        .call(
            &database,
            TestCaller::member("acct:query-owner"),
            "query_record",
            json!({"steps":[{"step":"filter","ancestor_id":folder,"facets":[{"key":"lane","gte":10}]}]}),
        )
        .await?;
    assert_eq!(visible_lane_diagnostic["total"], 0);
    assert_eq!(
        visible_lane_diagnostic["messages"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(visible_lane_diagnostic["messages"][0]
        .as_str()
        .unwrap()
        .starts_with("1 records"));

    let hidden_selector = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "query_record",
            json!({"steps":[{"step":"filter","owner_id":owner}]}),
        )
        .await
        .unwrap_err()
        .to_string();
    let missing = "90e50000-0000-4000-8000-000000000008";
    let missing_selector = harness
        .call(
            &database,
            TestCaller::member("acct:query-denied"),
            "query_record",
            json!({"steps":[{"step":"filter","owner_id":missing}]}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(hidden_selector, missing_selector.replace(missing, owner));

    if expect_partial_gaps {
        for unsupported in [
            json!({"steps":[{"step":"filter"}],"as_of":{"content_seq":1}}),
            json!({"steps":[{"step":"filter"}],"include_interpretation":true}),
            json!({"steps":[{"step":"filter"}],"include_coordination":true}),
            json!({"steps":[{"step":"filter"}],"activity":{"actions":{"any":[]}}}),
        ] {
            assert!(harness
                .call(&database, TestCaller::Local, "query_record", unsupported)
                .await
                .is_err());
        }
        assert!(harness
            .call(
                &database,
                TestCaller::Local,
                "scan",
                json!({"query":"alpha"}),
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("scan lexical axis"));
    } else {
        let lexical = harness
            .call(
                &database,
                TestCaller::Local,
                "scan",
                json!({"query":"alpha"}),
            )
            .await?;
        assert!(lexical["axes"].get("lexical").is_some());
    }

    let isolated = harness.fresh_logical_database().await?;
    call(
        harness,
        &isolated,
        "create_record",
        json!({"id":beta,"type":"Document","kind":"note","name":"Isolated beta","reason":REASON}),
    )
    .await?;
    let isolated_result = harness
        .call(
            &isolated,
            TestCaller::Local,
            "query_record",
            json!({"steps":[{"step":"filter","ids":[beta]}]}),
        )
        .await?;
    assert_eq!(isolated_result["total"], 1);
    assert_eq!(isolated_result["records"][0]["name"], "Isolated beta");
    let primary_result = harness
        .call(
            &database,
            TestCaller::Local,
            "query_record",
            json!({"steps":[{"step":"filter","ids":[beta]}]}),
        )
        .await?;
    assert_eq!(primary_result["total"], 1);
    assert_eq!(primary_result["records"][0]["name"], "Beta");
    harness.close(&isolated).await;
    harness.close(&database).await;
    Ok(())
}

/// Shared observable contract for the qualified backend-native search slice.
/// Candidate selection stays physical; every assertion here is backend-neutral
/// caller-visible semantics.
pub async fn portable_native_search<H: ContractHarness>(harness: &H) -> Result<()> {
    let database = harness.fresh_logical_database().await?;
    let folder = "5ea50000-0000-4000-8000-000000000004";
    let member = "5ea50000-0000-4000-8000-000000000006";
    let name_hit = "5ea50000-0000-4000-8000-000000000009";
    let body_hit = "5ea50000-0000-4000-8000-000000000002";
    let hidden = "5ea50000-0000-4000-8000-000000000005";
    let mutable = "5ea50000-0000-4000-8000-000000000008";
    let archived = "5ea50000-0000-4000-8000-000000000001";
    let camel = "5ea50000-0000-4000-8000-000000000003";
    let prefix = "5ea50000-0000-4000-8000-00000000000a";
    let redacted_intermediate = "5ea50000-0000-4000-8000-00000000000b";
    let visible_strict_descendant = "5ea50000-0000-4000-8000-00000000000d";
    let visible_near_descendant = "5ea50000-0000-4000-8000-00000000000c";
    for arguments in [
        json!({"id":folder,"type":"Collection","kind":"folder","name":"Search scope","home_id":UNFILED_ID,"reason":REASON}),
        json!({"id":member,"type":"Entity","kind":"person","name":"Search member","reason":REASON}),
        json!({"id":name_hit,"type":"Document","kind":"note","name":"Meeting alpha","body":"short agenda","home_id":folder,"reason":REASON}),
        json!({"id":body_hit,"type":"Document","kind":"note","name":"Zeta memo","body":"meeting meeting meeting meeting meeting meeting","home_id":folder,"reason":REASON}),
        json!({"id":hidden,"type":"Document","kind":"note","name":"Meeting private","body":"meeting","home_id":folder,"reason":REASON}),
        json!({"id":mutable,"type":"Document","kind":"note","name":"Mutable note","body":"before mutation","home_id":folder,"reason":REASON}),
        json!({"id":archived,"type":"Document","kind":"note","name":"Archive target","body":"archivelexeme","home_id":folder,"reason":REASON}),
        json!({"id":camel,"type":"Document","kind":"note","name":"DetailRecordLayout","home_id":folder,"reason":REASON}),
        json!({"id":prefix,"type":"Document","kind":"note","name":"Running plan","home_id":folder,"reason":REASON}),
        json!({"id":redacted_intermediate,"type":"Collection","kind":"folder","name":"Redacted intermediate","home_id":folder,"reason":REASON}),
        json!({"id":visible_strict_descendant,"type":"Document","kind":"note","name":"Scoped survivor","body":"scopebridgelexeme","home_id":redacted_intermediate,"reason":REASON}),
        json!({"id":visible_near_descendant,"type":"Document","kind":"note","name":"Redacted intermediate survivor","home_id":redacted_intermediate,"reason":REASON}),
    ] {
        create(harness, &database, arguments).await?;
    }
    harness
        .provision_member(&database, member, "acct:search", "principal:search")
        .await?;
    harness
        .restrict_record_to_account_for_test(&database, hidden, "acct:other")
        .await?;
    harness
        .restrict_record_to_account_for_test(&database, redacted_intermediate, "acct:other")
        .await?;
    for record_id in [visible_strict_descendant, visible_near_descendant] {
        harness
            .restrict_record_to_account_for_test(&database, record_id, "acct:search")
            .await?;
    }

    let caller = TestCaller::member("acct:search");
    let meeting = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"meeting","scope":folder}),
        )
        .await?;
    assert_eq!(meeting["hits"][0]["id"], name_hit, "name relevance wins");
    assert_eq!(meeting["hits"][1]["id"], body_hit);
    assert_eq!(meeting["hits"][0]["home_id"], folder);
    assert!(meeting["hits"][0]["snippet"]
        .as_str()
        .unwrap()
        .contains('['));
    assert!(!meeting.to_string().contains(hidden));
    let again = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"meeting","scope":folder}),
        )
        .await?;
    assert_eq!(meeting, again, "search ties and shaping are deterministic");
    let page = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"meeting","scope":folder,"limit":1}),
        )
        .await?;
    assert_eq!(page["returned"], 1);
    assert_eq!(page["limit_reached"], true);

    let redacted_path_hit = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"scopebridgelexeme","scope":folder}),
        )
        .await?;
    assert_eq!(
        redacted_path_hit["hits"][0]["id"],
        visible_strict_descendant
    );
    assert_eq!(
        redacted_path_hit["hits"][0]["home_id"],
        Value::Null,
        "a policy-redacted intermediate must not prune its visible child or leak as home_id"
    );
    let redacted_path_near = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"redacted intermediate survi","scope":folder}),
        )
        .await?;
    let near_prefix = redacted_path_near["near_misses"]["name_prefix"]
        .as_array()
        .expect("thin search has prefix near misses");
    assert!(
        near_prefix
            .iter()
            .any(|row| row["id"] == visible_near_descendant && row["home_id"].is_null()),
        "the scoped near-miss walk must also cross a policy-redacted intermediate"
    );

    let hidden_scope = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"meeting","scope":hidden}),
        )
        .await
        .unwrap_err()
        .to_string();
    let missing_scope = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"meeting","scope":"5ea50000-0000-4000-8000-000000000007"}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(
        hidden_scope,
        missing_scope.replace("5ea50000-0000-4000-8000-000000000007", hidden),
        "unauthorized scopes are missing-equivalent"
    );

    let infix = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"detail record layout","scope":folder}),
        )
        .await?;
    assert_eq!(infix["thin"], true);
    assert!(infix["near_misses"]["name_infix"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == camel));
    let prefix_result = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"runni","scope":folder}),
        )
        .await?;
    assert!(prefix_result["near_misses"]["name_prefix"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == prefix));

    call(
        harness,
        &database,
        "update_record",
        json!({
            "id": mutable,
            "body": "freshneedle now indexed",
            "if_body_digest": hex::encode(Sha256::digest(b"before mutation")),
            "reason": REASON
        }),
    )
    .await?;
    let fresh = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"freshneedle","scope":folder}),
        )
        .await?;
    assert_eq!(fresh["hits"][0]["id"], mutable);

    call(
        harness,
        &database,
        "archive_record",
        json!({"id":archived,"reason":REASON}),
    )
    .await?;
    assert_eq!(
        harness
            .call(
                &database,
                caller.clone(),
                "search",
                json!({"query":"archivelexeme","scope":folder}),
            )
            .await?["returned"],
        0
    );
    assert_eq!(
        harness
            .call(
                &database,
                caller.clone(),
                "search",
                json!({"query":"archivelexeme","scope":folder,"include_archived":true}),
            )
            .await?["hits"][0]["id"],
        archived
    );

    for hostile in ["OR", "\" ) (", "100%_safe"] {
        harness
            .call(
                &database,
                caller.clone(),
                "search",
                json!({"query":hostile,"scope":folder}),
            )
            .await?;
    }
    let punctuation = harness
        .call(
            &database,
            caller.clone(),
            "search",
            json!({"query":"***","scope":folder}),
        )
        .await?;
    assert_eq!(punctuation["returned"], 0);
    assert!(punctuation["near_misses"]["name_prefix"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(punctuation["near_misses"]["name_infix"]
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(
        harness
            .call(&database, caller, "search", json!({"query":"   "}))
            .await
            .unwrap_err()
            .to_string(),
        "search: 'query' must be non-empty"
    );
    harness.assert_replay_equivalent(&database).await?;
    harness
        .create_search_hidden_overflow_for_test(&database, folder, hidden)
        .await?;
    let after_hidden_overflow = harness
        .call(
            &database,
            TestCaller::member("acct:search"),
            "search",
            json!({"query":"meeting","scope":folder}),
        )
        .await?;
    assert_eq!(after_hidden_overflow["hits"][0]["id"], name_hit);
    assert_eq!(after_hidden_overflow["hits"][1]["id"], body_hit);
    assert_eq!(after_hidden_overflow["returned"], 2);
    harness.close(&database).await;
    Ok(())
}
/// Shared typed-facet and valid-time observation corpus. Fixture-only schema
/// setup is physical because schema/vocabulary mutation parity is a separate
/// ledger slice; every observable assertion dispatches through production MCP.
pub async fn portable_facets<H: ContractHarness>(harness: &H) -> Result<()> {
    let database = harness.fresh_logical_database().await?;
    let metric = "fac70000-0000-4000-8000-000000000004";
    call(
        harness,
        &database,
        "create_record",
        json!({
            "id":metric,"type":"Outcome","kind":"target","name":"Metric",
            "facets":{"current":99},"reason":REASON
        }),
    )
    .await?;

    let first = call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"set","record_id":metric,"key":"current","value":10,"as_of":"2026-08-01T01:00:00+01:00","reason":REASON}),
    )
    .await?;
    assert_eq!(first["as_of"], "2026-08-01T00:00:00.000Z");
    let correction = call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"set","record_id":metric,"key":"current","value":11,"as_of":"2026-08-01T00:00:00Z","reason":REASON}),
    )
    .await?;
    assert!(correction["event_seq"].as_i64() > first["event_seq"].as_i64());
    call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"set","record_id":metric,"key":"current","value":20,"as_of":"2026-08-02T00:00:00Z","reason":REASON}),
    )
    .await?;
    call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"unset","record_id":metric,"key":"current","as_of":"2026-08-03T00:00:00Z","reason":REASON}),
    )
    .await?;

    let page_one = call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"list","record_id":metric,"key":"current","limit":1}),
    )
    .await?;
    assert_eq!(page_one["observations"][0]["value"], "11");
    assert_eq!(page_one["next_after_as_of"], "2026-08-01T00:00:00.000Z");
    let page_two = call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"list","record_id":metric,"key":"current","after_as_of":page_one["next_after_as_of"],"limit":2}),
    )
    .await?;
    assert_eq!(page_two["observations"][0]["value"], "20");
    assert_eq!(page_two["observations"][1]["op"], "unset");
    assert_eq!(page_two["next_after_as_of"], "2026-08-03T00:00:00.000Z");
    let page_three = call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"list","record_id":metric,"key":"current","after_as_of":page_two["next_after_as_of"],"limit":2}),
    )
    .await?;
    assert_eq!(page_three["observations"][0]["value"], "99");
    assert_eq!(page_three["next_after_as_of"], Value::Null);
    let bounded_window = call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"list","record_id":metric,"key":"current","from_as_of":"2026-08-02T00:00:00Z","to_as_of":"2026-08-02T00:00:00Z"}),
    )
    .await?;
    assert_eq!(bounded_window["observations"].as_array().unwrap().len(), 1);
    assert_eq!(bounded_window["observations"][0]["value"], "20");
    for (arguments, expected) in [
        (
            json!({"action":"list","record_id":metric,"key":"current","limit":0}),
            "manage_facet_observations: 'limit' must be between 1 and 1000",
        ),
        (
            json!({"action":"list","record_id":metric,"key":"current","limit":1001}),
            "manage_facet_observations: 'limit' must be between 1 and 1000",
        ),
        (
            json!({"action":"list","record_id":metric,"key":"current","from_as_of":"2026-08-03T00:00:00Z","to_as_of":"2026-08-02T00:00:00Z"}),
            "manage_facet_observations: 'from_as_of' must be earlier than or equal to 'to_as_of'",
        ),
        (
            json!({"action":"set","record_id":metric,"key":"current","value":30,"as_of":"not-a-timestamp","reason":REASON}),
            "manage_facet_observations: 'as_of' must be an RFC3339 timestamp (for example 2026-08-01T09:30:00Z)",
        ),
        (
            json!({"action":"set","record_id":metric,"key":"lifecycle","value":"open","as_of":"2026-08-04T00:00:00Z","reason":REASON}),
            "manage_facet_observations: 'lifecycle' is a spine facet — set it via the top-level 'lifecycle' argument, not 'facets'",
        ),
    ] {
        let error = harness
            .call(
                &database,
                TestCaller::Local,
                "manage_facet_observations",
                arguments,
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(error, expected);
    }
    let resolved_metric = call(
        harness,
        &database,
        "resolve_facets",
        json!({"record_id":metric}),
    )
    .await?;
    assert_eq!(resolved_metric["values"][0]["key"], "current");
    assert_eq!(resolved_metric["values"][0]["value"], "99");
    harness.assert_replay_equivalent(&database).await?;

    harness
        .install_facet_governance_fixture_for_test(&database)
        .await?;

    let missing_required = call(
        harness,
        &database,
        "preview_record_shape",
        json!({
            "type": "WorkItem",
            "kind": "task",
            "facets": { "confidence": "probable", "score": 7, "effort": "s" }
        }),
    )
    .await?;
    assert_eq!(missing_required["proposed_facets"]["status"], "rejected");
    assert_eq!(
        missing_required["proposed_facets"]["assessments"][0]["value_resolution"]["classification"],
        "active_alias"
    );
    assert_eq!(
        missing_required["proposed_facets"]["required_declarations"][0]["issues"],
        json!(["required_facet_not_supplied"])
    );
    let preview_heads = missing_required["advisory_basis"]["event_heads"].clone();
    let accepted_preview = call(
        harness,
        &database,
        "preview_record_shape",
        json!({
            "type": "WorkItem",
            "kind": "task",
            "facets": {
                "confidence": "probable",
                "score": 7,
                "effort": "s",
                "mandatory": "yes"
            }
        }),
    )
    .await?;
    assert_eq!(accepted_preview["proposed_facets"]["status"], "accepted");
    assert_eq!(
        accepted_preview["advisory_basis"]["event_heads"],
        preview_heads
    );
    harness
        .install_ineligible_facet_records_for_test(&database)
        .await?;
    for record_id in [
        "facet:attribution",
        "facet:malformed-comment",
        "facet:target-mismatch",
        "facet:targeted-reply",
        "facet:reply-on-reply",
    ] {
        for (tool, arguments, expected) in [
            (
                "resolve_facets",
                json!({"record_id":record_id}),
                format!("record {record_id} does not exist"),
            ),
            (
                "suggest_facet_values",
                json!({"record_id":record_id,"facet_key":"confidence"}),
                format!("suggest_facet_values: record {record_id} does not exist"),
            ),
            (
                "manage_facet_observations",
                json!({"action":"list","record_id":record_id,"key":"score"}),
                format!("manage_facet_observations: record {record_id} does not exist"),
            ),
        ] {
            assert_eq!(
                harness
                    .call(&database, TestCaller::Local, tool, arguments)
                    .await
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
        let before = harness
            .facet_event_count_for_test(&database, record_id)
            .await?;
        for arguments in [
            json!({"action":"set","record_id":record_id,"key":"score","value":1,"as_of":"2026-08-05T00:00:00Z","reason":REASON}),
            json!({"action":"unset","record_id":record_id,"key":"score","as_of":"2026-08-05T00:00:00Z","reason":REASON}),
        ] {
            assert_eq!(
                harness
                    .call(
                        &database,
                        TestCaller::Local,
                        "manage_facet_observations",
                        arguments,
                    )
                    .await
                    .unwrap_err()
                    .to_string(),
                format!("manage_facet_observations: record {record_id} does not exist")
            );
        }
        assert_eq!(
            harness
                .facet_event_count_for_test(&database, record_id)
                .await?,
            before
        );
    }
    let governed = "fac70000-0000-4000-8000-000000000001";
    call(
        harness,
        &database,
        "create_record",
        json!({
            "id":governed,"type":"WorkItem","kind":"task","name":"Governed",
            "facets":{"score":7,"effort":"s","confidence":"probable","mandatory":"yes","z-key":"z","Å-key":"ring","ä-key":"umlaut"},"reason":REASON
        }),
    )
    .await?;
    let by_record = call(
        harness,
        &database,
        "resolve_facets",
        json!({"record_id":governed}),
    )
    .await?;
    assert_eq!(by_record["shape"]["score"]["type"], "number");
    assert_eq!(by_record["shape"]["effort"]["values"], json!(["s", "m"]));
    assert_eq!(
        by_record["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["key"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "confidence",
            "effort",
            "mandatory",
            "score",
            "z-key",
            "Å-key",
            "ä-key",
        ]
    );
    let by_type = call(
        harness,
        &database,
        "resolve_facets",
        json!({"type":"WorkItem","kind":"task"}),
    )
    .await?;
    assert_eq!(by_type["shape"], by_record["shape"]);
    assert_eq!(
        call(
            harness,
            &database,
            "resolve_facets",
            json!({"type":"WorkItem","kind":"task"}),
        )
        .await?,
        by_type
    );

    let suggestions = call(
        harness,
        &database,
        "suggest_facet_values",
        json!({"record_id":governed,"facet_key":"confidence"}),
    )
    .await?;
    let shape_guarantee = suggestions["shape_guarantee"].clone();
    let run_context = suggestions["run_context"].clone();
    assert_eq!(
        suggestions,
        json!({
            "facet_key":"confidence",
            "type":"WorkItem",
            "kind":"task",
            "declared_type":null,
            "vocabulary":{"id":"voc:contract-confidence","name":"contract-confidence"},
            "suggestions":[
                {"id":"vv:contract-confidence:likely","vocabulary_id":"voc:contract-confidence","value":"likely","gloss":null,"status":"active","ordinal":100.0,"terminality":"open","metadata":{},"alias_of":null},
                {"id":"vv:contract-confidence:probable","vocabulary_id":"voc:contract-confidence","value":"probable","gloss":null,"status":"active","ordinal":100.0,"terminality":"open","metadata":{},"alias_of":"vv:contract-confidence:likely","canonical":{"id":"vv:contract-confidence:likely","value":"likely"}},
                {"id":"vv:contract-confidence:unicode-z","vocabulary_id":"voc:contract-confidence","value":"Ångström","gloss":null,"status":"active","ordinal":150.0,"terminality":"open","metadata":{},"alias_of":null},
                {"id":"vv:contract-confidence:unicode-a","vocabulary_id":"voc:contract-confidence","value":"äther","gloss":null,"status":"active","ordinal":150.0,"terminality":"open","metadata":{},"alias_of":null},
                {"id":"vv:contract-confidence:won","vocabulary_id":"voc:contract-confidence","value":"won","gloss":null,"status":"active","ordinal":200.0,"terminality":"terminal_positive","metadata":{},"alias_of":null}
            ],
            "shape_guarantee":shape_guarantee,
            "run_context":run_context,
        })
    );
    assert_eq!(
        call(
            harness,
            &database,
            "suggest_facet_values",
            json!({"record_id":governed,"facet_key":"confidence"}),
        )
        .await?,
        suggestions
    );
    let no_vocabulary = call(
        harness,
        &database,
        "suggest_facet_values",
        json!({"record_id":governed,"facet_key":"score"}),
    )
    .await?;
    assert_eq!(no_vocabulary["vocabulary"], Value::Null);
    assert!(no_vocabulary["suggestions"].as_array().unwrap().is_empty());

    for (arguments, expected) in [
        (
            json!({"id":"face70a0-0000-4000-8000-000000000001","type":"WorkItem","kind":"task","name":"Invalid","facets":{"score":"7","mandatory":"yes"},"reason":REASON}),
            "requires a JSON number",
        ),
        (
            json!({"id":"face70a0-0000-4000-8000-000000000001","type":"WorkItem","kind":"task","name":"Invalid","facets":{"effort":"xl","mandatory":"yes"},"reason":REASON}),
            "declared values set",
        ),
        (
            json!({"id":"face70a0-0000-4000-8000-000000000001","type":"WorkItem","kind":"task","name":"Invalid","facets":{"confidence":"speculative","mandatory":"yes"},"reason":REASON}),
            "not an active member",
        ),
        (
            json!({"id":"face70a0-0000-4000-8000-000000000001","type":"WorkItem","kind":"task","name":"Invalid","facets":{"score":7},"reason":REASON}),
            "missing required facet 'mandatory'",
        ),
    ] {
        let error = harness
            .call(&database, TestCaller::Local, "create_record", arguments)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
        let absent = harness
            .call(
                &database,
                TestCaller::Local,
                "resolve_facets",
                json!({"record_id":"face70a0-0000-4000-8000-000000000001"}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(
            absent,
            "record face70a0-0000-4000-8000-000000000001 does not exist"
        );
    }

    for (facets, expected) in [
        (json!({"score":"8"}), "requires a JSON number"),
        (json!({"effort":"xl"}), "declared values set"),
        (json!({"confidence":"speculative"}), "not an active member"),
        (
            json!({"confidence":{"value":"likely","vocab_ref":"rec:voc:other"}}),
            "conflicting vocab_ref",
        ),
        (
            json!({"mandatory":null}),
            "missing required facet 'mandatory'",
        ),
    ] {
        let error = harness
            .call(
                &database,
                TestCaller::Local,
                "update_record",
                json!({"id":governed,"facets":facets,"reason":REASON}),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }

    for (arguments, expected) in [
        (
            json!({"action":"set","record_id":governed,"key":"score","value":"42","as_of":"2026-08-04T00:00:00Z","reason":REASON}),
            "requires a JSON number",
        ),
        (
            json!({"action":"set","record_id":governed,"key":"effort","value":"xl","as_of":"2026-08-04T00:00:00Z","reason":REASON}),
            "declared values set",
        ),
        (
            json!({"action":"set","record_id":governed,"key":"confidence","value":"speculative","as_of":"2026-08-04T00:00:00Z","reason":REASON}),
            "not an active member",
        ),
    ] {
        let error = harness
            .call(
                &database,
                TestCaller::Local,
                "manage_facet_observations",
                arguments,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(expected), "{error}");
    }
    let no_invalid_writes = call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"list","record_id":governed,"key":"score"}),
    )
    .await?;
    assert_eq!(
        no_invalid_writes["observations"].as_array().unwrap().len(),
        1
    );
    assert_eq!(no_invalid_writes["observations"][0]["value"], "7");

    let owner = "fac70000-0000-4000-8000-000000000006";
    let hidden = "fac70000-0000-4000-8000-000000000002";
    call(
        harness,
        &database,
        "create_record",
        json!({"id":owner,"type":"Entity","kind":"person","name":"Facet owner","reason":REASON}),
    )
    .await?;
    harness
        .provision_member(
            &database,
            owner,
            "acct:facet-owner",
            "principal:facet-owner",
        )
        .await?;
    let hidden_scope = "fac70000-0000-4000-8000-000000000003";
    call(
        harness,
        &database,
        "create_record",
        json!({"id":hidden_scope,"type":"Collection","kind":"folder","name":"Hidden facet scope","reason":REASON}),
    )
    .await?;
    harness
        .restrict_record_to_account_for_test(&database, hidden_scope, "acct:facet-owner")
        .await?;
    harness
        .install_hidden_scoped_facet_schema_for_test(&database, hidden_scope)
        .await?;
    call(harness, &database, "create_record", json!({"id":hidden,"type":"WorkItem","kind":"task","name":"Hidden facet record","home_id":hidden_scope,"facets":{"mandatory":"yes","private-only":"unconstrained-create"},"reason":REASON})).await?;
    harness
        .restrict_record_to_account_for_test(&database, hidden, "acct:facet-owner")
        .await?;
    let local_scoped = call(
        harness,
        &database,
        "resolve_facets",
        json!({"record_id":hidden}),
    )
    .await?;
    assert!(local_scoped["shape"].get("private-only").is_none());
    assert!(local_scoped["shape_guarantee"]
        .as_str()
        .unwrap()
        .contains("filing home never contributes schema"));
    assert_eq!(
        local_scoped["values"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["key"] == "private-only")
            .unwrap()["value"],
        "unconstrained-create"
    );
    let scoped_events_before = harness
        .facet_event_count_for_test(&database, hidden)
        .await?;
    call(
        harness,
        &database,
        "update_record",
        json!({"id":hidden,"facets":{"private-only":"unconstrained-update"},"reason":REASON}),
    )
    .await?;
    call(
        harness,
        &database,
        "manage_facet_observations",
        json!({"action":"set","record_id":hidden,"key":"private-only","value":"unconstrained-observation","as_of":"2026-08-05T00:00:00Z","reason":REASON}),
    )
    .await?;
    assert_eq!(
        harness
            .facet_event_count_for_test(&database, hidden)
            .await?,
        scoped_events_before + 2
    );
    let locally_written_scoped = call(
        harness,
        &database,
        "resolve_facets",
        json!({"record_id":hidden}),
    )
    .await?;
    assert_eq!(
        locally_written_scoped["values"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["key"] == "private-only")
            .unwrap()["value"],
        "unconstrained-update"
    );
    let scoped_suggestion = call(
        harness,
        &database,
        "suggest_facet_values",
        json!({"record_id":hidden,"facet_key":"private-only"}),
    )
    .await?;
    assert_eq!(scoped_suggestion["declared_type"], Value::Null);
    assert_eq!(scoped_suggestion["vocabulary"], Value::Null);
    let denied_scoped = harness
        .call(
            &database,
            TestCaller::member("acct:denied"),
            "resolve_facets",
            json!({"type":"WorkItem","kind":"task"}),
        )
        .await?;
    assert!(denied_scoped["shape"].get("private-only").is_none());
    for (tool, arguments) in [
        ("resolve_facets", json!({"record_id":hidden})),
        (
            "suggest_facet_values",
            json!({"record_id":hidden,"facet_key":"confidence"}),
        ),
        (
            "manage_facet_observations",
            json!({"action":"list","record_id":hidden,"key":"score"}),
        ),
    ] {
        let error = harness
            .call(
                &database,
                TestCaller::member("acct:denied"),
                tool,
                arguments,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("does not exist"), "{error}");
        assert!(!error.contains("Hidden facet record"), "{error}");
    }
    for arguments in [
        json!({"action":"set","record_id":hidden,"key":"score","value":1,"as_of":"2026-08-05T00:00:00Z","reason":REASON}),
        json!({"action":"unset","record_id":hidden,"key":"score","as_of":"2026-08-05T00:00:00Z","reason":REASON}),
    ] {
        assert_eq!(
            harness
                .call(
                    &database,
                    TestCaller::member("acct:denied"),
                    "manage_facet_observations",
                    arguments,
                )
                .await
                .unwrap_err()
                .to_string(),
            format!("manage_facet_observations: record {hidden} does not exist")
        );
    }

    let overflow = "fac70000-0000-4000-8000-000000000005";
    call(
        harness,
        &database,
        "create_record",
        json!({"id":overflow,"type":"Document","kind":"facet_limits","name":"Facet response bound","reason":REASON}),
    )
    .await?;
    harness
        .install_facet_bounds_overflow_for_test(&database, overflow)
        .await?;
    for (tool, arguments, expected) in [
        (
            "resolve_facets",
            json!({"record_id":overflow}),
            "resolve_facets: value set exceeds 10000 rows",
        ),
        (
            "suggest_facet_values",
            json!({"record_id":overflow,"facet_key":"choice"}),
            "suggest_facet_values: suggestion set exceeds 10000 rows",
        ),
    ] {
        assert_eq!(
            harness
                .call(&database, TestCaller::Local, tool, arguments)
                .await
                .unwrap_err()
                .to_string(),
            expected
        );
    }

    let isolated = harness.fresh_logical_database().await?;
    let absent = harness
        .call(
            &isolated,
            TestCaller::Local,
            "resolve_facets",
            json!({"record_id":metric}),
        )
        .await
        .unwrap_err()
        .to_string();
    assert_eq!(absent, format!("record {metric} does not exist"));
    for (tool, arguments, expected) in [
        (
            "suggest_facet_values",
            json!({"record_id":metric,"facet_key":"confidence"}),
            format!("suggest_facet_values: record {metric} does not exist"),
        ),
        (
            "manage_facet_observations",
            json!({"action":"list","record_id":metric,"key":"score"}),
            format!("manage_facet_observations: record {metric} does not exist"),
        ),
    ] {
        assert_eq!(
            harness
                .call(&isolated, TestCaller::Local, tool, arguments)
                .await
                .unwrap_err()
                .to_string(),
            expected
        );
    }
    let isolated_shape = call(
        harness,
        &isolated,
        "resolve_facets",
        json!({"type":"WorkItem","kind":"task"}),
    )
    .await?;
    assert!(isolated_shape["shape"].get("score").is_none());
    harness.close(&isolated).await;
    harness.close(&database).await;
    Ok(())
}
