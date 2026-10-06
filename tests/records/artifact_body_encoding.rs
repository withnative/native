//! `body_encoding` on the whole-body HTML app writes (`create_record.body`,
//! `update_record.body_set`): the server decodes at the tool boundary, so an
//! encoded and a raw submission of the same body are equivalent.

use std::io::Write;

use base64::Engine as _;
use flate2::{write::GzEncoder, Compression};
use native_ce::artifact_html::BODY_LIMIT;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::{create_database, Db};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const HTML_DOCUMENT: &str = include_str!("../fixtures/native-html-v1-document.html");
const RAW_ID: &str = "a7720000-0000-4000-8000-000000000001";
const ENCODED_ID: &str = "a7720000-0000-4000-8000-000000000002";

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn gzip_b64(bytes: &[u8]) -> String {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes).unwrap();
    b64(&encoder.finish().unwrap())
}

fn digest(body: &str) -> String {
    hex::encode(Sha256::digest(body.as_bytes()))
}

/// The fixture padded with an HTML comment to exactly `bytes` UTF-8 bytes.
fn padded_document(bytes: usize) -> String {
    let filler = bytes - HTML_DOCUMENT.len() - "<!---->\n".len();
    let padded = HTML_DOCUMENT.replacen(
        "</main>",
        &format!("<!--{}-->\n</main>", "x".repeat(filler)),
        1,
    );
    assert_eq!(padded.len(), bytes);
    padded
}

async fn fixture() -> (Db, ToolRegistry) {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    (db, registry)
}

async fn try_call(
    registry: &ToolRegistry,
    db: &Db,
    tool: &str,
    arguments: Value,
) -> native_ce::Result<Value> {
    let result = registry
        .call(db.clone(), Caller::local(), tool, arguments)
        .await;
    db.drain_captures_for_tests().await;
    result
}

fn create_args(id: &str, body: &str, encoding: Option<&str>) -> Value {
    let mut args = json!({
        "id": id, "type": "Document", "kind": "artifact", "name": id, "body": body,
        "facets": { "runtime": "native.html.v1" },
        "reason": "Exercise body_encoding on an HTML app write."
    });
    if let Some(encoding) = encoding {
        args["body_encoding"] = json!(encoding);
    }
    args
}

async fn create(
    registry: &ToolRegistry,
    db: &Db,
    id: &str,
    body: &str,
    encoding: Option<&str>,
) -> Value {
    try_call(
        registry,
        db,
        "create_record",
        create_args(id, body, encoding),
    )
    .await
    .unwrap()
}

async fn record_count(db: &Db, id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn event_count(db: &Db, id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM content_events WHERE record_id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

async fn stored_body(db: &Db, id: &str) -> String {
    sqlx::query_scalar("SELECT body FROM records WHERE id = ?")
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn encoded_create_is_equivalent_to_raw_create() {
    let (db, registry) = fixture().await;
    let raw = create(&registry, &db, RAW_ID, HTML_DOCUMENT, None).await;
    for (n, (encoding, body)) in [
        ("base64", b64(HTML_DOCUMENT.as_bytes())),
        ("gzip+base64", gzip_b64(HTML_DOCUMENT.as_bytes())),
        ("utf8", HTML_DOCUMENT.to_owned()),
    ]
    .into_iter()
    .enumerate()
    {
        let id = format!("a7720000-0000-4000-8000-0000000001{n:02}");
        let encoded = create(&registry, &db, &id, &body, Some(encoding)).await;
        assert_eq!(
            encoded["html_body_write"], raw["html_body_write"],
            "{encoding}"
        );
        assert_eq!(encoded["body_digest"], raw["body_digest"], "{encoding}");
        assert_eq!(stored_body(&db, &id).await, HTML_DOCUMENT, "{encoding}");
    }
    assert_eq!(raw["body_digest"], json!(digest(HTML_DOCUMENT)));
    db.close().await;
}

#[tokio::test]
async fn encoded_and_raw_submissions_share_an_idempotency_key() {
    let (db, registry) = fixture().await;
    let mut first = create_args(ENCODED_ID, HTML_DOCUMENT, None);
    first["idempotency_key"] = json!("body-encoding-key");
    let created = try_call(&registry, &db, "create_record", first)
        .await
        .unwrap();
    let events_after_create = event_count(&db, ENCODED_ID).await;
    let mut raw_retry = create_args(ENCODED_ID, HTML_DOCUMENT, None);
    raw_retry["idempotency_key"] = json!("body-encoding-key");
    let raw_replay = try_call(&registry, &db, "create_record", raw_retry)
        .await
        .unwrap();
    assert_eq!(
        raw_replay["source_event_id"], created["source_event_id"],
        "{raw_replay}"
    );
    let mut retry = create_args(
        ENCODED_ID,
        &gzip_b64(HTML_DOCUMENT.as_bytes()),
        Some("gzip+base64"),
    );
    retry["idempotency_key"] = json!("body-encoding-key");
    let replay = try_call(&registry, &db, "create_record", retry)
        .await
        .unwrap();
    // A replay returns the original receipt: same record, same source event.
    assert_eq!(
        replay["source_event_id"], created["source_event_id"],
        "{replay}"
    );
    assert_eq!(replay["id"], created["id"]);
    assert_eq!(
        event_count(&db, ENCODED_ID).await,
        events_after_create,
        "the retries must not append"
    );
    db.close().await;
}

#[tokio::test]
async fn encoded_update_body_set_replaces_with_the_decoded_body() {
    let (db, registry) = fixture().await;
    let first = create(&registry, &db, RAW_ID, HTML_DOCUMENT, None).await;
    let next = HTML_DOCUMENT.replace("Decision brief", "Decision brief, revised");
    let updated = try_call(
        &registry,
        &db,
        "update_record",
        json!({
            "id": RAW_ID, "body_set": gzip_b64(next.as_bytes()), "body_encoding": "gzip+base64",
            "if_body_digest": first["body_digest"], "reason": "Replace the app source, gzip+base64."
        }),
    )
    .await
    .unwrap();
    assert_eq!(updated["body_digest"], json!(digest(&next)), "{updated}");
    assert_eq!(stored_body(&db, RAW_ID).await, next);
    // body_append / body_replace never take an encoding.
    for op in [
        json!({"body_append": "aGk="}),
        json!({"body_replace": [{"old": "a", "new": "b"}]}),
    ] {
        let mut args = json!({"id": RAW_ID, "body_encoding": "base64", "reason": "Not an encodable operation."});
        args.as_object_mut()
            .unwrap()
            .extend(op.as_object().unwrap().clone());
        let error = try_call(&registry, &db, "update_record", args)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("body_encoding_without_body"), "{error}");
    }
    db.close().await;
}

#[tokio::test]
async fn invalid_encodings_are_refused_and_write_nothing() {
    let (db, registry) = fixture().await;
    let bomb = gzip_b64(&vec![b' '; 64 * 1024 * 1024]);
    let mut not_utf8 = HTML_DOCUMENT.as_bytes().to_vec();
    not_utf8.push(0xff);
    let over = padded_document(BODY_LIMIT + 1);
    let cases = [
        (
            "hex",
            b64(HTML_DOCUMENT.as_bytes()),
            "body_encoding_unknown",
        ),
        (
            "base64",
            "!!! not base64 !!!".to_owned(),
            "body_encoding_invalid_base64",
        ),
        (
            "gzip+base64",
            b64(HTML_DOCUMENT.as_bytes()),
            "body_encoding_invalid_gzip",
        ),
        ("base64", b64(&not_utf8), "body_encoding_invalid_utf8"),
        (
            "gzip+base64",
            gzip_b64(&not_utf8),
            "body_encoding_invalid_utf8",
        ),
        ("gzip+base64", bomb, "body_encoding_too_large"),
        ("base64", b64(over.as_bytes()), "body_encoding_too_large"),
        (
            "gzip+base64",
            gzip_b64(over.as_bytes()),
            "body_encoding_too_large",
        ),
        (
            "base64",
            "A".repeat(BODY_LIMIT * 2),
            "body_encoding_too_large",
        ),
    ];
    for (n, (encoding, body, code)) in cases.into_iter().enumerate() {
        let id = format!("a7720000-0000-4000-8000-0000000002{n:02}");
        let error = try_call(
            &registry,
            &db,
            "create_record",
            create_args(&id, &body, Some(encoding)),
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(error.contains(code), "{encoding}: {error}");
        assert!(error.starts_with("create_record: "), "{error}");
        assert_eq!(
            record_count(&db, &id).await,
            0,
            "{encoding}: nothing may be written"
        );
    }
    db.close().await;
}

#[tokio::test]
async fn decoded_body_at_the_limit_is_accepted_and_one_byte_over_is_refused() {
    let (db, registry) = fixture().await;
    let at_limit = padded_document(BODY_LIMIT);
    for (encoding, body, id) in [
        ("base64", b64(at_limit.as_bytes()), RAW_ID),
        ("gzip+base64", gzip_b64(at_limit.as_bytes()), ENCODED_ID),
    ] {
        let created = create(&registry, &db, id, &body, Some(encoding)).await;
        assert_eq!(
            created["html_body_write"]["utf8_bytes"], BODY_LIMIT,
            "{encoding}"
        );
        assert_eq!(
            created["body_digest"],
            json!(digest(&at_limit)),
            "{encoding}"
        );
    }
    // The raw route still enforces its own limit on the decoded text, so a
    // limit-sized body that decodes cleanly cannot dodge validation.
    let over = padded_document(BODY_LIMIT + 1);
    let error = try_call(
        &registry,
        &db,
        "create_record",
        create_args("a7720000-0000-4000-8000-000000000003", &over, None),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(error.contains("html_source_too_large"), "{error}");
    db.close().await;
}

#[tokio::test]
async fn create_many_rejects_body_encoding_items() {
    let (db, registry) = fixture().await;
    let error = try_call(
        &registry,
        &db,
        "create_many",
        json!({
            "reason": "body_encoding is not offered by create_many",
            "records": [
                {"type": "Document", "kind": "note", "name": "plain", "body": "plain"},
                {"type": "Document", "kind": "note", "name": "encoded", "body": b64(b"hi"), "body_encoding": "base64"}
            ]
        }),
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("records[1].body_encoding is not supported"),
        "{error}"
    );
    let created: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE name IN ('plain', 'encoded')")
            .fetch_one(db.pool())
            .await
            .unwrap();
    assert_eq!(created, 0, "the refusal precedes every write");
    db.close().await;
}
