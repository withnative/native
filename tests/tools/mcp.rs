//! Public-package evidence for the portable MCP registry and stdio seam.
//!
//! The held hosting package retains the end-to-end HTTP transport copies of
//! these contracts. These focused tests keep the public authorization evidence
//! rooted exclusively in public `native_ce::mcp` APIs.

use std::sync::Arc;

use native_ce::mcp::{
    register_builtin_tools, register_surface_tools, Caller, StdioServer, ToolRegistry, GUIDE_SPECS,
    PROTOCOL_VERSION,
};
use native_ce::Db;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};

fn public_registry() -> Arc<ToolRegistry> {
    let mut registry = ToolRegistry::new();
    register_builtin_tools(&mut registry).unwrap();
    register_surface_tools(&mut registry).unwrap();
    Arc::new(registry)
}

async fn drive_stdio(registry: Arc<ToolRegistry>, db: Db, messages: &[String]) -> Vec<Value> {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (server_read, server_write) = tokio::io::split(server_io);
    let server = StdioServer::new(registry, db, Caller::local());
    let serve = async move {
        server
            .serve(BufReader::new(server_read), server_write)
            .await
            .unwrap();
    };
    let (mut client_read, mut client_write) = tokio::io::split(client_io);
    let input = messages
        .iter()
        .map(|message| format!("{message}\n"))
        .collect::<String>();
    let talk = async move {
        client_write.write_all(input.as_bytes()).await.unwrap();
        client_write.shutdown().await.unwrap();
        let mut output = String::new();
        client_read.read_to_string(&mut output).await.unwrap();
        output
    };
    let (_, output) = tokio::join!(serve, talk);
    output
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn rpc(id: i64, method: &str, params: Value) -> String {
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
}

fn modern_message(id: i64, method: &str, mut params: Value) -> String {
    params.as_object_mut().unwrap().insert(
        "_meta".to_string(),
        json!({
            "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
                "name": "native-ce-test",
                "version": "1.0.0",
            },
            "io.modelcontextprotocol/clientCapabilities": {},
        }),
    );
    rpc(id, method, params)
}

#[tokio::test]
async fn registry_returns_structured_data_not_text() {
    let registry = public_registry();
    let db = native_ce::create_database(":memory:").await.unwrap();
    let value = registry
        .call(db.clone(), Caller::local(), "engine_info", json!({}))
        .await
        .unwrap();

    assert!(value.is_object());
    assert_eq!(value["engine"], "native-ce");
    assert_eq!(
        value["schema_version"],
        native_ce::CURRENT_ENGINE_SCHEMA_VERSION
    );
    assert!(value["storage_profile"].is_object());
    assert!(value["query_sql"].is_object());
    db.close().await;
}

#[tokio::test]
async fn attribution_reads_render_by_default_and_preserve_explicit_json_over_stdio() {
    const BEARER: &str = "700cac00-0000-4000-8000-000000000018";

    let registry = public_registry();
    let db = native_ce::create_database(":memory:").await.unwrap();
    registry
        .call(
            db.clone(),
            Caller::local(),
            "create_record",
            json!({
                "id":BEARER,
                "type":"Document",
                "kind":"note",
                "name":"Direct attribution bearer",
                "body":"No claims have been authored yet.",
                "reason":"create direct attribution transport fixture"
            }),
        )
        .await
        .unwrap();
    let responses = drive_stdio(
        registry,
        db.clone(),
        &[
            rpc(
                1,
                "tools/call",
                json!({
                    "name":"read_attributions",
                    "arguments":{"bearer_id":BEARER}
                }),
            ),
            rpc(
                2,
                "tools/call",
                json!({
                    "name":"read_attributions",
                    "arguments":{"bearer_id":BEARER,"format":"json"}
                }),
            ),
        ],
    )
    .await;
    db.close().await;

    let text = &responses[0]["result"];
    assert_eq!(text["isError"], false, "{text}");
    let rendered = text["content"][0]["text"].as_str().unwrap();
    for expected in [
        BEARER,
        "0 caller-visible claim(s)",
        "live current attribution state",
        "Interpretation projection:",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected}: {rendered}"
        );
    }
    assert!(
        serde_json::from_str::<Value>(rendered).is_err(),
        "{rendered}"
    );
    assert!(text.get("structuredContent").is_none(), "{text}");

    let exact = &responses[1]["result"];
    assert_eq!(exact["isError"], false, "{exact}");
    assert_eq!(
        exact["content"][0]["text"].as_str().unwrap(),
        exact["structuredContent"].to_string()
    );
}

#[tokio::test]
async fn guidance_reads_render_without_claiming_updates_and_preserve_explicit_json_over_stdio() {
    let registry = public_registry();
    let db = native_ce::create_database(":memory:").await.unwrap();
    let responses = drive_stdio(
        registry,
        db.clone(),
        &[
            rpc(
                1,
                "tools/call",
                json!({
                    "name":"manage_instructions",
                    "arguments":{"action":"list"}
                }),
            ),
            rpc(
                2,
                "tools/call",
                json!({
                    "name":"manage_instructions",
                    "arguments":{"action":"list","format":"json"}
                }),
            ),
            rpc(
                3,
                "tools/call",
                json!({
                    "name":"manage_onboarding",
                    "arguments":{"action":"list_programmes"}
                }),
            ),
            rpc(
                4,
                "tools/call",
                json!({
                    "name":"manage_onboarding",
                    "arguments":{"action":"list_programmes","format":"json"}
                }),
            ),
        ],
    )
    .await;
    db.close().await;

    for (index, heading) in [
        (0, "Instruction binding list (read-only):"),
        (2, "Onboarding programme list (read-only):"),
    ] {
        let result = &responses[index]["result"];
        assert_eq!(result["isError"], false, "{result}");
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(heading), "{text}");
        assert!(!text.contains("updated"), "{text}");
        assert!(serde_json::from_str::<Value>(text).is_err(), "{text}");
        assert!(result.get("structuredContent").is_none(), "{result}");
    }
    for index in [1, 3] {
        let result = &responses[index]["result"];
        assert_eq!(result["isError"], false, "{result}");
        assert_eq!(
            serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap(),
            result["structuredContent"]
        );
    }
}

#[tokio::test]
async fn engine_info_exposes_the_active_profile_without_enabling_enforcement() {
    let registry = public_registry();
    let db = native_ce::create_database(":memory:").await.unwrap();
    let value = registry
        .call(db.clone(), Caller::local(), "engine_info", json!({}))
        .await
        .unwrap();
    let profile = &value["storage_profile"];

    assert_eq!(profile["format"], "native.storage-runtime.v1");
    assert_eq!(profile["profile_format"], "native.storage-profile.v1");
    assert_eq!(profile["id"], "sqlite-local");
    assert_eq!(profile["revision"], 2);
    assert_eq!(profile["backend"]["engine_family"], "sqlite");
    assert_eq!(profile["backend"]["implementation"], "bundled-sqlite");
    assert_eq!(profile["mode"], "embedded");
    assert_eq!(profile["enforcement"], "off");
    assert_eq!(profile["policy_revision"], 0);
    assert_eq!(profile["target_profiles"], json!([]));
    assert_eq!(
        profile["capabilities"]["native.search.lexical.v1"]["support"],
        "full"
    );
    assert_eq!(
        profile["capabilities"]["native.search.semantic.v1"]["support"],
        "planned"
    );
    assert_eq!(
        profile["capabilities"]["native.canonical-interchange.v1"]["support"],
        "full"
    );
    assert_eq!(
        profile["capabilities"]["native.operation.record-read.v1"]["support"],
        "full"
    );
    assert!(value.get("portability_audit").is_none());
    db.close().await;
}

#[tokio::test]
async fn read_guide_is_verbatim_and_text_only_in_both_stdio_eras() {
    let guide = GUIDE_SPECS
        .iter()
        .find(|guide| guide.topic == "capabilities")
        .unwrap();
    let args = json!({ "topic": guide.topic, "run_key": "scout-chair-a748b2" });
    let db = native_ce::create_database(":memory:").await.unwrap();
    let responses = drive_stdio(
        public_registry(),
        db.clone(),
        &[
            rpc(
                1,
                "tools/call",
                json!({ "name": "read_guide", "arguments": args.clone() }),
            ),
            modern_message(
                2,
                "tools/call",
                json!({ "name": "read_guide", "arguments": args }),
            ),
        ],
    )
    .await;
    db.close().await;

    for response in [&responses[0]["result"], &responses[1]["result"]] {
        assert_eq!(response["isError"], false);
        assert!(response.get("structuredContent").is_none(), "{response}");
        let text = response["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with(guide.markdown), "{text}");
        assert!(text.contains("Run context:"), "{text}");
    }
}
