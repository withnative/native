//! Exercise the shipped executable, including discovery and a corrected retry.
#![cfg(feature = "mcp-executor-prototype")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use serde_json::{json, Value};

struct StdioClient {
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<String>,
    next_id: u64,
}

impl StdioClient {
    fn new(directory: &std::path::Path) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mcp-stdio"));
        command
            .env_clear()
            .env("NATIVE_CE_MCP_SURFACE", "executor")
            .current_dir(directory)
            .arg(directory.join("records.db"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Ok(profile) = std::env::var("LLVM_PROFILE_FILE") {
            command.env("LLVM_PROFILE_FILE", profile);
        }
        let mut child = command.spawn().unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, responses) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        Self {
            child,
            stdin,
            responses,
            next_id: 0,
        }
    }

    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request = json!({"jsonrpc":"2.0","id":self.next_id,"method":method,"params":params});
        writeln!(self.stdin, "{request}").unwrap();
        self.stdin.flush().unwrap();
        let line = self
            .responses
            .recv_timeout(Duration::from_secs(30))
            .unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], self.next_id, "{response}");
        assert!(response.get("error").is_none(), "{response}");
        response["result"].clone()
    }

    fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.rpc("tools/call", json!({"name":tool,"arguments":arguments}))
    }
}

impl Drop for StdioClient {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn text(result: &Value) -> &str {
    result["content"][0]["text"].as_str().unwrap()
}

fn assert_format_contract_error(result: &Value, supported: Value) {
    let repair = &result["structuredContent"]["repair"];
    assert_eq!(repair["code"], "operation_contract_repair", "{result}");
    assert_eq!(repair["error_class"], "validation_failure", "{result}");
    assert_eq!(repair["failing_pointer"], "/format", "{result}");
    assert_eq!(repair["expected_shape"]["supported_values"], supported);
    assert_eq!(repair["expected_shape"]["enum"], supported);
    assert!(repair["guidance"].is_null(), "{result}");
    assert!(!text(result).contains("envelope matched"), "{result}");
    assert!(!text(result).contains("authorization"), "{result}");
    assert!(!text(result).contains("concurrency"), "{result}");
}

#[test]
fn records_read_format_discovery_representation_and_one_step_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let mut client = StdioClient::new(directory.path());
    client.rpc(
        "initialize",
        json!({
            "protocolVersion":"2024-11-05", "capabilities":{},
            "clientInfo":{"name":"records-format-test","version":"1"}
        }),
    );
    let catalogue = client.rpc("tools/list", json!({}));
    let descriptor = |name: &str| {
        catalogue["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|tool| tool["name"] == name)
            .unwrap()
    };
    let schema = &descriptor("records_read")["inputSchema"];
    assert_eq!(
        schema["properties"]["format"]["enum"],
        json!(["text", "json"])
    );
    assert!(schema["properties"]["arguments"]["description"]
        .as_str()
        .unwrap()
        .contains("format in the executor envelope"));
    let validator = jsonschema::validator_for(schema).unwrap();
    let bootstrap = client.call("bootstrap", json!({"format":"json"}));
    assert_eq!(bootstrap["isError"], false, "{bootstrap}");
    let run_key = bootstrap["structuredContent"]["run"]["run_key"]
        .as_str()
        .unwrap();
    let base =
        json!({"operation":"get_record","arguments":{"ids":["native:root"]},"run_key":run_key});
    let mut rendered = None;
    let mut exact_json = None;
    for format in [None, Some("json"), Some("text")] {
        let mut request = base.clone();
        if let Some(format) = format {
            request["format"] = json!(format);
        }
        assert!(validator.is_valid(&request));
        let result = client.call("records_read", request);
        assert_eq!(result["isError"], false, "{result}");
        if format == Some("json") {
            let body: Value = serde_json::from_str(text(&result)).unwrap();
            assert_eq!(body, result["structuredContent"]);
            assert_eq!(body["records"][0]["id"], "native:root");
            assert!(body["records"][0]["kind_governance"].is_object());
            assert!(body["records"][0]["contribution"]["interpretation_limits"].is_array());
            assert_eq!(body["resolve"], true);
            assert_eq!(body["children_limit"], 200);
            assert_eq!(text(&result), result["structuredContent"].to_string());
            exact_json = Some(text(&result).to_owned());
        } else {
            assert!(!text(&result).trim_start().starts_with('{'));
            assert!(text(&result).contains("native:root"));
            assert!(!text(&result).contains("Read scope:"));
            let omitted = text(&result)
                .lines()
                .find(|line| line.contains("Additional record fields omitted from text:"))
                .unwrap();
            assert!(omitted.contains("kind_governance"));
            assert!(omitted.contains("contribution"));
            assert!(!text(&result).contains("interpretation_limits"));
            assert!(result.get("structuredContent").is_none());
            if let Some(default) = &rendered {
                assert_eq!(text(&result), default);
            } else {
                rendered = Some(text(&result).to_string());
            }
        }
    }

    let mut nested = base.clone();
    nested["arguments"]["format"] = json!("json");
    let error = client.call("records_read", nested.clone());
    assert_eq!(error["isError"], true, "{error}");
    assert!(text(&error).contains("arguments.format"), "{error}");
    assert!(text(&error).contains("envelope"), "{error}");
    let repair = &error["structuredContent"]["repair"];
    assert_eq!(repair["retry_ready"], true, "{error}");
    let example = &repair["expected_shape"]["request_example"];
    assert!(validator.is_valid(example), "{example}");
    assert_eq!(example["arguments"]["ids"], json!(["<record-reference>"]));
    let mut corrected = nested.clone();
    for correction in repair["corrections"].as_array().unwrap() {
        let pointer = correction["pointer"].as_str().unwrap();
        let (parent, field) = pointer.rsplit_once('/').unwrap();
        let object = corrected
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap();
        if correction["remove"] == true {
            object.remove(field);
        } else {
            let value = if let Some(from) = correction["from"].as_str() {
                nested.pointer(from).unwrap().clone()
            } else {
                correction["value"].clone()
            };
            object.insert(field.into(), value);
        }
    }
    assert_eq!(corrected["run_key"], run_key);
    assert_eq!(corrected["format"], "json");
    assert!(corrected["arguments"].get("format").is_none());
    assert!(validator.is_valid(&corrected));
    let retry = client.call("records_read", corrected);
    assert_eq!(retry["isError"], false, "{retry}");
    assert_eq!(
        serde_json::from_str::<Value>(text(&retry)).unwrap(),
        retry["structuredContent"]
    );
    assert_eq!(
        retry["structuredContent"]["records"][0]["id"],
        "native:root"
    );
    // Text reads and the recovery path must not alter the exact JSON read.
    assert_eq!(text(&retry), exact_json.as_deref().unwrap());

    for invalid in [json!("yaml"), json!(17), Value::Null] {
        let mut request = base.clone();
        request["format"] = invalid;
        assert!(!validator.is_valid(&request));
        let error = client.call("records_read", request.clone());
        assert_eq!(error["isError"], true, "{error}");
        assert!(text(&error).contains("get_record"), "{error}");
        assert!(
            text(&error).contains("must be \"text\" or \"json\""),
            "{error}"
        );
        assert_format_contract_error(&error, json!(["text", "json"]));
        request["format"] = error["structuredContent"]["repair"]["expected_shape"]
            ["supported_values"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| **value == "json")
            .unwrap()
            .clone();
        let retry = client.call("records_read", request);
        assert_eq!(retry["isError"], false, "{retry}");
        assert_eq!(
            serde_json::from_str::<Value>(text(&retry)).unwrap(),
            retry["structuredContent"]
        );
        assert_eq!(
            retry["structuredContent"]["records"][0]["id"],
            "native:root"
        );
    }

    let mut nested_invalid = base.clone();
    nested_invalid["arguments"]["format"] = json!("yaml");
    let error = client.call("records_read", nested_invalid);
    assert_eq!(error["isError"], true, "{error}");
    assert_eq!(
        error["structuredContent"]["repair"]["retry_ready"], false,
        "{error}"
    );

    // JSON-only operations stay JSON-only in discovery and runtime, including
    // the values suggested when the caller supplies an unknown format.
    let system = &descriptor("system_read")["inputSchema"];
    assert_eq!(system["properties"]["format"]["enum"], json!(["json"]));
    let validator = jsonschema::validator_for(system).unwrap();
    for format in [None, Some("json"), Some("text"), Some("yaml")] {
        let mut request = json!({"operation":"ping","arguments":{},"run_key":run_key});
        if let Some(format) = format {
            request["format"] = json!(format);
        }
        let supported = format.is_none() || format == Some("json");
        assert_eq!(validator.is_valid(&request), supported);
        let result = client.call("system_read", request.clone());
        assert_eq!(result["isError"], !supported, "{result}");
        if supported {
            assert_eq!(
                serde_json::from_str::<Value>(text(&result)).unwrap(),
                result["structuredContent"]
            );
        } else {
            assert!(text(&result).contains("ping"), "{result}");
            assert!(text(&result).contains("\"json\""), "{result}");
            assert!(!text(&result).contains("must be \"text\" or"), "{result}");
            assert_format_contract_error(&result, json!(["json"]));
            request["format"] = result["structuredContent"]["repair"]["expected_shape"]
                ["supported_values"][0]
                .clone();
            let retry = client.call("system_read", request);
            assert_eq!(retry["isError"], false, "{retry}");
            assert_eq!(
                serde_json::from_str::<Value>(text(&retry)).unwrap(),
                retry["structuredContent"]
            );
        }
    }
}
