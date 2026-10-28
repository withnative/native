use super::*;
use crate::native_cli::setup::tests::{McpHook, WS_A};
use crate::native_cli::status::tests::{start_node_with, Running};
use std::future::Future;
use std::path::Path;
use std::sync::Arc;

// ---- helpers ---------------------------------------------------------------------------

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

fn invocation(command: Command, list: &[&str]) -> Invocation {
    match parse(command, &args(list), None) {
        Parsed::Run(invocation) => *invocation,
        other => panic!("expected a runnable command for {list:?}, got {other:?}"),
    }
}

fn usage_of(command: Command, list: &[&str]) -> String {
    match parse(command, &args(list), None) {
        Parsed::Usage(message) => message,
        other => panic!("expected a usage error for {list:?}, got {other:?}"),
    }
}

/// Run a future on its own thread with a large stack, as `native` runs: the
/// engine's dispatch futures are too deep for a test thread's default stack in
/// a debug build.
fn big_stack<T: Send + 'static>(future: impl Future<Output = T> + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(future)
        })
        .unwrap()
        .join()
        .unwrap()
}

/// One command against a local database.
async fn local(command: Command, db: &Path, list: &[&str]) -> Report {
    let mut all = list.to_vec();
    let flag = format!("--local={}", db.display());
    all.push(&flag);
    execute(&invocation(command, &all)).await
}

fn json_of(report: &Report) -> Value {
    serde_json::from_str(report.stdout.trim())
        .unwrap_or_else(|_| panic!("stdout is not one JSON value: {report:#?}"))
}

/// A run key from the server's own bootstrap, as the client fetches one.
async fn issue_run_key(db: &Path) -> String {
    let inv = invocation(Command::Search, &["x"]);
    let session = Session::open(
        &Backend::Local {
            db: Some(db.to_path_buf()),
        },
        inv.timeout,
    )
    .await
    .unwrap_or_else(|why| panic!("{why}"));
    let mut client = Client {
        session,
        invocation: &inv,
        tools: None,
        run_key: None,
        notes: Vec::new(),
        next_id: 1,
        mutations: BTreeMap::new(),
    };
    let key = match client.bootstrap().await {
        Ok(key) => key,
        Err(Failure(report)) => panic!("{report:?}"),
    };
    assert!(client.notes[0].contains(&key), "{:?}", client.notes);
    client.session.close().await;
    key
}

const NOTE: &str = r#"{"type":"Document","kind":"note","name":"Launch plan","body":"ship the launch on friday","reason":"capture the plan"}"#;

// ---- the command line -----------------------------------------------------------------------

#[test]
fn call_takes_an_executor_an_operation_and_json_arguments() {
    let inv = invocation(
        Command::Call,
        &[
            "records_read",
            "search",
            r#"{"query":"x"}"#,
            "--text",
            "--timeout",
            "7",
        ],
    );
    assert_eq!(
        inv.action,
        Action::Call {
            executor: "records_read".into(),
            operation: "search".into(),
            arguments: json!({"query":"x"}),
        }
    );
    assert!(inv.text);
    assert_eq!(inv.timeout, Duration::from_secs(7));
    assert_eq!(inv.backend, Backend::Node { config_dir: None });
    // No arguments is an empty object.
    let inv = invocation(Command::Call, &["system_read", "ping"]);
    assert!(matches!(inv.action, Action::Call { arguments, .. } if arguments == json!({})));
}

#[test]
fn the_database_follows_local_only_when_it_looks_like_a_path() {
    let path = |list: &[&str]| invocation(Command::Call, list).backend;
    assert_eq!(
        path(&["--local", "./n.db", "records_read", "search"]),
        Backend::Local {
            db: Some("./n.db".into())
        }
    );
    assert_eq!(
        path(&["records_read", "search", "--local=/tmp/x"]),
        Backend::Local {
            db: Some("/tmp/x".into())
        }
    );
    // A bare word after --local is the executor, not the database.
    assert_eq!(
        path(&["--local", "records_read", "search"]),
        Backend::Local { db: None }
    );
    assert_eq!(
        invocation(Command::Search, &["words", "--local"]).backend,
        Backend::Local { db: None }
    );
}

#[test]
fn malformed_command_lines_are_usage_errors() {
    assert!(usage_of(Command::Call, &["records_read"]).contains("<executor> <operation>"));
    assert!(usage_of(Command::Call, &["a", "b", "{not json"]).contains("not valid JSON"));
    assert!(usage_of(Command::Call, &["a", "b", "[1]"]).contains("JSON object"));
    assert!(usage_of(Command::Call, &["a", "b", "{}", "--args-file", "x"]).contains("not both"));
    assert!(usage_of(Command::Call, &["--describe", "a"]).contains("--describe needs"));
    assert!(usage_of(Command::Call, &["--list", "--describe", "a", "b"]).contains("cannot be used"));
    assert!(usage_of(Command::Call, &["a", "b", "--nope"]).contains("unknown option"));
    assert!(usage_of(Command::Call, &["a", "b", "--timeout", "0"]).contains("positive"));
    assert!(usage_of(Command::Call, &["a", "b", "--run-key"]).contains("needs a value"));
    assert!(
        usage_of(Command::Call, &["a", "b", "--local=x", "--config-dir", "y"])
            .contains("cannot be used together")
    );
    assert!(usage_of(Command::Search, &[]).contains("words"));
    assert!(usage_of(Command::Search, &["x", "--limit", "no"]).contains("--limit"));
    assert!(usage_of(Command::Get, &[]).contains("reference"));
    assert!(usage_of(Command::Sql, &["select 1", "select 2"]).contains("quote"));
    // --param belongs to sql, --limit to search.
    assert!(usage_of(Command::Get, &["x", "--param", "1"]).contains("unknown option"));
    assert_eq!(parse(Command::Sql, &args(&["--help"]), None), Parsed::Help);
}

#[test]
fn the_run_key_comes_from_the_flag_or_the_environment() {
    let from = |env: Option<&str>, list: &[&str]| match parse(
        Command::Search,
        &args(list),
        env.map(str::to_owned),
    ) {
        Parsed::Run(inv) => inv.run_key,
        other => panic!("{other:?}"),
    };
    assert_eq!(from(None, &["x"]), None);
    assert_eq!(from(Some("env-key"), &["x"]).as_deref(), Some("env-key"));
    assert_eq!(
        from(Some("env-key"), &["x", "--run-key", "flag-key"]).as_deref(),
        Some("flag-key")
    );
    assert_eq!(from(Some("  "), &["x"]), None);
}

#[test]
fn sql_parameters_keep_json_types_and_otherwise_are_text() {
    let inv = invocation(
        Command::Sql,
        &[
            "select ?1",
            "--param",
            "42",
            "--param",
            "true",
            "--param",
            "plain words",
            "--param",
            "\"42\"",
        ],
    );
    let Action::Sql { parameters, .. } = inv.action else {
        panic!()
    };
    assert_eq!(
        parameters,
        vec![json!(42), json!(true), json!("plain words"), json!("42")]
    );
}

#[test]
fn arguments_can_come_from_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("args.json");
    std::fs::write(&file, r#"{"query":"from a file"}"#).unwrap();
    let inv = invocation(
        Command::Call,
        &[
            "records_read",
            "search",
            "--args-file",
            file.to_str().unwrap(),
        ],
    );
    assert!(
        matches!(inv.action, Action::Call { arguments, .. } if arguments == json!({"query":"from a file"}))
    );
    let missing = dir.path().join("nope.json");
    assert!(usage_of(
        Command::Call,
        &["a", "b", "--args-file", missing.to_str().unwrap()]
    )
    .contains("cannot read"));
}

#[test]
fn every_command_has_help_with_examples_and_the_exit_codes() {
    for command in [Command::Call, Command::Search, Command::Get, Command::Sql] {
        let help = usage(command);
        assert!(help.contains("examples:"), "{help}");
        assert!(
            help.contains("exit codes:") && help.contains("3  held"),
            "{help}"
        );
        assert!(help.contains("--local"), "{help}");
    }
    let call = usage(Command::Call);
    assert!(
        call.contains("--list") && call.contains("--describe"),
        "{call}"
    );
    assert!(call.contains("create_record"), "{call}");
}

// ---- classification ---------------------------------------------------------------------------

fn tool_result(structured: Value, is_error: bool) -> Value {
    json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":structured.to_string()}],"structuredContent":structured,"isError":is_error}})
}

fn rpc_error(data: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"the server said no","data":data}})
}

/// Every shape of reply the node, the engine and hosted produce, and what it
/// must be taken to mean. The success rows are the only ones that may exit 0.
fn classification_rows() -> Vec<(String, Value, Kind)> {
    use Kind::*;
    let mut rows: Vec<(String, Value, Kind)> = Vec::new();
    let mut add = |name: String, reply: Value, kind: Kind| rows.push((name, reply, kind));

    // Each outcome value, as structured content with isError true and false,
    // and as the data of a JSON-RPC error.
    let outcomes: &[(&str, Kind, Kind, Kind)] = &[
        // outcome, isError false, isError true, in a JSON-RPC error
        ("accepted_pending", Held, Held, Held),
        ("refused", Refused, Refused, Refused),
        ("not_sent", Refused, Refused, Refused),
        ("failed", Refused, Refused, Refused),
        ("rejected", Refused, Refused, Refused),
        ("conflict", Refused, Refused, Refused),
        ("unknown", Uncertain, Uncertain, Uncertain),
        ("uncertain", Uncertain, Uncertain, Uncertain),
        ("partial", Uncertain, Uncertain, Uncertain),
        ("unconfirmed", Uncertain, Uncertain, Uncertain),
        ("indeterminate", Uncertain, Uncertain, Uncertain),
        ("committed", Ok, Refused, Refused),
        ("replayed", Ok, Refused, Refused),
        ("planned", Ok, Refused, Refused),
        ("already_applied", Ok, Refused, Refused),
        ("inspected", Ok, Refused, Refused),
        ("created", Ok, Refused, Refused),
        ("existing", Ok, Refused, Refused),
        ("replaced", Ok, Refused, Refused),
        ("proposed", Ok, Refused, Refused),
        ("accepted", Ok, Refused, Refused),
        ("superseded", Ok, Refused, Refused),
        ("current", Ok, Refused, Refused),
        ("migrated", Ok, Refused, Refused),
        // Not outcomes the engine emits: no longer assumed to be success.
        ("applied", Uncertain, Uncertain, Uncertain),
        ("success", Uncertain, Uncertain, Uncertain),
        ("a_value_nobody_defined", Uncertain, Uncertain, Uncertain),
    ];
    for (outcome, plain, flagged, in_error) in outcomes {
        let body = json!({"outcome": outcome});
        add(
            format!("outcome {outcome}, isError false"),
            tool_result(body.clone(), false),
            *plain,
        );
        add(
            format!("outcome {outcome}, isError true"),
            tool_result(body.clone(), true),
            *flagged,
        );
        add(
            format!("outcome {outcome}, JSON-RPC error"),
            rpc_error(body),
            *in_error,
        );
    }
    // No outcome at all.
    add(
        "plain result".into(),
        tool_result(json!({"id":"r"}), false),
        Ok,
    );
    add(
        "flagged result".into(),
        tool_result(json!({"error":"x"}), true),
        Refused,
    );
    add(
        "result without structured content".into(),
        json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hello"}]}}),
        Ok,
    );
    add(
        "result with isError absent".into(),
        json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":{"id":"r"}}}),
        Ok,
    );
    add(
        "JSON-RPC error without data".into(),
        json!({"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boom"}}),
        Refused,
    );

    // `applied`: true, false, partial, unknown, null; with isError both ways,
    // and inside a JSON-RPC error.
    for (applied, plain, flagged, in_error) in [
        (json!(true), Ok, Ok, Uncertain),
        (json!(false), Refused, Refused, Refused),
        (json!("partial"), Uncertain, Uncertain, Uncertain),
        (json!("unknown"), Uncertain, Uncertain, Uncertain),
        (json!(null), Ok, Refused, Refused),
    ] {
        let body = json!({"applied": applied});
        add(
            format!("applied {applied}, isError false"),
            tool_result(body.clone(), false),
            plain,
        );
        add(
            format!("applied {applied}, isError true"),
            tool_result(body.clone(), true),
            flagged,
        );
        add(
            format!("applied {applied}, JSON-RPC error"),
            rpc_error(body),
            in_error,
        );
    }
    add(
        "partial: true".into(),
        tool_result(json!({"partial":true}), false),
        Uncertain,
    );
    add(
        "partial: true, flagged".into(),
        tool_result(json!({"partial":true}), true),
        Uncertain,
    );
    add(
        "partial: false".into(),
        tool_result(json!({"partial":false}), false),
        Ok,
    );
    // Applied and refused at once: not known.
    add(
        "applied true with outcome refused".into(),
        tool_result(json!({"applied":true,"outcome":"refused"}), true),
        Uncertain,
    );
    // Held beats a flag; uncertain beats a held-looking outcome only through the node's note.
    add(
        "accepted_pending with applied false".into(),
        tool_result(json!({"outcome":"accepted_pending","applied":false}), false),
        Held,
    );

    // The node's annotation, in both places, decides whatever the reply says.
    let journal =
        json!({"outcome":"uncertain","idempotency_key":"k-1","key_origin":"node","attempts":2});
    for (is_error, body) in [
        (false, json!({"id":"r","node_journal":journal})),
        (
            true,
            json!({"error":"later refusal","applied":false,"node_journal":journal}),
        ),
        (
            true,
            json!({"error":"refused","outcome":"refused","node_journal":journal}),
        ),
    ] {
        add(
            format!("node_journal uncertain in structuredContent {body}"),
            tool_result(body, is_error),
            Uncertain,
        );
    }
    add(
        "node_journal uncertain in error data".into(),
        rpc_error(json!({"outcome":"not_sent","node_journal":journal})),
        Uncertain,
    );
    add(
        "node_journal uncertain beside hosted's own data".into(),
        rpc_error(json!({"upstream_data":{"outcome":"refused"},"node_journal":journal})),
        Uncertain,
    );
    add(
        "node_journal elsewhere is ignored".into(),
        tool_result(json!({"id":"r","detail":{"node_journal":journal}}), false),
        Ok,
    );

    // Hosted's gateway framing.
    add(
        "gateway 503".into(),
        rpc_error(json!({"http_status":503})),
        Uncertain,
    );
    add(
        "gateway 404".into(),
        rpc_error(json!({"http_status":404})),
        Refused,
    );
    add(
        "gateway body says unknown".into(),
        rpc_error(json!({"http_status":502,"upstream_body":{"outcome":"unknown"}})),
        Uncertain,
    );
    add(
        "gateway body nested error says refused".into(),
        rpc_error(json!({"http_status":400,"upstream_body":{"error":{"outcome":"refused"}}})),
        Refused,
    );
    add(
        "status conflict".into(),
        tool_result(json!({"status":"conflict"}), false),
        Refused,
    );
    add(
        "status stale".into(),
        tool_result(json!({"status":"stale"}), false),
        Uncertain,
    );
    add(
        "status rejected with an act".into(),
        tool_result(json!({"status":"rejected","act":7}), false),
        Ok,
    );
    add(
        "status rejected without one".into(),
        tool_result(json!({"status":"rejected"}), false),
        Uncertain,
    );

    // No usable reply.
    add("empty object".into(), json!({}), Uncertain);
    add(
        "envelope only".into(),
        json!({"jsonrpc":"2.0","id":1}),
        Uncertain,
    );
    add(
        "null result".into(),
        json!({"jsonrpc":"2.0","id":1,"result":null}),
        Uncertain,
    );
    add(
        "string result".into(),
        json!({"jsonrpc":"2.0","id":1,"result":"fine"}),
        Uncertain,
    );
    add("not an object".into(), json!("ok"), Uncertain);
    rows
}

#[test]
fn every_reply_shape_is_classified_by_its_markers_whatever_is_error_says() {
    let rows = classification_rows();
    assert!(rows.len() > 90, "{}", rows.len());
    let mut wrong = Vec::new();
    for (name, reply, expected) in &rows {
        let got = classify(reply).kind;
        if got != *expected {
            wrong.push(format!(
                "{name}: expected {expected:?}, got {got:?} ({reply})"
            ));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    // Nothing but a success row may ever exit 0.
    for (name, reply, expected) in &rows {
        let report = report_of(
            reply,
            &invocation(Command::Call, &["a", "b"]),
            "a",
            "b",
            None,
        );
        assert_eq!(
            report.exit == 0,
            *expected == Kind::Ok,
            "{name}: {report:?}"
        );
        assert!(
            report.exit != 0 || report.stdout.contains('{') || report.stdout.contains("hello"),
            "{name}"
        );
    }
}

#[test]
fn the_account_config_refusal_that_reported_success_is_now_exit_4() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");
        // The real executor answers this with a result that is not flagged as an
        // error, `outcome: "refused"` and no config to replace.
        let report = local(
            Command::Call,
            &db,
            &[
                "records_write",
                "manage_account_config.replace",
                r#"{"kind":"focus_preferences","reason":"test","expected_record_id":"11111111-1111-4111-8111-111111111111"}"#,
            ],
        )
        .await;
        assert_eq!(report.exit, 4, "{report:#?}");
        assert!(report.stdout.is_empty(), "{report:#?}");
        assert!(
            report
                .stderr
                .contains("native: refused: the server reported the outcome 'refused'"),
            "{}",
            report.stderr
        );
    });
}

#[test]
fn exit_codes_are_the_documented_five() {
    assert_eq!(
        [Kind::Ok, Kind::Held, Kind::Refused, Kind::Uncertain].map(Kind::exit),
        [0, 3, 4, 5]
    );
    assert_eq!(EXIT_UNREACHABLE, 2);
}

#[test]
fn explanations_name_the_reason_the_code_and_the_next_step_and_nothing_else() {
    let invocation_for = invocation(Command::Call, &["a", "b"]);
    let validation = tool_result(
        json!({"error":"executor prototype validation_failure: \"reason\" is a required property","repair":{"code":"operation_contract_repair","error_class":"validation_failure","reason_code":"required_field_missing","failing_pointer":"/arguments/reason","expected_shape":{"keyword":"required"}}}),
        true,
    );
    let report = report_of(
        &validation,
        &invocation_for,
        "records_write",
        "create_record",
        None,
    );
    assert_eq!(report.exit, 4);
    assert!(report.stdout.is_empty());
    for expected in [
        "native: refused: validation_failure: \"reason\" is a required property",
        "  code: operation_contract_repair/validation_failure/required_field_missing",
        "  at: /arguments/reason",
        "  next: native call --describe records_write create_record",
    ] {
        assert!(report.stderr.contains(expected), "{}", report.stderr);
    }
    let held = tool_result(
        json!({"outcome":"accepted_pending","idempotency_key":"key-1","reason":"hosted_unreachable","record_id":"rec-1","queue_position":1}),
        false,
    );
    let report = report_of(
        &held,
        &invocation_for,
        "records_write",
        "create_record",
        None,
    );
    assert_eq!(report.exit, 3);
    assert!(report.stdout.contains("accepted_pending"), "{report:?}");
    assert!(
        report.stderr.contains("held (accepted_pending)"),
        "{}",
        report.stderr
    );
    assert!(
        report.stderr.contains("idempotency_key: key-1")
            && report.stderr.contains("record_id: rec-1")
    );
    let uncertain = json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"Write outcome uncertain. Retry the same call with idempotency_key=k","data":{"outcome":"uncertain","idempotency_key":"k","retry":"Send this exact call again."}}});
    let report = report_of(
        &uncertain,
        &invocation_for,
        "records_write",
        "create_record",
        None,
    );
    assert_eq!(report.exit, 5);
    assert!(
        report.stderr.contains("uncertain: Write outcome uncertain"),
        "{}",
        report.stderr
    );
    assert!(
        report.stderr.contains("code: uncertain") && report.stderr.contains("idempotency_key: k")
    );
}

// ---- local mode ----------------------------------------------------------------------------------

#[test]
fn local_search_get_sql_and_call_work_in_process() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");

        // call create_record: a write through the same dispatch as `native mcp --local`.
        let created = local(
            Command::Call,
            &db,
            &["records_write", "create_record", NOTE],
        )
        .await;
        assert_eq!(created.exit, 0, "{created:#?}");
        let created = json_of(&created);
        let id = created["id"].as_str().unwrap().to_owned();
        let short = created["display_reference"].as_str().unwrap().to_owned();
        assert_eq!(created["name"], "Launch plan");

        // search finds it.
        let found = local(Command::Search, &db, &["launch", "--limit", "5"]).await;
        assert_eq!(found.exit, 0, "{found:#?}");
        let found = json_of(&found);
        assert_eq!(found["limit"], 5);
        assert_eq!(found["hits"][0]["id"], id.as_str());

        // get opens it by the short reference, and several at once.
        let got = local(Command::Get, &db, &[&short]).await;
        assert_eq!(got.exit, 0, "{got:#?}");
        let got = json_of(&got);
        assert_eq!(got["records"][0]["status"], "found");
        assert_eq!(got["records"][0]["body"], "ship the launch on friday");

        // sql, with a parameter.
        let rows = local(
            Command::Sql,
            &db,
            &[
                "SELECT id, name FROM records WHERE name = ?1 ORDER BY id",
                "--param",
                "Launch plan",
            ],
        )
        .await;
        assert_eq!(rows.exit, 0, "{rows:#?}");
        let rows = json_of(&rows);
        assert_eq!(rows["rows"][0]["id"], id.as_str());
        assert_eq!(rows["row_count"], 1);

        // A second record, linked to the first with manage_links.add.
        let second = local(
            Command::Call,
            &db,
            &[
                "records_write",
                "create_record",
                r#"{"type":"Document","kind":"note","name":"Follow-up","body":"after the launch","reason":"follow up"}"#,
            ],
        )
        .await;
        let second_id = json_of(&second)["id"].as_str().unwrap().to_owned();
        let link = format!(
            r#"{{"source_id":"{id}","target_id":"{second_id}","relationship":"relates_to"}}"#
        );
        let linked = local(
            Command::Call,
            &db,
            &["records_write", "manage_links.add", &link],
        )
        .await;
        assert_eq!(linked.exit, 0, "{linked:#?}");
        let links = local(
            Command::Sql,
            &db,
            &["SELECT source_id, target_id FROM links ORDER BY created_at, id"],
        )
        .await;
        assert_eq!(json_of(&links)["rows"][0]["target_id"], second_id.as_str());

        // --text is the server's text form, not JSON.
        let text = local(Command::Search, &db, &["launch", "--text"]).await;
        assert_eq!(text.exit, 0);
        assert!(
            text.stdout.contains("hit(s) for \"launch\""),
            "{}",
            text.stdout
        );
        assert!(serde_json::from_str::<Value>(text.stdout.trim()).is_err());

        // A run key issued by bootstrap is passed through and attaches the call.
        let key = issue_run_key(&db).await;
        let keyed = local(Command::Search, &db, &["launch", "--run-key", &key]).await;
        assert_eq!(json_of(&keyed)["run_context"]["run_key"], key.as_str());
        // Calls need none: the same search without one succeeds, unattached.
        let bare = local(Command::Search, &db, &["launch"]).await;
        assert_eq!(bare.exit, 0);
        assert_eq!(json_of(&bare)["run_context"]["run_key"], Value::Null);
    });
}

#[test]
fn local_refusals_and_misses_exit_4_with_a_reason_and_the_code() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");

        // Missing required fields: a validation error that names the field.
        let bad = local(
            Command::Call,
            &db,
            &["records_write", "create_record", r#"{"name":"x"}"#],
        )
        .await;
        assert_eq!(bad.exit, 4, "{bad:#?}");
        assert!(bad.stdout.is_empty());
        assert!(
            bad.stderr.contains("native: refused: validation_failure"),
            "{}",
            bad.stderr
        );
        assert!(bad
            .stderr
            .contains("code: operation_contract_repair/validation_failure"));
        assert!(bad
            .stderr
            .contains("next: native call --describe records_write create_record"));

        // An operation that does not exist.
        let unknown = local(Command::Call, &db, &["records_write", "no_such_operation"]).await;
        assert_eq!(unknown.exit, 4, "{unknown:#?}");
        assert!(
            unknown.stderr.contains("native: refused:"),
            "{}",
            unknown.stderr
        );

        // A reference that does not exist: the lookup still answers, but it is a failure.
        let missing = local(Command::Get, &db, &["no-such-record"]).await;
        assert_eq!(missing.exit, 4);
        assert!(json_of(&missing)["records"][0]["status"] == "not_found");
        assert!(
            missing.stderr.contains("not found: no-such-record"),
            "{}",
            missing.stderr
        );
        let missing_text = local(Command::Get, &db, &["no-such-record", "--text"]).await;
        assert_eq!(missing_text.exit, 4, "{missing_text:#?}");

        // Bad SQL is refused with the engine's own code.
        let sql = local(Command::Sql, &db, &["DELETE FROM records"]).await;
        assert_eq!(sql.exit, 4, "{sql:#?}");
        assert!(sql.stderr.contains("code:"), "{}", sql.stderr);

        // Nothing credential-shaped is ever printed.
        for report in [&bad, &unknown, &missing, &sql] {
            assert!(!report.stderr.to_lowercase().contains("bearer"));
        }
    });
}

#[test]
fn local_list_and_describe_are_discovered_live() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");

        let all = local(Command::Call, &db, &["--list"]).await;
        assert_eq!(all.exit, 0, "{all:#?}");
        let all = json_of(&all);
        let executors = all["executors"].as_object().unwrap();
        let total: usize = executors
            .values()
            .map(|ops| ops.as_object().unwrap().len())
            .sum();
        assert_eq!(all["count"].as_u64().unwrap() as usize, total);
        assert!(total > 100, "{total}");
        assert_eq!(executors["records_write"]["create_record"], "mutation");
        assert_eq!(executors["records_read"]["get_history"], "read");
        // Writes that must be planned first say so.
        assert!(executors
            .values()
            .flat_map(|ops| ops.as_object().unwrap().values())
            .any(|access| access.as_str().unwrap().ends_with("+plan")));
        assert!(
            all.to_string().len() < 20_000,
            "the listing should stay small enough to read: {} bytes",
            all.to_string().len()
        );

        let filtered = local(Command::Call, &db, &["--list", "sql_read", "--text"]).await;
        assert_eq!(filtered.exit, 0, "{filtered:#?}");
        assert!(
            filtered.stdout.contains("sql_read.query_sql"),
            "{}",
            filtered.stdout
        );
        assert!(
            !filtered.stdout.contains("records_write"),
            "{}",
            filtered.stdout
        );
        let hostile = local(Command::Call, &db, &["--list", "x' OR '1'='1"]).await;
        assert_eq!(hostile.exit, 2, "{hostile:#?}");

        let described = local(
            Command::Call,
            &db,
            &["--describe", "records_write", "create_record"],
        )
        .await;
        assert_eq!(described.exit, 0, "{described:#?}");
        let described = json_of(&described);
        assert_eq!(described["operation"], "create_record");
        assert!(described["input_schema"]["properties"]["reason"].is_object());
        let nope = local(Command::Call, &db, &["--describe", "records_write", "nope"]).await;
        assert_eq!(nope.exit, 4, "{nope:#?}");
    });
}

#[test]
fn a_call_to_an_unadvertised_operation_goes_through_call_executor() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");
        let created = local(
            Command::Call,
            &db,
            &["records_write", "create_record", NOTE],
        )
        .await;
        let id = json_of(&created)["id"].as_str().unwrap().to_owned();
        // records_read.get_history is not in the directly advertised set.
        let history = local(
            Command::Call,
            &db,
            &[
                "records_read",
                "get_history",
                &format!(r#"{{"record_id":"{id}"}}"#),
            ],
        )
        .await;
        assert_eq!(history.exit, 0, "{history:#?}");
    });
}

#[test]
fn an_unopenable_local_database_is_exit_2() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let not_a_database = dir.path().join("plain.db");
        std::fs::write(&not_a_database, b"this is not sqlite").unwrap();
        let report = local(Command::Search, &not_a_database, &["x"]).await;
        assert_eq!(report.exit, 2, "{report:#?}");
        assert!(report.stdout.is_empty());
        assert!(report.stderr.starts_with("native: "), "{}", report.stderr);
    });
}

// ---- hosted mode: a real node against the fake hosted server -------------------------------

/// Hosted's engine, on its own thread (its futures are deep): the fake hosted
/// server hands it every tool call but the two setup makes.
struct HostedEngine {
    requests:
        tokio::sync::mpsc::UnboundedSender<(Value, tokio::sync::oneshot::Sender<Option<Value>>)>,
    _dir: tempfile::TempDir,
}

impl HostedEngine {
    fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosted-engine.db");
        let (requests, mut inbox) = tokio::sync::mpsc::unbounded_channel::<(
            Value,
            tokio::sync::oneshot::Sender<Option<Value>>,
        )>();
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async move {
                        let (surface, _profile, experimental) =
                            crate::native_cli::resolve_local_stdio_env().unwrap();
                        let executor = crate::native_cli::LocalExecutor::open(
                            &path.to_string_lossy(),
                            surface,
                            experimental,
                        )
                        .await
                        .unwrap();
                        while let Some((message, reply)) = inbox.recv().await {
                            let _ = reply.send(executor.handle(message).await);
                        }
                        executor.close().await;
                    });
            })
            .unwrap();
        Self {
            requests,
            _dir: dir,
        }
    }

    fn hook(&self) -> McpHook {
        let requests = self.requests.clone();
        Arc::new(move |message| {
            let requests = requests.clone();
            Box::pin(async move {
                let (reply, answer) = tokio::sync::oneshot::channel();
                requests.send((message, reply)).ok()?;
                answer.await.ok().flatten()
            })
        })
    }

    /// Ask the engine directly, as hosted's own reader would.
    async fn ask(&self, message: Value) -> Value {
        self.hook()(message).await.expect("the engine answers")
    }
}

struct Hosted {
    running: Running,
    engine: HostedEngine,
}

impl Hosted {
    async fn start() -> Self {
        let engine = HostedEngine::start();
        let running = start_node_with(false, &[], Some(engine.hook())).await;
        Self { running, engine }
    }

    /// One command through the node's socket.
    async fn run(&self, command: Command, list: &[&str]) -> Report {
        let config = self.running.install.config.display().to_string();
        let mut all = list.to_vec();
        all.extend(["--config-dir", &config, "--timeout", "30"]);
        execute(&invocation(command, &all)).await
    }

    /// Records matching a word, asked of hosted's engine itself.
    async fn hosted_hits(&self, word: &str) -> usize {
        let reply = self
            .engine
            .ask(json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"records_read","arguments":{"operation":"search","format":"json","arguments":{"query":word}}}}))
            .await;
        reply["result"]["structuredContent"]["hits"]
            .as_array()
            .map_or(0, Vec::len)
    }
}

fn keyed(name: &str, key: &str) -> String {
    json!({"type":"Document","kind":"note","name":name,"body":format!("{name} body"),"reason":"hosted test","idempotency_key":key}).to_string()
}

#[tokio::test]
async fn hosted_read_and_write_go_through_the_node() {
    let hosted = Hosted::start().await;

    let created = hosted
        .run(
            Command::Call,
            &[
                "records_write",
                "create_record",
                &keyed("Quarterly launch", "key-write-1"),
            ],
        )
        .await;
    assert_eq!(created.exit, 0, "{created:#?}");
    let id = json_of(&created)["id"].as_str().unwrap().to_owned();
    assert_eq!(hosted.hosted_hits("quarterly").await, 1);

    // The shortcuts read it back through the node.
    let found = hosted.run(Command::Search, &["quarterly"]).await;
    assert_eq!(found.exit, 0, "{found:#?}");
    assert_eq!(json_of(&found)["hits"][0]["id"], id.as_str());
    let got = hosted.run(Command::Get, &[&id]).await;
    assert_eq!(got.exit, 0, "{got:#?}");
    assert_eq!(json_of(&got)["records"][0]["status"], "found");
    let rows = hosted
        .run(
            Command::Sql,
            &[
                "SELECT name FROM records WHERE id = ?1 ORDER BY id",
                "--param",
                &id,
            ],
        )
        .await;
    assert_eq!(json_of(&rows)["rows"][0]["name"], "Quarterly launch");

    // Discovery goes through the node too.
    let listed = hosted
        .run(Command::Call, &["--list", "records_write"])
        .await;
    assert_eq!(listed.exit, 0, "{listed:#?}");
    assert_eq!(
        json_of(&listed)["executors"]["records_write"]["create_record"],
        "mutation"
    );
    let described = hosted
        .run(
            Command::Call,
            &["--describe", "records_write", "create_record"],
        )
        .await;
    assert_eq!(described.exit, 0, "{described:#?}");
    assert!(json_of(&described)["input_schema"]["properties"]["idempotency_key"].is_object());
    assert!(!WS_A.is_empty());
}

#[tokio::test]
async fn hosted_refusals_exit_4_and_apply_nothing() {
    let hosted = Hosted::start().await;
    // Invalid arguments: hosted's own validation error.
    let invalid = hosted
        .run(
            Command::Call,
            &[
                "records_write",
                "create_record",
                r#"{"name":"missing the rest"}"#,
            ],
        )
        .await;
    assert_eq!(invalid.exit, 4, "{invalid:#?}");
    assert!(
        invalid.stderr.contains("native: refused:"),
        "{}",
        invalid.stderr
    );
    assert!(invalid.stderr.contains("code:"), "{}", invalid.stderr);
    // A well-formed write hosted refuses on the merits: linking to records that do not exist.
    let link = hosted
        .run(
            Command::Call,
            &[
                "records_write",
                "manage_links.add",
                r#"{"source_id":"no-such-a","target_id":"no-such-b","relationship":"relates_to"}"#,
            ],
        )
        .await;
    assert_eq!(link.exit, 4, "{link:#?}");
    assert!(link.stdout.is_empty());
    assert_eq!(hosted.hosted_hits("missing").await, 0);
}

#[tokio::test]
async fn a_write_held_while_hosted_is_down_is_exit_3_and_delivered_when_it_returns() {
    let hosted = Hosted::start().await;
    // While hosted is up the node learns the operation's contract.
    let first = hosted
        .run(
            Command::Call,
            &[
                "records_write",
                "create_record",
                &keyed("Before the outage", "key-before"),
            ],
        )
        .await;
    assert_eq!(first.exit, 0, "{first:#?}");

    hosted.running.hosted.shut_down();
    let held = hosted
        .run(
            Command::Call,
            &[
                "records_write",
                "create_record",
                &keyed("During the outage", "key-during"),
            ],
        )
        .await;
    assert_eq!(held.exit, 3, "{held:#?}");
    let body = json_of(&held);
    assert_eq!(body["outcome"], "accepted_pending");
    assert_eq!(body["idempotency_key"], "key-during");
    assert!(
        held.stderr.contains("held (accepted_pending)"),
        "{}",
        held.stderr
    );
    assert!(
        held.stderr.contains("idempotency_key: key-during"),
        "{}",
        held.stderr
    );
    assert_eq!(
        hosted.hosted_hits("outage").await,
        1,
        "only the first write reached hosted"
    );

    // Repeating the call while it waits is still held, and does not double it.
    let again = hosted
        .run(
            Command::Call,
            &[
                "records_write",
                "create_record",
                &keyed("During the outage", "key-during"),
            ],
        )
        .await;
    assert_eq!(again.exit, 3, "{again:#?}");

    hosted.running.hosted.restart().await;
    let mut delivered = false;
    for _ in 0..240 {
        if hosted.hosted_hits("during").await == 1 {
            delivered = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(delivered, "the held write never reached hosted");

    // Now the same call returns the original receipt.
    let settled = hosted
        .run(
            Command::Call,
            &[
                "records_write",
                "create_record",
                &keyed("During the outage", "key-during"),
            ],
        )
        .await;
    assert_eq!(settled.exit, 0, "{settled:#?}");
    assert_eq!(hosted.hosted_hits("during").await, 1);
}

#[tokio::test]
async fn no_node_is_exit_2_with_a_hint() {
    let dir = tempfile::tempdir().unwrap();
    // No configuration at all.
    let report = execute(&invocation(
        Command::Search,
        &["x", "--config-dir", dir.path().to_str().unwrap()],
    ))
    .await;
    assert_eq!(report.exit, 2);
    assert!(report.stdout.is_empty());
    assert!(report.stderr.contains("native setup"), "{}", report.stderr);
    assert!(report.stderr.contains("--local"), "{}", report.stderr);

    // Configured, but nothing is running.
    let hosted = Hosted::start().await;
    let config = hosted.running.install.config.display().to_string();
    let Running {
        install,
        _node: node,
        ..
    } = hosted.running;
    drop(node);
    let report = execute(&invocation(
        Command::Call,
        &["records_read", "search", "{}", "--config-dir", &config],
    ))
    .await;
    assert_eq!(report.exit, 2, "{report:#?}");
    assert!(report.stderr.contains("not running"), "{}", report.stderr);
    assert!(
        report.stderr.contains("native service install"),
        "{}",
        report.stderr
    );
    drop(install);
}

// ---- scripted servers ----------------------------------------------------------------------------------

type Calls = Arc<std::sync::Mutex<Vec<Value>>>;

/// A scripted server: it lists some tools, answers the catalogue's `access`
/// lookup with `access` (`None`: no row), and hands every other `tools/call`
/// to `on_call` (`None`: the connection drops). Every `tools/call` made is
/// logged.
fn scripted_client<'a>(
    inv: &'a Invocation,
    access: Option<&'static str>,
    mut on_call: impl FnMut(&Value) -> Option<Value> + Send + 'static,
) -> (Client<'a>, Calls) {
    let calls: Calls = Arc::default();
    let log = calls.clone();
    let script = move |message: Value| -> Option<Value> {
        let id = message["id"].clone();
        let result = |result: Value| Some(json!({"jsonrpc":"2.0","id":id,"result":result}));
        if message["method"] == "tools/list" {
            return result(json!({"tools":[
                {"name":"records_read","inputSchema":{"properties":{"operation":{"enum":["search"]}}}},
                {"name":"sql_read","inputSchema":{"properties":{"operation":{"enum":["query_sql"]}}}},
                {"name":"bootstrap","inputSchema":{"properties":{}}},
                {"name":"call_executor","inputSchema":{}}]}));
        }
        let sql = message
            .pointer("/params/arguments/arguments/sql")
            .and_then(Value::as_str)
            .unwrap_or("");
        if sql.starts_with("SELECT access FROM catalog_operations") {
            let rows = access.map_or(json!([]), |a| json!([{ "access": a }]));
            return result(tool_result(json!({"rows": rows}), false)["result"].clone());
        }
        log.lock().unwrap().push(message.clone());
        on_call(&message)
    };
    let client = Client {
        session: Session::Scripted(Box::new(script)),
        invocation: inv,
        tools: None,
        run_key: None,
        notes: Vec::new(),
        next_id: 1,
        mutations: BTreeMap::new(),
    };
    (client, calls)
}

fn call_names(calls: &Calls) -> Vec<String> {
    calls
        .lock()
        .unwrap()
        .iter()
        .map(|m| {
            format!(
                "{}:{}",
                m["params"]["name"].as_str().unwrap(),
                m["params"]["arguments"]["run_key"]
            )
        })
        .collect()
}

async fn finish(client: &mut Client<'_>) -> Report {
    match run_action(client).await {
        Ok(report) => report,
        Err(Failure(report)) => report,
    }
}

/// The wording of the real refusals, from the server's source:
/// `manage_instructions.resolve`, `record_progress`, kernel-v2 coordination.
const RUN_KEY_REFUSALS: [&str; 3] = [
    "manage_instructions: resolve requires an existing run_key; pass the run_key from bootstrap on this call",
    "record_progress requires Bootstrap's exact run_key",
    "kernel-v2 coordination requires a full run_key from bootstrap or run_key='new'",
];

/// How the real server delivers one: a bare JSON-RPC internal error.
fn real_run_key_refusal(id: &Value, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":message}})
}

#[tokio::test]
async fn a_refusal_for_a_missing_run_key_gets_a_bootstrap_and_one_retry() {
    for refusal in RUN_KEY_REFUSALS {
        let inv = invocation(
            Command::Call,
            &["guidance_read", "manage_instructions.resolve", "{}"],
        );
        let (mut client, calls) = scripted_client(&inv, Some("read"), move |m| {
            let id = &m["id"];
            let ok = |r: Value| Some(json!({"jsonrpc":"2.0","id":id,"result":r}));
            match m.pointer("/params/arguments/operation").and_then(Value::as_str) {
                _ if m.pointer("/params/name") == Some(&json!("bootstrap")) => ok(
                    tool_result(json!({"run":{"run_key":"issued-key-1"}}), false)["result"].clone(),
                ),
                _ if m.pointer("/params/arguments/run_key").is_none() => {
                    Some(real_run_key_refusal(id, refusal))
                }
                _ => ok(tool_result(
                    json!({"resolved":true,"run_context":{"run_key":m.pointer("/params/arguments/run_key")}}),
                    false,
                )["result"]
                    .clone()),
            }
        });
        let report = finish(&mut client).await;
        assert_eq!(report.exit, 0, "{refusal}: {report:#?}");
        assert_eq!(json_of(&report)["run_context"]["run_key"], "issued-key-1");
        assert!(client.notes[0].contains("issued-key-1") && client.notes[0].contains("--run-key"));
        // One refused try, one bootstrap, one retry that carries the key.
        assert_eq!(
            call_names(&calls),
            [
                "call_executor:null",
                "bootstrap:null",
                "call_executor:\"issued-key-1\""
            ],
            "{refusal}"
        );
    }
}

#[tokio::test]
async fn the_real_server_s_run_key_refusal_is_retried_end_to_end() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");
        let report = local(
            Command::Call,
            &db,
            &["guidance_read", "manage_instructions.resolve", "{}"],
        )
        .await;
        assert_eq!(report.exit, 0, "{report:#?}");
        assert!(
            report.stderr.contains("native: run key: "),
            "{}",
            report.stderr
        );
        // A key the caller supplies is never replaced: the refusal is shown.
        let report = local(
            Command::Call,
            &db,
            &[
                "guidance_read",
                "manage_instructions.resolve",
                "{}",
                "--run-key",
                "not-a-real-key",
            ],
        )
        .await;
        assert_eq!(report.exit, 4, "{report:#?}");
        assert!(
            report.stderr.contains("requires an existing run_key"),
            "{}",
            report.stderr
        );
        assert!(report.stderr.contains("--run-key"), "{}", report.stderr);
    });
}

#[tokio::test]
async fn a_run_key_refusal_is_never_retried_unless_nothing_ran() {
    let wording = RUN_KEY_REFUSALS[0];
    // Replies that mention the run key but say something happened, or might have.
    let unsafe_replies = [
        (
            "outcome unknown",
            tool_result(json!({"error":wording,"outcome":"unknown"}), true),
        ),
        (
            "outcome uncertain",
            tool_result(json!({"error":wording,"outcome":"uncertain"}), true),
        ),
        (
            "applied true",
            tool_result(json!({"error":wording,"applied":true}), true),
        ),
        (
            "applied partial",
            tool_result(json!({"error":wording,"applied":"partial"}), true),
        ),
        (
            "partial",
            tool_result(json!({"error":wording,"partial":true}), true),
        ),
        (
            "held",
            tool_result(json!({"error":wording,"outcome":"accepted_pending"}), false),
        ),
        (
            "node journal",
            rpc_error(json!({"node_journal":{"outcome":"uncertain"}})),
        ),
        ("gateway failure", rpc_error(json!({"http_status":502}))),
        (
            "outcome refused",
            tool_result(json!({"error":wording,"outcome":"refused"}), true),
        ),
    ];
    for (name, reply) in unsafe_replies {
        let with_wording = if reply.get("error").is_some() {
            let mut reply = reply;
            reply["error"]["message"] = json!(wording);
            reply
        } else {
            reply
        };
        assert!(
            !run_key_retry_is_safe(&with_wording),
            "{name}: {with_wording}"
        );
    }
    // Pre-execution refusals: bare, explicitly not sent, or applied false.
    let id = json!(1);
    for (name, reply) in [
        ("real shape", real_run_key_refusal(&id, wording)),
        ("not_sent", {
            let mut r = rpc_error(json!({"outcome":"not_sent"}));
            r["error"]["message"] = json!(wording);
            r
        }),
        (
            "applied false",
            tool_result(json!({"error":wording,"applied":false}), true),
        ),
        (
            "a code naming run_key",
            tool_result(
                json!({"error":"nope","error_code":"RUN_KEY_REQUIRED"}),
                true,
            ),
        ),
    ] {
        assert!(run_key_retry_is_safe(&reply), "{name}: {reply}");
    }
    // Wording about something else is not a run-key refusal.
    assert!(!run_key_refusal(&real_run_key_refusal(
        &id,
        "record not found"
    )));
    assert!(!run_key_refusal(&tool_result(
        json!({"run_context":{"notes":["pass run_key on every call"]}}),
        false
    )));

    // End to end: an uncertain reply that happens to mention the run key is not retried.
    let inv = invocation(Command::Call, &["records_write", "create_record", "{}"]);
    let (mut client, calls) = scripted_client(&inv, Some("mutation"), move |m| {
        Some(json!({"jsonrpc":"2.0","id":m["id"],"result":tool_result(
            json!({"error":wording,"outcome":"unknown"}), true)["result"].clone()}))
    });
    let report = finish(&mut client).await;
    assert_eq!(report.exit, 5, "{report:#?}");
    assert_eq!(call_names(&calls), ["call_executor:null"]);
}

#[tokio::test]
async fn whether_a_lost_reply_is_uncertain_follows_the_catalogue_not_the_command() {
    let lost = |_: &Value| None;
    // A read operation: unreachable, whichever command asked for it.
    let inv = invocation(Command::Call, &["records_read", "search", "{}"]);
    let (mut client, _) = scripted_client(&inv, Some("read"), lost);
    assert_eq!(finish(&mut client).await.exit, 2);
    // A mutation: uncertain, even through the `search` shortcut.
    let inv = invocation(Command::Search, &["words"]);
    let (mut client, _) = scripted_client(&inv, Some("mutation"), lost);
    let report = finish(&mut client).await;
    assert_eq!(report.exit, 5, "{report:#?}");
    assert!(
        report.stderr.contains("may or may not"),
        "{}",
        report.stderr
    );
    // Not in the catalogue at all: treated as a possible write.
    let inv = invocation(Command::Call, &["records_write", "future_op", "{}"]);
    let (mut client, _) = scripted_client(&inv, None, lost);
    assert_eq!(finish(&mut client).await.exit, 5);
    // An operation whose name cannot be looked up safely is also a possible write.
    let inv = invocation(Command::Call, &["records_read", "it's", "{}"]);
    let (mut client, _) = scripted_client(&inv, Some("read"), lost);
    assert_eq!(finish(&mut client).await.exit, 5);
    // And the answer is asked for once per operation.
    let inv = invocation(Command::Call, &["records_read", "search", "{}"]);
    let (mut client, calls) = scripted_client(&inv, Some("read"), |m| {
        Some(
            json!({"jsonrpc":"2.0","id":m["id"],"result":tool_result(json!({"hits":[]}), false)["result"].clone()}),
        )
    });
    assert_eq!(finish(&mut client).await.exit, 0);
    assert!(
        client
            .mutations
            .get(&("records_read".into(), "search".into()))
            == Some(&false)
    );
    assert_eq!(call_names(&calls).len(), 1);
}

#[test]
fn a_node_journal_note_makes_it_uncertain_and_names_the_original_key() {
    let inv = invocation(Command::Call, &["records_write", "create_record"]);
    let journal = json!({"outcome":"uncertain","idempotency_key":"orig-key-7","key_origin":"node","journal_entry":"j-9","attempts":3});
    let replies = [
        // Hosted's later answer was a plain refusal; the note is beside it.
        (
            "result",
            tool_result(
                json!({"error":"hosted refused","applied":false,"node_journal":journal}),
                true,
            ),
        ),
        (
            "error data",
            rpc_error(json!({"outcome":"refused","node_journal":journal})),
        ),
    ];
    for (place, reply) in replies {
        let report = report_of(
            &reply,
            &inv,
            "records_write",
            "create_record",
            Some("caller-key"),
        );
        assert_eq!(report.exit, 5, "{place}: {report:#?}");
        assert!(report.stdout.is_empty(), "{place}");
        // The key the node named, never the caller's or a new one.
        assert!(
            report.stderr.contains("idempotency_key: orig-key-7"),
            "{place}: {}",
            report.stderr
        );
        assert!(
            !report.stderr.contains("caller-key"),
            "{place}: {}",
            report.stderr
        );
        assert!(
            report.stderr.contains("retry with this same key"),
            "{place}: {}",
            report.stderr
        );
        assert!(
            report.stderr.contains("\"idempotency_key\":\"orig-key-7\""),
            "{place}: {}",
            report.stderr
        );
        assert!(
            report.stderr.contains("Never use a fresh key"),
            "{place}: {}",
            report.stderr
        );
        assert!(
            report.stderr.contains("earlier attempt"),
            "{place}: {}",
            report.stderr
        );
        assert!(
            report.stderr.contains("key_origin: node"),
            "{place}: {}",
            report.stderr
        );
    }
    // Without a key in the reply, the key the caller sent is what to reuse.
    let reply = tool_result(
        json!({"error":"x","node_journal":{"outcome":"uncertain"}}),
        true,
    );
    let report = report_of(
        &reply,
        &inv,
        "records_write",
        "create_record",
        Some("caller-key"),
    );
    assert_eq!(report.exit, 5);
    assert!(
        report.stderr.contains("idempotency_key: caller-key"),
        "{}",
        report.stderr
    );
}

#[test]
fn nothing_was_applied_is_said_only_when_the_reply_says_so() {
    let inv = invocation(Command::Call, &["records_write", "create_record"]);
    let says =
        |reply: Value| report_of(&reply, &inv, "records_write", "create_record", None).stderr;
    // Partial and retryable: retrying is safe only with the same key, which is printed.
    let partial = says(tool_result(
        json!({"error":"some of it","applied":"partial","retryable":true,"idempotency_key":"k-partial"}),
        true,
    ));
    assert!(!partial.contains("nothing was applied"), "{partial}");
    assert!(
        partial.contains("retryable: only with the same idempotency_key (k-partial)"),
        "{partial}"
    );
    // The same without a key: not safely retryable.
    let keyless = says(tool_result(
        json!({"error":"some","applied":"partial","retryable":true}),
        true,
    ));
    assert!(
        !keyless.contains("nothing was applied") && keyless.contains("not safely"),
        "{keyless}"
    );
    // Unknown outcome, retryable: still not "nothing applied".
    let unknown = says(tool_result(
        json!({"error":"timed out","outcome":"unknown","retryable":true,"idempotency_key":"k-u"}),
        true,
    ));
    assert!(
        !unknown.contains("nothing was applied") && unknown.contains("k-u"),
        "{unknown}"
    );
    // A refusal that says nothing about application does not claim it either.
    let silent = says(tool_result(json!({"error":"nope","retryable":true}), true));
    assert!(!silent.contains("nothing was applied"), "{silent}");
    // applied:false and not_sent do.
    for body in [
        json!({"error":"nope","applied":false,"retryable":true}),
        json!({"error":"nope","outcome":"not_sent","retryable":true}),
    ] {
        let said = says(tool_result(body.clone(), true));
        assert!(
            said.contains("retryable: yes (the reply says nothing was applied)"),
            "{body}: {said}"
        );
    }
}

/// A config directory whose node is a scripted socket server: each request
/// line goes to `answer`, whose reply is written back (`None` hangs up;
/// `Some(Null)` stays silent; `{"__delay_ms": n, "reply": …}` answers late).
async fn scripted_node(
    template: &Hosted,
    answer: impl Fn(&Value) -> Option<Value> + Send + Sync + 'static,
) -> (tempfile::TempDir, tempfile::TempDir) {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    let socket_dir = tempfile::tempdir().unwrap();
    let listener = tokio::net::UnixListener::bind(socket_dir.path().join("node.sock")).unwrap();
    let answer = Arc::new(answer);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let answer = answer.clone();
            tokio::spawn(async move {
                let (read, mut write) = stream.into_split();
                let mut lines = BufReader::new(read).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    let request: Value = serde_json::from_str(&line).unwrap();
                    match answer(&request) {
                        // Say nothing, keeping the connection open.
                        Some(Value::Null) => std::future::pending::<()>().await,
                        Some(reply) => {
                            // `{"__delay_ms": n, "reply": …}` answers after n ms.
                            let reply = match reply.get("__delay_ms").and_then(Value::as_u64) {
                                Some(ms) => {
                                    tokio::time::sleep(Duration::from_millis(ms)).await;
                                    reply["reply"].clone()
                                }
                                None => reply,
                            };
                            write
                                .write_all(format!("{reply}\n").as_bytes())
                                .await
                                .unwrap();
                        }
                        None => return,
                    }
                }
            });
        }
    });
    let mut config: Value = serde_json::from_slice(
        &std::fs::read(
            template
                .running
                .install
                .config
                .join(super::super::setup::NODE_FILE),
        )
        .unwrap(),
    )
    .unwrap();
    config["socket_directory"] = json!(socket_dir.path());
    let config_dir = tempfile::tempdir().unwrap();
    std::fs::write(
        config_dir.path().join(super::super::setup::NODE_FILE),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    (config_dir, socket_dir)
}

#[tokio::test]
async fn a_node_that_says_nothing_is_a_timeout_not_a_hang() {
    let template = Hosted::start().await;
    // Answers the handshake, then never answers a call.
    let (config, _socket) = scripted_node(&template, |request| {
        if request["method"] == "initialize" {
            Some(json!({"jsonrpc":"2.0","id":request["id"],"result":{"protocolVersion":"2025-06-18"}}))
        } else {
            Some(Value::Null)
        }
    })
    .await;
    let mut inv = invocation(
        Command::Search,
        &["x", "--config-dir", config.path().to_str().unwrap()],
    );
    inv.timeout = Duration::from_secs(1);
    let report = execute(&inv).await;
    assert_eq!(report.exit, 2, "{report:#?}");
    assert!(
        report.stderr.contains("no reply within"),
        "{}",
        report.stderr
    );
}

#[tokio::test]
async fn a_reply_lost_after_a_call_is_uncertain_for_a_call_and_unreachable_for_a_read() {
    let template = Hosted::start().await;
    let (config, _socket) = scripted_node(&template, |request| {
        let id = request["id"].clone();
        match request["method"].as_str() {
            Some("initialize") => {
                Some(json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18"}}))
            }
            Some("tools/list") => Some(
                json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"call_executor","inputSchema":{}}]}}),
            ),
            Some("tools/call") if request.to_string().contains("SELECT access FROM catalog_operations") => {
                // The catalogue classifies `search` as a read and `create_record` as a mutation.
                let access = if request.to_string().contains("operation = 'search'") {
                    "read"
                } else {
                    "mutation"
                };
                Some(json!({"jsonrpc":"2.0","id":id,"result":tool_result(json!({"rows":[{"access":access}]}), false)["result"].clone()}))
            }
            // The connection drops with the call in flight.
            _ => None,
        }
    })
    .await;
    let dir = config.path().to_str().unwrap();
    let write = execute(&invocation(
        Command::Call,
        &["records_write", "create_record", "{}", "--config-dir", dir],
    ))
    .await;
    assert_eq!(write.exit, 5, "{write:#?}");
    assert!(
        write.stderr.contains("uncertain") && write.stderr.contains("may or may not"),
        "{}",
        write.stderr
    );
    let read = execute(&invocation(Command::Search, &["x", "--config-dir", dir])).await;
    assert_eq!(read.exit, 2, "{read:#?}");
}

// ---- late and stray replies ------------------------------------------------------------------------

fn catalogue_lookup(request: &Value) -> bool {
    request
        .to_string()
        .contains("SELECT access FROM catalog_operations")
}

/// The scripted node of the late-reply regression: it answers the handshake
/// and tool listing at once, the catalogue lookup after `lookup_delay_ms`, and
/// a write with `write` (`None`: never).
fn late_catalogue_node(
    lookup_delay_ms: u64,
    write: Option<Value>,
) -> impl Fn(&Value) -> Option<Value> + Send + Sync + 'static {
    move |request| {
        let id = request["id"].clone();
        match request["method"].as_str() {
            Some("initialize") => {
                Some(json!({"jsonrpc":"2.0","id":id,"result":{"protocolVersion":"2025-06-18"}}))
            }
            Some("tools/list") => Some(
                json!({"jsonrpc":"2.0","id":id,"result":{"tools":[{"name":"call_executor","inputSchema":{}}]}}),
            ),
            Some("tools/call") if catalogue_lookup(request) => Some(json!({
                "__delay_ms": lookup_delay_ms,
                "reply": {"jsonrpc":"2.0","id":id,"result":tool_result(
                    json!({"columns":["access"],"rows":[{"access":"mutation"}]}), false)["result"].clone()},
            })),
            Some("tools/call") => match &write {
                Some(receipt) => Some(
                    json!({"jsonrpc":"2.0","id":id,"result":tool_result(receipt.clone(), false)["result"].clone()}),
                ),
                None => Some(Value::Null),
            },
            _ => None,
        }
    }
}

#[tokio::test]
async fn a_late_catalogue_reply_is_never_taken_for_the_writes_receipt() {
    let template = Hosted::start().await;
    // The catalogue answers after the 1 s budget, as the reproduction did.
    let (config, _socket) = scripted_node(
        &template,
        late_catalogue_node(1500, Some(json!({"id":"WRITE-RECEIPT","type":"Document"}))),
    )
    .await;
    let report = execute(&invocation(
        Command::Call,
        &[
            "records_write",
            "create_record",
            "{}",
            "--config-dir",
            config.path().to_str().unwrap(),
            "--timeout",
            "1",
        ],
    ))
    .await;
    // The write is on a fresh connection and its own reply is what is printed.
    assert_eq!(report.exit, 0, "{report:#?}");
    assert!(report.stdout.contains("WRITE-RECEIPT"), "{report:#?}");
    assert!(!report.stdout.contains("rows"), "{report:#?}");

    // And with no receipt for the write, the late catalogue reply is not one: uncertain.
    let (config, _socket) = scripted_node(&template, late_catalogue_node(1500, None)).await;
    let report = execute(&invocation(
        Command::Call,
        &[
            "records_write",
            "create_record",
            "{}",
            "--config-dir",
            config.path().to_str().unwrap(),
            "--timeout",
            "1",
        ],
    ))
    .await;
    assert_eq!(report.exit, 5, "{report:#?}");
    assert!(report.stdout.is_empty(), "{report:#?}");
    assert!(
        report.stderr.contains("may or may not"),
        "{}",
        report.stderr
    );
}

#[tokio::test]
async fn the_client_matches_replies_by_id_and_does_not_reuse_a_spent_connection() {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("node.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    tokio::spawn(async move {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        let mut served = 0;
        while let Ok(Some(line)) = lines.next_line().await {
            let request: Value = serde_json::from_str(&line).unwrap();
            served += 1;
            if served == 3 {
                // Never answers the third request, and answers it much later.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
            for noise in [
                json!({"jsonrpc":"2.0","method":"notifications/message","params":{}}),
                // A reply to some earlier request, with other contents.
                json!({"jsonrpc":"2.0","id":7777,"result":{"which":"stale"}}),
                json!({"jsonrpc":"2.0","id":request["id"],"result":{"which":"real","echo":request["method"]}}),
                // A late duplicate under the same number is also skipped by the next request's number.
            ] {
                let _ = write.write_all(format!("{noise}\n").as_bytes()).await;
            }
        }
    });
    let mut connection = Connection::open(
        "test",
        dir.path(),
        &socket,
        Duration::from_secs(1),
        &Limits::standard(),
    )
    .await
    .unwrap_or_else(|info| panic!("{info:?}"));
    // Stray lines before the answer are skipped, whatever ids the caller used.
    for (n, method) in ["a", "b"].into_iter().enumerate() {
        let reply = connection
            .exchange(json!({"jsonrpc":"2.0","id":42,"method":method}), n == 0)
            .await
            .unwrap();
        assert_eq!(reply["result"]["which"], "real", "{reply}");
        assert_eq!(reply["result"]["echo"], method);
        // Numbered by the connection (1, 2, ...), not by the caller (42).
        assert_eq!(reply["id"], n + 1);
    }
    // The third request is answered after the budget: an error, not a late reply.
    let error = connection
        .exchange(json!({"jsonrpc":"2.0","id":42,"method":"c"}), false)
        .await
        .unwrap_err();
    assert!(error.contains("no reply within"), "{error}");
    assert!(connection.is_spent(), "the third request timed out");
    // A spent connection sends nothing more.
    let error = connection
        .exchange(json!({"jsonrpc":"2.0","method":"d"}), false)
        .await
        .unwrap_err();
    assert!(error.contains("earlier error"), "{error}");
}

// ---- successes the engine reports through `outcome` ---------------------------------------------

/// A database with the account-config kind and shape registered, as hosted
/// workspaces have them.
async fn database_with_account_config(path: &Path) {
    use crate::meta::{
        promote_value, propose_value_with_kind_metadata_as, write_user_schema_config,
        KindMetadataV1, SchemaConfigOptions, VocabularyValueTerminality,
    };
    let db = crate::create_database(&path.to_string_lossy())
        .await
        .unwrap();
    let id = propose_value_with_kind_metadata_as(
        &db,
        "kind:Configuration",
        "focus_preferences",
        None,
        0.0,
        VocabularyValueTerminality::Open,
        Some(KindMetadataV1::legacy("Configuration", "focus_preferences")),
        None,
    )
    .await
    .unwrap();
    promote_value(&db, &id).await.unwrap();
    let shape: Value = serde_json::from_str(include_str!(
        "../../mcp/tools/account_config/preferences-shape.json"
    ))
    .unwrap();
    write_user_schema_config(
        &db,
        json!({"shapes":{"Configuration:focus_preferences":{"facets":{"focus.preferences":shape}}}}),
        SchemaConfigOptions::default(),
    )
    .await
    .unwrap();
    db.close().await;
}

#[test]
fn real_executor_successes_that_say_created_existing_and_replaced_exit_0_with_their_receipts() {
    big_stack(async {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("notes.db");
        database_with_account_config(&db).await;
        let ensure = r#"{"kind":"focus_preferences","reason":"provision preferences"}"#;

        // ensure on a fresh account: created.
        let created = local(
            Command::Call,
            &db,
            &["records_write", "manage_account_config.ensure", ensure],
        )
        .await;
        assert_eq!(created.exit, 0, "{created:#?}");
        let receipt = json_of(&created);
        assert_eq!(receipt["outcome"], "created", "{receipt}");
        assert_eq!(receipt["created"], true);
        let id = receipt["record_id"].as_str().unwrap().to_owned();

        // ensure again: existing.
        let existing = local(
            Command::Call,
            &db,
            &["records_write", "manage_account_config.ensure", ensure],
        )
        .await;
        assert_eq!(existing.exit, 0, "{existing:#?}");
        assert_eq!(json_of(&existing)["outcome"], "existing");
        assert_eq!(json_of(&existing)["record_id"], id.as_str());

        // Make the config unusable (deleted), then replace it.
        {
            let opened = crate::open_existing_database(&db.to_string_lossy())
                .await
                .unwrap();
            let mut tx = crate::db::begin_write(opened.write_pool()).await.unwrap();
            crate::store::append_in(
                &opened,
                &mut tx,
                crate::store::AppendSpec {
                    record_id: id.clone(),
                    event_type: "record.deleted".into(),
                    payload: json!({}),
                    actor: None,
                },
                &mut crate::act::ActAllocation::new(),
            )
            .await
            .unwrap();
            opened.commit_content(tx).await.unwrap();
            opened.close().await;
        }
        let replace = format!(
            r#"{{"kind":"focus_preferences","reason":"recover","expected_record_id":"{id}"}}"#
        );
        let replaced = local(
            Command::Call,
            &db,
            &["records_write", "manage_account_config.replace", &replace],
        )
        .await;
        assert_eq!(replaced.exit, 0, "{replaced:#?}");
        let receipt = json_of(&replaced);
        assert_eq!(receipt["outcome"], "replaced", "{receipt}");
        assert_ne!(receipt["record_id"], id.as_str());

        // The same replacement again is a replay of the first: also a success.
        let again = local(
            Command::Call,
            &db,
            &["records_write", "manage_account_config.replace", &replace],
        )
        .await;
        assert_eq!(again.exit, 0, "{again:#?}");
        assert_eq!(json_of(&again)["outcome"], "replayed");
    });
}

#[test]
fn every_success_outcome_the_engine_emits_is_accepted() {
    for outcome in OUTCOMES_OK {
        let plain = tool_result(json!({"outcome": outcome, "id": "r"}), false);
        assert_eq!(classify(&plain).kind, Kind::Ok, "{outcome}");
    }
    // The ones named in the allowlist's source list.
    for outcome in [
        "inspected",
        "created",
        "existing",
        "replaced",
        "replayed",
        "committed",
        "planned",
        "proposed",
        "accepted",
        "superseded",
        "already_applied",
        "current",
        "migrated",
    ] {
        assert!(OUTCOMES_OK.contains(&outcome), "{outcome}");
    }
}
