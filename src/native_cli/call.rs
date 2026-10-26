//! `native call`, `native search`, `native get`, `native sql`: Native from the
//! command line, for agents and scripts.
//!
//! Every command is an MCP `tools/call` made to one of two places:
//!
//! * **hosted mode** (the default): the running node, over its Unix socket,
//!   through [`node_client`] (the same bounded, peer-checked client `native
//!   status` uses). Reads fail over to the node's local copy and writes go
//!   through the node's outbox, exactly as for an agent connected with `native
//!   node connect`. Nothing is sent to hosted from this process.
//! * **local mode** (`--local [<db>]`): the same registry and executor dispatch
//!   as `native mcp --local`, run in this process against one SQLite file. No
//!   subprocess, no node, no account.
//!
//! Nothing here knows an operation's name or arguments. A call is routed to
//! the tool the server advertises for it (`tools/list`), or through
//! `call_executor` when it advertises none; `--list` reads
//! `catalog_operations` and `--describe` asks `describe_operation`.
//!
//! Exit codes: 0 success, 2 the node cannot be reached, the configuration is
//! wrong or the command line is malformed, 3 held (`accepted_pending`), 4
//! refused or a validation error, 5 uncertain.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::node_client::{clean, Connection, Limits};

pub const EXIT_OK: u8 = 0;
/// The node cannot be reached, the configuration is invalid, or the command
/// line is malformed.
pub const EXIT_UNREACHABLE: u8 = 2;
/// The write was accepted but not yet applied (`accepted_pending`).
pub const EXIT_HELD: u8 = 3;
/// Refused, or the call did not validate.
pub const EXIT_REFUSED: u8 = 4;
/// The outcome is not known.
pub const EXIT_UNCERTAIN: u8 = 5;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const ENV_RUN_KEY: &str = "NATIVE_RUN_KEY";

// ---- command line -------------------------------------------------------------------

/// The four commands of this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Call,
    Search,
    Get,
    Sql,
}

impl Command {
    fn name(self) -> &'static str {
        match self {
            Command::Call => "native call",
            Command::Search => "native search",
            Command::Get => "native get",
            Command::Sql => "native sql",
        }
    }
}

/// Where the commands run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// The running node, found through `<config-dir>/node.json`.
    Node { config_dir: Option<PathBuf> },
    /// This process, against one SQLite file (`None`: the default database).
    Local { db: Option<PathBuf> },
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Call {
        executor: String,
        operation: String,
        arguments: Value,
    },
    List {
        executor: Option<String>,
    },
    Describe {
        executor: String,
        operation: String,
    },
    Search {
        query: String,
        limit: Option<u64>,
    },
    Get {
        refs: Vec<String>,
    },
    Sql {
        query: String,
        parameters: Vec<Value>,
    },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Invocation {
    pub backend: Backend,
    pub run_key: Option<String>,
    pub text: bool,
    pub timeout: Duration,
    pub action: Action,
}

/// What the command line asked for.
#[derive(Debug, PartialEq)]
pub enum Parsed {
    Help,
    Run(Box<Invocation>),
    /// A usage mistake: the message, to print above the usage.
    Usage(String),
}

fn usage_error(message: impl Into<String>) -> Parsed {
    Parsed::Usage(message.into())
}

/// Whether the argument after `--local` is the database path rather than the
/// next positional word. Paths contain a separator or a dot; executor names,
/// operations and search words usually do not. `--local=<path>` is always
/// unambiguous.
fn looks_like_path(argument: &str) -> bool {
    !argument.starts_with('-')
        && (argument.contains('/') || argument.contains('.') || argument.starts_with('~'))
}

/// Parse one command's arguments (after the command word).
pub fn parse(command: Command, args: &[String], env_run_key: Option<String>) -> Parsed {
    let mut local: Option<Option<PathBuf>> = None;
    let mut config_dir: Option<PathBuf> = None;
    let mut run_key = env_run_key.filter(|k| !k.trim().is_empty());
    let mut text = false;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut args_file: Option<String> = None;
    let mut list = false;
    let mut describe = false;
    let mut limit: Option<u64> = None;
    let mut params: Vec<Value> = Vec::new();
    let mut positional: Vec<String> = Vec::new();

    let mut index = 0;
    // A value for `flag`: the next argument.
    macro_rules! value {
        ($flag:expr) => {{
            index += 1;
            match args.get(index) {
                Some(v) => v.clone(),
                None => return usage_error(format!("{} needs a value", $flag)),
            }
        }};
    }
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "-h" | "--help" => return Parsed::Help,
            "--text" => text = true,
            "--local" => {
                let db = match args.get(index + 1) {
                    Some(next) if looks_like_path(next) => {
                        index += 1;
                        Some(PathBuf::from(next))
                    }
                    _ => None,
                };
                local = Some(db);
            }
            "--config-dir" => config_dir = Some(PathBuf::from(value!("--config-dir"))),
            "--run-key" => run_key = Some(value!("--run-key")),
            "--timeout" => match value!("--timeout").parse::<u64>() {
                Ok(secs) if secs > 0 => timeout = Duration::from_secs(secs),
                _ => return usage_error("--timeout must be a positive number of seconds"),
            },
            "--args-file" if command == Command::Call => {
                args_file = Some(value!("--args-file"));
            }
            "--list" if command == Command::Call => list = true,
            "--describe" if command == Command::Call => describe = true,
            "--limit" if command == Command::Search => match value!("--limit").parse::<u64>() {
                Ok(n) if n > 0 => limit = Some(n),
                _ => return usage_error("--limit must be a positive whole number"),
            },
            "--param" if command == Command::Sql => {
                let raw = value!("--param");
                params.push(parse_param(&raw));
            }
            other if other.starts_with("--local=") => {
                let path = &other["--local=".len()..];
                local = Some((!path.is_empty()).then(|| PathBuf::from(path)));
            }
            other if other.starts_with("--") && other.len() > 2 => {
                return usage_error(format!("unknown option: {other}"));
            }
            _ => positional.push(args[index].clone()),
        }
        index += 1;
    }

    if local.is_some() && config_dir.is_some() {
        return usage_error("--local and --config-dir cannot be used together");
    }
    let backend = match local {
        Some(db) => Backend::Local { db },
        None => Backend::Node { config_dir },
    };
    let run = |action| {
        Parsed::Run(Box::new(Invocation {
            backend: backend.clone(),
            run_key: run_key.clone(),
            text,
            timeout,
            action,
        }))
    };

    match command {
        Command::Call => {
            if list && describe {
                return usage_error("--list and --describe cannot be used together");
            }
            if list {
                if args_file.is_some() || positional.len() > 1 {
                    return usage_error("--list takes at most an executor name to filter by");
                }
                return run(Action::List {
                    executor: positional.pop(),
                });
            }
            if describe {
                return match positional.as_slice() {
                    [executor, operation] => run(Action::Describe {
                        executor: executor.clone(),
                        operation: operation.clone(),
                    }),
                    _ => usage_error("--describe needs <executor> <operation>"),
                };
            }
            let (executor, operation, inline) = match positional.as_slice() {
                [executor, operation] => (executor, operation, None),
                [executor, operation, json] => (executor, operation, Some(json.as_str())),
                [] | [_] => {
                    return usage_error(
                        "native call needs <executor> <operation> [<json-args>] (see --list)",
                    )
                }
                _ => {
                    return usage_error(
                        "too many arguments; quote the JSON arguments as one argument",
                    )
                }
            };
            let arguments = match (inline, &args_file) {
                (Some(_), Some(_)) => {
                    return usage_error("give the arguments inline or with --args-file, not both")
                }
                (Some(json), None) => json.to_owned(),
                (None, Some(path)) => match read_args_file(path) {
                    Ok(text) => text,
                    Err(why) => return usage_error(why),
                },
                (None, None) => "{}".to_owned(),
            };
            match serde_json::from_str::<Value>(&arguments) {
                Ok(value) if value.is_object() => run(Action::Call {
                    executor: executor.clone(),
                    operation: operation.clone(),
                    arguments: value,
                }),
                Ok(_) => usage_error("the arguments must be a JSON object"),
                Err(error) => usage_error(format!(
                    "the arguments are not valid JSON (line {}, column {}); quote them as one argument, or use --args-file",
                    error.line(),
                    error.column()
                )),
            }
        }
        Command::Search => {
            if positional.is_empty() {
                return usage_error("native search needs the words to search for");
            }
            run(Action::Search {
                query: positional.join(" "),
                limit,
            })
        }
        Command::Get => {
            if positional.is_empty() {
                return usage_error("native get needs at least one record reference");
            }
            run(Action::Get { refs: positional })
        }
        Command::Sql => match positional.as_slice() {
            [query] => run(Action::Sql {
                query: query.clone(),
                parameters: params,
            }),
            [] => usage_error("native sql needs a query (quote it as one argument)"),
            _ => usage_error("quote the query as one argument"),
        },
    }
}

/// A `--param` value: JSON when it parses as a scalar or a typed
/// `{"type","value"}` object, otherwise the text itself.
fn parse_param(raw: &str) -> Value {
    match serde_json::from_str::<Value>(raw) {
        Ok(value @ (Value::Bool(_) | Value::Number(_) | Value::Null | Value::String(_))) => value,
        Ok(value @ Value::Object(_)) => value,
        _ => Value::String(raw.to_owned()),
    }
}

/// The arguments file's text (`-` is standard input), bounded.
fn read_args_file(path: &str) -> Result<String, String> {
    use std::io::Read as _;
    const MAX: u64 = 16 * 1024 * 1024;
    let mut text = String::new();
    let read = if path == "-" {
        std::io::stdin().take(MAX + 1).read_to_string(&mut text)
    } else {
        match std::fs::File::open(path) {
            Ok(file) => file.take(MAX + 1).read_to_string(&mut text),
            Err(error) => {
                return Err(format!(
                    "cannot read {path} ({})",
                    super::node_client::io_kind(&error)
                ))
            }
        }
    };
    match read {
        Ok(_) if text.len() as u64 > MAX => Err(format!("{path} is larger than 16 MiB")),
        Ok(_) => Ok(text),
        Err(_) => Err(format!("cannot read {path} as text")),
    }
}

// ---- what a command produced ----------------------------------------------------------

/// The result of running one command: what to print and the exit code.
#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub exit: u8,
    pub stdout: String,
    pub stderr: String,
}

impl Report {
    fn failed(exit: u8, message: impl Into<String>) -> Self {
        Self {
            exit,
            stdout: String::new(),
            stderr: format!("native: {}\n", message.into()),
        }
    }

    fn unreachable(message: impl Into<String>) -> Self {
        Self::failed(EXIT_UNREACHABLE, message)
    }
}

/// How a tool reply is to be understood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ok,
    /// Accepted but not yet applied.
    Held,
    Refused,
    Uncertain,
}

impl Kind {
    fn exit(self) -> u8 {
        match self {
            Kind::Ok => EXIT_OK,
            Kind::Held => EXIT_HELD,
            Kind::Refused => EXIT_REFUSED,
            Kind::Uncertain => EXIT_UNCERTAIN,
        }
    }
}

fn text_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

/// The `structuredContent` of a result, if any.
fn structured_of(reply: &Value) -> Option<&Value> {
    reply
        .pointer("/result/structuredContent")
        .filter(|v| v.is_object())
}

/// Outcomes that mean the call took effect (or, for a plan or an inspection,
/// asked for nothing to take effect). Built from every `outcome` a tool reply
/// can carry as success in the engine (grep of `"outcome"` and the enums
/// serialized as one, in `src/mcp` and `src/node`, 22 Oct 2026):
///
/// * `mcp/tools/account_config.rs` `Outcome` (serde snake_case):
///   `inspected`, `created`, `existing`, `replaced`, `replayed` (`refused` is
///   below);
/// * `mcp/tools/canvas.rs` and `mcp/kernel_v2/canvas*.rs`: `committed`,
///   `replayed`, `planned` (`conflict` and `rejected` are below);
/// * `mcp/tools/hcp/context_write.rs`: `proposed`, `accepted`, `superseded`
///   (`refused` and `unconfirmed` are below);
/// * `node/gate/queue.rs`: `already_applied` (a held write whose key hosted
///   had already applied);
/// * `migrations.rs`: `current`, `migrated` (`failed` is below).
///
/// An outcome in none of the three lists is not assumed to be success.
const OUTCOMES_OK: &[&str] = &[
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
];
/// Nothing was applied, or the call was invalid.
const OUTCOMES_REFUSED: &[&str] = &["refused", "not_sent", "failed", "rejected", "conflict"];
/// Whether anything was applied is not known.
const OUTCOMES_UNCERTAIN: &[&str] = &[
    "unknown",
    "uncertain",
    "partial",
    "unconfirmed",
    "indeterminate",
];

/// What a reply says about itself, gathered from the places the node, the
/// engine and hosted put it.
struct Signals<'a> {
    /// A JSON-RPC `error`.
    rpc_error: Option<&'a Value>,
    /// A JSON-RPC `result`.
    result: Option<&'a Value>,
    /// `result.isError` is true.
    is_error: bool,
    /// `outcome`, from the result's structured content or the error's data
    /// (or hosted's body inside it).
    outcome: Option<&'a str>,
    /// `applied`, from the same places.
    applied: Option<&'a Value>,
    /// `partial: true`.
    partial: bool,
    /// The node's `node_journal.outcome`.
    node_outcome: Option<&'a str>,
    /// A hosted gateway status carried by an error.
    http_status: Option<u64>,
    /// Hosted's `status` (`conflict`, `stale`, `rejected`) with its `act`.
    status: Option<&'a str>,
    act_committed: bool,
}

impl<'a> Signals<'a> {
    fn of(reply: &'a Value) -> Self {
        let rpc_error = reply.get("error").filter(|e| !e.is_null());
        let result = reply.get("result").filter(|r| r.is_object());
        // Bodies that carry markers, most specific first: a result's
        // structured content; an error's data; hosted's body inside it.
        let mut bodies: Vec<&Value> = Vec::new();
        if let Some(structured) = structured_of(reply) {
            bodies.push(structured);
        }
        if let Some(data) = rpc_error.and_then(|e| e.get("data")) {
            if data.is_object() {
                bodies.push(data);
            }
            if let Some(upstream) = data.get("upstream_body").filter(|b| b.is_object()) {
                bodies.push(upstream);
                if let Some(nested) = upstream.get("error").filter(|e| e.is_object()) {
                    bodies.push(nested);
                }
            }
            if let Some(original) = data.get("upstream_data").filter(|d| d.is_object()) {
                bodies.push(original);
            }
        }
        let field = |name: &str| bodies.iter().find_map(|body| body.get(name));
        let node_pointers = [
            "/error/data/node_journal",
            "/result/structuredContent/node_journal",
        ];
        Signals {
            rpc_error,
            result,
            is_error: result.and_then(|r| r.get("isError")) == Some(&Value::Bool(true)),
            outcome: field("outcome").and_then(Value::as_str),
            applied: field("applied").filter(|v| !v.is_null()),
            partial: field("partial") == Some(&Value::Bool(true)),
            node_outcome: node_pointers
                .iter()
                .find_map(|p| reply.pointer(p).and_then(|j| j.get("outcome")))
                .and_then(Value::as_str),
            http_status: rpc_error
                .and_then(|e| e.pointer("/data/http_status"))
                .and_then(Value::as_u64),
            status: field("status").and_then(Value::as_str),
            act_committed: field("act")
                .and_then(Value::as_i64)
                .is_some_and(|act| act > 0),
        }
    }

    fn outcome_in(&self, list: &[&str]) -> bool {
        self.outcome.is_some_and(|o| list.contains(&o))
    }

    fn applied_true(&self) -> bool {
        self.applied == Some(&Value::Bool(true))
    }
}

/// One classification rule: the first that gives an answer decides.
type Rule = (&'static str, fn(&Signals<'_>) -> Option<Kind>);

/// The classifier, as a table, in priority order. Success is the last row and
/// needs a result with no negative or unknown marker above it, whatever
/// `isError` says: the node and hosted both report refusals, unknown outcomes
/// and partial application in replies that are not flagged as errors.
const RULES: &[Rule] = &[
    // Accepted by the node (or by hosted, `canonical: false`), to be applied later.
    ("held", |s| {
        (s.outcome == Some("accepted_pending")).then_some(Kind::Held)
    }),
    // The node says an earlier attempt may have committed, whatever the final
    // reply (even a refusal) says.
    ("node_journal_uncertain", |s| {
        s.node_outcome
            .is_some_and(|o| OUTCOMES_UNCERTAIN.contains(&o))
            .then_some(Kind::Uncertain)
    }),
    // Neither a result nor an error: nothing to call a success.
    ("no_reply", |s| {
        (s.result.is_none() && s.rpc_error.is_none()).then_some(Kind::Uncertain)
    }),
    ("outcome_uncertain", |s| {
        s.outcome_in(OUTCOMES_UNCERTAIN).then_some(Kind::Uncertain)
    }),
    // `applied` as text (`"partial"`), or `partial: true`.
    ("applied_partial", |s| {
        (matches!(s.applied, Some(v) if !v.is_boolean()) || s.partial).then_some(Kind::Uncertain)
    }),
    // Hosted's staleness and unfinished rejections.
    ("status_stale", |s| {
        (s.status == Some("stale") || (s.status == Some("rejected") && !s.act_committed))
            .then_some(Kind::Uncertain)
    }),
    // Applied, and also refused: contradictory, so not known.
    ("contradiction", |s| {
        (s.applied_true()
            && (s.outcome_in(OUTCOMES_REFUSED)
                || s.status == Some("conflict")
                || s.rpc_error.is_some()))
        .then_some(Kind::Uncertain)
    }),
    // A gateway failure that is not a client error may have followed a commit.
    ("gateway_failure", |s| {
        s.http_status
            .filter(|status| !(400..500).contains(status))
            .map(|_| Kind::Uncertain)
    }),
    ("outcome_refused", |s| {
        s.outcome_in(OUTCOMES_REFUSED).then_some(Kind::Refused)
    }),
    ("conflict", |s| {
        (s.status == Some("conflict")).then_some(Kind::Refused)
    }),
    ("applied_false", |s| {
        (s.applied == Some(&Value::Bool(false))).then_some(Kind::Refused)
    }),
    // An outcome that is neither known good nor known bad is not success.
    ("outcome_unrecognised", |s| {
        s.outcome
            .is_some_and(|o| !OUTCOMES_OK.contains(&o))
            .then_some(Kind::Uncertain)
    }),
    ("rpc_error", |s| s.rpc_error.map(|_| Kind::Refused)),
    // Committed, but the receipt could not be rebuilt: it happened.
    ("applied_receipt_lost", |s| {
        (s.is_error && s.applied_true()).then_some(Kind::Ok)
    }),
    ("is_error", |s| s.is_error.then_some(Kind::Refused)),
    ("ok", |s| s.result.map(|_| Kind::Ok)),
];

/// How a reply is to be understood, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Verdict {
    kind: Kind,
    /// The rule that decided.
    rule: &'static str,
    /// The idempotency key the reply names: the write's own, or the node's.
    key: Option<String>,
    /// The reply says explicitly that nothing was applied (`not_sent`, or
    /// `applied: false`), the only case that may be called "nothing applied".
    nothing_applied: bool,
}

/// Classify a tool reply. Held: `accepted_pending`. Uncertain: an unknown,
/// uncertain or partial outcome, `applied` as text, a node journal note that
/// an earlier attempt may have committed, or no usable reply. Refused: a
/// refusal outcome, `applied: false`, a JSON-RPC error, or `isError`. Success
/// only when none of these says otherwise.
fn classify(reply: &Value) -> Verdict {
    let signals = Signals::of(reply);
    let (rule, kind) = RULES
        .iter()
        .find_map(|(name, rule)| rule(&signals).map(|kind| (*name, kind)))
        .unwrap_or(("unreadable", Kind::Uncertain));
    let key = [
        "/error/data/node_journal/idempotency_key",
        "/result/structuredContent/node_journal/idempotency_key",
        "/error/data/idempotency_key",
        "/result/structuredContent/idempotency_key",
    ]
    .iter()
    .find_map(|p| text_at(reply, p))
    .map(str::to_owned);
    Verdict {
        kind,
        rule,
        key,
        nothing_applied: signals.applied == Some(&Value::Bool(false))
            || signals.outcome == Some("not_sent"),
    }
}

/// The server's text form of a result.
fn text_form(reply: &Value) -> String {
    let blocks: Vec<&str> = reply
        .pointer("/result/content")
        .and_then(Value::as_array)
        .map(|blocks| {
            blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    blocks.join("\n")
}

/// The structured form of a result, as compact JSON. A result without
/// structured content is its JSON text when that parses, else `{"text": …}`.
fn json_form(reply: &Value) -> String {
    if let Some(structured) = structured_of(reply) {
        return structured.to_string();
    }
    let text = text_form(reply);
    match serde_json::from_str::<Value>(&text) {
        Ok(value) => value.to_string(),
        Err(_) => json!({ "text": text }).to_string(),
    }
}

/// A line of the server's message without the engine's wrapper prefix.
fn short_message(message: &str) -> String {
    let first = message.lines().next().unwrap_or(message);
    let first = first.strip_prefix("executor prototype ").unwrap_or(first);
    clean(first, 400)
}

/// Why a reply is not a success: short lines for stderr, ending in what to do
/// next where the reply says. Never the arguments, never credentials.
/// `call_key` is the `idempotency_key` the caller put in the call, if any.
fn explain(
    verdict: &Verdict,
    reply: &Value,
    executor: &str,
    operation: &str,
    call_key: Option<&str>,
) -> Vec<String> {
    let kind = verdict.kind;
    let label = match kind {
        Kind::Ok => "ok",
        Kind::Held => "held (accepted_pending)",
        Kind::Refused => "refused",
        Kind::Uncertain => "uncertain",
    };
    let signals = Signals::of(reply);
    let structured = structured_of(reply);
    let field = |pointer: &str| structured.and_then(|s| text_at(s, pointer));
    let mut lines = Vec::new();

    // The reason, from the reply's own words.
    let reason = if let Some(error) = signals.rpc_error {
        short_message(
            error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("the server returned an error"),
        )
    } else if let Some(message) = field("/error") {
        short_message(message)
    } else if kind == Kind::Uncertain && signals.result.is_none() {
        "the reply carried no result".to_owned()
    } else if let Some(outcome) = signals.outcome {
        match field("/refusal") {
            Some(why) => format!(
                "the server reported the outcome '{}' ({})",
                clean(outcome, 60),
                clean(why, 80)
            ),
            None => format!("the server reported the outcome '{}'", clean(outcome, 60)),
        }
    } else {
        short_message(&text_form(reply))
    };
    match kind {
        Kind::Held => {
            let why = field("/reason").unwrap_or("hosted cannot take writes now");
            lines.push(format!(
                "{label}: the node is holding this write and will send it when hosted can take it ({})",
                clean(why, 80)
            ));
        }
        _ => lines.push(format!("{label}: {reason}")),
    }

    // Codes.
    let class = field("/repair/error_class");
    let code_parts: Vec<&str> = [
        field("/error_code").or(field("/repair/code")),
        class,
        field("/repair/reason_code"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if let Some(error) = signals.rpc_error {
        if let Some(code) = text_at(error, "/data/outcome") {
            lines.push(format!("  code: {code}"));
        } else if let Some(code) = error.get("code").and_then(Value::as_i64) {
            lines.push(format!("  code: jsonrpc {code}"));
        }
    } else if !code_parts.is_empty() {
        lines.push(format!("  code: {}", code_parts.join("/")));
    } else if let Some(outcome) = signals.outcome {
        lines.push(format!("  code: {outcome}"));
    } else if signals.applied.is_some() {
        lines.push(format!(
            "  code: applied={}",
            clean(
                &signals.applied.map(Value::to_string).unwrap_or_default(),
                40
            )
        ));
    }
    if let Some(pointer) = field("/repair/failing_pointer") {
        lines.push(format!("  at: {}", clean(pointer, 120)));
    }
    if class == Some("validation_failure") {
        if let Some(shape) = structured.and_then(|s| s.pointer("/repair/expected_shape")) {
            lines.push(format!("  expected: {}", clean(&shape.to_string(), 300)));
        }
    }

    // Held writes: where they are.
    if kind == Kind::Held {
        for (pointer, name) in [
            ("/idempotency_key", "idempotency_key"),
            ("/record_id", "record_id"),
            ("/target_record_id", "target_record_id"),
            ("/journal_entry", "journal_entry"),
        ] {
            if let Some(value) = field(pointer) {
                lines.push(format!("  {name}: {}", clean(value, 120)));
            }
        }
        if structured.and_then(|s| s.get("may_already_be_applied")) == Some(&Value::Bool(true)) {
            lines.push("  note: an earlier attempt may already have been applied".to_owned());
        }
        lines.push(
            "  next: repeat the same call with the same idempotency_key to see whether it was delivered ('pending' until then)".to_owned(),
        );
        return lines;
    }

    // The key a retry must reuse.
    let key = verdict.key.as_deref().or(call_key);
    if let Some(journal) = [
        "/error/data/node_journal",
        "/result/structuredContent/node_journal",
    ]
    .iter()
    .find_map(|p| reply.pointer(p))
    {
        for (pointer, name) in [
            ("/journal_entry", "journal_entry"),
            ("/attempts", "attempts"),
        ] {
            if let Some(value) = journal.pointer(pointer) {
                lines.push(format!(
                    "  {name}: {}",
                    clean(
                        &value
                            .as_str()
                            .map_or_else(|| value.to_string(), str::to_owned),
                        80
                    )
                ));
            }
        }
        if let Some(origin) = text_at(journal, "/key_origin") {
            lines.push(format!("  key_origin: {}", clean(origin, 20)));
        }
    } else if let Some(entry) = signals
        .rpc_error
        .and_then(|e| text_at(e, "/data/journal_entry"))
    {
        lines.push(format!("  journal_entry: {}", clean(entry, 120)));
    }
    if let Some(key) = key {
        lines.push(format!("  idempotency_key: {}", clean(key, 120)));
    }

    if let Some(retry) = signals.rpc_error.and_then(|e| text_at(e, "/data/retry")) {
        lines.push(format!("  next: {}", clean(retry, 400)));
    }
    if let Some(recovery) = field("/recovery") {
        lines.push(format!("  next: {}", clean(recovery, 300)));
    }

    // Retryability, said only as far as the reply supports it.
    let retryable = structured.and_then(|s| s.get("retryable")) == Some(&Value::Bool(true));
    if retryable {
        if verdict.nothing_applied && kind == Kind::Refused {
            lines.push("  retryable: yes (the reply says nothing was applied)".to_owned());
        } else if let Some(key) = key {
            lines.push(format!(
                "  retryable: only with the same idempotency_key ({}); it may already have been applied",
                clean(key, 120)
            ));
        } else {
            lines.push(
                "  retryable: not safely: it may already have been applied and the reply names no idempotency_key; read the record first".to_owned(),
            );
        }
    }

    if kind == Kind::Uncertain {
        let earlier = signals
            .node_outcome
            .is_some_and(|o| OUTCOMES_UNCERTAIN.contains(&o));
        if earlier {
            lines.push(
                "  note: an earlier attempt of this write may have been applied, whatever the final reply says".to_owned(),
            );
        }
        match key {
            Some(key) => lines.push(format!(
                "  next: retry with this same key: add \"idempotency_key\":\"{}\" to the arguments and repeat the call (hosted applies a key once). Never use a fresh key, which could apply the write twice. Or read the record to check first",
                clean(key, 120)
            )),
            None => lines.push(
                "  next: the write may have been applied. Read the record to check before repeating it; if the operation takes an idempotency_key, set one so a repeat is safe".to_owned(),
            ),
        }
    } else if run_key_refusal(reply) {
        lines.push(
            "  next: this server wants a run key issued by bootstrap: pass --run-key <key> (or set NATIVE_RUN_KEY)".to_owned(),
        );
    } else if structured.and_then(|s| s.get("repair")).is_some()
        && !executor.is_empty()
        && !operation.is_empty()
    {
        lines.push(format!(
            "  next: native call --describe {executor} {operation}"
        ));
    }
    lines
}

/// Whether a refusal says the call needs a (valid) run key. The server has no
/// stable code for it: `manage_instructions.resolve`, `record_progress` and
/// the kernel-v2 coordination calls refuse with plain engine errors ("... requires
/// an existing run_key; pass the run_key from bootstrap on this call", "...
/// requires Bootstrap's exact run_key", "... requires a full run_key from
/// bootstrap or run_key='new'"). A code or repair marker naming `run_key`
/// is honoured if one ever appears; the wording is the fallback.
fn run_key_refusal(reply: &Value) -> bool {
    let signals = Signals::of(reply);
    if signals.rpc_error.is_none() && !signals.is_error {
        return false;
    }
    let structured = structured_of(reply);
    let marker = [
        structured.and_then(|s| text_at(s, "/error_code")),
        structured.and_then(|s| text_at(s, "/repair/reason_code")),
        signals.rpc_error.and_then(|e| text_at(e, "/data/code")),
        signals
            .rpc_error
            .and_then(|e| text_at(e, "/data/error_code")),
    ]
    .into_iter()
    .flatten()
    .any(|code| code.to_lowercase().contains("run_key"));
    if marker {
        return true;
    }
    let message = signals
        .rpc_error
        .and_then(|e| e.get("message").and_then(Value::as_str))
        .or_else(|| structured.and_then(|s| text_at(s, "/error")))
        .unwrap_or("")
        .to_lowercase();
    message.contains("run_key")
        && ["requires", "required", "missing", "must"]
            .iter()
            .any(|word| message.contains(word))
}

/// A run-key refusal that is safe to answer by bootstrapping and trying the
/// call again: the server refused before executing anything. The reply must
/// name no outcome (or `not_sent`), no `applied` (or `applied: false`), no
/// partial application and no node journal note; and it must not be held or
/// uncertain by the classifier.
fn run_key_retry_is_safe(reply: &Value) -> bool {
    if !run_key_refusal(reply) {
        return false;
    }
    let signals = Signals::of(reply);
    let verdict = classify(reply);
    verdict.kind == Kind::Refused
        && matches!(signals.outcome, None | Some("not_sent"))
        && matches!(signals.applied, None | Some(Value::Bool(false)))
        && !signals.partial
        && signals.node_outcome.is_none()
}

// ---- sessions ------------------------------------------------------------------------------

/// The node's socket, and what is needed to open it again.
struct NodeLink {
    connection: Connection,
    config_path: PathBuf,
    socket: PathBuf,
    timeout: Duration,
}

impl NodeLink {
    async fn connect(
        config_path: &Path,
        socket: &Path,
        timeout: Duration,
    ) -> Result<Connection, String> {
        let detail = |info: super::node_client::NodeInfo| info.detail.unwrap_or_default();
        let mut connection =
            Connection::open("native", config_path, socket, timeout, &Limits::standard())
                .await
                .map_err(detail)?;
        connection
            .initialize("native-cli", "2025-06-18")
            .await
            .map_err(detail)?;
        Ok(connection)
    }
}

enum Session {
    Node(Box<NodeLink>),
    #[cfg(feature = "mcp-executor-prototype")]
    Local(Box<super::LocalExecutor>),
    /// A scripted server, for tests of replies no real server gives.
    #[cfg(test)]
    Scripted(Box<dyn FnMut(Value) -> Option<Value> + Send>),
}

impl Session {
    async fn open(backend: &Backend, timeout: Duration) -> Result<Self, String> {
        match backend {
            Backend::Node { config_dir } => {
                let dir = config_dir
                    .clone()
                    .or_else(super::login::default_config_dir)
                    .ok_or_else(|| {
                        "cannot find the config directory; set HOME or pass --config-dir".to_owned()
                    })?;
                let config_path = dir.join(super::setup::NODE_FILE);
                let detail = |info: super::node_client::NodeInfo| info.detail.unwrap_or_default();
                let config = super::node_client::read_config(&config_path).map_err(detail)?;
                let socket = config.socket_path();
                let connection = NodeLink::connect(&config_path, &socket, timeout).await?;
                Ok(Session::Node(Box::new(NodeLink {
                    connection,
                    config_path,
                    socket,
                    timeout,
                })))
            }
            Backend::Local { db } => Self::open_local(db.as_deref()).await,
        }
    }

    #[cfg(feature = "mcp-executor-prototype")]
    async fn open_local(db: Option<&std::path::Path>) -> Result<Self, String> {
        let path = db
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(super::default_local_db_path);
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|error| {
                    format!(
                        "cannot create the database directory {} ({})",
                        parent.display(),
                        super::node_client::io_kind(&error)
                    )
                })?;
        }
        let (surface, _profile, experimental) = super::resolve_local_stdio_env()?;
        let executor = super::LocalExecutor::open(&path.to_string_lossy(), surface, experimental)
            .await
            .map_err(|error| error.to_string())?;
        let session = Session::Local(Box::new(executor));
        Ok(session)
    }

    #[cfg(not(feature = "mcp-executor-prototype"))]
    async fn open_local(_db: Option<&std::path::Path>) -> Result<Self, String> {
        Err("this build has no local executor surface".to_owned())
    }

    /// Send one JSON-RPC request and wait for its reply. `Err` is a transport
    /// failure: the reply never came.
    async fn request(&mut self, message: Value) -> Result<Value, String> {
        match self {
            Session::Node(link) => {
                // A connection that failed or timed out may still have a reply
                // on its way, which must not be taken for the next request's:
                // never reuse it. Open another.
                if link.connection.is_spent() {
                    link.connection =
                        NodeLink::connect(&link.config_path, &link.socket, link.timeout).await?;
                }
                link.connection.exchange(message, false).await
            }
            #[cfg(feature = "mcp-executor-prototype")]
            Session::Local(executor) => executor
                .handle(message)
                .await
                .ok_or_else(|| "the server sent no reply".to_owned()),
            #[cfg(test)]
            Session::Scripted(script) => {
                script(message).ok_or_else(|| "the node closed the connection".to_owned())
            }
        }
    }

    async fn close(self) {
        #[cfg(feature = "mcp-executor-prototype")]
        if let Session::Local(executor) = self {
            executor.close().await;
        }
    }
}

/// What `tools/list` says is advertised: tool name to its `operation` enum
/// (`None` when the tool takes no operation).
struct Tools(BTreeMap<String, Option<BTreeSet<String>>>);

impl Tools {
    fn from_reply(reply: &Value) -> Self {
        let mut tools = BTreeMap::new();
        for tool in reply
            .pointer("/result/tools")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                continue;
            };
            let operations = tool
                .pointer("/inputSchema/properties/operation/enum")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                });
            tools.insert(name.to_owned(), operations);
        }
        Tools(tools)
    }

    /// The operation is advertised directly under the executor's own tool.
    fn direct(&self, executor: &str, operation: &str) -> bool {
        matches!(self.0.get(executor), Some(Some(ops)) if ops.contains(operation))
    }

    fn has(&self, name: &str) -> bool {
        self.0.contains_key(name)
    }
}

/// A command that stopped before it had a reply to classify.
struct Failure(Report);

struct Client<'a> {
    session: Session,
    invocation: &'a Invocation,
    tools: Option<Tools>,
    run_key: Option<String>,
    /// Notes for stderr that are not part of any one reply (a fresh run key).
    notes: Vec<String>,
    next_id: u64,
    /// Whether each operation may change anything, from the catalogue.
    mutations: BTreeMap<(String, String), bool>,
}

impl<'a> Client<'a> {
    fn next_id(&mut self) -> u64 {
        self.next_id += 1;
        self.next_id
    }

    /// One `tools/call`. A transport failure is unreachable (exit 2) for a read
    /// and uncertain (exit 5) for a call that may have been a write.
    async fn tools_call(
        &mut self,
        name: &str,
        arguments: Value,
        may_write: bool,
    ) -> Result<Value, Failure> {
        let id = self.next_id();
        let message = json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":name,"arguments":arguments}});
        self.session.request(message).await.map_err(|why| {
            Failure(if may_write {
                Report::failed(
                    EXIT_UNCERTAIN,
                    format!(
                        "uncertain: {why}; the call may or may not have been applied. Read the record to check before repeating a write (an idempotency_key makes a repeat safe)"
                    ),
                )
            } else {
                Report::unreachable(why)
            })
        })
    }

    async fn tools(&mut self) -> Result<&Tools, Failure> {
        if self.tools.is_none() {
            let id = self.next_id();
            let message = json!({"jsonrpc":"2.0","id":id,"method":"tools/list"});
            let reply = self
                .session
                .request(message)
                .await
                .map_err(|why| Failure(Report::unreachable(why)))?;
            if reply.get("error").is_some() {
                return Err(Failure(Report::unreachable(
                    "the server could not list its tools",
                )));
            }
            self.tools = Some(Tools::from_reply(&reply));
        }
        Ok(self.tools.as_ref().expect("tools were just listed"))
    }

    /// The run key to use, bootstrapping once (and saying so) if asked to.
    async fn bootstrap(&mut self) -> Result<String, Failure> {
        let reply = self
            .tools_call("bootstrap", json!({"format":"json"}), false)
            .await?;
        let key = structured_of(&reply)
            .and_then(|s| text_at(s, "/run/run_key").or_else(|| text_at(s, "/session/run_key")))
            .map(str::to_owned);
        let Some(key) = key else {
            return Err(Failure(Report::failed(
                EXIT_REFUSED,
                "the server needs a run key and bootstrap did not issue one",
            )));
        };
        self.notes.push(format!(
            "run key: {key} (reuse it with --run-key {key} or NATIVE_RUN_KEY={key})"
        ));
        Ok(key)
    }

    /// Whether an operation may change anything, from the catalogue's
    /// `access` (`read` is the only access that cannot). An operation the
    /// catalogue does not classify, or a catalogue that cannot be read, counts
    /// as a possible write: a lost reply is then uncertain, not unreachable.
    async fn may_write(&mut self, executor: &str, operation: &str) -> bool {
        let key = (executor.to_owned(), operation.to_owned());
        if let Some(known) = self.mutations.get(&key) {
            return *known;
        }
        let plain = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        };
        let mut write = true;
        if plain(executor) && plain(operation) {
            let sql = format!(
                "SELECT access FROM catalog_operations WHERE executor = '{executor}' AND operation = '{operation}'"
            );
            if let Ok(reply) = self
                .send("sql_read", "query_sql", json!({ "sql": sql }), false, true)
                .await
            {
                let access = structured_of(&reply)
                    .filter(|_| classify(&reply).kind == Kind::Ok)
                    .and_then(|s| s.pointer("/rows/0/access"))
                    .and_then(Value::as_str);
                write = access != Some("read");
            }
        }
        self.mutations.insert(key, write);
        write
    }

    /// Route one operation to the tool that advertises it, or to
    /// `call_executor`, and return the raw reply. Whether a lost reply is
    /// uncertain follows the operation's catalogue classification.
    async fn invoke(
        &mut self,
        executor: &str,
        operation: &str,
        arguments: Value,
        want_json: bool,
    ) -> Result<Value, Failure> {
        let may_write = self.may_write(executor, operation).await;
        self.send(executor, operation, arguments, may_write, want_json)
            .await
    }

    async fn send(
        &mut self,
        executor: &str,
        operation: &str,
        arguments: Value,
        may_write: bool,
        want_json: bool,
    ) -> Result<Value, Failure> {
        let direct = self.tools().await?.direct(executor, operation);
        let call_executor = !direct && self.tools().await?.has("call_executor");
        let build = |client: &Self| {
            let mut envelope = Map::new();
            if call_executor {
                envelope.insert("executor".into(), json!(executor));
            }
            envelope.insert("operation".into(), json!(operation));
            envelope.insert("arguments".into(), arguments.clone());
            if let Some(key) = &client.run_key {
                envelope.insert("run_key".into(), json!(key));
            }
            if want_json || !client.invocation.text {
                envelope.insert("format".into(), json!("json"));
            }
            Value::Object(envelope)
        };
        let tool = if call_executor {
            "call_executor"
        } else {
            executor
        };
        let reply = self.tools_call(tool, build(self), may_write).await?;
        // Only a refusal made before anything ran may be answered by a
        // bootstrap and a second try; never an unknown, uncertain, applied or
        // partial result.
        if self.run_key.is_none() && run_key_retry_is_safe(&reply) {
            let key = self.bootstrap().await?;
            self.run_key = Some(key);
            return self.tools_call(tool, build(self), may_write).await;
        }
        Ok(reply)
    }

    async fn describe(&mut self, executor: &str, operation: &str) -> Result<Value, Failure> {
        self.tools_call(
            "describe_operation",
            json!({"executor":executor,"operation":operation}),
            false,
        )
        .await
    }
}

// ---- running a command -----------------------------------------------------------------------

/// Turn one reply into a report. `call_key` is the `idempotency_key` the
/// caller put in the call, if any.
fn report_of(
    reply: &Value,
    invocation: &Invocation,
    executor: &str,
    operation: &str,
    call_key: Option<&str>,
) -> Report {
    let verdict = classify(reply);
    let kind = verdict.kind;
    let mut report = Report {
        exit: kind.exit(),
        ..Report::default()
    };
    let show = matches!(kind, Kind::Ok | Kind::Held) && reply.get("result").is_some();
    if show {
        let body = if invocation.text {
            text_form(reply)
        } else {
            json_form(reply)
        };
        report.stdout = format!("{body}\n");
    }
    if kind != Kind::Ok {
        for line in explain(&verdict, reply, executor, operation, call_key) {
            report
                .stderr
                .push_str(&format!("native: {line}\n").replacen("native:   ", "  ", 1));
        }
    } else if reply.pointer("/result/isError") == Some(&Value::Bool(true)) {
        // Committed, receipt not rebuilt: still a success, with a note.
        report.stderr.push_str(
            "native: applied, but the receipt could not be rebuilt; repeat the call with the same idempotency_key to get it\n",
        );
    }
    report
}

const CATALOG_SQL: &str =
    "SELECT executor, operation, access, plan_required FROM catalog_operations";

async fn list_operations(
    client: &mut Client<'_>,
    executor: Option<&str>,
) -> Result<Report, Failure> {
    let mut sql = CATALOG_SQL.to_owned();
    if let Some(executor) = executor {
        let plain = !executor.is_empty()
            && executor
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if !plain {
            return Ok(Report::failed(
                EXIT_UNREACHABLE,
                "the executor name to filter by may contain only letters, digits, _ . -",
            ));
        }
        sql.push_str(&format!(" WHERE executor = '{executor}'"));
    }
    sql.push_str(" ORDER BY executor, operation");
    let reply = client
        .send("sql_read", "query_sql", json!({ "sql": sql }), false, true)
        .await?;
    if classify(&reply).kind != Kind::Ok {
        return Ok(report_of(
            &reply,
            client.invocation,
            "sql_read",
            "query_sql",
            None,
        ));
    }
    let rows = structured_of(&reply)
        .and_then(|s| s.get("rows"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let truncated =
        structured_of(&reply).and_then(|s| s.get("truncated")) == Some(&Value::Bool(true));
    // One entry per operation: its access, with `+plan` when a write must be
    // planned first. How a call reaches it (an advertised tool or
    // `call_executor`) is `native`'s business, not the caller's.
    let mut by_executor: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    let mut count = 0;
    for row in &rows {
        let executor = row.get("executor").and_then(Value::as_str).unwrap_or("");
        let operation = row.get("operation").and_then(Value::as_str).unwrap_or("");
        let planned = row
            .get("plan_required")
            .is_some_and(|v| v.as_i64() == Some(1) || v == &Value::Bool(true));
        let access = format!(
            "{}{}",
            row.get("access").and_then(Value::as_str).unwrap_or("?"),
            if planned { "+plan" } else { "" }
        );
        by_executor
            .entry(executor.to_owned())
            .or_default()
            .insert(operation.to_owned(), json!(access));
        count += 1;
    }
    let body = if client.invocation.text {
        let mut text = String::new();
        for (executor, operations) in &by_executor {
            for (operation, access) in operations {
                text.push_str(&format!(
                    "{executor}.{operation}  {}\n",
                    access.as_str().unwrap_or("?")
                ));
            }
        }
        text
    } else {
        format!("{}\n", json!({"count": count, "executors": by_executor}))
    };
    let mut report = Report {
        exit: EXIT_OK,
        stdout: body,
        stderr: String::new(),
    };
    if truncated {
        report
            .stderr
            .push_str("native: the catalogue listing was truncated by the server; filter with `native call --list <executor>`\n");
    }
    Ok(report)
}

async fn run_action(client: &mut Client<'_>) -> Result<Report, Failure> {
    let invocation = client.invocation;
    match &invocation.action {
        Action::List { executor } => list_operations(client, executor.as_deref()).await,
        Action::Describe {
            executor,
            operation,
        } => {
            let reply = client.describe(executor, operation).await?;
            Ok(report_of(&reply, invocation, executor, operation, None))
        }
        Action::Call {
            executor,
            operation,
            arguments,
        } => {
            let reply = client
                .invoke(executor, operation, arguments.clone(), false)
                .await?;
            let key = arguments.get("idempotency_key").and_then(Value::as_str);
            Ok(report_of(&reply, invocation, executor, operation, key))
        }
        Action::Search { query, limit } => {
            let mut arguments = json!({ "query": query });
            if let Some(limit) = limit {
                arguments["limit"] = json!(limit);
            }
            let reply = client
                .invoke("records_read", "search", arguments, false)
                .await?;
            Ok(report_of(
                &reply,
                invocation,
                "records_read",
                "search",
                None,
            ))
        }
        Action::Get { refs } => {
            let reply = client
                .invoke("records_read", "get_record", json!({ "ids": refs }), false)
                .await?;
            let mut report = report_of(&reply, invocation, "records_read", "get_record", None);
            if report.exit == EXIT_OK {
                let text = text_form(&reply);
                let missing: Vec<String> = if invocation.text {
                    refs.iter()
                        .filter(|r| {
                            text.lines()
                                .any(|line| line.trim_end() == format!("{r}  NOT FOUND"))
                        })
                        .map(|r| clean(r, 80))
                        .collect()
                } else {
                    structured_of(&reply)
                        .and_then(|s| s.get("records"))
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter(|r| r.get("status").and_then(Value::as_str) != Some("found"))
                        .map(|r| clean(r.get("id").and_then(Value::as_str).unwrap_or("?"), 80))
                        .collect()
                };
                if !missing.is_empty() {
                    report.exit = EXIT_REFUSED;
                    report.stderr.push_str(&format!(
                        "native: not found: {} (find it with `native search <words>`)\n",
                        missing.join(", ")
                    ));
                }
            }
            Ok(report)
        }
        Action::Sql { query, parameters } => {
            let mut arguments = json!({ "sql": query });
            if !parameters.is_empty() {
                arguments["parameters"] = json!(parameters);
            }
            let reply = client
                .invoke("sql_read", "query_sql", arguments, false)
                .await?;
            Ok(report_of(&reply, invocation, "sql_read", "query_sql", None))
        }
    }
}

/// Run one command to completion and report what it produced.
pub async fn execute(invocation: &Invocation) -> Report {
    let session = match Session::open(&invocation.backend, invocation.timeout).await {
        Ok(session) => session,
        Err(why) => {
            let mut message = why;
            if matches!(invocation.backend, Backend::Node { .. }) {
                message.push_str(
                    "\nnative: for a local database that needs no node, add --local <db> (for example `--local ./notes.db`)",
                );
            }
            return Report::unreachable(message);
        }
    };
    let mut client = Client {
        session,
        invocation,
        tools: None,
        run_key: invocation.run_key.clone(),
        notes: Vec::new(),
        next_id: 1,
        mutations: BTreeMap::new(),
    };
    let mut report = match run_action(&mut client).await {
        Ok(report) => report,
        Err(Failure(report)) => report,
    };
    let notes = std::mem::take(&mut client.notes);
    client.session.close().await;
    for note in notes {
        report.stderr.insert_str(0, &format!("native: {note}\n"));
    }
    report
}

// ---- the binary's entry point ---------------------------------------------------------------

/// Run `native call|search|get|sql` with its arguments (after the command
/// word), printing to stdout and stderr, and return the exit code.
pub fn main(command: Command, args: &[String]) -> u8 {
    let env_run_key = std::env::var(ENV_RUN_KEY).ok();
    let invocation = match parse(command, args, env_run_key) {
        Parsed::Help => {
            println!("{}", usage(command));
            return EXIT_OK;
        }
        Parsed::Usage(message) => {
            eprintln!(
                "{}: {message}\n{}\nrun `{} --help` for examples",
                command.name(),
                synopsis(command),
                command.name()
            );
            return EXIT_UNREACHABLE;
        }
        Parsed::Run(invocation) => invocation,
    };
    if matches!(invocation.backend, Backend::Local { .. }) {
        // Owner-only database files, as `native mcp --local` makes them: set
        // before the engine creates the database and its sidecar files.
        // SAFETY: no other thread exists yet (the runtime is built below).
        unsafe {
            libc::umask(0o077);
        }
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("native: cannot start runtime: {error}");
            return EXIT_UNREACHABLE;
        }
    };
    let report = runtime.block_on(execute(&invocation));
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(report.stdout.as_bytes());
    let _ = std::io::stderr().write_all(report.stderr.as_bytes());
    report.exit
}

// ---- help --------------------------------------------------------------------------------------

const COMMON_OPTIONS: &str = "\
common options:
  --local [<db>]      use a local SQLite database in this process instead of the node
                      (created if missing; default ~/.local/share/native/local.db).
                      Give the path right after --local, or write --local=<db>.
  --config-dir <dir>  hosted mode: where node.json is (default ~/.config/native)
  --run-key <key>     attach the call to a run (or set NATIVE_RUN_KEY); optional
  --text              print the server's text form instead of JSON
  --timeout <secs>    how long to wait for the node or a reply (default 60)

output: JSON on stdout (the result's structured content); --text for the server's text.
Results say the call is 'not attached to a run': ignore that, no run key is needed.
Errors go to stderr as a short reason, the server's code and a next step. Nothing secret
is ever printed.

exit codes:
  0  success
  2  cannot reach the node, bad configuration or a malformed command line
  3  held: accepted_pending - the write is accepted and will be applied later
  4  refused or invalid (validation error, not found, nothing was applied)
  5  uncertain - the write may or may not have been applied; read first, or repeat with the same idempotency_key";

pub fn synopsis(command: Command) -> &'static str {
    match command {
        Command::Call => "usage: native call <executor> <operation> [<json-args>] [--args-file <path|->] [options]\n       native call --list [<executor>]\n       native call --describe <executor> <operation>",
        Command::Search => "usage: native search <words...> [--limit N] [options]",
        Command::Get => "usage: native get <ref>... [options]",
        Command::Sql => "usage: native sql <query> [--param <value>]... [options]",
    }
}

pub fn usage(command: Command) -> String {
    let body = match command {
        Command::Call => "\
Call any Native operation. Find the operations with --list, see one's arguments with
--describe, then call it with its arguments as a JSON object.

  native call --list                       every operation by executor, with read / mutation (+plan)
  native call --list records_write         only one executor's operations
  native call --describe records_write create_record     the arguments it takes (JSON schema)

examples:
  native call records_write create_record '{\"type\":\"Document\",\"kind\":\"note\",\"name\":\"Plan\",\"body\":\"Ship it\",\"reason\":\"capture the plan\"}' --local ./notes.db
  native call records_write manage_links.add '{\"source_id\":\"<id>\",\"target_id\":\"<id>\",\"relationship\":\"relates_to\"}' --local ./notes.db
  echo '{\"query\":\"plan\"}' | native call records_read search --args-file - --local ./notes.db

The JSON arguments are the operation's own arguments: an object, as one quoted argument.
Do not nest run_key or format in them. An unknown operation or a bad argument is refused
with exit 4 and a pointer to --describe. A write the node cannot send yet is held (exit 3)
and delivered later; repeat the call with the idempotency_key shown to check on it.",
        Command::Search => "\
Search records by words (all words must match).

examples:
  native search launch plan --local ./notes.db
  native search onboarding --limit 5
  native search \"release notes\" --text

Each hit has an id and short display_reference; open one with `native get <ref>`.",
        Command::Get => "\
Open one or more records by id or short reference (from search results).

examples:
  native get 5c64def --local ./notes.db
  native get 5c64def 8c0fef1 --text

A reference that does not exist exits 4. For other reads use `native sql` or `native call --list`.",
        Command::Sql => "\
Run one read-only SQL query (SELECT or WITH) over your records.

examples:
  native sql \"SELECT id, name, type FROM records ORDER BY id LIMIT 10\" --local ./notes.db
  native sql \"SELECT id, name FROM records WHERE name LIKE ?1\" --param '%plan%'
  native sql \"SELECT operation, access FROM catalog_operations WHERE executor = ?1 ORDER BY operation\" --param records_write

--param values bind to the positional placeholders ?1, ?2, ... in order (a bare ? is not accepted). A value that is valid JSON (42, true, null,
\"text\") keeps that type; anything else is text. Use ORDER BY with LIMIT.

Discover what you can query:
  native sql \"SELECT relation_name FROM catalog_relations ORDER BY 1\"
  native sql \"SELECT column_name FROM catalog_columns WHERE relation_name = 'records' ORDER BY column_position\"
More: `native call guidance_read read_guide '{\"topic\":\"query-sql\"}'`.",
    };
    format!("{}\n\n{body}\n\n{COMMON_OPTIONS}", synopsis(command))
}

#[cfg(test)]
pub(crate) mod tests;
