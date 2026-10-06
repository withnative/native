//! Fresh-agent harness for the v2 kernel generic contract.
//!
//! Requires `--features v2-kernel-probe`. No ontology knowledge lives here:
//! fixtures arrive as JSON files at runtime. Stdout carries JSON only —
//! every failure (usage or engine, including the uniform refusal) prints
//! `{"error": "<message>"}` and exits nonzero.
//!
//! `v2_contract --db <file> --as <auth_binding> <subcommand> [--key value]...`
//! Subcommands match the operation names `describe` advertises, plus the
//! admin set needed to build a world: `init`, `principal`, `home`, `grant`,
//! `install`, `adopt`, `disable`, `package-install`, `package-adopt`,
//! `package-disable`, `consumer-register`, `consumer-retire`,
//! `package-preview-adopt`, `package-preview-disable`,
//! `definition-preview-adopt`, `definition-preview-disable`, `describe`,
//! `create`, `link`, `query`, `consumer-list`, `package-surface-read`,
//! `revise`, `read`, `history`.
//! JSON payloads come from `--json <file | ->`. Package manifests arrive as
//! the canonical manifest JSON value (`native.package-manifest@1`).
//! Consumer commands call `native_ce::dependency` (preview, register,
//! retire, list); definition previews take `--scope` or `--global true`.

use native_ce::db::Db;
use native_ce::kernel;
use std::collections::HashMap;
use std::process::ExitCode;

struct Args {
    db: String,
    as_binding: Option<String>,
    cmd: String,
    flags: HashMap<String, String>,
}

fn fail(message: String) -> ! {
    println!("{}", serde_json::json!({"error": message}));
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut raw = std::env::args().skip(1);
    let mut db = None;
    let mut as_binding = None;
    let mut cmd = None;
    let mut flags = HashMap::new();
    while let Some(arg) = raw.next() {
        if arg == "--db" {
            db = raw.next();
        } else if arg == "--as" {
            as_binding = raw.next();
        } else if arg.starts_with("--") {
            let key = arg.trim_start_matches('-').to_string();
            let value = raw
                .next()
                .unwrap_or_else(|| fail(format!("missing value for --{key}")));
            flags.insert(key, value);
        } else if cmd.is_none() {
            cmd = Some(arg);
        } else {
            fail(format!("unexpected argument '{arg}'"));
        }
    }
    Args {
        db: db.unwrap_or_else(|| fail("missing --db <file>".to_string())),
        as_binding,
        cmd: cmd.unwrap_or_else(|| fail("missing <subcommand>".to_string())),
        flags,
    }
}

fn flag(args: &Args, name: &str) -> String {
    args.flags
        .get(name)
        .cloned()
        .unwrap_or_else(|| fail(format!("missing --{name}")))
}

fn read_json_bytes(args: &Args) -> Vec<u8> {
    let from = flag(args, "json");
    if from == "-" {
        let mut buf = Vec::new();
        use std::io::Read as _;
        std::io::stdin()
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| fail(e.to_string()));
        buf
    } else {
        std::fs::read(&from).unwrap_or_else(|e| fail(format!("cannot read {from}: {e}")))
    }
}

fn read_json_value(args: &Args) -> serde_json::Value {
    let bytes = read_json_bytes(args);
    serde_json::from_slice(&bytes).unwrap_or_else(|e| fail(format!("invalid JSON: {e}")))
}

fn read_json_object(args: &Args) -> serde_json::Map<String, serde_json::Value> {
    match read_json_value(args) {
        serde_json::Value::Object(map) => map,
        _ => fail("--json must hold a JSON object".to_string()),
    }
}

fn read_manifest(args: &Args) -> native_ce::package_manifest::PackageManifest {
    let value = read_json_value(args);
    native_ce::package_manifest::PackageManifest::from_canonical_value(&value)
        .unwrap_or_else(|e| fail(e.to_string()))
}

fn read_u32(args: &Args, name: &str) -> u32 {
    flag(args, name)
        .parse()
        .unwrap_or_else(|_| fail(format!("bad --{name}")))
}

fn preview_scope(args: &Args) -> Option<String> {
    if args.flags.get("global").is_some_and(|v| v == "true") {
        return None;
    }
    Some(flag(args, "scope"))
}

fn read_expected_seq(args: &Args) -> Option<i64> {
    args.flags.get("expected-seq").map(|s| {
        s.parse()
            .unwrap_or_else(|_| fail("bad --expected-seq".to_string()))
    })
}

fn read_ack_reads(args: &Args) -> Vec<String> {
    let raw = flag(args, "ack-reads");
    let parsed: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| fail(format!("bad --ack-reads: {e}")));
    let items = parsed
        .as_array()
        .unwrap_or_else(|| fail("bad --ack-reads: must be a JSON array of strings".to_string()));
    items
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| {
                    fail("bad --ack-reads: must be a JSON array of strings".to_string())
                })
                .to_string()
        })
        .collect()
}

async fn open_db(args: &Args) -> Db {
    native_ce::db::open_database(&args.db)
        .await
        .unwrap_or_else(|e| fail(e.to_string()))
}

async fn caller_id(db: &Db, args: &Args) -> String {
    let binding = args
        .as_binding
        .clone()
        .unwrap_or_else(|| fail("missing --as <auth_binding>".to_string()));
    kernel::resolve_principal_by_binding(db, &binding)
        .await
        .unwrap_or_else(|e| fail(e.to_string()))
        .map(|(id, _, _)| id)
        .unwrap_or_else(|| fail("unknown auth binding".to_string()))
}

fn grants_from(value: &serde_json::Value) -> Vec<(String, String)> {
    match value {
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(subject, capability)| {
                (
                    subject.clone(),
                    capability.as_str().unwrap_or_default().to_string(),
                )
            })
            .collect(),
        _ => fail("--json grants must be an object {subject_id: capability}".to_string()),
    }
}

async fn run_admin(args: &Args, db: &Db, actor: &str) -> serde_json::Value {
    match args.cmd.as_str() {
        "principal" => {
            let id = kernel::create_principal(
                db,
                &flag(args, "kind"),
                &flag(args, "label"),
                &flag(args, "binding"),
                actor,
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"principal_id": id})
        }
        "home" => {
            // Optional --json object {subject_id: capability}; absent means
            // anchorless (inherits the parent policy).
            let entries: Option<Vec<(String, String)>> = args
                .flags
                .contains_key("json")
                .then(|| grants_from(&read_json_value(args)));
            let borrowed: Option<Vec<(&str, &str)>> = entries
                .as_ref()
                .map(|list| list.iter().map(|(s, c)| (s.as_str(), c.as_str())).collect());
            let id = kernel::create_home(db, &flag(args, "parent"), borrowed.as_deref(), actor)
                .await
                .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"home_id": id})
        }
        "grant" => {
            let list = grants_from(&read_json_value(args));
            let borrowed: Vec<(&str, &str)> =
                list.iter().map(|(s, c)| (s.as_str(), c.as_str())).collect();
            kernel::replace_home_policy(db, actor, &flag(args, "home"), &borrowed)
                .await
                .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"ok": true})
        }
        "install" => {
            let version: u32 = flag(args, "version")
                .parse()
                .unwrap_or_else(|_| fail("bad --version".to_string()));
            let identity = kernel::install_definition_as(
                db,
                actor,
                &flag(args, "family"),
                version,
                &read_json_bytes(args),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"family": identity.family, "version": identity.version, "digest": identity.digest})
        }
        "adopt" => {
            let version: u32 = flag(args, "version")
                .parse()
                .unwrap_or_else(|_| fail("bad --version".to_string()));
            let pin = native_ce::meta::definition_artifact::RevisionIdentity {
                family: flag(args, "family"),
                version,
                digest: flag(args, "digest"),
            };
            kernel::adopt_definition_at(
                db,
                actor,
                &pin.family.clone(),
                Some(&pin),
                &flag(args, "scope"),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"ok": true})
        }
        "disable" => {
            kernel::adopt_definition_at(
                db,
                actor,
                &flag(args, "family"),
                None,
                &flag(args, "scope"),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"ok": true})
        }
        "package-install" => {
            let manifest = read_manifest(args);
            let identity = kernel::install_package_as(db, actor, &manifest)
                .await
                .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({
                "namespace": identity.namespace,
                "name": identity.name,
                "version": identity.version,
                "digest": identity.digest,
            })
        }
        "package-adopt" => {
            let manifest = read_manifest(args);
            let ack = read_ack_reads(args);
            let identity = manifest.identity().unwrap_or_else(|e| fail(e.to_string()));
            let receipt = kernel::adopt_package_at(
                db,
                actor,
                &flag(args, "scope"),
                &manifest,
                Some(&identity),
                &ack,
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&receipt).unwrap_or_else(|e| fail(e.to_string()))
        }
        "package-disable" => {
            let manifest = read_manifest(args);
            if let Some(raw) = args.flags.get("ack-reads") {
                let parsed: serde_json::Value = serde_json::from_str(raw)
                    .unwrap_or_else(|e| fail(format!("bad --ack-reads: {e}")));
                let empty = parsed.as_array().is_some_and(|a| a.is_empty());
                if !empty {
                    fail("package disable tombstone carries no acknowledgment".to_string());
                }
            }
            let receipt =
                kernel::adopt_package_at(db, actor, &flag(args, "scope"), &manifest, None, &[])
                    .await
                    .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&receipt).unwrap_or_else(|e| fail(e.to_string()))
        }
        "consumer-register" => {
            let view = native_ce::dependency::register_consumer_at(
                db,
                actor,
                &flag(args, "scope"),
                &flag(args, "consumer-kind"),
                &flag(args, "namespace"),
                &flag(args, "name"),
                &flag(args, "family"),
                read_u32(args, "version"),
                &flag(args, "digest"),
                read_expected_seq(args),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&view).unwrap_or_else(|e| fail(e.to_string()))
        }
        "consumer-retire" => {
            let Some(expected) = read_expected_seq(args) else {
                fail("missing --expected-seq <event_seq>".to_string());
            };
            let view = native_ce::dependency::retire_consumer_at(
                db,
                actor,
                &flag(args, "scope"),
                &flag(args, "consumer-kind"),
                &flag(args, "namespace"),
                &flag(args, "name"),
                &flag(args, "family"),
                Some(expected),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&view).unwrap_or_else(|e| fail(e.to_string()))
        }
        "package-preview-adopt" => {
            let manifest = read_manifest(args);
            let impact = native_ce::dependency::preview_package_adopt(
                db,
                actor,
                &flag(args, "scope"),
                &manifest,
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&impact).unwrap_or_else(|e| fail(e.to_string()))
        }
        "package-preview-disable" => {
            let manifest = read_manifest(args);
            let impact = native_ce::dependency::preview_package_disable(
                db,
                actor,
                &flag(args, "scope"),
                &manifest,
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&impact).unwrap_or_else(|e| fail(e.to_string()))
        }
        "definition-preview-adopt" => {
            let pin = native_ce::meta::definition_artifact::RevisionIdentity {
                family: flag(args, "family"),
                version: read_u32(args, "version"),
                digest: flag(args, "digest"),
            };
            let scope = preview_scope(args);
            let impact = native_ce::dependency::preview_definition_change(
                db,
                actor,
                scope.as_deref(),
                &pin.family.clone(),
                Some(&pin),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&impact).unwrap_or_else(|e| fail(e.to_string()))
        }
        "definition-preview-disable" => {
            let scope = preview_scope(args);
            let impact = native_ce::dependency::preview_definition_change(
                db,
                actor,
                scope.as_deref(),
                &flag(args, "family"),
                None,
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&impact).unwrap_or_else(|e| fail(e.to_string()))
        }
        other => fail(format!("unknown subcommand '{other}'")),
    }
}

async fn run_data(args: &Args, db: &Db, caller: &str) -> serde_json::Value {
    match args.cmd.as_str() {
        "describe" => kernel::describe_world_as(db, caller)
            .await
            .unwrap_or_else(|e| fail(e.to_string())),
        "create" => {
            let id = kernel::create_as(
                db,
                caller,
                &flag(args, "family"),
                &flag(args, "kind"),
                &read_json_object(args),
                &flag(args, "home"),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"id": id})
        }
        "link" => {
            kernel::link_as(
                db,
                caller,
                &flag(args, "source"),
                &flag(args, "predicate"),
                &flag(args, "target"),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"ok": true})
        }
        "query" => {
            let filters = args
                .flags
                .get("json")
                .map(|_| read_json_value(args))
                .unwrap_or(serde_json::Value::Null);
            let equals: Vec<(String, serde_json::Value)> = filters
                .get("equals")
                .and_then(|v| v.as_object())
                .map(|map| map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            let borrowed: Vec<(&str, serde_json::Value)> = equals
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect();
            let linked: Option<(String, String, String)> = filters.get("linked_to").map(|v| {
                (
                    v.get("predicate")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    v.get("id")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    v.get("direction")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default()
                        .to_string(),
                )
            });
            let linked_ref = linked
                .as_ref()
                .map(|(p, i, d)| (p.as_str(), i.as_str(), d.as_str()));
            let limit = filters.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
            let cursor = filters.get("cursor").and_then(|v| v.as_str());
            let page = kernel::query_as(
                db,
                caller,
                &flag(args, "family"),
                &flag(args, "kind"),
                &borrowed,
                linked_ref,
                limit,
                cursor,
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&page).unwrap_or_else(|e| fail(e.to_string()))
        }
        "consumer-list" => {
            let views = native_ce::dependency::list_consumers_as(db, caller, &flag(args, "scope"))
                .await
                .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&views).unwrap_or_else(|e| fail(e.to_string()))
        }
        "package-surface-read" => {
            let filters = args
                .flags
                .get("json")
                .map(|_| read_json_value(args))
                .unwrap_or(serde_json::Value::Null);
            let equals: Vec<(String, serde_json::Value)> = filters
                .get("equals")
                .and_then(|v| v.as_object())
                .map(|map| map.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                .unwrap_or_default();
            let borrowed: Vec<(&str, serde_json::Value)> = equals
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect();
            let linked: Option<(String, String, String)> = filters.get("linked_to").map(|v| {
                (
                    v.get("predicate")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    v.get("id")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    v.get("direction")
                        .and_then(|p| p.as_str())
                        .unwrap_or_default()
                        .to_string(),
                )
            });
            let linked_ref = linked
                .as_ref()
                .map(|(p, i, d)| (p.as_str(), i.as_str(), d.as_str()));
            let limit: usize = args
                .flags
                .get("limit")
                .map(|s| {
                    s.parse()
                        .unwrap_or_else(|_| fail("bad --limit".to_string()))
                })
                .or_else(|| {
                    filters
                        .get("limit")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as usize)
                })
                .unwrap_or(20);
            let cursor_owned = args.flags.get("cursor").cloned().or_else(|| {
                filters
                    .get("cursor")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
            });
            let view = kernel::render_package_surface_as(
                db,
                caller,
                &flag(args, "scope"),
                &flag(args, "namespace"),
                &flag(args, "name"),
                &flag(args, "read-token"),
                &flag(args, "family"),
                &flag(args, "kind"),
                &borrowed,
                linked_ref,
                limit,
                cursor_owned.as_deref(),
            )
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&view).unwrap_or_else(|e| fail(e.to_string()))
        }
        "revise" => {
            kernel::revise_as(db, caller, &flag(args, "id"), &read_json_object(args))
                .await
                .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::json!({"ok": true})
        }
        "read" => {
            let view = kernel::read_record_as(db, caller, &flag(args, "id"))
                .await
                .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&view).unwrap_or_else(|e| fail(e.to_string()))
        }
        "history" => {
            let events = kernel::history_as(db, caller, &flag(args, "id"))
                .await
                .unwrap_or_else(|e| fail(e.to_string()));
            serde_json::to_value(&events).unwrap_or_else(|e| fail(e.to_string()))
        }
        other => fail(format!("unknown subcommand '{other}'")),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = parse_args();
    if args.cmd == "init" {
        let kind = args
            .flags
            .get("kind")
            .cloned()
            .unwrap_or_else(|| "account".to_string());
        let label = flag(&args, "label");
        let binding = flag(&args, "binding");
        let (_, id) = kernel::create_v2_database(&args.db, &kind, &label, &binding)
            .await
            .unwrap_or_else(|e| fail(e.to_string()));
        println!("{}", serde_json::json!({"principal_id": id}));
        return ExitCode::SUCCESS;
    }
    let db = open_db(&args).await;
    let caller = caller_id(&db, &args).await;
    let out = match args.cmd.as_str() {
        "principal"
        | "home"
        | "grant"
        | "install"
        | "adopt"
        | "disable"
        | "package-install"
        | "package-adopt"
        | "package-disable"
        | "consumer-register"
        | "consumer-retire"
        | "package-preview-adopt"
        | "package-preview-disable"
        | "definition-preview-adopt"
        | "definition-preview-disable" => run_admin(&args, &db, &caller).await,
        _ => run_data(&args, &db, &caller).await,
    };
    println!("{out}");
    ExitCode::SUCCESS
}
