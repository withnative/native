//! Manual, synthetic historical-read timing/RSS evidence. No normal test skips.
use native_ce::mcp::kernel_v2::register_kernel_v2_tools;
use native_ce::mcp::registry::{Caller, EngineHandle, ToolRegistry};
use native_ce::{db::Db, events::KERNEL_ROOT_ID, kernel};
use serde_json::{json, Value};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

fn registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();
    native_ce::mcp::register_builtin_tools(&mut registry).unwrap();
    native_ce::mcp::register_surface_tools(&mut registry).unwrap();
    register_kernel_v2_tools(&mut registry).unwrap();
    registry
}
async fn call_as(world: &World, credential: &str, name: &str, args: Value) -> Result<Value> {
    Ok(registry()
        .call_engine(
            EngineHandle::KernelV2(world.db.clone()),
            Caller::authenticated(credential),
            name,
            args,
        )
        .await?)
}
struct World {
    _dir: tempfile::TempDir,
    db: Db,
    admin: String,
    first: String,
    second: String,
}
async fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    let (db, admin) = kernel::create_v2_database(
        dir.path().join("v2.db").to_str().unwrap(),
        "account",
        "Admin",
        "acct:admin",
    )
    .await
    .unwrap();
    let viewer = kernel::create_principal(&db, "account", "Viewer", "acct:viewer", &admin)
        .await
        .unwrap();
    let definition = json!({
        "family": "fixture.mcp", "version": 1, "interpreter": "native.defn/2",
        "primary_type": "Document", "kinds": [{"token": "note", "description": "MCP fixture",
            "maturity": "current", "identity": {"field": "title"},
            "fields": [{"name": "title", "type": "text", "required": true}, {"name": "body", "type": "text", "required": false}],
            "links": [{"predicate": "relates_to", "target": {"primary_type": "Document", "kind": "note"}, "direction": "out", "cardinality": "many"}]}]
    });
    let pin = kernel::install_definition_as(
        &db,
        &admin,
        "fixture.mcp",
        1,
        &serde_json::to_vec(&definition).unwrap(),
    )
    .await
    .unwrap();
    kernel::adopt_definition_as(&db, &admin, &pin.family, Some(&pin))
        .await
        .unwrap();
    let home = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[(&viewer, "view")]), &admin)
        .await
        .unwrap();
    let private = kernel::create_home(&db, KERNEL_ROOT_ID, Some(&[]), &admin)
        .await
        .unwrap();
    let mut ids = Vec::new();
    for (title, home) in [("Alpha", &home), ("Beta", &home), ("Secret", &private)] {
        ids.push(
            kernel::create_as(
                &db,
                &admin,
                "fixture.mcp",
                "note",
                json!({"title": title, "body": "original"})
                    .as_object()
                    .unwrap(),
                home,
            )
            .await
            .unwrap(),
        );
    }
    kernel::revise_as(
        &db,
        &admin,
        &ids[0],
        json!({"body": "revised"}).as_object().unwrap(),
    )
    .await
    .unwrap();
    kernel::link_as(&db, &admin, &ids[0], "relates_to", &ids[1])
        .await
        .unwrap();
    kernel::link_as(&db, &admin, &ids[0], "relates_to", &ids[2])
        .await
        .unwrap();
    World {
        _dir: dir,
        db,
        admin,
        first: ids[0].clone(),
        second: ids[1].clone(),
    }
}
async fn install_comment_carrier(world: &World) {
    let manifest = native_ce::v2_standard::v1_compat::package();
    let identity = manifest.identity().unwrap();
    kernel::install_package_as(&world.db, &world.admin, &manifest)
        .await
        .unwrap();
    kernel::adopt_package_at(
        &world.db,
        &world.admin,
        KERNEL_ROOT_ID,
        &manifest,
        Some(&identity),
        &manifest.declared_reads,
    )
    .await
    .unwrap();
}

async fn seed(count: usize) -> Result<()> {
    let w = world().await;
    install_comment_carrier(&w).await;
    let target = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(
        &w.db,
        &w.admin,
        &w.first,
        "benchmark before",
        target.revision,
    )
    .await
    .unwrap();
    call_as(
        &w,
        "acct:admin",
        "attach_text",
        json!({"record_id":w.first,"text":"x".repeat(4*1024*1024),"filename":"synthetic.txt"}),
    )
    .await
    .unwrap();
    let home = target.home_id;
    for i in 0..count {
        let fields = json!({"title":format!("Synthetic {i:05}"),"body":"synthetic note"});
        kernel::create_as(
            &w.db,
            &w.admin,
            "fixture.mcp",
            "note",
            fields.as_object().unwrap(),
            &home,
        )
        .await?;
        if i % 1000 == 999 {
            eprintln!("seeded {} records", i + 1);
        }
    }
    let before: i64 = sqlx::query_scalar("SELECT max(seq) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let target = kernel::read_record_as(&w.db, &w.admin, &w.first)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(
        &w.db,
        &w.admin,
        &w.first,
        "benchmark after",
        target.revision,
    )
    .await
    .unwrap();
    let event: String =
        sqlx::query_scalar("SELECT id FROM content_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
    // Context measures an older event. Unrelated later edits cannot change
    // its subject-local before/after delta.
    let other = kernel::read_record_as(&w.db, &w.admin, &w.second)
        .await
        .unwrap()
        .unwrap();
    kernel::set_body_as(
        &w.db,
        &w.admin,
        &w.second,
        "later unrelated edit",
        other.revision,
    )
    .await
    .unwrap();
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
        .fetch_one(w.db.pool())
        .await
        .unwrap();
    let manifest = json!({"record_id":w.first,"event_id":event,"before_seq":before,"synthetic_records":count,"content_events":events,"bound_blob_bytes":4*1024*1024});
    std::fs::write(
        w._dir.path().join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    w.db.close().await;
    println!("fixture={}", w._dir.keep().display());
    Ok(())
}

async fn read(fixture: &std::path::Path, operation: &str) -> Result<()> {
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(fixture.join("manifest.json")).unwrap()).unwrap();
    let db = kernel::open_marked_v2_database(fixture.join("v2.db").to_str().unwrap())
        .await
        .unwrap();
    let (tool, args) = match operation {
        "diff" => (
            "render_record_version_diff",
            json!({"record_id":manifest["record_id"],"before_seq":manifest["before_seq"]}),
        ),
        "context" => (
            "get_event_context",
            json!({"event_id":manifest["event_id"]}),
        ),
        _ => panic!("unknown benchmark operation"),
    };
    let registry = registry();
    let start = std::time::Instant::now();
    let value = registry
        .call_engine(
            EngineHandle::KernelV2(db.clone()),
            Caller::authenticated("acct:viewer"),
            tool,
            args,
        )
        .await
        .unwrap();
    let elapsed = start.elapsed();
    if operation == "diff" {
        assert_eq!(value["before"]["record"]["body"], "benchmark before");
        assert_eq!(value["after"]["record"]["body"], "benchmark after");
    } else {
        assert_eq!(value["delta"]["before"], "benchmark before");
        assert_eq!(value["delta"]["after"], "benchmark after");
    }
    eprintln!("operation={operation} elapsed_ms={:.3} synthetic_records={} content_events={} bound_blob_bytes={}",elapsed.as_secs_f64()*1000.0,manifest["synthetic_records"],manifest["content_events"],manifest["bound_blob_bytes"]);
    db.close().await;
    Ok(())
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("seed") => {
            let count = args
                .get(2)
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(10_000);
            if count == 0 || count > 100_000 {
                return Err("record count must be 1..100000".into());
            }
            seed(count).await
        }
        Some("diff" | "context") if args.len() == 3 => {
            read(std::path::Path::new(&args[2]), &args[1]).await
        }
        _ => Err(
            "usage: v2-history-bench seed [record-count] | diff FIXTURE | context FIXTURE".into(),
        ),
    }
}
fn main() -> Result<()> {
    // Match the stack used by the repository's narrow kernel test commands.
    std::thread::Builder::new()
        .stack_size(67_108_864)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?
                .block_on(run())
        })?
        .join()
        .map_err(|_| "benchmark worker panicked")?
}
