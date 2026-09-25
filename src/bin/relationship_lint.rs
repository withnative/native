use std::collections::{BTreeSet, HashSet};
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};

use native_ce::query::relationship_lint::{
    self, EligibleRequest, RetrievalRequest, RevalidateRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Command {
    InitializeFixture {
        database: String,
        runtime: FixtureRuntime,
        #[serde(default = "default_fixture_actor")]
        actor: String,
        #[serde(default = "default_workspace_name")]
        workspace_name: String,
    },
    ListEligible {
        database: String,
        #[serde(flatten)]
        request: EligibleRequest,
    },
    Retrieve {
        database: String,
        #[serde(flatten)]
        request: RetrievalRequest,
    },
    Revalidate {
        database: String,
        #[serde(flatten)]
        request: RevalidateRequest,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum ServeOpen {
    Open { database: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureRuntime {
    records: Vec<FixtureRecord>,
    #[serde(default)]
    queries: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FixtureRecord {
    id: String,
    #[serde(rename = "type")]
    record_type: String,
    kind: String,
    name: String,
    body: String,
    home_id: String,
    #[serde(default)]
    lifecycle: Option<String>,
}

fn default_fixture_actor() -> String {
    "experiment:jev-relationship-lint".into()
}

fn default_workspace_name() -> String {
    "Jev relationship-lint synthetic fixture".into()
}

fn emit(value: &Value) {
    println!(
        "{}",
        serde_json::to_string(value).expect("JSON response serializes")
    );
    std::io::stdout().flush().expect("flush JSON response");
}

#[tokio::main]
async fn main() {
    let serve = std::env::args()
        .skip(1)
        .any(|argument| argument == "--serve");
    let result = if serve {
        run_server().await.map(|()| None)
    } else {
        run().await.map(Some)
    };
    match result {
        Ok(Some(value)) => emit(&json!({"ok": true, "result": value})),
        Ok(None) => {}
        Err(error) => {
            emit(&json!({"ok": false, "error": error.to_string()}));
            std::process::exit(1);
        }
    }
}

async fn run_server() -> native_ce::Result<()> {
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    let first = lines
        .next()
        .transpose()
        .map_err(|error| native_ce::Error::engine(format!("read open request: {error}")))?
        .ok_or_else(|| native_ce::Error::engine("server requires an open request"))?;
    let ServeOpen::Open { database } = serde_json::from_str(&first)
        .map_err(|error| native_ce::Error::engine(format!("parse open request: {error}")))?;
    let requested_path = PathBuf::from(&database);
    if !requested_path.is_absolute() {
        return Err(native_ce::Error::engine(
            "server open database path must be absolute",
        ));
    }
    let canonical_path = std::fs::canonicalize(&requested_path)
        .map_err(|error| native_ce::Error::engine(format!("canonicalize database: {error}")))?;
    let canonical_database = canonical_path
        .to_str()
        .ok_or_else(|| native_ce::Error::engine("server database path must be UTF-8"))?;
    let db = native_ce::db::open_existing_database_standby_read_only(canonical_database).await?;
    emit(&json!({"ok": true, "result": {"ready": true}}));

    for line in lines {
        let result = match line {
            Ok(line) => execute_server_request(&db, &canonical_path, &line).await,
            Err(error) => Err(native_ce::Error::engine(format!(
                "read server request: {error}"
            ))),
        };
        match result {
            Ok(value) => emit(&json!({"ok": true, "result": value})),
            Err(error) => emit(&json!({"ok": false, "error": error.to_string()})),
        }
    }
    db.close().await;
    Ok(())
}

async fn execute_server_request(
    db: &native_ce::db::Db,
    canonical_path: &Path,
    input: &str,
) -> native_ce::Result<Value> {
    let command: Command = serde_json::from_str(input)
        .map_err(|error| native_ce::Error::engine(format!("parse request: {error}")))?;
    let (database, operation) = match command {
        Command::InitializeFixture { .. } => {
            return Err(native_ce::Error::engine(
                "fixture initialization is unavailable in a read-only server session",
            ));
        }
        Command::ListEligible { database, request } => (database, Operation::List(request)),
        Command::Retrieve { database, request } => (database, Operation::Retrieve(request)),
        Command::Revalidate { database, request } => (database, Operation::Revalidate(request)),
    };
    let request_path = std::fs::canonicalize(&database).map_err(|error| {
        native_ce::Error::engine(format!("canonicalize request database: {error}"))
    })?;
    if request_path != canonical_path {
        return Err(native_ce::Error::engine(
            "server session refuses a request for a different database",
        ));
    }
    execute_read(db, operation).await
}

async fn run() -> native_ce::Result<Value> {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(|error| native_ce::Error::engine(format!("read request: {error}")))?;
    let command: Command = serde_json::from_str(&input)
        .map_err(|error| native_ce::Error::engine(format!("parse request: {error}")))?;
    if let Command::InitializeFixture {
        database,
        runtime,
        actor,
        workspace_name,
    } = command
    {
        return initialize_fixture(&database, runtime, &actor, &workspace_name).await;
    }
    let (database, operation) = match command {
        Command::InitializeFixture { .. } => unreachable!("handled above"),
        Command::ListEligible { database, request } => (database, Operation::List(request)),
        Command::Retrieve { database, request } => (database, Operation::Retrieve(request)),
        Command::Revalidate { database, request } => (database, Operation::Revalidate(request)),
    };
    let db = native_ce::db::open_existing_database_standby_read_only(&database).await?;
    let value = execute_read(&db, operation).await?;
    db.close().await;
    Ok(value)
}

async fn execute_read(db: &native_ce::db::Db, operation: Operation) -> native_ce::Result<Value> {
    match operation {
        Operation::List(request) => Ok(serde_json::to_value(
            relationship_lint::list_eligible(db, &request).await?,
        )?),
        Operation::Retrieve(request) => Ok(serde_json::to_value(
            relationship_lint::retrieve(db, &request).await?,
        )?),
        Operation::Revalidate(request) => Ok(serde_json::to_value(
            relationship_lint::revalidate(db, &request).await?,
        )?),
    }
}

enum Operation {
    List(EligibleRequest),
    Retrieve(RetrievalRequest),
    Revalidate(RevalidateRequest),
}

async fn initialize_fixture(
    database: &str,
    runtime: FixtureRuntime,
    actor: &str,
    workspace_name: &str,
) -> native_ce::Result<Value> {
    if actor.trim().is_empty() || workspace_name.trim().is_empty() {
        return Err(native_ce::Error::engine(
            "fixture actor and workspace_name must not be blank",
        ));
    }
    let path = absolute_path(database)?;
    reject_existing_sqlite_family(&path)?;
    validate_runtime(&runtime)?;

    let path_text = path
        .to_str()
        .ok_or_else(|| native_ce::Error::engine("fixture database path must be UTF-8"))?;
    let db = native_ce::db::create_database_named(path_text, workspace_name).await?;
    let homes = runtime
        .records
        .iter()
        .map(|record| record.home_id.clone())
        .collect::<BTreeSet<_>>();
    for (index, home_id) in homes.iter().enumerate() {
        native_ce::store::create_record_as(
            &db,
            json!({
                "id": home_id,
                "type": "Collection",
                "kind": "folder",
                "name": format!("Synthetic fixture home {}", index + 1),
                "home_id": native_ce::schema::ROOT_RECORD_ID,
            }),
            Some(actor),
        )
        .await?;
        install_fixture_policy(&db, actor, home_id).await?;
    }
    for record in &runtime.records {
        let mut fields = serde_json::Map::new();
        fields.insert("id".into(), json!(record.id));
        fields.insert("type".into(), json!(record.record_type));
        fields.insert("kind".into(), json!(record.kind));
        fields.insert("name".into(), json!(record.name));
        fields.insert("body".into(), json!(record.body));
        fields.insert("home_id".into(), json!(record.home_id));
        if let Some(lifecycle) = &record.lifecycle {
            fields.insert("lifecycle".into(), json!(lifecycle));
        }
        native_ce::store::create_record_as(&db, Value::Object(fields), Some(actor)).await?;
        install_fixture_policy(&db, actor, &record.id).await?;
    }
    let origin_database_id = sqlx::query_scalar::<_, String>(
        "SELECT origin_db_id FROM database_identity WHERE singleton=1",
    )
    .fetch_one(db.pool())
    .await?;
    db.close().await;
    owner_only(&path)?;

    let bytes = std::fs::metadata(&path)?.len();
    let sha256 = sha256_file(&path)?;
    let runtime_sha256 = hex::encode(Sha256::digest(serde_jcs::to_vec(&runtime)?));
    Ok(json!({
        "contract": "native.relationship-lint-fixture.v1",
        "database": path,
        "bytes": bytes,
        "sha256": sha256,
        "origin_database_id": origin_database_id,
        "record_count": runtime.records.len(),
        "home_count": homes.len(),
        "runtime_sha256": runtime_sha256,
        "actor": actor,
        "authorization": "native_members_edit_plus_fixture_actor_manage",
    }))
}

async fn install_fixture_policy(
    db: &native_ce::db::Db,
    actor: &str,
    record_id: &str,
) -> native_ce::Result<()> {
    native_ce::authorization::replace_explicit_policy(
        db,
        actor,
        record_id,
        vec![
            native_ce::authorization::AllowEntry::members(
                native_ce::authorization::Capability::Edit,
            ),
            native_ce::authorization::AllowEntry::account(
                actor,
                native_ce::authorization::Capability::Manage,
            ),
        ],
    )
    .await
}

fn validate_runtime(runtime: &FixtureRuntime) -> native_ce::Result<()> {
    if runtime.records.is_empty() {
        return Err(native_ce::Error::engine(
            "fixture runtime must contain records",
        ));
    }
    let mut ids = HashSet::new();
    let mut homes = HashSet::new();
    for record in &runtime.records {
        if !ids.insert(record.id.as_str()) {
            return Err(native_ce::Error::engine(format!(
                "duplicate fixture record id {}",
                record.id
            )));
        }
        if record.id.trim().is_empty()
            || record.name.trim().is_empty()
            || record.body.trim().is_empty()
            || record.home_id.trim().is_empty()
        {
            return Err(native_ce::Error::engine(
                "fixture record id, name, body, and home_id must not be blank",
            ));
        }
        let expected_kind = match record.record_type.as_str() {
            "Document" => "note",
            "WorkItem" => "task",
            other => {
                return Err(native_ce::Error::engine(format!(
                    "fixture record type must be Document or WorkItem, got {other}"
                )))
            }
        };
        if record.kind != expected_kind {
            return Err(native_ce::Error::engine(format!(
                "fixture {} must use kind {expected_kind}",
                record.id
            )));
        }
        homes.insert(record.home_id.as_str());
    }
    if homes.iter().any(|home| ids.contains(home)) {
        return Err(native_ce::Error::engine(
            "fixture home ids must be distinct from fixture record ids",
        ));
    }
    for query in &runtime.queries {
        let Some(subject_id) = query.get("subject_id").and_then(Value::as_str) else {
            return Err(native_ce::Error::engine(
                "every fixture query must carry subject_id",
            ));
        };
        if !ids.contains(subject_id) {
            return Err(native_ce::Error::engine(format!(
                "fixture query subject {subject_id} is absent"
            )));
        }
    }
    Ok(())
}

fn absolute_path(raw: &str) -> native_ce::Result<PathBuf> {
    let path = PathBuf::from(raw);
    if path.as_os_str().is_empty() {
        return Err(native_ce::Error::engine(
            "fixture database path must not be blank",
        ));
    }
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn reject_existing_sqlite_family(path: &Path) -> native_ce::Result<()> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        if candidate.try_exists()? {
            return Err(native_ce::Error::engine(format!(
                "fixture initialization refuses existing path {}",
                candidate.display()
            )));
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn sha256_file(path: &Path) -> native_ce::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.write_all(&buffer[..read])?;
    }
    Ok(hex::encode(digest.finalize()))
}

#[cfg(unix)]
fn owner_only(path: &Path) -> native_ce::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn owner_only(_path: &Path) -> native_ce::Result<()> {
    Ok(())
}
