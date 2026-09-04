//! What a `native.mdx.v2` board's cold open actually costs, end to end.
//!
//! A measurement tool, not a test. It is a `dev-tools` binary for the reason
//! the other nine are: it is not a product surface, it costs a full link of
//! the library, and a plain `cargo build`/`cargo test` should not pay for it.
//! It is not an `#[ignore]`d test either — that marker is reserved here for
//! credentialed and CI-only entrypoints, and a measurement is neither.
//!
//! ```text
//! cargo run --release --features dev-tools --bin board-render-cost
//! BOARD_RECORDS=48 BOARD_NOISE=500 cargo run --release --features dev-tools --bin board-render-cost
//! BOARD_SHAPE=two-port cargo run --release --features dev-tools --bin board-render-cost
//! ```
//!
//!
//! Shapes: the default is the original 144-record `kind:selection` board over
//! `Caller::local()`. `BOARD_SHAPE=two-port` instead seeds a `kind:folder`
//! Collection holding 768 `home_id` children under a five-deep folder chain
//! plus a `kind:query` Collection carrying a saved governed SQL definition
//! capped at 300 rows over a dedicated `kind:sheet` sidecar population,
//! bound to a two-port `native.mdx.v2` artifact
//! (`native.collection-envelope.v1` + `native.relation-envelope.v1`), and
//! drives every setup and render call through a credentialed hosted member
//! caller with `include_timing:true`. An unknown `BOARD_SHAPE` warns on
//! stderr and runs the legacy default; it never silently selects a shape.
//! `BOARD_FOLDER_CHILDREN=48` rescales the folder port; the governed sidecar
//! stays capped at 300 rows.
//!
//! What it found on 25 Aug 2026, at 144 records and 863 content events:
//!
//! ```text
//! replay alone       31.35s   for 863 content events
//! render 1           30.92s   cache="miss"   plan 135,957 bytes
//! render 3           31.20s   cache="hit"    plan 135,955 bytes
//! ```
//!
//! The replay was the render — ~98% of the wall clock, against about 200ms of
//! compile, execute, validate and plan assembly. That turned out not to be
//! what folding an event log costs. `lens::replay_projection` held a bare
//! pooled connection, so every projector statement autocommitted, and a
//! scratch database is a real WAL file under `$TMPDIR` at SQLite's default
//! `synchronous=FULL`. The fold was paying a flush four to six times per
//! event. It now runs in one transaction, and the same run on the same machine
//! reads:
//!
//! ```text
//! replay alone      256ms    for 863 content events
//! render 1          862ms    cache="miss"   plan 135,957 bytes
//! render 3          828ms    cache="hit"    plan 135,955 bytes
//! ```
//!
//! So a board's cold open is about 0.86s rather than 31s, and the replay is
//! now roughly 30% of it rather than 98%.
//!
//! Two things the original run said still hold, and one is now sharper:
//!
//! A `cache="hit"` still costs what a miss costs, because what is cached is
//! the compiled body and the compile was never the cost. That observation is
//! more interesting after the fix than before it: of the ~860ms a 144-record
//! render takes, ~256ms is replay and ~213ms is compile, execute, validate and
//! assembly, which left roughly 400ms attributed to nothing measured here.
//!
//! That 400ms stopped being a hole when the render began reporting its own phases —
//! `mdx::RenderTelemetry`, threaded through `render_mdx_v2` in
//! `src/mcp/tools/artifacts.rs` — and they account for ~98% of the wall clock
//! this binary measures from outside. Before ordinary at-head renders moved to
//! one pinned live read transaction, the machine that took these numbers
//! reported this split at 144 records:
//!
//! ```text
//! snapshot_open + snapshot_replay   ~66%   allocating and folding the log
//! resolve_inputs                    ~15%   almost entirely `resolve_collection`
//! execute + output_decode + validate ~7%
//! snapshot_close                     ~7%   AFTER the plan is built
//! observed_versions                  ~3%
//! compile, graph_link, preflight, plan_assembly, module_closure  <1% together
//! ```
//!
//! Ordinary at-head v2 renders no longer create, replay, or close that scratch
//! projection. They report `snapshot_begin` and `snapshot_release` instead;
//! explicit historical renders retain replay because a live transaction cannot
//! represent an old content boundary. Re-run this binary for current timings;
//! the table above is retained to state what the optimization removed.
//!
//! Read those as shares, not durations. The absolute figures above were taken
//! on a machine no reader of this file is on, which is the whole reason this is
//! a tool you run rather than a gate that passes.
//!
//! Two of the three things that looked like the answer beforehand were not.
//! `render_observed_versions` issues one query per (record, facet) pair and
//! looked like the obvious suspect at 144 sequential round trips; it is ~3%.
//! The canonical-JSON and digest pass over the whole record set is under 4ms.
//! What the instrumentation actually found was `resolve_collection` — the
//! board's own paged query — and `scratch.close()`, which costs about as much
//! as executing the MDX and happens after the plan already exists. Neither was
//! visible to anyone before, from here or from anywhere else.
//!
//! To read the phases from a running server rather than from this binary, set
//! `NATIVE_CE_MDX_TELEMETRY_SECS` (see `serve.rs`).
//!
//! `BOARD_NOISE` is still the load-bearing knob: it adds records the board
//! does NOT bind, so they reach the event log without reaching the plan. The
//! effect it exposes is much smaller now but has not gone away — 12 bound
//! records with 132 unbound ones renders in ~516ms against ~439ms for 12
//! records alone, where before the fix those were ~11s against ~2.7s. Cost
//! still tracks the size of the event log rather than the card count or the
//! bytes shipped; it is just no longer the thing that decides the wall clock.
//!
//! Nothing here is a threshold. A wall-clock number measured on one machine is
//! not a fact about any other, which is the other reason this is a tool you
//! run and read rather than a gate that passes or fails.

use std::time::{Duration, Instant};

use native_artifact_runtime::mdx::sha256_hex;
use native_artifact_runtime::mdx_v2::canonical_json_bytes;
use native_ce::mcp::{register_surface_tools, Caller, ToolRegistry};
use native_ce::query::sql_contract::LOGICAL_CATALOG_REVISION;
use native_ce::{apply_schema, create_database, open_database, Db};
use serde_json::{json, Value};

const ARTIFACT: &str = "b0a2d000-0000-4000-8000-000000000001";
const COLLECTION: &str = "b0a2d000-0000-4000-8000-000000000002";
/// Override with `BOARD_RECORDS=48` to see how the cost scales.
fn record_count() -> usize {
    std::env::var("BOARD_RECORDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(144)
}

/// The Backlog board as saved in the workspace this was measured against: six
/// `DropTarget` lanes over `triage`, every card declaring `fields={["kind"]}`.
const BOARD_SOURCE: &str = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { board: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "board" } },
    { capability: "navigation.record.user_gesture", scope: {} }
  ],
  interactions: [
    { id: "to_untriaged", label: "Untriaged", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "untriaged" } },
    { id: "to_triaged", label: "Triaged", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "triaged" } },
    { id: "to_committed", label: "Committed", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "committed" } }
  ]
}

<div class="board">
  <div class="lane">
    <DropTarget entry="to_untriaged">
      {props.input.records.filter(r => r.facets.triage === "untriaged").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_triaged">
      {props.input.records.filter(r => r.facets.triage === "triaged").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_committed">
      {props.input.records.filter(r => r.facets.triage === "committed").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
</div>
"#;

async fn call(registry: &ToolRegistry, db: &Db, tool: &str, arguments: Value) -> Value {
    registry
        .call(db.clone(), Caller::local(), tool, arguments)
        .await
        .unwrap_or_else(|error| json!({ "error": error.to_string() }))
}

/// Names and summaries sized like the real backlog's — median 107 and 387
/// characters. The text itself is synthetic on purpose: the payload cost
/// depends on the sizes, and workspace prose does not belong in the repo.
fn filler(len: usize, seed: usize) -> String {
    const WORDS: [&str; 12] = [
        "record",
        "artifact",
        "triage",
        "backlog",
        "agent",
        "workspace",
        "facet",
        "lifecycle",
        "render",
        "payload",
        "transfer",
        "projection",
    ];
    let mut text = String::new();
    let mut index = seed;
    while text.len() < len {
        index = index.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        text.push_str(WORDS[index % WORDS.len()]);
        text.push(' ');
    }
    text.truncate(len);
    text
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // The legacy board stays the default: an unset `BOARD_SHAPE` — or one
    // that names nothing known — runs it rather than silently opting into a
    // heavier fixture. Pass `BOARD_SHAPE=two-port` for the folder+sidecar shape.
    match std::env::var("BOARD_SHAPE").unwrap_or_default().as_str() {
        "two-port" => run_two_port().await,
        "" | "legacy" => run_legacy().await,
        unknown => {
            eprintln!(
                "unknown BOARD_SHAPE={unknown:?}; expected \"legacy\" or \"two-port\" — running the legacy default"
            );
            run_legacy().await
        }
    }
}

/// Original 144-record `kind:selection` measurement over `Caller::local()`.
/// Kept so the first board-cost numbers stay reproducible; it remains the
/// default shape, with [`run_two_port`] opt-in via `BOARD_SHAPE=two-port`.
async fn run_legacy() {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();

    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": ARTIFACT, "type": "Document", "kind": "artifact", "name": "Backlog board",
                "body": BOARD_SOURCE, "facets": { "runtime": "native.mdx.v2" },
                "reason": "Measure the render cost of a realistic board." }),
    )
    .await;
    call(
        &registry,
        &db,
        "create_record",
        json!({ "id": COLLECTION, "type": "Collection", "kind": "selection", "name": "Backlog",
                "reason": "Bind the board's input." }),
    )
    .await;

    let lanes = ["untriaged", "triaged", "committed"];
    let build = Instant::now();
    let records = record_count();
    for index in 0..records {
        let id = format!("b0a2d000-0000-4000-8000-{index:012}");
        call(
            &registry,
            &db,
            "create_record",
            json!({ "id": id, "type": "Document", "kind": "note",
                    "name": filler(107, index), "summary": filler(387, index + 1_000),
                    "facets": { "triage": lanes[index % lanes.len()], "area": "artifacts",
                                "filed_by": "Claude", "source": filler(60, index + 2_000) },
                    "reason": "Populate the board measurement." }),
        )
        .await;
        call(
            &registry,
            &db,
            "manage_links",
            json!({ "action": "add", "source_id": id, "target_id": COLLECTION,
                    "relationship": "member_of" }),
        )
        .await;
    }
    // Records the board does NOT bind. They add events to the log without
    // adding cards, which separates "cost of the board" from "cost of the
    // workspace the board lives in".
    let noise = std::env::var("BOARD_NOISE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    for index in 0..noise {
        call(
            &registry,
            &db,
            "create_record",
            json!({ "id": format!("b0a2d000-0000-4000-8000-1{index:011}"),
                    "type": "Document", "kind": "note",
                    "name": filler(107, index), "summary": filler(387, index + 1_000),
                    "facets": { "area": "artifacts" },
                    "reason": "Unbound records, to grow the event log only." }),
        )
        .await;
    }
    let built = build.elapsed();

    let bound = call(
        &registry,
        &db,
        "manage_artifact_inputs",
        json!({ "action": "bind", "artifact_id": ARTIFACT, "port_name": "board",
                "collection_id": COLLECTION }),
    )
    .await;
    assert_eq!(bound["status"], "bound", "{bound:#}");
    grant_requested_capabilities(&registry, &db).await;

    // The same replay a render performs internally, timed on its own. The
    // render path allocates a fresh in-memory projection and replays the whole
    // content-event prefix into it before it compiles or executes anything
    // (`render_mdx_v2` in `src/mcp/tools/artifacts.rs`), so this is the
    // denominator every other number here is measured against.
    let head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(db.pool())
        .await
        .unwrap();
    let scratch = open_database(":memory:").await.unwrap();
    apply_schema(&scratch).await.unwrap();
    let replay_started = Instant::now();
    native_ce::query::lens::replay_projection(&db, &scratch, head)
        .await
        .unwrap();
    println!(
        "replay alone       {:?}  for {head} content events",
        replay_started.elapsed()
    );

    for attempt in 1..=3 {
        let started = Instant::now();
        let rendered = call(&registry, &db, "render_artifact", json!({ "id": ARTIFACT })).await;
        let elapsed = started.elapsed();
        assert_eq!(rendered["status"], "rendered", "{rendered:#}");
        let plan = serde_json::to_string(&rendered["plan"]).unwrap();
        let tree = serde_json::to_string(&rendered["plan"]["tree"]).unwrap();
        println!(
            "render {attempt}  {elapsed:?}  cache={}  plan {} bytes  tree {} bytes",
            rendered["plan"]["cache"]["state"],
            plan.len(),
            tree.len()
        );
    }
    println!("fixture build      {built:?} for {records} records");
}

// ---------------------------------------------------------------------------
// Two-port shape (default): 768 folder children at ancestor depth five plus a
// governed SQL sidecar, all under a credentialed hosted member caller.
// ---------------------------------------------------------------------------

/// Hosted member identity used for every tool call in the two-port shape.
/// `Caller::authenticated` never sets the trusted-local bypass, so every
/// setup and render call goes through the same `effective_capability` +
/// containment-path authorization a production caller pays for. Genesis grants
/// `members -> edit` on `native:root`, so this caller can file the fixture
/// and hold `input.read` grants without any extra policy seeding.
const MEMBER_ACCOUNT: &str = "acct:board-bench-member";
const MEMBER_PERSON_ID: &str = "b0a2d100-0000-4000-8000-000000000003";

/// Provision the member's portable identity before anything measured runs.
///
/// Production hosts verify membership in the catalog plane before a database
/// is selected; a fresh in-memory database has no catalog plane, so the
/// harness mints the same two rows here (person record + canonical account
/// binding, mirroring `enrol` in `tests/tools/workspace_naming.rs` and
/// `bind_account` in `tests/tools/authorization_contract.rs`). Only the
/// person-record creation uses `Caller::local()` — the same provisioning
/// bypass the enrol helpers use — and the `account` binding is inserted
/// through a deliberately privileged file-owner pool to the same temp file
/// (`Db::path()`), because `account` is a reserved internal-only binding
/// system and the public `manage_bindings` tool must refuse it. Both steps
/// sit outside the timed fixture build; every fixture, bind, grant, and
/// render call below goes through [`member_caller`].
async fn seed_member_identity(registry: &ToolRegistry, db: &Db) {
    let person = call(
        registry,
        db,
        "create_record",
        json!({ "id": MEMBER_PERSON_ID, "type": "Entity", "kind": "person",
                "name": "Board benchmark member",
                "reason": "Provision the credentialed benchmark caller." }),
    )
    .await;
    assert_tool_ok(&person, "create benchmark member person");
    // Reserved-system setup, not measured work: cross the file-owner boundary
    // explicitly like the integration-test fixtures do. `Db::pool()` is
    // physically read-only, so open a one-connection writer to the same
    // backing file (`:memory:` databases are temp files; see `db::ephemeral_file`).
    let options: sqlx::sqlite::SqliteConnectOptions =
        std::str::FromStr::from_str(&format!("sqlite:{}", db.path().display()))
            .expect("benchmark database path is a valid sqlite URL");
    let setup_pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            options
                .create_if_missing(false)
                .foreign_keys(true)
                .busy_timeout(std::time::Duration::from_secs(5)),
        )
        .await
        .expect("open privileged benchmark setup pool");
    sqlx::query(
        "INSERT INTO bindings (record_id, system, identifier, is_canonical) VALUES (?, 'account', ?, 1)",
    )
    .bind(MEMBER_PERSON_ID)
    .bind(MEMBER_ACCOUNT)
    .execute(&setup_pool)
    .await
    .expect("bind benchmark account");
    setup_pool.close().await;
}

fn member_caller() -> Caller {
    Caller::authenticated(MEMBER_ACCOUNT)
        .with_hosting_context("host:board-bench", "db:board-bench")
        .with_hosting_owner(false)
}

async fn call_as(
    registry: &ToolRegistry,
    db: &Db,
    caller: Caller,
    tool: &str,
    arguments: Value,
) -> Value {
    registry
        .call(db.clone(), caller, tool, arguments)
        .await
        .unwrap_or_else(|error| json!({ "error": error.to_string() }))
}

fn assert_tool_ok(value: &Value, context: &str) {
    assert!(value.get("error").is_none(), "{context} failed: {value:#}");
}

const TWO_PORT_ARTIFACT: &str = "b0a2d100-0000-4000-8000-000000000001";
const TWO_PORT_QUERY: &str = "b0a2d100-0000-4000-8000-000000000002";
/// Five nested folders below `native:root` (levels 0..4); the leaf (level 4)
/// is bound, so a leaf child has five folder ancestors plus `native:root`.
const FOLDER_DEPTH: usize = 5;
/// Children on the leaf folder. Override with `BOARD_FOLDER_CHILDREN=48`.
const FOLDER_CHILDREN_DEFAULT: usize = 768;
/// Saved governed SQL row cap for the sidecar port.
const GOVERNED_ROW_CAP: usize = 300;

fn folder_children() -> usize {
    std::env::var("BOARD_FOLDER_CHILDREN")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(FOLDER_CHILDREN_DEFAULT)
}

fn folder_id(level: usize) -> String {
    format!("b0a2d101-0000-4000-8000-{level:012}")
}

fn folder_child_id(index: usize) -> String {
    format!("b0a2d102-0000-4000-8000-{index:012}")
}

/// Sidecar population ids. A distinct prefix keeps them disjoint from the
/// board children above: the renderer indexes canonical inputs by record id,
/// so a governed row reusing a board id with a slimmer `{id, name}` shape
/// would evict the full collection record (or vice versa) and fail the other
/// port's identity check as fabricated.
fn sidecar_id(index: usize) -> String {
    format!("b0a2d103-0000-4000-8000-{index:012}")
}

/// Output columns for the sidecar: stable `id` identity first, deterministic
/// `name, id` order. Shape mirrors `SavedSqlColumn` serialization
/// (`{"name","type","nullable"}`), and the digest mirrors
/// `saved_sql_schema_sha256` (SHA-256 over canonical column JSON).
fn governed_columns() -> Value {
    json!([
        { "name": "id", "type": "identifier", "nullable": false },
        { "name": "name", "type": "text", "nullable": false },
    ])
}

fn governed_schema_sha256() -> String {
    // Reuses the runtime's canonicalization and digest so the benchmark tracks
    // `saved_sql_schema_sha256` instead of a local copy.
    sha256_hex(&canonical_json_bytes(&governed_columns()))
}

/// Saved governed SQL definition (v1.1) stored as the `query` facet of the
/// `kind:query` Collection. `catalog_revision` tracks
/// `LOGICAL_CATALOG_REVISION` by value, not by comment; if the catalog moves,
/// creation fails closed here rather than measuring the wrong shape.
///
/// The predicate selects the dedicated `kind:sheet` sidecar population, not
/// every `Document`: the board port already carries the `kind:note` children
/// as full collection records, and a governed `{id, name}` row reusing one of
/// those ids would collide in the renderer's id-indexed canonical inputs and
/// fail the other port as a fabricated record. Both populations stay
/// `type:Document` so the sidecar still exercises the same records-relation
/// path at its 300-row cap.
fn governed_definition_value(schema_sha: &str) -> Value {
    json!({
        "v": "1.1",
        "kind": "governed_sql",
        "profile": { "id": "sqlite-local", "revision": 1 },
        "catalog_revision": LOGICAL_CATALOG_REVISION,
        "relations": {
            "records": { "identity": "native.query-sql.records", "semantic_version": 1 }
        },
        "sql": "SELECT id,name FROM records WHERE type=?1 AND kind=?2",
        "parameters": [{ "type": "text", "value": "Document" }, { "type": "text", "value": "sheet" }],
        "output": {
            "columns": governed_columns(),
            "schema_sha256": schema_sha,
            "row_identity": ["id"],
            "order": [
                { "column": "name", "direction": "asc" },
                { "column": "id", "direction": "asc" }
            ]
        },
        "bounds": { "rows": GOVERNED_ROW_CAP }
    })
}

/// Two-port artifact: `board` is the 768-child folder, `rows` is the governed
/// SQL sidecar. Both ports are exercised below (`native.inputs.board.records`
/// lanes plus a `RecordTable` over `native.inputs.rows.relation.rows`);
/// interactions stay bound to the writable folder port because relation ports
/// are read-only by construction.
fn two_port_source(schema_sha: &str) -> String {
    format!(
        r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{
    board: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }},
    rows: {{
      envelope: "native.relation-envelope.v1", required: true, expose_to_root: true,
      schema_sha256: "{schema_sha}",
      relations: {{ records: {{ identity: "native.query-sql.records", semantic_version: 1 }} }}
    }}
  }},
  module_inputs: {{}},
  capability_requests: [
    {{ capability: "input.read", scope: {{ port: "board" }} }},
    {{ capability: "input.read", scope: {{ port: "rows" }} }},
    {{ capability: "navigation.record.user_gesture", scope: {{}} }}
  ],
  interactions: [
    {{ id: "to_untriaged", label: "Untriaged", effect: "facet.set", slots: {{ record: {{ domain: {{ kind: "bound_input", port: "board" }} }} }}, facet: "triage", value: {{ from: "literal", value: "untriaged" }} }},
    {{ id: "to_triaged", label: "Triaged", effect: "facet.set", slots: {{ record: {{ domain: {{ kind: "bound_input", port: "board" }} }} }}, facet: "triage", value: {{ from: "literal", value: "triaged" }} }},
    {{ id: "to_committed", label: "Committed", effect: "facet.set", slots: {{ record: {{ domain: {{ kind: "bound_input", port: "board" }} }} }}, facet: "triage", value: {{ from: "literal", value: "committed" }} }}
  ]
}}

<div class="board">
  <div class="lane">
    <DropTarget entry="to_untriaged">
      {{native.inputs.board.records.filter(r => r.facets.triage === "untriaged").map(r => <RecordCard record={{r}} fields={{["kind"]}} draggable={{true}} />)}}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_triaged">
      {{native.inputs.board.records.filter(r => r.facets.triage === "triaged").map(r => <RecordCard record={{r}} fields={{["kind"]}} draggable={{true}} />)}}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_committed">
      {{native.inputs.board.records.filter(r => r.facets.triage === "committed").map(r => <RecordCard record={{r}} fields={{["kind"]}} draggable={{true}} />)}}
    </DropTarget>
  </div>
  <div class="sidecar">
    <RecordTable records={{native.inputs.rows.relation.rows}} columns={{["name"]}} />
  </div>
</div>
"#
    )
}

/// Print the content-free `include_timing` split next to the outer wall time
/// so the two can be compared directly: per-phase microseconds, cache state,
/// typed compile/execute/validate totals, and this-render record/byte counts.
fn print_timing_split(rendered: &Value, elapsed: Duration) {
    let timing = rendered
        .pointer("/plan/timing")
        .or_else(|| rendered.get("timing"));
    let Some(timing) = timing else {
        println!("  timing: <absent>");
        return;
    };
    let phases = timing
        .get("phases")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut ordered: Vec<(&String, u64)> = phases
        .iter()
        .map(|(name, micros)| (name, micros.as_u64().unwrap_or(0)))
        .collect();
    ordered.sort_by_key(|item| std::cmp::Reverse(item.1));
    let phase_sum: u64 = ordered.iter().map(|(_, micros)| micros).sum();
    println!(
        "  timing: wall={}ms phases_sum={}ms cache={} input_records={} output_nodes={}",
        elapsed.as_millis(),
        phase_sum / 1_000,
        timing.pointer("/cache/state").unwrap_or(&Value::Null),
        timing.get("input_records").unwrap_or(&Value::Null),
        timing.get("output_nodes").unwrap_or(&Value::Null),
    );
    for (name, micros) in ordered {
        println!("    phase {name}  {micros}us");
    }
    println!(
        "    compile={} execute={} validate={} input_bytes={} output_bytes={}",
        timing.get("compile_micros").unwrap_or(&Value::Null),
        timing.get("execute_micros").unwrap_or(&Value::Null),
        timing.get("validate_micros").unwrap_or(&Value::Null),
        timing.get("input_json_bytes").unwrap_or(&Value::Null),
        timing.get("output_json_bytes").unwrap_or(&Value::Null),
    );
}

async fn run_two_port() {
    let db = create_database(":memory:").await.unwrap();
    let mut registry = ToolRegistry::new();
    register_surface_tools(&mut registry).unwrap();
    // Unmeasured provisioning (see `seed_member_identity`); the clock starts
    // at `build` below and every call from there on is the member caller.
    seed_member_identity(&registry, &db).await;
    let caller = member_caller();
    let children = folder_children();

    let schema_sha = governed_schema_sha256();
    let created = call_as(
        &registry,
        &db,
        caller.clone(),
        "create_record",
        json!({ "id": TWO_PORT_ARTIFACT, "type": "Document", "kind": "artifact",
                "name": "Backlog board (two-port)",
                "body": two_port_source(&schema_sha),
                "facets": { "runtime": "native.mdx.v2" },
                "reason": "Measure the 768-record two-port render under real authorization." }),
    )
    .await;
    assert_tool_ok(&created, "create two-port artifact");

    // Five nested folders below `native:root` (levels 0..4): each level's
    // `home_id` is its parent, so a leaf child has five folder ancestors plus
    // `native:root`, and every per-ancestor authorization check in the render
    // has five folder hops to fold.
    let mut parent = "native:root".to_string();
    for level in 0..FOLDER_DEPTH {
        let id = folder_id(level);
        let folder = call_as(
            &registry,
            &db,
            caller.clone(),
            "create_record",
            json!({ "id": id, "type": "Collection", "kind": "folder",
                    "name": format!("Bench depth {level}"), "home_id": parent,
                    "reason": "Nest the benchmark folder to ancestor depth five." }),
        )
        .await;
        assert_tool_ok(&folder, "create benchmark folder");
        parent = id;
    }
    let leaf = parent;

    let definition = governed_definition_value(&schema_sha);
    let query = call_as(
        &registry,
        &db,
        caller.clone(),
        "create_record",
        json!({ "id": TWO_PORT_QUERY, "type": "Collection", "kind": "query",
                "name": "Benchmark governed sidecar",
                "facets": { "query": serde_json::to_string(&definition).unwrap() },
                "reason": "Carry the capped governed SQL sidecar definition." }),
    )
    .await;
    assert_tool_ok(&query, "create governed query Collection");

    // Dedicated sidecar population for the governed port: `GOVERNED_ROW_CAP`
    // `kind:sheet` Documents filed under the depth-0 folder, outside the
    // bound leaf's subtree so the board port never sees them. Unmeasured
    // setup like the folders above; the clock below covers only the board
    // children. `sheet` is a governed `kind:Document` value disjoint from the
    // board's `note` children and the artifact's own `artifact` kind.
    let sidecar_home = folder_id(0);
    for index in 0..GOVERNED_ROW_CAP {
        let record = call_as(
            &registry,
            &db,
            caller.clone(),
            "create_record",
            json!({ "id": sidecar_id(index), "type": "Document", "kind": "sheet",
                    "home_id": sidecar_home,
                    "name": filler(107, index + 100_000),
                    "summary": filler(120, index + 200_000),
                    "reason": "Populate the governed sidecar population." }),
        )
        .await;
        assert_tool_ok(&record, "create sidecar record");
    }

    let lanes = ["untriaged", "triaged", "committed"];
    let build = Instant::now();
    for index in 0..children {
        let id = folder_child_id(index);
        let record = call_as(
            &registry,
            &db,
            caller.clone(),
            "create_record",
            json!({ "id": id, "type": "Document", "kind": "note", "home_id": leaf,
                    "name": filler(107, index), "summary": filler(387, index + 1_000),
                    "facets": { "triage": lanes[index % lanes.len()], "area": "artifacts",
                                "filed_by": "Claude", "source": filler(60, index + 2_000) },
                    "reason": "Populate the two-port benchmark folder." }),
        )
        .await;
        assert_tool_ok(&record, "create benchmark child");
    }
    let built = build.elapsed();

    for (port_name, collection_id) in [("board", leaf.as_str()), ("rows", TWO_PORT_QUERY)] {
        let bound = call_as(
            &registry,
            &db,
            caller.clone(),
            "manage_artifact_inputs",
            json!({ "action": "bind", "artifact_id": TWO_PORT_ARTIFACT,
                    "port_name": port_name, "collection_id": collection_id }),
        )
        .await;
        assert_eq!(bound["status"], "bound", "{bound:#}");
    }
    grant_two_port_capabilities(&registry, &db, caller.clone()).await;

    println!(
        "two-port fixture  {children} folder children at depth {FOLDER_DEPTH} + governed sidecar cap {GOVERNED_ROW_CAP}  build={built:?}"
    );
    for attempt in 1..=3 {
        let started = Instant::now();
        let rendered = call_as(
            &registry,
            &db,
            caller.clone(),
            "render_artifact",
            json!({ "id": TWO_PORT_ARTIFACT, "include_timing": true }),
        )
        .await;
        let elapsed = started.elapsed();
        assert_eq!(rendered["status"], "rendered", "{rendered:#}");
        // The render saw the whole folder port: `input_records` counts this
        // render only, so it must cover at least the folder children. The
        // governed sidecar's 300-row cap is enforced by the saved definition's
        // bounds rather than the output — the render carries no sidecar row
        // count short of walking the plan tree, so no cap assertion here.
        let timing = rendered
            .pointer("/plan/timing")
            .expect("two-port render carries plan.timing");
        let input_records = timing
            .get("input_records")
            .and_then(Value::as_u64)
            .expect("timing carries input_records");
        assert!(
            input_records as usize >= children,
            "render saw all {children} folder children (input_records={input_records})"
        );
        let plan = serde_json::to_string(&rendered["plan"]).unwrap();
        println!(
            "render {attempt}  {elapsed:?}  cache={}  plan {} bytes",
            rendered["plan"]["cache"]["state"],
            plan.len(),
        );
        print_timing_split(&rendered, elapsed);
    }
}

/// Grant the two-port source's requests as the same member caller:
/// `input.read` on both ports plus root navigation.
async fn grant_two_port_capabilities(registry: &ToolRegistry, db: &Db, caller: Caller) {
    let subjects = call_as(
        registry,
        db,
        caller.clone(),
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": TWO_PORT_ARTIFACT }),
    )
    .await;
    let subject = subjects["subjects"]
        .as_array()
        .and_then(|subjects| subjects.first().cloned())
        .unwrap_or_else(|| panic!("the artifact source requests capabilities: {subjects:#}"));
    for (capability, scope) in [
        ("input.read", json!({ "artifact_port": "board" })),
        ("input.read", json!({ "artifact_port": "rows" })),
        ("navigation.record.user_gesture", json!({})),
    ] {
        let granted = call_as(
            registry,
            db,
            caller.clone(),
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": TWO_PORT_ARTIFACT,
                "subject_kind": "artifact_source", "subject_record_id": TWO_PORT_ARTIFACT,
                "subject_event_id": subject["subject_event_id"],
                "source_sha256": subject["source_sha256"],
                "capability": capability, "scope": scope
            }),
        )
        .await;
        assert!(granted.get("error").is_none(), "{granted:#}");
    }
}

/// Grant every capability the board's source requests — `input.read` for the
/// bound port and `navigation.record.user_gesture` for its cards. Rendering
/// refuses at preflight without both.
async fn grant_requested_capabilities(registry: &ToolRegistry, db: &Db) {
    let subjects = call(
        registry,
        db,
        "manage_artifact_module_grants",
        json!({ "action": "read", "artifact_id": ARTIFACT }),
    )
    .await;
    let subject = subjects["subjects"]
        .as_array()
        .and_then(|subjects| subjects.first().cloned())
        .unwrap_or_else(|| panic!("the artifact source requests capabilities: {subjects:#}"));
    // The request scope names the port; the grant scope names
    // `artifact_port`, and navigation is a root request that must be granted
    // at exactly the empty scope it asks for.
    for (capability, scope) in [
        ("input.read", json!({ "artifact_port": "board" })),
        ("navigation.record.user_gesture", json!({})),
    ] {
        let granted = call(
            registry,
            db,
            "manage_artifact_module_grants",
            json!({
                "action": "grant", "artifact_id": ARTIFACT, "subject_kind": "artifact_source",
                "subject_record_id": ARTIFACT,
                "subject_event_id": subject["subject_event_id"],
                "source_sha256": subject["source_sha256"],
                "capability": capability, "scope": scope
            }),
        )
        .await;
        assert!(granted.get("error").is_none(), "{granted:#}");
    }
}
