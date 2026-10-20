//! Gated host-only run authority. A ledger run ID is NOT a principal ID:
//! it links a fixed owning principal to one separate `kind=run` principal.
//! Contexts are Rust host handles, never deserializable request attribution.
use super::*;

pub(super) const DDL: &str = "CREATE TABLE kernel_runs (id TEXT PRIMARY KEY, owner_principal TEXT NOT NULL REFERENCES kernel_principals(principal_id), run_principal TEXT NOT NULL UNIQUE REFERENCES kernel_principals(principal_id), opened_seq INTEGER NOT NULL, head INTEGER NOT NULL, closed INTEGER NOT NULL CHECK(closed IN (0,1)))";
pub(super) const OWNER_INDEX_DDL: &str =
    "CREATE INDEX idx_kernel_runs_owner ON kernel_runs(owner_principal,opened_seq)";
pub(crate) const OPEN: &str = "kernel.run_opened.v1";
pub(crate) const INTENT: &str = "kernel.run_intent_set.v1";
pub(crate) const CLOSE: &str = "kernel.run_closed.v1";

#[derive(Clone)]
pub struct RunContext {
    run_id: String,
    owner: String,
    genesis_id: String,
}
impl std::fmt::Debug for RunContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunContext(<host-minted>)")
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Witness {
    pub run_id: String,
    pub owner: String,
    pub run_principal: String,
    pub head: i64,
    pub closed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenPayload {
    owner: String,
    run_principal: String,
}

// Owned v2 has no v1 database_identity table. The immutable, host-minted
// kernel genesis event identifies this logical database and survives replay.
async fn genesis_identity(conn: &mut SqliteConnection) -> Result<String> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM content_events WHERE type=? AND record_id=? AND actor=?",
    )
    .bind(KERNEL_GENESIS_EVENT)
    .bind(KERNEL_ROOT_ID)
    .bind(KERNEL_GENESIS_ACTOR)
    .fetch_all(conn)
    .await?;
    if ids.len() != 1 {
        return Err(Error::engine("run context requires one kernel genesis"));
    }
    Ok(ids.into_iter().next().expect("one genesis"))
}
async fn host(conn: &mut SqliteConnection, actor: &str) -> Result<()> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_root_bootstrap WHERE principal_id=?)",
    )
    .bind(actor)
    .fetch_one(conn)
    .await?;
    if !authorized {
        return Err(Error::engine(
            "run registration requires kernel host authority",
        ));
    }
    Ok(())
}
/// Internal verified-host adapter only; no tool or public arbitrary-owner registration.
#[allow(dead_code)] // Hosted activation is intentionally outside this gated slice.
pub(crate) async fn register_run_as(
    db: &Db,
    host_principal: &str,
    owner: &str,
    run_principal: &str,
) -> Result<RunContext> {
    let mut tx = begin_write(db.write_pool()).await?;
    host(&mut tx, host_principal).await?;
    let id = Uuid::new_v4().to_string();
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_kernel_run_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: OPEN.into(),
            payload: serde_json::to_value(OpenPayload {
                owner: owner.into(),
                run_principal: run_principal.into(),
            })?,
            actor: Some(host_principal.into()),
        },
        &mut acts,
    )
    .await?;
    let genesis_id = genesis_identity(&mut tx).await?;
    tx.commit().await?;
    Ok(RunContext {
        run_id: id,
        owner: owner.into(),
        genesis_id,
    })
}
/// Recover an opaque context only after the host has authenticated this principal.
/// It can resolve closed runs for receipt-only retries; mutation separately refuses close.
#[allow(dead_code)]
pub(crate) async fn context_as(
    db: &Db,
    authenticated_owner: &str,
    run_id: &str,
) -> Result<RunContext> {
    let mut tx = db.write_pool().begin().await?;
    let w = witness(&mut tx, run_id).await?;
    if w.owner != authenticated_owner {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let genesis_id = genesis_identity(&mut tx).await?;
    Ok(RunContext {
        run_id: run_id.into(),
        owner: w.owner,
        genesis_id,
    })
}
pub(super) async fn resolve(
    conn: &mut SqliteConnection,
    context: &RunContext,
    require_open: bool,
) -> Result<Witness> {
    if genesis_identity(conn).await? != context.genesis_id {
        return Err(Error::engine("run context database mismatch"));
    }
    let w = witness(conn, &context.run_id).await?;
    if w.owner != context.owner {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    if require_open && w.closed {
        return Err(Error::engine("run_closed"));
    }
    Ok(w)
}
pub(super) async fn witness(conn: &mut SqliteConnection, run_id: &str) -> Result<Witness> {
    let row: Option<(String, String, i64, bool)> = sqlx::query_as(
        "SELECT owner_principal,run_principal,head,closed FROM kernel_runs WHERE id=?",
    )
    .bind(run_id)
    .fetch_optional(conn)
    .await?;
    let (owner, run_principal, head, closed) = row.ok_or_else(|| Error::engine("unknown_run"))?;
    Ok(Witness {
        run_id: run_id.into(),
        owner,
        run_principal,
        head,
        closed,
    })
}
#[allow(dead_code)]
pub(crate) async fn close_run_as(db: &Db, context: &RunContext) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let w = resolve(&mut tx, context, true).await?;
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_kernel_run_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: w.run_id,
            event_type: CLOSE.into(),
            payload: serde_json::json!({"expected_head":w.head}),
            actor: Some(w.owner),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let logged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND actor IS ? AND payload IS ? AND created_at=?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(&event.event_type).bind(&event.actor).bind(&event.payload).bind(&event.created_at).fetch_one(&mut *conn).await?;
    if !logged {
        return Err(Error::engine(
            "run projection requires the kernel-issued logged event",
        ));
    }
    match event.event_type.as_str() {
        OPEN => {
            let p: OpenPayload = event_payload(event)?;
            if event.actor.as_deref() != Some(&p.owner) {
                host(conn, event.actor.as_deref().unwrap_or_default()).await?;
            }
            let owner_kind: Option<String> =
                sqlx::query_scalar("SELECT kind FROM kernel_principals WHERE principal_id=?")
                    .bind(&p.owner)
                    .fetch_optional(&mut *conn)
                    .await?;
            let run_kind: Option<String> =
                sqlx::query_scalar("SELECT kind FROM kernel_principals WHERE principal_id=?")
                    .bind(&p.run_principal)
                    .fetch_optional(&mut *conn)
                    .await?;
            if !matches!(owner_kind.as_deref(), Some("account" | "agent"))
                || run_kind.as_deref() != Some("run")
                || Uuid::parse_str(&event.record_id).is_err()
            {
                return Err(Error::engine("invalid kernel run linkage"));
            }
            sqlx::query("INSERT INTO kernel_runs(id,owner_principal,run_principal,opened_seq,head,closed) VALUES(?,?,?,?,?,0)").bind(&event.record_id).bind(p.owner).bind(p.run_principal).bind(event.local_seq).bind(event.local_seq).execute(conn).await?;
        }
        INTENT => {
            let p: IntentPayload = event_payload(event)?;
            let w = witness(conn, &event.record_id).await?;
            if w.closed || w.head != p.expected_head || event.actor.as_deref() != Some(&w.owner) {
                return Err(Error::conflict("run intent witness mismatch"));
            }
            if p.intent.len() > 32768 {
                return Err(Error::engine("run intent exceeds byte limit"));
            }
            sqlx::query("UPDATE kernel_runs SET head=? WHERE id=?")
                .bind(event.local_seq)
                .bind(&event.record_id)
                .execute(conn)
                .await?;
        }
        CLOSE => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct ClosePayload {
                expected_head: i64,
            }
            let p: ClosePayload = event_payload(event)?;
            let w = witness(conn, &event.record_id).await?;
            if w.closed || w.head != p.expected_head || event.actor.as_deref() != Some(&w.owner) {
                return Err(Error::conflict("run close witness mismatch"));
            }
            sqlx::query("UPDATE kernel_runs SET closed=1,head=? WHERE id=?")
                .bind(event.local_seq)
                .bind(&event.record_id)
                .execute(conn)
                .await?;
        }
        _ => return Err(Error::engine("unknown run ledger event")),
    }
    Ok(())
}

/// Host adapter: the authenticated principal can only open its own run.
/// Run keys correlate requests; they are never authority or actor attribution.
/// An existing key is resolved only for its owner, including closed receipt retries.
pub(crate) async fn reject_historical_key_on(conn: &mut SqliteConnection, key: &str) -> Result<()> {
    if historical_key_on(conn, key).await? {
        return Err(Error::engine(
            "historical imported run cannot authorize runtime writes; bootstrap a new run",
        ));
    }
    Ok(())
}
async fn historical_key_on(conn: &mut SqliteConnection, key: &str) -> Result<bool> {
    let historical:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_v1_state WHERE section IN ('runs','run_intents','claims') AND json_extract(payload,'$.run_key')=?1 UNION ALL SELECT 1 FROM kernel_v1_state WHERE section IN ('member_obligations','member_obligation_progress') AND json_extract(payload,'$.updated_run_key')=?1 UNION ALL SELECT 1 FROM content_events WHERE run_key=?1 AND type='kernel.legacy_recorded.v1')").bind(key).fetch_one(conn).await?;
    Ok(historical)
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn reject_historical_key_as(db: &Db, key: &str) -> Result<()> {
    let mut conn = db.write_pool().acquire().await?;
    reject_historical_key_on(&mut conn, key).await
}
pub async fn open_run_as(db: &Db, authenticated_principal: &str, key: &str) -> Result<RunContext> {
    if !matches!(
        crate::runkey::validate_full(Some(key)),
        crate::runkey::KeyOutcome::Valid(_)
    ) {
        return Err(Error::engine("invalid full run key"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    reject_historical_key_on(&mut tx, key).await?;
    let binding = format!("mcp-run:{key}");
    let existing: Option<String> = sqlx::query_scalar("SELECT r.id FROM kernel_runs r JOIN kernel_principals p ON p.principal_id=r.run_principal WHERE p.auth_binding=?")
        .bind(&binding).fetch_optional(&mut *tx).await?;
    let genesis_id = genesis_identity(&mut tx).await?;
    if let Some(id) = existing {
        let w = witness(&mut tx, &id).await?;
        if w.owner != authenticated_principal {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
        return Ok(RunContext {
            run_id: id,
            owner: w.owner,
            genesis_id,
        });
    }
    let kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM kernel_principals WHERE principal_id=?")
            .bind(authenticated_principal)
            .fetch_optional(&mut *tx)
            .await?;
    if !matches!(kind.as_deref(), Some("account" | "agent")) {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let id = Uuid::new_v4().to_string();
    let run_principal = Uuid::new_v4().to_string();
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: run_principal.clone(),
            event_type: KERNEL_PRINCIPAL_CREATED_EVENT.into(),
            payload: serde_json::json!({"kind":"run", "display_label":key, "auth_binding":binding}),
            actor: Some(authenticated_principal.into()),
        },
        &mut acts,
    )
    .await?;
    crate::store::append_kernel_run_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: id.clone(),
            event_type: OPEN.into(),
            payload: serde_json::to_value(OpenPayload {
                owner: authenticated_principal.into(),
                run_principal,
            })?,
            actor: Some(authenticated_principal.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(RunContext {
        run_id: id,
        owner: authenticated_principal.into(),
        genesis_id,
    })
}

impl RunContext {
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
}

/// Mint using the existing storage-free run-key vocabulary and collision rules.
pub async fn mint_run_as(db: &Db, principal: &str, agent_key: Option<&str>) -> Result<String> {
    Ok(mint_run_with_context_as(db, principal, agent_key).await?.0)
}

/// Keep the context from admission when bootstrap also needs the run state.
pub(crate) async fn mint_run_with_context_as(
    db: &Db,
    principal: &str,
    agent_key: Option<&str>,
) -> Result<(String, RunContext)> {
    let keys: Vec<String> = sqlx::query_scalar("SELECT substr(auth_binding,9) FROM kernel_principals WHERE kind='run' AND auth_binding LIKE 'mcp-run:%'")
        .fetch_all(db.write_pool()).await?;
    let mut taken = keys.into_iter().collect();
    loop {
        let key = match agent_key {
            Some(agent) => crate::runkey::mint_run_for_agent(agent, &taken)?,
            None => crate::runkey::mint_fresh_agent_run(&taken)?,
        };
        let mut conn = db.write_pool().acquire().await?;
        let historical = historical_key_on(&mut conn, &key).await?;
        drop(conn);
        if historical {
            taken.insert(key);
            continue;
        }
        // Admission rechecks inside the write transaction, fencing concurrent
        // imports; a source key can never gain native authority.
        let context = open_run_as(db, principal, &key).await?;
        return Ok((key, context));
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IntentPayload {
    expected_head: i64,
    intent: String,
}
async fn intent_on(conn: &mut SqliteConnection, run: &str) -> Result<Option<IntentPayload>> {
    let json: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(run)
    .bind(INTENT)
    .fetch_optional(conn)
    .await?;
    json.map(|s| serde_json::from_str(&s).map_err(Into::into))
        .transpose()
}
pub async fn run_intent_as(db: &Db, context: &RunContext) -> Result<Option<String>> {
    let mut tx = db.write_pool().begin().await?;
    let w = resolve(&mut tx, context, false).await?;
    Ok(intent_on(&mut tx, &w.run_id).await?.map(|p| p.intent))
}
/// Intent is event sourced; repeats with identical content append nothing.
/// Model declarations are omitted by the MCP adapter in this slice.
pub async fn set_run_intent_as(db: &Db, context: &RunContext, intent: &str) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let w = resolve(&mut tx, context, true).await?;
    let old = intent_on(&mut tx, &w.run_id).await?;
    if old.as_ref().is_some_and(|p| p.intent == intent) {
        return Ok(());
    }
    if intent.len() > 32768 {
        return Err(Error::engine("run intent exceeds byte limit"));
    }
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_kernel_run_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: w.run_id,
            event_type: INTENT.into(),
            payload: serde_json::to_value(IntentPayload {
                expected_head: w.head,
                intent: intent.into(),
            })?,
            actor: Some(w.owner),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
/// Idempotent host close, with owner checked by the opaque context.
pub async fn finish_run_as(db: &Db, context: &RunContext) -> Result<bool> {
    let mut tx = begin_write(db.write_pool()).await?;
    let w = resolve(&mut tx, context, false).await?;
    if w.closed {
        return Ok(false);
    }
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_kernel_run_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: w.run_id,
            event_type: CLOSE.into(),
            payload: serde_json::json!({"expected_head":w.head}),
            actor: Some(w.owner),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

/// Observe the authenticated owner's run, including its closed state.
pub async fn run_witness_as(db: &Db, context: &RunContext) -> Result<Witness> {
    let mut conn = db.write_pool().acquire().await?;
    resolve(&mut conn, context, false).await
}
