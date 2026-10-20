//! App actions are user actions. Admission, effects and their attribution
//! share one transaction/act; private facts never advance an artifact clock.
use super::*;

pub(in crate::kernel::app_installs) const ACTION_STARTED: &str = "kernel.app_action_started.v1";
pub(in crate::kernel::app_installs) const ACTION_RECORDED: &str = "kernel.app_action_recorded.v1";
pub(crate) const ACTIONS_DDL: &str = "CREATE TABLE kernel_app_actions (
 event_id TEXT PRIMARY KEY, admitted_event_id TEXT NOT NULL UNIQUE,
 principal TEXT NOT NULL, package TEXT NOT NULL, version TEXT NOT NULL,
 install_generation TEXT NOT NULL, revocation_epoch INTEGER NOT NULL,
 operation TEXT NOT NULL, request_digest TEXT NOT NULL,
 outputs_json TEXT NOT NULL CHECK(json_valid(outputs_json)),
 event_seq INTEGER NOT NULL REFERENCES content_events(seq))";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Started {
    format: u32,
    account: String,
    package: String,
    version: String,
    generation: String,
    install_event_seq: i64,
    revocation_epoch: i64,
    frozen_source_seq: i64,
    pin: Value,
    operation: String,
    request_digest: String,
    reason: Option<String>,
}

impl Started {
    fn request(&self) -> Result<InstallRequest> {
        Ok(InstallRequest {
            package: self.package.clone(),
            version: self.version.clone(),
            digest: string(&self.pin, "digest")?.into(),
            artifact_id: string(&self.pin, "artifact_id")?.into(),
            source_revision: string(&self.pin, "source_revision")?.into(),
            declaration: serde_json::from_str(string(&self.pin, "consented_declaration")?)?,
            reason: "Verify the retained app action witness".into(),
            request: None,
            idempotency_key: None,
            expected_install_event_id: Some(self.generation.clone()),
        })
    }

    fn validate(&self) -> Result<()> {
        if self.format != 1
            || self.package.is_empty()
            || self.version.is_empty()
            || self.generation.is_empty()
            || self.account.is_empty()
            || self.install_event_seq <= 0
            || self.frozen_source_seq <= 0
            || self.revocation_epoch < 0
            || self.operation.is_empty()
            || !self
                .operation
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'_')
            || self.request_digest.len() != 64
            || !self
                .request_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(invalid("invalid app action admission"));
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
#[serde(deny_unknown_fields)]
struct Output {
    event_id: String,
    record_id: String,
    event_seq: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    format: u32,
    admitted_event_id: String,
    outputs: Vec<Output>,
}

#[derive(sqlx::FromRow)]
struct StartWitness {
    local_seq: i64,
    id: String,
    record_id: String,
    event_type: String,
    payload: String,
    actor: Option<String>,
    act: Option<i64>,
}

/// Opaque, transaction-local witness. There is no public constructor and no
/// deserialization path that could turn an old approval into live authority.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) struct PendingAppAction {
    event: EventRow,
    facts: Started,
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn start_app_action_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    actor: &str,
    operation: &str,
    request_digest: String,
    reason: Option<String>,
    acts: &mut crate::act::ActAllocation,
) -> Result<Option<Box<PendingAppAction>>> {
    let Some(admitted) = crate::kernel::app_installs::admit_dispatched_on(tx, actor).await? else {
        return Ok(None);
    };
    if !matches!(
        operation,
        "attach_text" | "create_record" | "update_record" | "manage_links" | "archive_record"
    ) {
        return Err(Error::engine(
            "native app write attribution is unavailable for this operation",
        ));
    }
    let facts = Started {
        format: 1,
        account: admitted.account,
        package: admitted.package,
        version: admitted.version,
        generation: admitted.generation,
        install_event_seq: admitted.install_event_seq,
        revocation_epoch: admitted.revocation_epoch,
        frozen_source_seq: admitted.frozen_source_seq,
        pin: admitted.pin,
        operation: operation.into(),
        request_digest,
        reason,
    };
    facts.validate()?;
    let event = append_in(
        db,
        tx,
        AppendSpec {
            record_id: aggregate(actor, &facts.package),
            event_type: ACTION_STARTED.into(),
            actor: Some(actor.into()),
            payload: serde_json::to_value(&facts)?,
        },
        acts,
    )
    .await?;
    Ok(Some(Box::new(PendingAppAction { event, facts })))
}

async fn outputs_between(
    conn: &mut SqliteConnection,
    start_seq: i64,
    act: Option<i64>,
    before: i64,
) -> Result<Vec<Output>> {
    let act = act.ok_or_else(|| invalid("app action has no act"))?;
    Ok(sqlx::query_as("SELECT id AS event_id,record_id,seq AS event_seq FROM main.content_events WHERE act=? AND seq>? AND seq<? ORDER BY seq")
        .bind(act).bind(start_seq).bind(before).fetch_all(conn).await?)
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn finish_app_action_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    actor: &str,
    pending: Option<Box<PendingAppAction>>,
    acts: &mut crate::act::ActAllocation,
) -> Result<Option<Value>> {
    let Some(pending) = pending else {
        return Ok(None);
    };
    if pending.event.actor.as_deref() != Some(actor) || pending.event.act != acts.get() {
        return Err(invalid("app action transaction identity changed"));
    }
    let outputs = outputs_between(tx, pending.event.local_seq, pending.event.act, i64::MAX).await?;
    let event = append_in(
        db,
        tx,
        AppendSpec {
            record_id: pending.event.record_id.clone(),
            event_type: ACTION_RECORDED.into(),
            actor: Some(actor.into()),
            payload: serde_json::to_value(Recorded {
                format: 1,
                admitted_event_id: pending.event.id.clone(),
                outputs,
            })?,
        },
        acts,
    )
    .await?;
    Ok(Some(
        json!({"schema":"native.app-action.v1","event_id":event.id,
        "admitted_event_id":pending.event.id,"package":pending.facts.package,
        "version":pending.facts.version,"install_event_id":pending.facts.generation}),
    ))
}

/// The sealed writer checks live source View before this fact is appended.
/// Replay checks the historical consent/source witnesses without applying
/// today's hosted roster or source permissions to a past accepted action.
pub(in crate::kernel::app_installs) async fn project_started(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: Started = event_payload(event)?;
    p.validate()?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("app action actor missing"))?;
    if event.record_id != aggregate(actor, &p.package)
        || event.act.is_none()
        || require_member(conn, actor, event.local_seq).await? != p.account
    {
        return Err(invalid("app action account/aggregate witness changed"));
    }
    let request = p.request()?;
    let source = source_on(conn, &request).await?;
    let current: Option<(String,String,String,bool,Option<String>,i64)> = sqlx::query_as(
        "SELECT row_json,generation,status,executable,refusal,event_seq FROM kernel_app_installs WHERE principal=? AND package=?",
    ).bind(actor).bind(&p.package).fetch_optional(&mut *conn).await?;
    let Some((raw, generation, status, executable, refusal, seq)) = current else {
        return Err(invalid("app action consent witness missing"));
    };
    let row: Value = serde_json::from_str(&raw)?;
    let declaration: Value = serde_json::from_str(string(&row, "consented_declaration")?)?;
    if generation != p.generation
        || status != "installed"
        || !executable
        || refusal.is_some()
        || seq != p.install_event_seq
        || seq >= event.local_seq
        || source.event_seq != p.frozen_source_seq
        || source.event_seq >= event.local_seq
        || p.pin != source.pin
        || row["version"] != p.version
        || row["digest"] != request.digest
        || row["artifact_id"] != request.artifact_id
        || row["consented_source_revision"] != request.source_revision
        || declaration != request.declaration
        || row["adoption"] != "shell_adopt.v1"
        || row["consent_revocation_seq"].as_i64().unwrap_or(0) != p.revocation_epoch
        || revocation_on(conn, actor, event.local_seq).await? != p.revocation_epoch
    {
        return Err(invalid("app action consent/source witness changed"));
    }
    Ok(())
}

pub(in crate::kernel::app_installs) async fn project_recorded(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: Recorded = event_payload(event)?;
    if p.format != 1 {
        return Err(invalid("invalid recorded app action"));
    }
    let start: StartWitness = sqlx::query_as("SELECT seq AS local_seq,id,record_id,type AS event_type,payload,actor,act FROM main.content_events WHERE id=?")
        .bind(&p.admitted_event_id).fetch_optional(&mut *conn).await?
        .ok_or_else(|| invalid("app action admission witness missing"))?;
    let facts: Started = serde_json::from_str(&start.payload)?;
    facts.validate()?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("app action actor missing"))?;
    if start.event_type != ACTION_STARTED
        || start.local_seq >= event.local_seq
        || start.actor != event.actor
        || start.record_id != event.record_id
        || start.act.is_none()
        || start.act != event.act
        || event.record_id != aggregate(actor, &facts.package)
        || outputs_between(conn, start.local_seq, start.act, event.local_seq).await? != p.outputs
    {
        return Err(invalid("app action output/act witness changed"));
    }
    sqlx::query("INSERT INTO kernel_app_actions VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .bind(&event.id)
        .bind(&start.id)
        .bind(actor)
        .bind(&facts.package)
        .bind(&facts.version)
        .bind(&facts.generation)
        .bind(facts.revocation_epoch)
        .bind(&facts.operation)
        .bind(&facts.request_digest)
        .bind(serde_json::to_string(&p.outputs)?)
        .bind(event.local_seq)
        .execute(conn)
        .await?;
    Ok(())
}

/// Additive explicit preparation can recover completed action rows from the
/// retained sealed admission/output witnesses. Live admission never calls it.
pub(in crate::kernel::app_installs) async fn ensure_schema(
    conn: &mut SqliteConnection,
) -> Result<()> {
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='kernel_app_actions')")
        .fetch_one(&mut *conn).await?;
    if present {
        return Ok(());
    }
    sqlx::query(ACTIONS_DDL).execute(&mut *conn).await?;
    let events =
        crate::conformance::rebuild::read_events_of_types(conn, &[ACTION_RECORDED]).await?;
    for event in events {
        project_recorded(conn, &event).await?;
    }
    Ok(())
}
