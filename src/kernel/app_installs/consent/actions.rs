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

// Decode-only 95 envelope. Canonical 94 serialization continues using Recorded.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded95 {
    format: u32,
    admitted_event_id: String,
    outputs: Vec<Output>,
    #[serde(default, deserialize_with = "ordinal95")]
    caller_write_ordinal: Option<i64>,
}

fn ordinal95<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> std::result::Result<Option<i64>, D::Error> {
    // Missing is allowed by default; a present null is not a producer shape.
    <i64 as Deserialize>::deserialize(decoder).map(Some)
}

async fn decode_recorded(
    conn: &mut SqliteConnection,
    event: &EventRow,
    admitted: Option<&crate::standby::kernel_v2_delta::ProjectionShape>,
) -> Result<Recorded> {
    let Some(payload) = event.payload.as_deref() else {
        return event_payload(event);
    };
    let value: serde_json::Value = serde_json::from_str(payload)?;
    if value.get("caller_write_ordinal").is_none() {
        return event_payload(event);
    }
    let observation_envelope = match admitted {
        Some(shape) => shape.observation_envelope(),
        None => crate::standby::shapes::on(conn).await?.observation_envelope,
    };
    if !observation_envelope {
        return Err(invalid("app action ordinal is not in this receiver shape"));
    }
    let p: Recorded95 = serde_json::from_value(value)?;
    let _preserved_in_event = p.caller_write_ordinal;
    Ok(Recorded {
        format: p.format,
        admitted_event_id: p.admitted_event_id,
        outputs: p.outputs,
    })
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

// These witnesses certify comparisons only. The fixed Update driver retains
// the actual W0 Open loan, local start/digest/args and SAME mutable act memo.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) enum RoutedActionBinding<'p> {
    App(RoutedAppBinding<'p>),
    NonApp(RoutedNonAppBinding),
}
#[cfg(feature = "v2-kernel-probe")]
struct RoutedScope {
    credential: String,
    principal: String,
    target: String,
    request_digest: String,
    app: Option<crate::mcp::app_attribution::AppAttribution>,
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) struct RoutedAppBinding<'p> {
    scope: RoutedScope,
    pending: &'p PendingAppAction,
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) struct RoutedNonAppBinding {
    scope: RoutedScope,
}
#[cfg(feature = "v2-kernel-probe")]
impl RoutedActionBinding<'_> {
    pub(crate) fn require_update_scope(
        &self,
        caller: &crate::mcp::registry::Caller,
        actor: &str,
        target: &str,
        acts: &crate::act::ActAllocation,
    ) -> Result<()> {
        let scope = match self {
            Self::App(binding) => {
                if binding.pending.facts.request_digest != binding.scope.request_digest
                    || binding.pending.event.act.is_none()
                    || binding.pending.event.act != acts.get()
                {
                    return Err(invalid("routed app action act changed"));
                }
                &binding.scope
            }
            // None at bind-time is NOT memo identity. Intervening metadata can
            // allocate the original memo; fixed-driver continuity is essential.
            Self::NonApp(binding) => &binding.scope,
        };
        if scope.credential != caller.credential()
            || scope.principal != actor
            || scope.target != target
            || scope.app.as_ref() != caller.host_asserted_app()
        {
            return Err(invalid("routed update scope changed"));
        }
        Ok(())
    }
}
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn bind_update_action_on<'p>(
    conn: &mut SqliteConnection,
    pending: Option<&'p PendingAppAction>,
    caller: &crate::mcp::registry::Caller,
    actor: &str,
    original_args: &Value,
    original_request_digest: &str,
    acts: &crate::act::ActAllocation,
) -> Result<RoutedActionBinding<'p>> {
    let principal = crate::mcp::kernel_v2::principal_on(conn, caller).await?;
    if principal != actor {
        return Err(invalid("routed update principal changed"));
    }
    let target = original_args
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("routed update target missing"))?;
    let scope = RoutedScope {
        credential: caller.credential().to_owned(),
        principal,
        target: target.to_owned(),
        request_digest: original_request_digest.to_owned(),
        app: caller.host_asserted_app().cloned(),
    };
    let ambient = crate::provenance::current_app_claim();
    let admitted = crate::kernel::app_installs::admit_dispatched_on(conn, actor).await?;
    let Some(claim) = caller.host_asserted_app() else {
        if pending.is_some() || ambient.is_some() || admitted.is_some() {
            return Err(invalid("routed non-app absence disagreement"));
        }
        return Ok(RoutedActionBinding::NonApp(RoutedNonAppBinding { scope }));
    };
    if !ambient
        .as_ref()
        .is_some_and(|(_, app)| app.as_ref() == claim)
    {
        return Err(invalid("routed app dispatch disagreement"));
    }
    let admitted = admitted.ok_or_else(|| invalid("routed app admission missing"))?;
    let pending = pending.ok_or_else(|| invalid("routed app start missing"))?;
    let f = &pending.facts;
    if pending.event.actor.as_deref() != Some(actor)
        || pending.event.act.is_none()
        || pending.event.act != acts.get()
        || pending.event.record_id != aggregate(actor, &claim.package)
        || pending.event.event_type != ACTION_STARTED
        || f.operation != "update_record"
        || f.request_digest != original_request_digest
        || admitted.principal != actor
        || f.account != admitted.account
        || f.package != admitted.package
        || f.version != admitted.version
        || f.generation != admitted.generation
        || f.package != claim.package
        || f.version != claim.version
        || f.generation != claim.install_event_id
        || f.install_event_seq != admitted.install_event_seq
        || f.revocation_epoch != admitted.revocation_epoch
        || f.frozen_source_seq != admitted.frozen_source_seq
        || f.pin != admitted.pin
    {
        return Err(invalid("routed app start/source identity changed"));
    }
    let row: StartWitness = sqlx::query_as("SELECT seq AS local_seq,id,record_id,type AS event_type,payload,actor,act FROM main.content_events WHERE id=?")
        .bind(&pending.event.id).fetch_optional(&mut *conn).await?
        .ok_or_else(|| invalid("routed app start row missing"))?;
    if row.local_seq != pending.event.local_seq
        || row.id != pending.event.id
        || row.record_id != pending.event.record_id
        || row.event_type != pending.event.event_type
        || row.actor != pending.event.actor
        || row.act != pending.event.act
        || Some(row.payload.as_str()) != pending.event.payload.as_deref()
        || serde_json::from_str::<Value>(&row.payload)? != serde_json::to_value(f)?
    {
        return Err(invalid("routed app start row changed"));
    }
    Ok(RoutedActionBinding::App(RoutedAppBinding {
        scope,
        pending,
    }))
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn start_app_action_in(
    db: &Db,
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    operation: &str,
    request_digest: String,
    reason: Option<String>,
    acts: &mut crate::act::ActAllocation,
) -> Result<Option<Box<PendingAppAction>>> {
    let Some(admitted) = crate::kernel::app_installs::admit_dispatched_on(tx, actor).await? else {
        return Ok(None);
    };
    start_declared_app_action_in(
        db,
        tx,
        actor,
        std::sync::Arc::unwrap_or_clone(admitted),
        operation,
        request_digest,
        reason,
        acts,
    )
    .await
}

#[cfg(feature = "v2-kernel-probe")]
#[allow(clippy::too_many_arguments)]
pub(crate) async fn start_declared_app_action_in(
    db: &Db,
    tx: &mut sqlx::SqliteConnection,
    actor: &str,
    admitted: AppSourceAdmission,
    operation: &str,
    request_digest: String,
    reason: Option<String>,
    acts: &mut crate::act::ActAllocation,
) -> Result<Option<Box<PendingAppAction>>> {
    if admitted.principal != actor {
        return Err(invalid("app action principal changed"));
    }
    if !matches!(
        operation,
        "attach_text"
            | "create_record"
            | "update_record"
            | "merge_body"
            | "manage_links"
            | "archive_record"
            | "manage_canvas"
            | "manage_messages"
            | "invoke_artifact_interaction"
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
    let event = crate::store::append_on(
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
    tx: &mut sqlx::SqliteConnection,
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
    let event = crate::store::append_on(
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
        || !row["adoption"].as_str().is_some_and(verified_adoption)
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
    admitted: Option<&crate::standby::kernel_v2_delta::ProjectionShape>,
) -> Result<()> {
    let p = decode_recorded(conn, event, admitted).await?;
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
        project_recorded(conn, &event, None).await?;
    }
    Ok(())
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
#[test]
fn receiver95_recorded_decoder_is_closed_and_rejects_null_ordinal() {
    let old = serde_json::json!({"format":1,"admitted_event_id":"event","outputs":[]});
    let before =
        serde_json::to_vec(&serde_json::from_value::<Recorded>(old.clone()).unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(serde_json::from_slice::<Recorded>(&before).unwrap()).unwrap(),
        old
    );
    let mut new = old.clone();
    new["caller_write_ordinal"] = serde_json::json!(1);
    assert!(serde_json::from_value::<Recorded>(new.clone()).is_err());
    assert!(serde_json::from_value::<Recorded95>(new.clone()).is_ok());
    new["caller_write_ordinal"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<Recorded95>(new.clone()).is_err());
    new["caller_write_ordinal"] = serde_json::json!("1");
    assert!(serde_json::from_value::<Recorded95>(new.clone()).is_err());
    new["caller_write_ordinal"] = serde_json::json!(1);
    new["future_semantics"] = serde_json::json!(true);
    assert!(serde_json::from_value::<Recorded95>(new).is_err());
}
