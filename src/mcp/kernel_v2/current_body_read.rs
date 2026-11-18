//! Inactive current get_record composition. Ordinary output remains durable.
use super::*;
use crate::coedit::live::kernel_reads::{capture_current_bodies, CurrentReadRefusal};
use crate::kernel::body_evidence::NativeBodyBasis;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::time::Instant;

#[cfg(test)]
tokio::task_local! { static PROBE: (); }
#[cfg(test)]
pub(super) async fn with_current_body_probe<T>(work: impl std::future::Future<Output = T>) -> T {
    PROBE.scope((), work).await
}
#[cfg(test)]
pub(super) fn selected() -> bool {
    PROBE.try_with(|_| ()).is_ok()
}

pub(super) async fn get(db: &Db, caller: &Caller, args: Value) -> Result<Value> {
    let deadline = Instant::now() + get_batch_deadline();
    sql::require_no_read_session()?;
    let plan = Arc::new(get_plan(args)?);
    if plan.args.include_history_summary == Some(true) {
        return Err(Error::engine(
            "current body read: history enrichment requires a separate snapshot",
        ));
    }
    tokio::time::timeout_at(deadline, async {
        for attempt in 0..2 {
            let fence = capture_current_bodies(db, &plan.args.ids, deadline).await.map_err(Error::from)?;
            #[cfg(test)] checkpoint(db, Stage::AfterT1).await?;
            let room_ids = plan.args.ids.iter().filter(|id| fence.has_room(id)).cloned().collect::<std::collections::BTreeSet<_>>();
            let phase = materialize(db, caller, plan.clone(), room_ids).await?;
            #[cfg(test)] checkpoint(db, Stage::SqlClosed).await?;
            let (mut value, bases) = phase;
            match fence.validate(db, &bases).await {
                Ok(observations) => {
                    for row in value["records"].as_array_mut().ok_or_else(|| Error::engine("current body read: malformed staging result"))? {
                        if row["status"] != "found" { continue; }
                        let id = row["id"].as_str().ok_or_else(|| Error::engine("current body read: missing record id"))?;
                        let basis = bases.iter().find(|b| b.record_id == id).ok_or_else(|| Error::engine("current body read: virtual-root or unsupported record evidence"))?;
                        let observation = observations.iter().find(|o| o.record_id == id).ok_or_else(|| Error::engine("current body read: missing validation"))?;
                        let record_version = format!("rec:{}",basis.record_revision);
                        if row["body"] != json!(basis.body) || row["body_digest"] != json!(basis.digest)
                            || row["version"] != json!(record_version) || row["record_version"] != json!(record_version) {
                            return Err(Error::engine("current body read: durable formatter/evidence disagreement"));
                        }
                        let event = event_value(basis);
                        let committed = json!({"record_version":record_version,"body_present":basis.body.is_some(),"body_digest":basis.digest,"body_event":event});
                        let durable_revision = revision("d", json!(["native.body-revision.v1","durable",db.handle_id().to_string(),basis.record_id,
                            basis.birth.id,basis.body.is_some(),basis.digest,
                            basis.event.as_ref().map(|e|e.id.as_str()),basis.event.as_ref().map(|e|e.seq.to_string())]))?;
                        let live = if let Some(live) = &observation.live {
                            let token = revision("l",json!(["native.body-revision.v1","live",db.handle_id().to_string(),basis.record_id,
                                basis.birth.id,live.session,live.session,live.epoch.to_string(),true,live.digest,
                                basis.body.is_some(),basis.digest,basis.event.as_ref().map(|e|e.id.as_str()),basis.event.as_ref().map(|e|e.seq.to_string())]))?;
                            json!({"contract":"native.live-body.v1","state":"live","revision":token,"body":live.body,"body_present":true,
                                "body_digest":live.digest,"total_bytes":live.body.len(),"room_state":live.room_state,"dirty":live.dirty,"committed":committed})
                        } else { Value::Null };
                        row["body_read_contract"] = json!("native.current-body.v1");
                        row["body_basis"] = committed;
                        row["body_basis"]["revision"] = json!(durable_revision);
                        row["live_body"] = live;
                    }
                    encoded_size_within(&value, crate::query::sql_contract::MAX_RESULT_ENCODED_BYTES)?;
                    if Instant::now() >= deadline { return Err(CurrentReadRefusal::Deadline.into()); }
                    return Ok(value);
                }
                Err(CurrentReadRefusal::ChangedBasis) if attempt == 0 => {
                    #[cfg(test)] checkpoint(db, Stage::Retry).await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(Error::engine("current body read: repeated revision change"))
    }).await.map_err(|_| Error::engine("current body read: original batch deadline exceeded; no partial result"))?
}
/// Count escaping and all metadata through a capped sink, retaining no copy.
pub(super) fn encoded_size_within(value: &Value, limit: usize) -> Result<usize> {
    struct Capped {
        written: usize,
        limit: usize,
    }
    impl std::io::Write for Capped {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.written) {
                return Err(std::io::Error::other(
                    "current get_record encoded response cap exceeded",
                ));
            }
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Capped { written: 0, limit };
    serde_json::to_writer(&mut sink, value).map_err(|_| {
        Error::engine("current get_record exceeds encoded response limit; no partial result")
    })?;
    Ok(sink.written)
}
fn revision(tag: &str, coordinates: Value) -> Result<String> {
    let bytes = serde_json::to_vec(&coordinates)?;
    Ok(format!(
        "body:v1:{tag}:{}",
        hex::encode(Sha256::digest(bytes))
    ))
}
fn event_value(basis: &NativeBodyBasis) -> Value {
    basis.event.as_ref().map_or(
        Value::Null,
        |event| json!({"id":event.id,"seq":event.seq.to_string()}),
    )
}
async fn materialize(
    db: &Db,
    caller: &Caller,
    plan: Arc<GetPlan>,
    rooms: std::collections::BTreeSet<String>,
) -> Result<(Value, Vec<NativeBodyBasis>)> {
    let ids = plan.args.ids.clone();
    let reads = [
        ("records", "id"),
        ("records", "type"),
        ("records", "kind"),
        ("records", "name"),
        ("records", "archived"),
        ("records", "created_at"),
        ("records", "home_id"),
        ("links", "source_id"),
        ("links", "target_id"),
        ("links", "relationship"),
    ];
    sql::with_current_materialization(db, caller, &reads, &ids, |actor| async move {
        #[cfg(test)]
        checkpoint(db, Stage::SnapshotReady).await?;
        // All staging/hydration/enrichment borrows this strict owned session.
        let value = kernel::read_cache::with_capabilities(get_record_from_shared_plan_bounded(
            db,
            &actor,
            plan,
            Some(crate::query::sql_contract::MAX_RESULT_ENCODED_BYTES),
        ))
        .await?;
        let mut bases = Vec::new();
        for row in value["records"]
            .as_array()
            .ok_or_else(|| Error::engine("current body read: missing records"))?
        {
            if row["status"] != "found" {
                continue;
            }
            let id = row["id"]
                .as_str()
                .ok_or_else(|| Error::engine("current body read: missing id"))?
                .to_owned();
            let actual_actor = actor.clone();
            let is_live = rooms.contains(&id);
            let basis = sql::in_snapshot(db, &actor, move |conn| {
                Box::pin(async move {
                    let view = kernel::read_record_on(conn, &actual_actor, &id)
                        .await?
                        .ok_or_else(|| Error::engine(kernel::HIDDEN_OR_MISSING))?;
                    if is_live {
                        crate::coedit::kernel_v2::require_live_scope_on(conn, &actual_actor, &view)
                            .await?;
                    }
                    kernel::body_evidence::read_body_basis_on(conn, &view).await
                })
            })
            .await?;
            bases.push(basis);
        }
        #[cfg(test)]
        checkpoint(db, Stage::SqlMaterialized).await?;
        Ok((value, bases))
    })
    .await
    .map(sql::ClosedCurrentGet::into_owned)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Stage {
    AfterT1,
    SnapshotReady,
    SqlMaterialized,
    SqlRolledBack,
    SqlClosed,
    Retry,
}
#[cfg(test)]
pub(super) struct Gate {
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,
    fail: bool,
}
#[cfg(test)]
type Gates = std::collections::HashMap<(std::path::PathBuf, Stage), Arc<Gate>>;
#[cfg(test)]
static GATES: std::sync::LazyLock<std::sync::Mutex<Gates>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Gates::new()));
#[cfg(test)]
pub(super) fn gate(db: &Db, stage: Stage) -> Arc<Gate> {
    gate_with_failure(db, stage, false)
}
#[cfg(test)]
pub(super) fn gate_with_failure(db: &Db, stage: Stage, fail: bool) -> Arc<Gate> {
    let gate = Arc::new(Gate {
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
        fail,
    });
    GATES
        .lock()
        .unwrap()
        .insert((db.live_session_key().to_path_buf(), stage), gate.clone());
    gate
}
#[cfg(test)]
pub(super) async fn checkpoint(db: &Db, stage: Stage) -> Result<()> {
    let gate = GATES
        .lock()
        .unwrap()
        .remove(&(db.live_session_key().to_path_buf(), stage));
    if let Some(gate) = gate {
        gate.entered.notify_one();
        gate.release.notified().await;
        if gate.fail {
            return Err(Error::engine(
                "injected current read boundary failure; no closed candidate",
            ));
        }
    }
    Ok(())
}
